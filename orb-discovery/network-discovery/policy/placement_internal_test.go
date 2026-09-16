package policy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

// twoVrfMap is the case the whole feature exists for: one policy scanning
// subnets that belong to two different prebuilt VRFs.
func twoVrfMap() []config.SubnetMapEntry {
	return []config.SubnetMapEntry{
		{Prefix: "192.0.2.0/25", Vrf: "CORP", Tenant: "Corp"},
		{Prefix: "192.0.2.128/25", Vrf: "LAB", VrfTenant: "Labs", Tenant: "Lab-A"},
	}
}

// An address is filed in the VRF and tenant of the subnet it was found in, not
// in the policy's. Without this a policy could only ever populate one VRF.
func TestAddressTakesItsSubnetsVrfAndTenant(t *testing.T) {
	entries := twoVrfMap()
	r := prefixRunner(t, config.Defaults{Vrf: "FALLBACK", Tenant: "Fallback"}, entries)
	r.targets = parseTargets([]string{"192.0.2.0/24"})

	corpAddr, corpEntry := r.resolveAddress("192.0.2.10", "/32")
	corp, _ := r.ipAddressEntity(scannedHost("a.example.net"), corpAddr, "192.0.2.10", corpEntry, "p", nil)
	labAddr, labEntry := r.resolveAddress("192.0.2.200", "/32")
	lab, _ := r.ipAddressEntity(scannedHost("b.example.net"), labAddr, "192.0.2.200", labEntry, "p", nil)

	require.NotNil(t, corp.Vrf)
	require.NotNil(t, lab.Vrf)
	assert.Equal(t, "CORP", *corp.Vrf.Name)
	assert.Equal(t, "LAB", *lab.Vrf.Name)
	assert.Equal(t, "Corp", *corp.Tenant.Name)
	assert.Equal(t, "Lab-A", *lab.Tenant.Name)

	// Each prefix matches the addresses inside it, which is what lets NetBox
	// nest them.
	prefixes := r.prefixEntities(nil, "p")
	require.Len(t, prefixes, 2)
	assert.Equal(t, "CORP", *prefixes[0].(*diode.Prefix).Vrf.Name)
	assert.Equal(t, "LAB", *prefixes[1].(*diode.Prefix).Vrf.Name)
	assert.Equal(t, "Corp", *prefixes[0].(*diode.Prefix).Tenant.Name)
}

// The VRF's three identity fields are taken from one source or the other, never
// mixed. A reference pairing an entry's name with the defaults' rd describes a
// VRF that does not exist, and Diode answers that by creating one.
func TestEntryVrfDoesNotInheritDefaultsIdentity(t *testing.T) {
	entries := []config.SubnetMapEntry{{Prefix: "192.0.2.0/24", Vrf: "CORP"}}
	r := prefixRunner(t, config.Defaults{
		Vrf: "LAB", Rd: "65000:9", VrfTenant: "Labs", TenantGroup: "Groups",
	}, entries)

	vrf := r.prefixEntities(nil, "p")[0].(*diode.Prefix).Vrf
	require.NotNil(t, vrf)
	assert.Equal(t, "CORP", *vrf.Name)
	assert.Nil(t, vrf.Rd, "the defaults' rd describes the defaults' VRF, not this one")
	assert.Nil(t, vrf.Tenant, "the defaults' vrf_tenant describes the defaults' VRF, not this one")
}

// An entry with no vrf of its own inherits all three defaults fields together,
// which is the pre-existing single-VRF policy, unchanged.
func TestEntryWithoutVrfInheritsTheDefaults(t *testing.T) {
	entries := []config.SubnetMapEntry{{Prefix: "192.0.2.0/24"}}
	r := prefixRunner(t, config.Defaults{Vrf: "LAB", Rd: "65000:9"}, entries)

	vrf := r.prefixEntities(nil, "p")[0].(*diode.Prefix).Vrf
	require.NotNil(t, vrf)
	assert.Equal(t, "LAB", *vrf.Name)
	require.NotNil(t, vrf.Rd)
	assert.Equal(t, "65000:9", *vrf.Rd)
}

// A tenant group is inherited rather than taken atomically, since a deployment's
// tenants usually share one, and an entry whose tenant lives elsewhere says so.
func TestEntryTenantCarriesTheRightGroup(t *testing.T) {
	entries := []config.SubnetMapEntry{
		{Prefix: "192.0.2.0/25", Tenant: "Corp"},
		{Prefix: "192.0.2.128/25", Tenant: "Partner", TenantGroup: "External"},
	}
	r := prefixRunner(t, config.Defaults{Vrf: "LAB", Tenant: "Fallback", TenantGroup: "Internal"}, entries)

	prefixes := r.prefixEntities(nil, "p")
	inherited := prefixes[0].(*diode.Prefix).Tenant
	overridden := prefixes[1].(*diode.Prefix).Tenant
	require.NotNil(t, inherited.Group)
	require.NotNil(t, overridden.Group)
	assert.Equal(t, "Internal", *inherited.Group.Name)
	assert.Equal(t, "External", *overridden.Group.Name)
}

// defaults.prefix.tenant sits between the entry's tenant and defaults.tenant, so
// a deployment can own its prefixes and its addresses with different tenants.
// The entry still wins over both.
func TestPrefixTenantPrecedence(t *testing.T) {
	defaults := config.Defaults{Vrf: "LAB", Tenant: "AddressOwner"}
	defaults.Prefix.Tenant = "PrefixOwner"

	assert.Equal(t, "PrefixOwner", *prefixPlacement(defaults, nil).tenant.Name)
	assert.Equal(t, "AddressOwner", *addressPlacement(defaults, nil).tenant.Name)

	entry := &config.SubnetMapEntry{Prefix: "192.0.2.0/24", Tenant: "SubnetOwner"}
	assert.Equal(t, "SubnetOwner", *prefixPlacement(defaults, entry).tenant.Name)
	assert.Equal(t, "SubnetOwner", *addressPlacement(defaults, entry).tenant.Name)
}

// use_target_masks turns off inferring a mask from what was scanned. A
// subnet_map entry is not an inference, and suppressing it would leave a loose
// /32 beside the prefix the same policy just declared.
func TestSubnetMapOutranksUseTargetMasks(t *testing.T) {
	off := false
	entries := []config.SubnetMapEntry{{Prefix: "192.0.2.0/25"}}
	r := prefixRunner(t, config.Defaults{Vrf: "LAB"}, entries)
	r.targets = parseTargets([]string{"192.0.2.0/24"})
	r.scope.UseTargetMasks = &off

	matched, entry := r.resolveAddress("192.0.2.10", "/32")
	assert.Equal(t, "192.0.2.10/25", matched)
	assert.NotNil(t, entry)

	// Outside the map, use_target_masks: false still suppresses the target mask.
	unmatched, entry := r.resolveAddress("192.0.2.200", "/32")
	assert.Equal(t, "192.0.2.200/32", unmatched)
	assert.Nil(t, entry)
}

// An entry's custom_fields describe its subnet, so they reach the addresses in
// it as well as its prefix.
func TestEntryCustomFieldsReachTheAddress(t *testing.T) {
	entries := []config.SubnetMapEntry{
		{Prefix: "192.0.2.0/25", CustomFields: map[string]any{"lab_id": "312"}},
		{Prefix: "192.0.2.128/25"},
	}
	r := prefixRunner(t, config.Defaults{Vrf: "LAB"}, entries)
	r.targets = parseTargets([]string{"192.0.2.0/24"})

	base := map[string]any{"discovery_source": "network_discovery"}
	cache := r.entryCustomFieldCache(base)

	inside, entry := r.resolveAddress("192.0.2.10", "/32")
	ip, _ := r.ipAddressEntity(scannedHost("a.example.net"), inside, "192.0.2.10", entry, "p",
		entryCustomFields(base, entry, cache))
	assert.Contains(t, ip.CustomFields, "lab_id")
	assert.Contains(t, ip.CustomFields, "discovery_source")

	// A sibling subnet that declares none keeps the policy-wide fields alone.
	outside, other := r.resolveAddress("192.0.2.200", "/32")
	sibling, _ := r.ipAddressEntity(scannedHost("b.example.net"), outside, "192.0.2.200", other, "p",
		entryCustomFields(base, other, cache))
	assert.NotContains(t, sibling.CustomFields, "lab_id")
	assert.Contains(t, sibling.CustomFields, "discovery_source")

	// The policy-wide map itself is untouched, so the merge cannot leak between
	// subnets over a run.
	assert.NotContains(t, base, "lab_id")
}

// TestDryRunMultiVrfGolden is the multi-VRF counterpart to TestDryRunPrefixGolden:
// it walks a two-VRF subnet_map through the real dry-run client and asserts on
// the serialized payload NetBox will receive. What matters is that each address
// carries the same vrf as the prefix declared for its subnet, that the two
// subnets do not bleed into each other, and that each vrf object has exactly the
// shape its prebuilt VRF needs to be matched rather than duplicated.
func TestDryRunMultiVrfGolden(t *testing.T) {
	// Same escape hatch as TestDryRunPrefixGolden: point the env var at a
	// directory to keep the payload for inspection.
	outputDir := os.Getenv("NETWORK_DISCOVERY_DRYRUN_DIR")
	if outputDir == "" {
		outputDir = t.TempDir()
	}
	client, err := diode.NewDryRunClient("network-discovery", outputDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	entries := []config.SubnetMapEntry{
		{Prefix: "10.1.0.0/24", Vrf: "CORP", VrfTenant: "Corp", Tenant: "Corp"},
		{Prefix: "10.2.0.0/24", Tenant: "Lab-A"},
	}
	r := prefixRunner(t, config.Defaults{Vrf: "LAB-A", Tenant: "Fallback", TenantGroup: "Labs"}, entries)
	r.client = client
	r.targets = parseTargets([]string{"10.1.0.0/24", "10.2.0.0/24"})

	entities := r.prefixEntities(nil, "multi")
	for _, addr := range []string{"10.1.0.5", "10.2.0.5"} {
		masked, entry := r.resolveAddress(addr, "/32")
		ip, _ := r.ipAddressEntity(scannedHost(""), masked, addr, entry, "multi", nil)
		entities = append(entities, ip)
	}
	_, err = client.Ingest(context.Background(), entities)
	require.NoError(t, err)

	files, err := filepath.Glob(filepath.Join(outputDir, "*.json"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	t.Logf("dry-run output: %s", files[0])
	body, err := os.ReadFile(files[0])
	require.NoError(t, err)

	type ref struct {
		Name   string         `json:"name"`
		Tenant map[string]any `json:"tenant"`
		Group  map[string]any `json:"group"`
	}
	var payload struct {
		Entities []struct {
			Prefix *struct {
				Prefix string `json:"prefix"`
				Vrf    *ref   `json:"vrf"`
				Tenant *ref   `json:"tenant"`
			} `json:"prefix"`
			IPAddress *struct {
				Address string `json:"address"`
				Vrf     *ref   `json:"vrf"`
				Tenant  *ref   `json:"tenant"`
			} `json:"ip_address"`
		} `json:"entities"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))
	require.Len(t, payload.Entities, 4)

	corpPrefix, labPrefix := payload.Entities[0].Prefix, payload.Entities[1].Prefix
	corpAddr, labAddr := payload.Entities[2].IPAddress, payload.Entities[3].IPAddress
	require.NotNil(t, corpPrefix)
	require.NotNil(t, labPrefix)
	require.NotNil(t, corpAddr)
	require.NotNil(t, labAddr)

	assert.Equal(t, "10.1.0.0/24", corpPrefix.Prefix)
	assert.Equal(t, "10.2.0.0/24", labPrefix.Prefix)
	assert.Equal(t, "10.1.0.5/24", corpAddr.Address, "the address takes its subnet's mask")
	assert.Equal(t, "10.2.0.5/24", labAddr.Address)

	// Each address is in the VRF of its own prefix, which is what lets NetBox
	// file one under the other.
	assert.Equal(t, "CORP", corpPrefix.Vrf.Name)
	assert.Equal(t, "CORP", corpAddr.Vrf.Name)
	assert.Equal(t, "LAB-A", labPrefix.Vrf.Name)
	assert.Equal(t, "LAB-A", labAddr.Vrf.Name)

	// The entry's vrf carries its own vrf_tenant and nothing from the defaults;
	// the entry that names no vrf gets the defaults' name-only reference.
	require.NotNil(t, corpAddr.Vrf.Tenant)
	assert.Equal(t, "Corp", corpAddr.Vrf.Tenant["name"])
	assert.Nil(t, labAddr.Vrf.Tenant, "defaults.vrf has no vrf_tenant, so its reference must stay name-only")

	// Each entry's tenant owns its prefix and its addresses, and every tenant
	// reference carries the group, without which none of them would be found.
	for _, r := range []*ref{corpPrefix.Tenant, corpAddr.Tenant} {
		require.NotNil(t, r)
		assert.Equal(t, "Corp", r.Name)
	}
	for _, r := range []*ref{labPrefix.Tenant, labAddr.Tenant} {
		require.NotNil(t, r)
		assert.Equal(t, "Lab-A", r.Name)
	}
	for _, r := range []*ref{corpPrefix.Tenant, corpAddr.Tenant, labPrefix.Tenant, labAddr.Tenant} {
		require.NotNil(t, r.Group, "a group-less tenant reference matches nothing and Diode duplicates it")
		assert.Equal(t, "Labs", r.Group["name"])
	}
}
