package policy

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

func boolPtr(v bool) *bool { return &v }

// nestedMap is a parent, child and grandchild, validated so every entry carries
// its parsed network.
func nestedMap(t *testing.T) []config.SubnetMapEntry {
	t.Helper()
	entries := []config.SubnetMapEntry{
		{Prefix: "192.0.2.0/24", Status: "container", Role: "lab-aggregate"},
		{Prefix: "192.0.2.0/25", Role: "lab-servers"},
		{Prefix: "192.0.2.128/26", Role: "lab-gpu"},
	}
	require.NoError(t, config.ValidateSubnetMap(entries, testLogger()))
	return entries
}

// An address resolves to the most specific entry containing it, never a wider
// one, regardless of the order the entries were written in.
func TestSubnetMatcherLongestPrefixWins(t *testing.T) {
	matcher := newSubnetMatcher(nestedMap(t))
	for _, tt := range []struct{ ip, want string }{
		{"192.0.2.10", "192.0.2.0/25"},
		{"192.0.2.127", "192.0.2.0/25"},
		{"192.0.2.130", "192.0.2.128/26"},
		{"192.0.2.200", "192.0.2.0/24"},
	} {
		t.Run(tt.ip, func(t *testing.T) {
			entry := matcher.match(net.ParseIP(tt.ip))
			require.NotNil(t, entry)
			assert.Equal(t, tt.want, entry.Network().String())
		})
	}
	assert.Nil(t, matcher.match(net.ParseIP("198.51.100.1")))
}

// A nil matcher is the zero-configuration case and must not panic.
func TestSubnetMatcherNilSafe(t *testing.T) {
	var m *subnetMatcher
	assert.True(t, m.empty())
	assert.Nil(t, m.match(net.ParseIP("192.0.2.1")))
	assert.True(t, newSubnetMatcher(nil).empty())
}

// A matched address takes the mask of its entry, so it lands inside the prefix
// rather than as a loose /32. An unmatched one keeps the pre-existing
// target-mask behaviour.
func TestGetIPWithMaskPrefersSubnetMap(t *testing.T) {
	r := &Runner{
		logger:  testLogger(),
		targets: parseTargets([]string{"192.0.2.0/24", "198.51.100.0/24"}),
		matcher: newSubnetMatcher(nestedMap(t)),
	}
	assert.Equal(t, "192.0.2.10/25", r.getIPWithMask("192.0.2.10", "/32"))
	assert.Equal(t, "192.0.2.130/26", r.getIPWithMask("192.0.2.130", "/32"))
	assert.Equal(t, "192.0.2.200/24", r.getIPWithMask("192.0.2.200", "/32"))
	// Inside a target but outside the map: the target mask still applies.
	assert.Equal(t, "198.51.100.9/24", r.getIPWithMask("198.51.100.9", "/32"))
	// Outside both: the configured default.
	assert.Equal(t, "203.0.113.9/32", r.getIPWithMask("203.0.113.9", "/32"))
}

func TestGetIPWithMaskWithoutSubnetMap(t *testing.T) {
	r := &Runner{
		logger:  testLogger(),
		targets: parseTargets([]string{"192.0.2.0/24"}),
		matcher: newSubnetMatcher(nil),
	}
	assert.Equal(t, "192.0.2.10/24", r.getIPWithMask("192.0.2.10", "/32"))
}

func prefixRunner(t *testing.T, defaults config.Defaults, entries []config.SubnetMapEntry) *Runner {
	t.Helper()
	require.NoError(t, config.ValidateSubnetMap(entries, testLogger()))
	return &Runner{
		logger:    testLogger(),
		agentName: "lab-agent-01",
		matcher:   newSubnetMatcher(entries),
		scope:     config.Scope{Targets: []string{"192.0.2.0/24"}, SubnetMap: entries},
		config:    config.PolicyConfig{Defaults: defaults},
	}
}

// No subnet_map means no prefixes, which is what keeps an existing policy
// emitting addresses alone.
func TestNoPrefixesWithoutSubnetMap(t *testing.T) {
	r := prefixRunner(t, config.Defaults{Vrf: "LAB-A"}, nil)
	assert.Nil(t, r.prefixEntities(nil, "p"))
}

// The VRF reference carries the name and nothing else, which is what makes the
// Diode NetBox plugin match a prebuilt VRF instead of creating a second one:
// its name-only criterion applies only while rd and tenant are both null.
func TestPrefixVrfReferenceIsNameOnly(t *testing.T) {
	defaults := config.Defaults{Vrf: "LAB-A", Tenant: "LAB-A-TENANT"}
	r := prefixRunner(t, defaults, nestedMap(t))
	prefix := r.prefixEntities(nil, "p")[0].(*diode.Prefix)

	require.NotNil(t, prefix.Vrf)
	assert.Equal(t, "LAB-A", *prefix.Vrf.Name)
	assert.Nil(t, prefix.Vrf.Rd, "an rd the prebuilt VRF lacks stops it matching")
	assert.Nil(t, prefix.Vrf.Tenant,
		"defaults.tenant must not leak onto the VRF: that would switch matching to (name, tenant) "+
			"and miss a tenant-less prebuilt VRF. vrf_tenant is the opt-in for that.")
	// The tenant belongs on the prefix, not on the VRF reference.
	require.NotNil(t, prefix.Tenant)
	assert.Equal(t, "LAB-A-TENANT", *prefix.Tenant.Name)
}

// The reference must be able to mirror a prebuilt VRF that carries an rd or a
// tenant. The plugin skips any matcher whose fields are absent from the payload,
// so a name-only reference can only find a VRF that has neither, and Diode
// creates a second VRF instead of matching.
func TestPrefixVrfMirrorsThePrebuiltShape(t *testing.T) {
	t.Run("rd", func(t *testing.T) {
		r := prefixRunner(t, config.Defaults{Vrf: "LAB-A", Rd: "65000:1"}, nestedMap(t))
		vrf := r.prefixEntities(nil, "p")[0].(*diode.Prefix).Vrf
		require.NotNil(t, vrf.Rd)
		assert.Equal(t, "65000:1", *vrf.Rd)
		assert.Nil(t, vrf.Tenant)
	})

	t.Run("tenant", func(t *testing.T) {
		// vrf_tenant is separate from defaults.tenant on purpose: that one
		// describes the prefix and the address, this one makes the VRF match.
		r := prefixRunner(t, config.Defaults{Vrf: "LAB-A", Tenant: "LAB-A", VrfTenant: "312"}, nestedMap(t))
		prefix := r.prefixEntities(nil, "p")[0].(*diode.Prefix)
		require.NotNil(t, prefix.Vrf.Tenant)
		assert.Equal(t, "312", *prefix.Vrf.Tenant.Name)
		assert.Equal(t, "LAB-A", *prefix.Tenant.Name, "the prefix keeps its own tenant")
		assert.Nil(t, prefix.Vrf.Rd)
	})

	t.Run("address and prefix agree", func(t *testing.T) {
		r := prefixRunner(t, config.Defaults{Vrf: "LAB-A", VrfTenant: "312"}, nestedMap(t))
		r.targets = parseTargets([]string{"192.0.2.0/24"})
		prefix := r.prefixEntities(nil, "p")[0].(*diode.Prefix)
		ip, _ := r.ipAddressEntity(scannedHost("h.example.net"), "192.0.2.10/25", "192.0.2.10", "p", nil)
		require.NotNil(t, ip.Vrf.Tenant)
		assert.Equal(t, *prefix.Vrf.Tenant.Name, *ip.Vrf.Tenant.Name,
			"a reference that differs between the two would split them across two VRFs")
	})
}

// Every entry becomes a prefix in the same VRF, with no parent reference:
// NetBox derives the hierarchy from containment, so nesting is its job.
func TestPrefixEntitiesShape(t *testing.T) {
	defaults := config.Defaults{
		Vrf:    "LAB-A",
		Tenant: "LAB-A",
		Tags:   []string{"orb"},
		Prefix: config.PrefixDefaults{Status: "active", Role: "lab-data", IsPool: boolPtr(false)},
	}
	r := prefixRunner(t, defaults, nestedMap(t))
	entities := r.prefixEntities(nil, "p")
	require.Len(t, entities, 3)

	container := entities[0].(*diode.Prefix)
	assert.Equal(t, "192.0.2.0/24", *container.Prefix)
	assert.Equal(t, "container", *container.Status, "an entry status overrides defaults.prefix.status")
	require.NotNil(t, container.Role)
	assert.Equal(t, "lab-aggregate", *container.Role.Name)
	require.NotNil(t, container.IsPool)
	assert.False(t, *container.IsPool)
	assert.Nil(t, container.MarkUtilized, "an unset field is left off so NetBox keeps its own value")
	// A prefix carries its site through the tenant, never as a scope.
	assert.Nil(t, container.Scope)
	require.Len(t, container.Tags, 1)

	child := entities[1].(*diode.Prefix)
	assert.Equal(t, "192.0.2.0/25", *child.Prefix)
	assert.Equal(t, "active", *child.Status, "an unset entry status falls back to defaults.prefix.status")
	assert.Equal(t, "lab-servers", *child.Role.Name)
	assert.Equal(t, *container.Vrf.Name, *child.Vrf.Name, "children must share the parent's VRF to nest")
}

// An unset defaults.prefix block leaves those attributes off entirely, so Diode
// omits them and NetBox keeps what it has.
func TestPrefixEntitiesLeaveUnsetFieldsAlone(t *testing.T) {
	r := prefixRunner(t, config.Defaults{}, []config.SubnetMapEntry{{Prefix: "192.0.2.0/24"}})
	prefix := r.prefixEntities(nil, "p")[0].(*diode.Prefix)
	assert.Nil(t, prefix.Status)
	assert.Nil(t, prefix.Role)
	assert.Nil(t, prefix.Vrf)
	assert.Nil(t, prefix.Tenant)
	assert.Nil(t, prefix.IsPool)
	assert.Nil(t, prefix.MarkUtilized)
	assert.Nil(t, prefix.Description)
	assert.Nil(t, prefix.Tags)
}

// Policy custom fields reach every prefix; an entry's own block extends them.
func TestPrefixCustomFields(t *testing.T) {
	entries := []config.SubnetMapEntry{
		{Prefix: "192.0.2.0/24"},
		{Prefix: "198.51.100.0/24", CustomFields: map[string]any{"lab_id": "312"}},
	}
	r := prefixRunner(t, config.Defaults{Vrf: "LAB-A"}, entries)
	entities := r.prefixEntities(map[string]any{"discovery_source": "network_discovery"}, "p")

	plain := entities[0].(*diode.Prefix)
	require.Len(t, plain.CustomFields, 1)
	assert.Equal(t, diode.CustomFieldValueText("network_discovery"), plain.CustomFields["discovery_source"].Value)

	extended := entities[1].(*diode.Prefix)
	require.Len(t, extended.CustomFields, 2)
	assert.Equal(t, diode.CustomFieldValueText("312"), extended.CustomFields["lab_id"].Value)
	assert.Equal(t, diode.CustomFieldValueText("network_discovery"), extended.CustomFields["discovery_source"].Value)
}

// The same network declared twice is emitted once per run.
func TestPrefixDedupe(t *testing.T) {
	entries := []config.SubnetMapEntry{{Prefix: "192.0.2.0/24"}}
	require.NoError(t, config.ValidateSubnetMap(entries, testLogger()))
	b := newPrefixBuilder(config.Defaults{}, testLogger(), "p")
	b.add(&entries[0], nil)
	b.add(&entries[0], nil)
	assert.Len(t, b.entities(), 1)
}

// An address and the prefix containing it must reach NetBox in the same VRF, or
// NetBox cannot place the address under the prefix.
func TestAddressAndPrefixShareTheVrf(t *testing.T) {
	entries := nestedMap(t)
	r := prefixRunner(t, config.Defaults{Vrf: "LAB-A", Tenant: "LAB-A"}, entries)
	r.targets = parseTargets([]string{"192.0.2.0/24"})

	prefix := r.prefixEntities(nil, "p")[1].(*diode.Prefix)
	ip, _ := r.ipAddressEntity(scannedHost("host.example.net"),
		r.getIPWithMask("192.0.2.10", "/32"), "192.0.2.10", "p", nil)

	assert.Equal(t, "192.0.2.0/25", *prefix.Prefix)
	assert.Equal(t, "192.0.2.10/25", *ip.Address, "the address takes its prefix's mask")
	require.NotNil(t, ip.Vrf)
	assert.Equal(t, *prefix.Vrf.Name, *ip.Vrf.Name)
	assert.Nil(t, ip.Vrf.Rd)
	assert.Nil(t, ip.Vrf.Tenant)
}

// TestDryRunPrefixGolden walks a nested subnet_map through the real dry-run
// client, which is the path `dry_run: true` takes in production. It is the only
// test that asserts on the serialized payload NetBox will actually receive.
func TestDryRunPrefixGolden(t *testing.T) {
	outputDir := os.Getenv("NETWORK_DISCOVERY_DRYRUN_DIR")
	if outputDir == "" {
		outputDir = t.TempDir()
	}
	client, err := diode.NewDryRunClient("network-discovery", outputDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	entries := []config.SubnetMapEntry{
		{Prefix: "192.0.2.0/24", Status: "container", Role: "lab-aggregate"},
		{Prefix: "192.0.2.0/25", Role: "lab-servers", CustomFields: map[string]any{"lab_id": "312"}},
	}
	r := prefixRunner(t, config.Defaults{Vrf: "LAB-A", Tenant: "LAB-A"}, entries)
	r.client = client
	r.targets = parseTargets([]string{"192.0.2.0/24"})

	fields := map[string]any{"discovery_source": "network_discovery"}
	entities := r.prefixEntities(fields, "lab_a_scan")
	ip, _ := r.ipAddressEntity(scannedHost("host.example.net"),
		r.getIPWithMask("192.0.2.10", "/32"), "192.0.2.10", "lab_a_scan", fields)
	entities = append(entities, ip)

	_, err = client.Ingest(context.Background(), entities)
	require.NoError(t, err)

	files, err := filepath.Glob(filepath.Join(outputDir, "*.json"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	t.Logf("dry-run output: %s", files[0])

	body, err := os.ReadFile(files[0])
	require.NoError(t, err)

	var payload struct {
		Entities []struct {
			Prefix *struct {
				Prefix string                 `json:"prefix"`
				Status string                 `json:"status"`
				Vrf    map[string]any         `json:"vrf"`
				Role   *struct{ Name string } `json:"role"`
			} `json:"prefix"`
			IPAddress *struct {
				Address string         `json:"address"`
				Vrf     map[string]any `json:"vrf"`
			} `json:"ip_address"`
		} `json:"entities"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))
	require.Len(t, payload.Entities, 3)

	container := payload.Entities[0].Prefix
	child := payload.Entities[1].Prefix
	addr := payload.Entities[2].IPAddress
	require.NotNil(t, container)
	require.NotNil(t, child)
	require.NotNil(t, addr)

	assert.Equal(t, "192.0.2.0/24", container.Prefix)
	assert.Equal(t, "container", container.Status)
	assert.Equal(t, "192.0.2.0/25", child.Prefix)
	assert.Equal(t, "lab-servers", child.Role.Name)
	// The address takes the child's mask, so NetBox files it under the /25.
	assert.Equal(t, "192.0.2.10/25", addr.Address)

	// All three reference one VRF, by name and nothing else. This is what makes
	// the plugin match a prebuilt VRF rather than create a second one, and what
	// lets NetBox nest the child under the parent and the address under the child.
	for _, vrf := range []map[string]any{container.Vrf, child.Vrf, addr.Vrf} {
		require.NotNil(t, vrf)
		assert.Equal(t, "LAB-A", vrf["name"])
		assert.NotContains(t, vrf, "rd")
		assert.NotContains(t, vrf, "tenant")
	}
}

// NetBox makes Tenant unique on (group, name) with nulls_distinct=False, so the
// plugin reads an absent group as "group IS NULL" rather than "any group". A
// group-less reference therefore cannot find a tenant that sits in a group, and
// Diode creates a duplicate outside it. Every tenant the agent emits has to
// carry the group when there is one.
func TestTenantReferenceCarriesTheGroup(t *testing.T) {
	t.Run("group set reaches prefix, vrf and address", func(t *testing.T) {
		defaults := config.Defaults{
			Vrf: "VRF-Lab-312", VrfTenant: "312", Tenant: "312", TenantGroup: "Labs",
		}
		r := prefixRunner(t, defaults, nestedMap(t))
		r.targets = parseTargets([]string{"192.0.2.0/24"})

		prefix := r.prefixEntities(nil, "p")[0].(*diode.Prefix)
		ip, _ := r.ipAddressEntity(scannedHost("h.example.net"), "192.0.2.10/25", "192.0.2.10", "p", nil)

		for name, tenant := range map[string]*diode.Tenant{
			"prefix.tenant": prefix.Tenant,
			"vrf.tenant":    prefix.Vrf.Tenant,
			"address":       ip.Tenant,
		} {
			require.NotNil(t, tenant, name)
			require.NotNil(t, tenant.Group, name+" must carry the group or it matches a group-less tenant")
			assert.Equal(t, "Labs", *tenant.Group.Name, name)
			assert.Equal(t, "312", *tenant.Name, name)
		}
	})

	t.Run("no group leaves the reference group-less", func(t *testing.T) {
		r := prefixRunner(t, config.Defaults{Vrf: "V", Tenant: "312"}, nestedMap(t))
		prefix := r.prefixEntities(nil, "p")[0].(*diode.Prefix)
		require.NotNil(t, prefix.Tenant)
		assert.Nil(t, prefix.Tenant.Group,
			"inventing a group would miss a genuinely group-less tenant")
	})
}

// The VRF reference must carry only what identifies it. Tags, description and
// comments are not part of any VRF matcher, and sending them would make the
// agent an author of fields an operator owns. Absent keys are left out of the
// changeset entirely, so a prebuilt VRF keeps its own.
func TestVrfReferenceCarriesNothingItDoesNotNeed(t *testing.T) {
	defaults := config.Defaults{
		Vrf: "VRF-Lab-312", VrfTenant: "312", TenantGroup: "Labs",
		Tenant: "312",
		Tags:   []string{"orb", "Lab 312"},
	}
	r := prefixRunner(t, defaults, nestedMap(t))
	prefix := r.prefixEntities(nil, "p")[0].(*diode.Prefix)
	vrf := prefix.Vrf

	require.NotNil(t, vrf)
	assert.Equal(t, "VRF-Lab-312", *vrf.Name)
	// Identity only.
	require.NotNil(t, vrf.Tenant)
	assert.Equal(t, "312", *vrf.Tenant.Name)
	require.NotNil(t, vrf.Tenant.Group)
	assert.Equal(t, "Labs", *vrf.Tenant.Group.Name)
	// Everything else stays off it. defaults.tags belongs on the prefix and the
	// address; putting it on the VRF would merge agent tags into an operator's.
	assert.Nil(t, vrf.Tags, "defaults.tags must not reach the VRF reference")
	assert.Nil(t, vrf.Description)
	assert.Nil(t, vrf.Comments)
	assert.Nil(t, vrf.EnforceUnique)
	// The tags did reach the prefix, which is where they belong.
	require.Len(t, prefix.Tags, 2)
}
