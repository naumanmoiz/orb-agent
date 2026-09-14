package policy

import (
	"bytes"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
}

func vidPtr(v int) *int { return &v }

func boolPtr(v bool) *bool { return &v }

// nestedMap is the parent/child/grandchild arrangement from the config
// reference, validated so every entry carries its parsed network.
func nestedMap(t *testing.T) []config.SubnetMapEntry {
	t.Helper()
	entries := []config.SubnetMapEntry{
		{Prefix: "10.10.0.0/16", Status: "container", Role: "lab-aggregate"},
		{Prefix: "10.10.20.0/24", Role: "lab-servers", Vlan: &config.SubnetVlan{Vid: vidPtr(20), Name: "SERVERS"}},
		{Prefix: "10.10.20.128/25", Role: "lab-servers-gpu", Vlan: &config.SubnetVlan{Vid: vidPtr(21), Name: "SERVERS-GPU"}},
		{Prefix: "10.10.30.0/24", Role: "lab-mgmt", Vlan: &config.SubnetVlan{Vid: vidPtr(30), Name: "MGMT"}},
	}
	require.NoError(t, config.ValidateSubnetMap(entries, testLogger()))
	return entries
}

// An address resolves to the most specific entry containing it, never to a
// wider one, regardless of the order the entries were written in.
func TestSubnetMatcherLongestPrefixWins(t *testing.T) {
	matcher := newSubnetMatcher(nestedMap(t))

	tests := []struct {
		ip   string
		want string
	}{
		{"10.10.20.200", "10.10.20.128/25"},
		{"10.10.20.129", "10.10.20.128/25"},
		{"10.10.20.127", "10.10.20.0/24"},
		{"10.10.20.5", "10.10.20.0/24"},
		{"10.10.30.7", "10.10.30.0/24"},
		{"10.10.99.1", "10.10.0.0/16"},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			entry := matcher.match(net.ParseIP(tt.ip))
			require.NotNil(t, entry)
			assert.Equal(t, tt.want, entry.Network().String())
		})
	}
}

func TestSubnetMatcherNoMatch(t *testing.T) {
	matcher := newSubnetMatcher(nestedMap(t))
	assert.Nil(t, matcher.match(net.ParseIP("192.0.2.1")))
	assert.Nil(t, matcher.match(nil))

	empty := newSubnetMatcher(nil)
	assert.True(t, empty.empty())
	assert.Nil(t, empty.match(net.ParseIP("10.10.20.1")))

	// A nil matcher is the zero-configuration case and must not panic.
	var nilMatcher *subnetMatcher
	assert.True(t, nilMatcher.empty())
	assert.Nil(t, nilMatcher.match(net.ParseIP("10.10.20.1")))
}

// Entries that were never validated carry no network and are skipped rather
// than dereferenced.
func TestSubnetMatcherSkipsUnvalidatedEntries(t *testing.T) {
	matcher := newSubnetMatcher([]config.SubnetMapEntry{{Prefix: "10.10.20.0/24"}})
	assert.True(t, matcher.empty())
}

// A matched address takes the mask of its entry, and an unmatched one keeps the
// target-mask behaviour that predates subnet_map.
func TestGetIPWithMaskPrefersSubnetMap(t *testing.T) {
	r := &Runner{
		logger:  testLogger(),
		targets: parseTargets([]string{"10.10.0.0/16", "192.0.2.0/24"}),
		matcher: newSubnetMatcher(nestedMap(t)),
	}

	assert.Equal(t, "10.10.20.200/25", r.getIPWithMask("10.10.20.200", "/32"))
	assert.Equal(t, "10.10.20.5/24", r.getIPWithMask("10.10.20.5", "/32"))
	assert.Equal(t, "10.10.99.1/16", r.getIPWithMask("10.10.99.1", "/32"))
	// Inside a target but outside the map: the target mask still applies.
	assert.Equal(t, "192.0.2.9/24", r.getIPWithMask("192.0.2.9", "/32"))
	// Outside both: the configured default mask.
	assert.Equal(t, "198.51.100.9/32", r.getIPWithMask("198.51.100.9", "/32"))
	assert.Equal(t, "not-an-ip/32", r.getIPWithMask("not-an-ip", "/32"))
}

// With no subnet_map the mask logic is byte-for-byte the upstream behaviour.
func TestGetIPWithMaskWithoutSubnetMap(t *testing.T) {
	r := &Runner{
		logger:  testLogger(),
		targets: parseTargets([]string{"10.10.0.0/16"}),
		matcher: newSubnetMatcher(nil),
	}
	assert.Equal(t, "10.10.20.200/16", r.getIPWithMask("10.10.20.200", "/32"))
	assert.Equal(t, "198.51.100.9/32", r.getIPWithMask("198.51.100.9", "/32"))
}

func ipamRunner(t *testing.T, defaults config.Defaults, entries []config.SubnetMapEntry, custom map[string]any) *Runner {
	t.Helper()
	require.NoError(t, config.ValidateSubnetMap(entries, testLogger()))
	return &Runner{
		logger:    testLogger(),
		agentName: "lab-agent-01",
		matcher:   newSubnetMatcher(entries),
		scope:     config.Scope{Targets: []string{"10.10.0.0/16"}, SubnetMap: entries},
		config:    config.PolicyConfig{Defaults: defaults, CustomFields: custom},
	}
}

func buildIPAM(t *testing.T, r *Runner) []diode.Entity {
	t.Helper()
	tokens := scanTokens(r.agentName, "lab_scan", time.Date(2026, 9, 14, 10, 30, 0, 0, time.UTC))
	fields := resolveRunCustomFields(r.config, r.scope.SubnetMap, tokens, r.logger)
	return r.ipamEntities(fields, "lab_scan")
}

// No subnet_map means no Prefix and no VLAN entities at all, which is what
// keeps an upstream policy emitting addresses alone.
func TestIPAMEntitiesEmptyWithoutSubnetMap(t *testing.T) {
	r := ipamRunner(t, config.Defaults{Vrf: "LAB"}, nil, nil)
	assert.Nil(t, buildIPAM(t, r))
}

// Each entry yields one Prefix, and one VLAN only where a vlan is declared.
// The VLAN is emitted immediately before the prefix that references it, and the
// prefix nests the very same pointer.
func TestIPAMEntitiesShapeAndOrder(t *testing.T) {
	defaults := config.Defaults{
		Vrf:    "LAB-AUS-01",
		Rd:     "65000:1",
		Tenant: "LAB-AUS-01",
		Site:   "LAB-AUS-01",
		Tags:   []string{"orb"},
		Prefix: config.PrefixDefaults{Status: "active", Role: "lab-data", IsPool: boolPtr(false)},
		Vlan:   config.VlanDefaults{Status: "active", Group: config.VlanGroupParameters{Name: "LAB-AUS-01-VLANS"}},
	}
	r := ipamRunner(t, defaults, nestedMap(t), nil)
	entities := buildIPAM(t, r)

	// 4 prefixes + 3 VLANs.
	require.Len(t, entities, 7)

	container, ok := entities[0].(*diode.Prefix)
	require.True(t, ok, "the container declares no vlan, so its prefix comes first")
	assert.Equal(t, "10.10.0.0/16", *container.Prefix)
	assert.Equal(t, "container", *container.Status, "an entry status overrides defaults.prefix.status")
	require.NotNil(t, container.Role)
	assert.Equal(t, "lab-aggregate", *container.Role.Name)
	assert.Nil(t, container.Vlan)
	require.NotNil(t, container.Vrf)
	assert.Equal(t, "LAB-AUS-01", *container.Vrf.Name)
	assert.Equal(t, "65000:1", *container.Vrf.Rd)
	require.NotNil(t, container.Tenant)
	assert.Equal(t, "LAB-AUS-01", *container.Tenant.Name)
	require.NotNil(t, container.IsPool)
	assert.False(t, *container.IsPool)
	assert.Nil(t, container.MarkUtilized, "an unset field is left off so NetBox keeps its own value")
	// A prefix carries the site through its tenant, never as a scope.
	assert.Nil(t, container.Scope)

	vlan, ok := entities[1].(*diode.VLAN)
	require.True(t, ok, "a vlan is emitted before the prefix that references it")
	assert.Equal(t, int64(20), *vlan.Vid)
	assert.Equal(t, "SERVERS", *vlan.Name)
	assert.Equal(t, "active", *vlan.Status)
	require.NotNil(t, vlan.Site)
	assert.Equal(t, "LAB-AUS-01", *vlan.Site.Name, "defaults.site reaches the VLAN, not the prefix")
	require.NotNil(t, vlan.Group)
	assert.Equal(t, "LAB-AUS-01-VLANS", *vlan.Group.Name)
	assert.Equal(t, "lab-aus-01-vlans", *vlan.Group.Slug)
	scopeSite, ok := vlan.Group.Scope.(*diode.Site)
	require.True(t, ok, "a bare group name is scoped to defaults.site")
	assert.Equal(t, "LAB-AUS-01", *scopeSite.Name)

	servers, ok := entities[2].(*diode.Prefix)
	require.True(t, ok)
	assert.Equal(t, "10.10.20.0/24", *servers.Prefix)
	assert.Equal(t, "active", *servers.Status, "an unset entry status falls back to defaults.prefix.status")
	assert.Equal(t, "lab-servers", *servers.Role.Name)
	assert.Same(t, vlan, servers.Vlan, "the nested VLAN must be the very entity that was emitted")
	require.Len(t, servers.Tags, 1)
	assert.Equal(t, "orb", *servers.Tags[0].Name)
}

// The same VLAN declared twice is one entity, and a repeated prefix is emitted
// once per run.
func TestIPAMEntitiesDedupe(t *testing.T) {
	entries := []config.SubnetMapEntry{
		{Prefix: "10.10.20.0/24", Vlan: &config.SubnetVlan{Vid: vidPtr(20), Name: "SERVERS"}},
		{Prefix: "10.10.21.0/24", Vlan: &config.SubnetVlan{Vid: vidPtr(20), Name: "SERVERS"}},
	}
	r := ipamRunner(t, config.Defaults{Vrf: "LAB"}, entries, nil)
	entities := buildIPAM(t, r)

	var vlans []*diode.VLAN
	var prefixes []*diode.Prefix
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.VLAN:
			vlans = append(vlans, v)
		case *diode.Prefix:
			prefixes = append(prefixes, v)
		}
	}
	require.Len(t, vlans, 1, "one vid in one group is one VLAN, however many prefixes reference it")
	require.Len(t, prefixes, 2)
	assert.Same(t, vlans[0], prefixes[0].Vlan)
	assert.Same(t, vlans[0], prefixes[1].Vlan)
}

// The builder is driven once per entry, so calling add twice for the same
// network cannot duplicate it.
func TestIPAMBuilderIgnoresRepeatedNetworks(t *testing.T) {
	entries := []config.SubnetMapEntry{{Prefix: "10.10.20.0/24"}}
	require.NoError(t, config.ValidateSubnetMap(entries, testLogger()))

	builder := newIPAMBuilder(config.Defaults{}, testLogger(), "lab_scan")
	builder.add(&entries[0], nil)
	builder.add(&entries[0], nil)
	assert.Len(t, builder.entities(), 1)
}

// An unset defaults.prefix / defaults.vlan block leaves those attributes off
// the entity entirely, so Diode omits them and NetBox keeps what it has.
func TestIPAMEntitiesLeaveUnsetFieldsAlone(t *testing.T) {
	entries := []config.SubnetMapEntry{
		{Prefix: "10.10.20.0/24", Vlan: &config.SubnetVlan{Vid: vidPtr(20)}},
	}
	r := ipamRunner(t, config.Defaults{}, entries, nil)
	entities := buildIPAM(t, r)
	require.Len(t, entities, 2)

	vlan := entities[0].(*diode.VLAN)
	assert.Equal(t, "VLAN20", *vlan.Name, "NetBox requires a VLAN name, so an unnamed VLAN gets a placeholder")
	assert.Nil(t, vlan.Status)
	assert.Nil(t, vlan.Role)
	assert.Nil(t, vlan.Group)
	assert.Nil(t, vlan.Site)
	assert.Nil(t, vlan.Tenant)

	prefix := entities[1].(*diode.Prefix)
	assert.Nil(t, prefix.Status)
	assert.Nil(t, prefix.Role)
	assert.Nil(t, prefix.Vrf)
	assert.Nil(t, prefix.Tenant)
	assert.Nil(t, prefix.IsPool)
	assert.Nil(t, prefix.MarkUtilized)
	assert.Nil(t, prefix.Description)
	assert.Nil(t, prefix.Tags)
}

// An explicit scope_site on the group beats defaults.site, so the group can sit
// in a different site from the VLANs.
func TestVlanGroupScopePrecedence(t *testing.T) {
	entries := []config.SubnetMapEntry{{
		Prefix: "10.10.20.0/24",
		Vlan: &config.SubnetVlan{
			Vid:   vidPtr(20),
			Group: config.VlanGroupParameters{Name: "SHARED", ScopeSite: "HQ"},
		},
	}}
	r := ipamRunner(t, config.Defaults{Site: "LAB-AUS-01"}, entries, nil)
	vlan := buildIPAM(t, r)[0].(*diode.VLAN)

	site, ok := vlan.Group.Scope.(*diode.Site)
	require.True(t, ok)
	assert.Equal(t, "HQ", *site.Name)
	assert.Equal(t, "LAB-AUS-01", *vlan.Site.Name, "the VLAN itself still sits in defaults.site")
}

// A group name with no slug-able runes yields no group rather than an
// ingestion NetBox will reject for an empty slug.
func TestVlanGroupSkippedWhenSlugIsEmpty(t *testing.T) {
	entries := []config.SubnetMapEntry{{
		Prefix: "10.10.20.0/24",
		Vlan:   &config.SubnetVlan{Vid: vidPtr(20), Group: config.VlanGroupParameters{Name: "!!!"}},
	}}
	r := ipamRunner(t, config.Defaults{}, entries, nil)
	vlan := buildIPAM(t, r)[0].(*diode.VLAN)
	assert.Nil(t, vlan.Group)
}

// Policy custom fields reach every prefix; an entry's own block extends rather
// than replaces them.
func TestIPAMCustomFields(t *testing.T) {
	entries := []config.SubnetMapEntry{
		{Prefix: "10.10.20.0/24"},
		{Prefix: "10.10.30.0/24", CustomFields: map[string]any{"discovery_zone": "management"}},
	}
	r := ipamRunner(t, config.Defaults{}, entries, map[string]any{
		"discovery_agent":     "${AGENT_NAME}",
		"discovery_policy":    "${POLICY_NAME}",
		"discovery_last_seen": "${SCAN_TIMESTAMP}",
		"discovery_source":    "network_discovery",
	})
	entities := buildIPAM(t, r)

	plain := entities[0].(*diode.Prefix)
	require.Len(t, plain.CustomFields, 4)
	assert.Equal(t, diode.CustomFieldValueText("lab-agent-01"), plain.CustomFields["discovery_agent"].Value)
	assert.Equal(t, diode.CustomFieldValueText("lab_scan"), plain.CustomFields["discovery_policy"].Value)
	assert.NotContains(t, plain.CustomFields, "discovery_zone")
	// The timestamp must land on the datetime variant, not on text, or NetBox
	// rejects the changeset for a datetime custom field.
	assert.IsType(t, diode.CustomFieldValueDatetime{}, plain.CustomFields["discovery_last_seen"].Value)

	extended := entities[1].(*diode.Prefix)
	require.Len(t, extended.CustomFields, 5)
	assert.Equal(t, diode.CustomFieldValueText("management"), extended.CustomFields["discovery_zone"].Value)
	assert.Equal(t, diode.CustomFieldValueText("network_discovery"), extended.CustomFields["discovery_source"].Value)
}

// Every entity in a run shares one ${SCAN_TIMESTAMP}: resolving per entity
// would stamp addresses discovered seconds apart differently.
func TestRunCustomFieldsShareOneTimestamp(t *testing.T) {
	entries := []config.SubnetMapEntry{
		{Prefix: "10.10.20.0/24"},
		{Prefix: "10.10.30.0/24", CustomFields: map[string]any{"discovery_zone": "management"}},
	}
	require.NoError(t, config.ValidateSubnetMap(entries, testLogger()))
	cfg := config.PolicyConfig{CustomFields: map[string]any{"discovery_last_seen": "${SCAN_TIMESTAMP}"}}
	scanTime := time.Date(2026, 9, 14, 10, 30, 0, 0, time.UTC)

	fields := resolveRunCustomFields(cfg, entries, scanTokens("a", "p", scanTime), testLogger())
	assert.Equal(t, scanTime, fields.forEntry(nil)["discovery_last_seen"])
	assert.Equal(t, scanTime, fields.forEntry(&entries[1])["discovery_last_seen"])
}

// A block that cannot resolve is dropped with a log line, not fatal: an unset
// environment variable should not cost a scan's worth of addresses.
func TestRunCustomFieldsSurviveAnUnresolvableValue(t *testing.T) {
	entries := []config.SubnetMapEntry{
		{Prefix: "10.10.30.0/24", CustomFields: map[string]any{"discovery_zone": "${NOT_SET_ANYWHERE}"}},
	}
	require.NoError(t, config.ValidateSubnetMap(entries, testLogger()))
	cfg := config.PolicyConfig{CustomFields: map[string]any{"discovery_source": "network_discovery"}}

	fields := resolveRunCustomFields(cfg, entries, scanTokens("a", "p", time.Now()), testLogger())
	assert.Equal(t, "network_discovery", fields.forEntry(nil)["discovery_source"])
	// The entry falls back to the policy block rather than losing everything.
	assert.Equal(t, "network_discovery", fields.forEntry(&entries[0])["discovery_source"])
	assert.NotContains(t, fields.forEntry(&entries[0]), "discovery_zone")
}

// The run id reaches the new entity types, including the VLAN shared between a
// top-level entity and the prefix that nests it.
func TestAnnotateRunIDCoversPrefixAndVLAN(t *testing.T) {
	vlan := &diode.VLAN{Vid: diode.Int64(20), Name: diode.String("SERVERS")}
	prefix := &diode.Prefix{Prefix: diode.String("10.10.20.0/24"), Vlan: vlan}

	annotateEntitiesWithRunID([]diode.Entity{vlan, prefix}, "run-1")

	assert.Equal(t, "run-1", prefix.Metadata["run_id"])
	assert.Equal(t, "run-1", vlan.Metadata["run_id"])
}

// An address matching no subnet_map entry is emitted exactly as it was before
// the feature existed, carrying the policy custom fields and nothing else. No
// Prefix or VLAN is generated on its behalf.
func TestUnmatchedAddressFallsBackToAStandaloneIPAddress(t *testing.T) {
	entries := []config.SubnetMapEntry{{Prefix: "10.10.20.0/24", Vlan: &config.SubnetVlan{Vid: vidPtr(20)}}}
	r := ipamRunner(t, config.Defaults{Role: "host", Tenant: "LAB-AUS-01"}, entries,
		map[string]any{"discovery_source": "network_discovery"})
	r.targets = parseTargets([]string{"10.10.0.0/16", "192.0.2.0/24"})

	tokens := scanTokens(r.agentName, "lab_scan", time.Now())
	fields := resolveRunCustomFields(r.config, r.scope.SubnetMap, tokens, r.logger)

	unmatched := net.ParseIP("192.0.2.9")
	require.Nil(t, r.matcher.match(unmatched), "the address sits outside every subnet_map entry")

	ip, _ := r.ipAddressEntity(scannedHost("host.example.net"), r.getIPWithMask("192.0.2.9", "/32"),
		"192.0.2.9", "lab_scan", fields.forEntry(nil))

	assert.Equal(t, "192.0.2.9/24", *ip.Address, "an unmatched address keeps the target mask")
	assert.Equal(t, "host", *ip.Role)
	assert.Equal(t, "LAB-AUS-01", *ip.Tenant.Name)
	require.Len(t, ip.CustomFields, 1)
	assert.Equal(t, diode.CustomFieldValueText("network_discovery"), ip.CustomFields["discovery_source"].Value)

	// The subnet_map still emits its own prefix and VLAN, but nothing extra was
	// created for the unmatched address.
	assert.Len(t, buildIPAM(t, r), 2)
}

// A matched address picks up its entry's custom fields on top of the policy's.
func TestMatchedAddressCarriesEntryCustomFields(t *testing.T) {
	entries := []config.SubnetMapEntry{
		{Prefix: "10.10.30.0/24", CustomFields: map[string]any{"discovery_zone": "management"}},
	}
	r := ipamRunner(t, config.Defaults{}, entries, map[string]any{"discovery_source": "network_discovery"})

	tokens := scanTokens(r.agentName, "lab_scan", time.Now())
	fields := resolveRunCustomFields(r.config, r.scope.SubnetMap, tokens, r.logger)
	matched := r.matcher.match(net.ParseIP("10.10.30.7"))
	require.NotNil(t, matched)

	ip, _ := r.ipAddressEntity(scannedHost("mgmt.example.net"), "10.10.30.7/24", "10.10.30.7",
		"lab_scan", fields.forEntry(matched))

	require.Len(t, ip.CustomFields, 2)
	assert.Equal(t, diode.CustomFieldValueText("management"), ip.CustomFields["discovery_zone"].Value)
	assert.Equal(t, diode.CustomFieldValueText("network_discovery"), ip.CustomFields["discovery_source"].Value)
}
