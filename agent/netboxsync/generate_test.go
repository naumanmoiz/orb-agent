package netboxsync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/config"
)

func intPtr(i int) *int { return &i }

func baseConfig() config.NetBoxManager {
	return config.NetBoxManager{
		URL:   "https://netbox.example.com",
		Token: "x",
		NetworkDiscovery: config.NetBoxNetworkDiscovery{
			Enabled:  true,
			Schedule: "0 */6 * * *",
			Timeout:  30,
			Scope:    map[string]any{"top_ports": 100, "timing": 4},
		},
	}
}

func mustSettings(t testing.TB, cfg config.NetBoxManager) Settings {
	t.Helper()
	s, err := NewSettings(cfg)
	require.NoError(t, err)
	return s
}

func policyNames(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func scopeOf(t *testing.T, policy any) map[string]any {
	t.Helper()
	return policy.(map[string]any)["scope"].(map[string]any)
}

func targetsOf(t *testing.T, policy any) []string {
	t.Helper()
	var out []string
	for _, x := range scopeOf(t, policy)["targets"].([]any) {
		switch v := x.(type) {
		case string:
			out = append(out, v)
		case map[string]any:
			out = append(out, v["host"].(string))
		}
	}
	return out
}

func entriesOf(t *testing.T, policy any) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, e := range scopeOf(t, policy)["subnet_map"].([]any) {
		out = append(out, e.(map[string]any))
	}
	return out
}

// A three-level hierarchy: leaves are scanned in pass 1, and every parent's
// uncovered remainder in pass 2 with the parent's own attributes.
func TestGenerateThreeLevels(t *testing.T) {
	container := pfx(1, 10, "198.51.100.0/24", "container")
	container.VRF, container.RD, container.VRFTenant, container.VRFTenantGroup = "VRF-A", "65000:1", "Tenant V", "Group V"
	container.Tenant, container.TenantGroup, container.Tags = "Tenant A", "Group A", []string{"aggregate"}
	child := pfx(2, 10, "198.51.100.0/25", "active")
	child.VRF, child.RD, child.VRFTenant, child.VRFTenantGroup = "VRF-A", "65000:1", "Tenant V", "Group V"
	child.Tenant, child.Role, child.Tags = "Tenant B", "servers", []string{"servers"}
	grand := pfx(3, 10, "198.51.100.0/26", "active")
	grand.VRF, grand.Tenant, grand.Tags, grand.Description = "VRF-A", "Tenant C", []string{"gpu"}, "hand-written"
	reserved := pfx(4, 10, "198.51.100.64/27", "reserved") // counts for coverage, never scanned

	res := Generate([]*Prefix{container, child, grand, reserved}, mustSettings(t, baseConfig()))
	nd := res.Policies[NetworkDiscoveryBackend]
	require.NotNil(t, nd)
	assert.Equal(t, []string{"nb-nd-straggler-vrf-a-001", "nb-nd-vrf-a-001"}, policyNames(nd))

	scan := nd["nb-nd-vrf-a-001"]
	assert.Equal(t, []string{"198.51.100.0/26"}, targetsOf(t, scan), "only the leaf is scanned in pass 1")
	entries := entriesOf(t, scan)
	require.Len(t, entries, 1)
	assert.Equal(t, map[string]any{
		"prefix": "198.51.100.0/26", "emit_prefix": false, "vrf": "VRF-A",
		"tenant": "Tenant C", "status": "active", "tags": []any{"gpu"}, "address_tags": []any{"gpu"},
		"description": "hand-written",
	}, entries[0])
	cfg := scan.(map[string]any)["config"].(map[string]any)
	assert.Equal(t, "0 */6 * * *", cfg["schedule"])
	assert.Equal(t, 30, cfg["timeout"])
	assert.Equal(t, 100, scopeOf(t, scan)["top_ports"], "the scope template is merged in")

	straggler := nd["nb-nd-straggler-vrf-a-001"]
	assert.Equal(t, []string{"198.51.100.96/27", "198.51.100.128/25"}, targetsOf(t, straggler),
		"child leftover (minus the grandchild and the reserved prefix), then the container's")
	sm := entriesOf(t, straggler)
	require.Len(t, sm, 2)
	assert.Equal(t, "198.51.100.0/25", sm[0]["prefix"])
	assert.Equal(t, "Tenant B", sm[0]["tenant"])
	assert.Equal(t, "198.51.100.0/24", sm[1]["prefix"])
	assert.Equal(t, "65000:1", sm[1]["rd"])
	assert.Equal(t, "Tenant V", sm[1]["vrf_tenant"])
	assert.Equal(t, "Group V", sm[1]["vrf_tenant_group"])
	assert.Equal(t, "Group A", sm[1]["tenant_group"])
	assert.Equal(t, true, scopeOf(t, straggler)["ping_scan"])
	assert.NotContains(t, scopeOf(t, straggler), "top_ports", "ping_only drops the port scan")
	assert.Equal(t, "30 */6 * * *", straggler.(map[string]any)["config"].(map[string]any)["schedule"])

	assert.Equal(t, 1, res.Summary.ScanPrefixes)
	assert.Equal(t, 2, res.Summary.Parents)
}

// The same address space in two VRFs and the global table is three separate
// trees: no prefix in one is treated as covering a prefix in another.
func TestGenerateOverlappingVRFs(t *testing.T) {
	a := pfx(1, 10, "198.51.100.0/24", "active")
	a.VRF = "VRF-A"
	b := pfx(2, 20, "198.51.100.0/25", "active")
	b.VRF = "VRF-B"
	g := pfx(3, 0, "198.51.100.0/25", "active")
	res := Generate([]*Prefix{a, b, g}, mustSettings(t, baseConfig()))
	nd := res.Policies[NetworkDiscoveryBackend]
	assert.Equal(t, []string{"nb-nd-global-001", "nb-nd-vrf-a-001", "nb-nd-vrf-b-001"}, policyNames(nd))
	assert.Equal(t, []string{"198.51.100.0/24"}, targetsOf(t, nd["nb-nd-vrf-a-001"]), "VRF-A's /24 is a leaf")
	assert.Equal(t, "VRF-B", entriesOf(t, nd["nb-nd-vrf-b-001"])[0]["vrf"])
	assert.NotContains(t, entriesOf(t, nd["nb-nd-global-001"])[0], "vrf")
	assert.Equal(t, 0, res.Summary.Parents)
}

func TestGenerateVRFSlugCollision(t *testing.T) {
	a := pfx(1, 10, "192.0.2.0/24", "active")
	a.VRF = "VRF A"
	b := pfx(2, 11, "192.0.2.0/24", "active")
	b.VRF = "vrf-a"
	nd := Generate([]*Prefix{a, b}, mustSettings(t, baseConfig())).Policies[NetworkDiscoveryBackend]
	assert.Equal(t, []string{"nb-nd-vrf-a-v10-001", "nb-nd-vrf-a-v11-001"}, policyNames(nd))
}

func TestGenerateStragglerLimits(t *testing.T) {
	cfg := baseConfig()
	cfg.NetworkDiscovery.Straggler.MaxHostsPerParent = 200
	big := pfx(1, 0, "198.51.100.0/24", "container") // whole /24 leftover: within /20, 256 hosts
	huge := pfx(2, 0, "10.0.0.0/16", "container")    // /16 block is larger than /20: skipped
	multi := pfx(3, 0, "203.0.113.0/24", "active")
	child := pfx(4, 0, "203.0.113.0/26", "active") // leftover: .64/26 and .128/25 = 192 hosts
	grand := pfx(5, 0, "203.0.113.0/27", "active")
	small := pfx(6, 0, "192.0.2.0/24", "container")
	smallChild := pfx(7, 0, "192.0.2.0/30", "active")
	res := Generate([]*Prefix{big, huge, multi, child, grand, small, smallChild}, mustSettings(t, cfg))

	reasons := map[string]string{}
	for _, sk := range res.Summary.Skipped {
		reasons[sk.Block] = sk.Reason
	}
	assert.Contains(t, reasons["10.0.0.0/16"], "max_block_prefix_len")
	assert.Contains(t, reasons["198.51.100.0/24"], "max_hosts_per_parent", "256 hosts exceed the 200 cap")
	// 192.0.2.0/24 minus a /30 leaves .4/30 .8/29 .16/28 .32/27 .64/26 (124
	// addresses), and then .128/25 would take it past 200.
	assert.Contains(t, reasons["192.0.2.128/25"], "max_hosts_per_parent")
	_, smallKept := reasons["192.0.2.64/26"]
	assert.False(t, smallKept)

	targets := targetsOf(t, res.Policies[NetworkDiscoveryBackend]["nb-nd-straggler-global-001"])
	assert.Contains(t, targets, "203.0.113.128/25")
	assert.Contains(t, targets, "203.0.113.32/27", "the child's leftover around the grandchild")
	assert.NotContains(t, targets, "10.0.0.0/16")
}

func TestGenerateLeafSizeLimit(t *testing.T) {
	cfg := baseConfig()
	cfg.NetworkDiscovery.MaxBlockPrefixLenV4 = intPtr(24)
	res := Generate([]*Prefix{pfx(1, 0, "198.51.100.0/23", "active"), pfx(2, 0, "2001:db8::/64", "active")},
		mustSettings(t, cfg))
	assert.Len(t, res.Summary.Skipped, 2)
	assert.Nil(t, res.Policies[NetworkDiscoveryBackend])
	out, err := Render(res)
	require.NoError(t, err)
	assert.Contains(t, string(out), "# skipped 198.51.100.0/23 (prefix id 1")
}

func manyLeaves(vrfID int, vrf string, n int, startID int) []*Prefix {
	var out []*Prefix
	for i := 0; i < n; i++ {
		// 10.x.y.0/24 leaves inside one 10.0.0.0/8 container per VRF.
		cidr := fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
		p := pfx(startID+i, vrfID, cidr, "active")
		p.VRF = vrf
		out = append(out, p)
	}
	c := pfx(startID+n, vrfID, "10.0.0.0/8", "container")
	c.VRF = vrf
	return append(out, c)
}

func TestGenerateBatchingLimits(t *testing.T) {
	cfg := baseConfig()
	cfg.NetworkDiscovery.MaxTargetsPerPolicy = 4
	cfg.NetworkDiscovery.MaxHostsPerPolicy = 512 // two /24s
	cfg.NetworkDiscovery.Straggler.Enabled = new(bool)
	res := Generate(manyLeaves(10, "VRF-A", 7, 1), mustSettings(t, cfg))
	nd := res.Policies[NetworkDiscoveryBackend]
	assert.Equal(t, []string{"nb-nd-vrf-a-001", "nb-nd-vrf-a-002", "nb-nd-vrf-a-003", "nb-nd-vrf-a-004"}, policyNames(nd),
		"the host limit (2 x /24) is hit before the target limit")
	assert.Equal(t, []string{"10.0.0.0/24", "10.0.1.0/24"}, targetsOf(t, nd["nb-nd-vrf-a-001"]))
	assert.Len(t, entriesOf(t, nd["nb-nd-vrf-a-001"]), 2, "one subnet_map entry per prefix in the batch")

	cfg.NetworkDiscovery.MaxHostsPerPolicy = 1 << 20
	nd = Generate(manyLeaves(10, "VRF-A", 7, 1), mustSettings(t, cfg)).Policies[NetworkDiscoveryBackend]
	assert.Len(t, nd, 2, "now the target limit is hit first")
	assert.Len(t, targetsOf(t, nd["nb-nd-vrf-a-001"]), 4)
}

// Names are stable across refreshes, and a change in one VRF never touches
// another VRF's policies.
func TestGenerateNameStability(t *testing.T) {
	cfg := baseConfig()
	cfg.NetworkDiscovery.MaxTargetsPerPolicy = 10
	s := mustSettings(t, cfg)

	build := func(extra bool) map[string]any {
		ps := append(manyLeaves(10, "VRF-A", 25, 1), manyLeaves(20, "VRF-B", 25, 1000)...)
		if extra {
			p := pfx(5000, 20, "10.0.200.0/24", "active")
			p.VRF = "VRF-B"
			ps = append(ps, p)
		}
		return Generate(ps, s).Policies[NetworkDiscoveryBackend]
	}
	first, again := build(false), build(false)
	firstYAML, _ := yaml.Marshal(first)
	againYAML, _ := yaml.Marshal(again)
	assert.Equal(t, string(firstYAML), string(againYAML), "same input, byte-identical output")

	changed := build(true)
	for _, name := range policyNames(first) {
		a, _ := yaml.Marshal(first[name])
		b, _ := yaml.Marshal(changed[name])
		if strings.HasPrefix(name, "nb-nd-vrf-a-") || strings.HasPrefix(name, "nb-nd-straggler-vrf-a-") {
			assert.Equal(t, string(a), string(b), "VRF-A policy %s must not change", name)
		}
	}
	// Appending past the end of VRF-B changes only its last batch.
	assert.Equal(t, mustYAML(first["nb-nd-vrf-b-001"]), mustYAML(changed["nb-nd-vrf-b-001"]))
	assert.Equal(t, mustYAML(first["nb-nd-vrf-b-002"]), mustYAML(changed["nb-nd-vrf-b-002"]))
	assert.NotEqual(t, mustYAML(first["nb-nd-vrf-b-003"]), mustYAML(changed["nb-nd-vrf-b-003"]))
}

func mustYAML(v any) string {
	b, err := yaml.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestGenerateStagger(t *testing.T) {
	cfg := baseConfig()
	cfg.NetworkDiscovery.MaxTargetsPerPolicy = 1
	cfg.NetworkDiscovery.StaggerMinutes = 30
	cfg.NetworkDiscovery.Straggler.Enabled = new(bool)
	nd := Generate(manyLeaves(0, "", 3, 1), mustSettings(t, cfg)).Policies[NetworkDiscoveryBackend]
	var scheds []string
	for _, name := range policyNames(nd) {
		scheds = append(scheds, nd[name].(map[string]any)["config"].(map[string]any)["schedule"].(string))
	}
	assert.Equal(t, []string{"0 */6 * * *", "10 */6 * * *", "20 */6 * * *"}, scheds)
}

func TestGenerateStripsPlacementFromTemplates(t *testing.T) {
	cfg := baseConfig()
	cfg.NetworkDiscovery.Config = map[string]any{
		"defaults":      map[string]any{"vrf": "X", "tenant": "Y", "description": "kept"},
		"custom_fields": map[string]any{"discovery_last_seen": "${SCAN_TIMESTAMP}"},
	}
	cfg.NetworkDiscovery.Scope["targets"] = []any{"192.0.2.0/24"}
	res := Generate([]*Prefix{pfx(1, 0, "198.51.100.0/24", "active")}, mustSettings(t, cfg))
	policy := res.Policies[NetworkDiscoveryBackend]["nb-nd-global-001"].(map[string]any)
	defaults := policy["config"].(map[string]any)["defaults"].(map[string]any)
	assert.Equal(t, map[string]any{"description": "kept"}, defaults)
	assert.Equal(t, "${SCAN_TIMESTAMP}", policy["config"].(map[string]any)["custom_fields"].(map[string]any)["discovery_last_seen"],
		"tokens are left for the backend to resolve")
	assert.Equal(t, []string{"198.51.100.0/24"}, targetsOf(t, policy))
	assert.Len(t, res.Summary.Warnings, 3)
	// The template itself is not modified.
	assert.Equal(t, "X", cfg.NetworkDiscovery.Config["defaults"].(map[string]any)["vrf"])
}

func TestGenerateSNMP(t *testing.T) {
	cfg := baseConfig()
	cfg.NetworkDiscovery.Enabled = false
	cfg.SNMPDiscovery = config.NetBoxSNMPDiscovery{
		Enabled:        true,
		Authentication: map[string]any{"protocol_version": "SNMPv2c", "community": "${SNMP_COMMUNITY}"},
		Config: map[string]any{
			"timeout":  5,
			"defaults": map[string]any{"ip_address": map[string]any{"vrf": "X", "description": "kept"}},
		},
	}
	p := pfx(1, 10, "198.51.100.0/28", "active")
	p.VRF, p.RD, p.VRFTenant = "VRF-A", "65000:1", "Tenant V"
	p.Tenant, p.TenantGroup, p.Tags, p.Site = "Tenant A", "Group A", []string{"servers"}, "Site A"
	g := pfx(2, 0, "192.0.2.0/28", "active")
	res := Generate([]*Prefix{p, g}, mustSettings(t, cfg))
	assert.Nil(t, res.Policies[NetworkDiscoveryBackend])
	sp := res.Policies[SNMPDiscoveryBackend]
	assert.Equal(t, []string{"nb-snmp-global-001", "nb-snmp-vrf-a-001"}, policyNames(sp))

	policy := sp["nb-snmp-vrf-a-001"].(map[string]any)
	cfgOut := policy["config"].(map[string]any)
	assert.Equal(t, "15 */6 * * *", cfgOut["schedule"])
	assert.Equal(t, map[string]any{"device_description_from_sysdescr": false, "interface_description_from_ifalias": false},
		cfgOut["options"])
	assert.Equal(t, map[string]any{"description": "kept"}, cfgOut["defaults"].(map[string]any)["ip_address"])
	scope := policy["scope"].(map[string]any)
	assert.Equal(t, "${SNMP_COMMUNITY}", scope["authentication"].(map[string]any)["community"])
	target := scope["targets"].([]any)[0].(map[string]any)
	assert.Equal(t, "198.51.100.0/28", target["host"])
	od := target["override_defaults"].(map[string]any)
	assert.Equal(t, "Site A", od["site"])
	assert.Equal(t, map[string]any{"name": "Tenant A", "group": "Group A"}, od["tenant"])
	ip := od["ip_address"].(map[string]any)
	assert.Equal(t, map[string]any{"name": "VRF-A", "rd": "65000:1", "tenant": "Tenant V"}, ip["vrf"])
	assert.Equal(t, []any{"servers"}, ip["tags"])
	assert.Equal(t, ip["vrf"], od["prefix"].(map[string]any)["vrf"])

	globalTarget := sp["nb-snmp-global-001"].(map[string]any)["scope"].(map[string]any)["targets"].([]any)[0].(map[string]any)
	assert.NotContains(t, globalTarget, "override_defaults")
}

func TestNewSettingsStragglerSchedule(t *testing.T) {
	cfg := baseConfig()
	cfg.NetworkDiscovery.Schedule = "*/15 * * * *"
	_, err := NewSettings(cfg)
	require.Error(t, err, "an unshiftable schedule needs an explicit straggler_schedule")
	assert.Contains(t, err.Error(), "straggler_schedule")

	cfg.NetworkDiscovery.StragglerSchedule = "5 3 * * *"
	s, err := NewSettings(cfg)
	require.NoError(t, err)
	assert.Equal(t, "5 3 * * *", s.ND.StragglerSchedule)

	cfg = baseConfig()
	cfg.NetworkDiscovery.StragglerDelayMinutes = intPtr(45)
	assert.Equal(t, "45 */6 * * *", mustSettings(t, cfg).ND.StragglerSchedule)

	_, err = NewSettings(config.NetBoxManager{})
	require.Error(t, err, "nothing enabled")
}

// A company-sized NetBox: 5000 prefixes over 10 VRFs, nested three deep.
func TestGeneratePerformance(t *testing.T) {
	var ps []*Prefix
	id := 1
	for v := 1; v <= 10; v++ {
		vrf := fmt.Sprintf("VRF-%d", v)
		add := func(cidr, status string) {
			p := pfx(id, v, cidr, status)
			p.VRF, p.Tenant, p.Tags = vrf, "Tenant A", []string{"t"}
			ps = append(ps, p)
			id++
		}
		add("10.0.0.0/8", "container")
		for b := 0; b < 20; b++ {
			add(fmt.Sprintf("10.%d.0.0/16", b), "container")
			for c := 0; c < 24; c++ {
				add(fmt.Sprintf("10.%d.%d.0/24", b, c), "active")
			}
		}
	}
	require.GreaterOrEqual(t, len(ps), 5000)
	cfg := baseConfig()
	cfg.NetworkDiscovery.Straggler.MaxBlockPrefixLenV4 = intPtr(8)
	cfg.NetworkDiscovery.Straggler.MaxHostsPerParent = 1 << 30
	cfg.SNMPDiscovery.Enabled = true
	s := mustSettings(t, cfg)

	start := time.Now()
	res := Generate(ps, s)
	out, err := Render(res)
	elapsed := time.Since(start)
	require.NoError(t, err)
	t.Logf("%d prefixes -> %d scan, %d straggler, %d snmp policies, %d bytes in %s",
		len(ps), res.Summary.ScanPolicies, res.Summary.StragglerPolicies, res.Summary.SNMPPolicies, len(out), elapsed)
	assert.Less(t, elapsed, 2*time.Second)
	assert.Equal(t, 4800, res.Summary.ScanPrefixes)
	assert.Equal(t, 20, res.Summary.ScanPolicies, "4800 /24 leaves at 256 hosts each, 256 per policy by hosts")
}

func TestRenderAndWriteAtomic(t *testing.T) {
	res := Generate([]*Prefix{pfx(1, 0, "192.0.2.0/24", "active")}, mustSettings(t, baseConfig()))
	data, err := Render(res)
	require.NoError(t, err)
	var parsed map[string]map[string]any
	require.NoError(t, yaml.Unmarshal(data, &parsed))
	assert.Contains(t, parsed[NetworkDiscoveryBackend], "nb-nd-global-001")

	path := filepath.Join(t.TempDir(), "generated.yaml")
	require.NoError(t, WriteFileAtomic(path, data, 0o640))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, data, got)
	entries, _ := os.ReadDir(filepath.Dir(path))
	assert.Len(t, entries, 1, "no temporary file left behind")
}

func TestSyncerEndToEnd(t *testing.T) {
	nb := newFakeNetBox(t)
	nb.token = "Bearer nbt_abc.def"
	nb.addTenant(1, "Tenant A", "Group A")
	nb.addVRF(10, "VRF-A", "65000:1", 1)
	nb.addPrefix(fakePrefix{id: 1, prefix: "198.51.100.0/24", vrfID: 10, tenantID: 1, status: "container"})
	nb.addPrefix(fakePrefix{id: 2, prefix: "198.51.100.0/25", vrfID: 10, tenantID: 1, status: "active", tags: []string{"servers"}})
	srv := nb.serve()

	t.Setenv("TEST_NETBOX_URL", srv.URL)
	t.Setenv("TEST_NETBOX_TOKEN", "nbt_abc.def")
	cfg := baseConfig()
	cfg.URL, cfg.Token = "${TEST_NETBOX_URL}", "${TEST_NETBOX_TOKEN}"
	syncer, err := NewSyncer(cfg, nil)
	require.NoError(t, err)
	res, err := syncer.Run(context.Background())
	require.NoError(t, err)
	nd := res.Policies[NetworkDiscoveryBackend]
	assert.Equal(t, []string{"nb-nd-straggler-vrf-a-001", "nb-nd-vrf-a-001"}, policyNames(nd))
	e := entriesOf(t, nd["nb-nd-vrf-a-001"])[0]
	assert.Equal(t, "Tenant A", e["vrf_tenant"])
	assert.Equal(t, "Group A", e["vrf_tenant_group"])
	assert.Equal(t, "Group A", e["tenant_group"])
	assert.Equal(t, []any{"servers"}, e["address_tags"])
}
