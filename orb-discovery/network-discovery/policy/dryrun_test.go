package policy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

// examplePolicy is the scan policy from agent.example.yaml, in the shape the
// backend receives it over /api/v1/policies. Keeping it here means the sample
// config cannot drift away from what the code accepts without this failing.
const examplePolicy = `
policies:
  lab_scan:
    config:
      timeout: 10
      defaults:
        vrf: LAB-AUS-01
        tenant: LAB-AUS-01
        description: "Discovered by orb network_discovery"
        tags: [orb, network-discovery]
        site: LAB-AUS-01
        prefix:
          status: active
          role: lab-data
          is_pool: false
          mark_utilized: false
        vlan:
          status: active
          group: LAB-AUS-01-VLANS
      custom_fields:
        discovery_agent: "${AGENT_NAME}"
        discovery_policy: "${POLICY_NAME}"
        discovery_last_seen: "${SCAN_TIMESTAMP}"
        discovery_source: network_discovery
    scope:
      targets:
        - 10.10.0.0/16
      subnet_map:
        - prefix: 10.10.0.0/16
          status: container
          role: lab-aggregate
          description: "LAB-AUS-01 lab space"
        - prefix: 10.10.20.0/24
          description: "Lab server VLAN"
          role: lab-servers
          vlan: {vid: 20, name: SERVERS}
        - prefix: 10.10.20.128/25
          role: lab-servers-gpu
          vlan: {vid: 21, name: SERVERS-GPU}
        - prefix: 10.10.30.0/24
          role: lab-mgmt
          vlan: {vid: 30, name: MGMT}
          custom_fields:
            discovery_zone: management
`

// TestDryRunGolden walks the sample policy end to end and writes the Diode
// payload through the real dry-run client, which is the same path
// `dry_run: true` takes in production.
//
// It stands in for a live scan: nmap is not available in CI or on a developer
// laptop by default, so the discovered addresses are synthesized here while
// everything downstream of them is the production code path.
//
// Set NETWORK_DISCOVERY_DRYRUN_DIR to keep the JSON for inspection.
func TestDryRunGolden(t *testing.T) {
	var policies config.Policies
	require.NoError(t, yaml.Unmarshal([]byte(examplePolicy), &policies))
	policy := policies.Policies["lab_scan"]
	require.NoError(t, config.ValidateSubnetMap(policy.Scope.SubnetMap, testLogger()))

	outputDir := os.Getenv("NETWORK_DISCOVERY_DRYRUN_DIR")
	if outputDir == "" {
		outputDir = t.TempDir()
	}
	client, err := diode.NewDryRunClient("network-discovery", outputDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	r := &Runner{
		logger:    testLogger(),
		agentName: "lab-agent-01",
		client:    client,
		scope:     policy.Scope,
		config:    policy.Config,
		matcher:   newSubnetMatcher(policy.Scope.SubnetMap),
	}
	r.targets = parseTargets(policy.Scope.Targets)

	scanTime := time.Date(2026, 9, 14, 10, 30, 0, 0, time.UTC)
	fields := resolveRunCustomFields(r.config, r.scope.SubnetMap, scanTokens(r.agentName, "lab_scan", scanTime), r.logger)

	entities := r.ipamEntities(fields, "lab_scan")

	// Two addresses that stand in for a scan: one in the grandchild /25, one in
	// a subnet the map says nothing about.
	for _, addr := range []string{"10.10.20.200", "198.51.100.9"} {
		matched := r.matcher.match(parseIPForTest(addr))
		ip, _ := r.ipAddressEntity(scannedHost("host.example.net"),
			r.getIPWithMask(addr, "/32"), addr, "lab_scan", fields.forEntry(matched))
		entities = append(entities, ip)
	}

	annotateEntitiesWithRunID(entities, "11111111-2222-3333-4444-555555555555")
	_, err = client.Ingest(context.Background(), entities, diode.WithIngestMetadata(diode.Metadata{
		"policy_name": "lab_scan",
		"run_id":      "11111111-2222-3333-4444-555555555555",
	}))
	require.NoError(t, err)

	files, err := filepath.Glob(filepath.Join(outputDir, "*.json"))
	require.NoError(t, err)
	require.Len(t, files, 1, "dry-run writes one JSON file per ingest")
	t.Logf("dry-run output: %s", files[0])

	raw, err := os.ReadFile(files[0])
	require.NoError(t, err)
	var payload struct {
		Entities []map[string]json.RawMessage `json:"entities"`
	}
	require.NoError(t, json.Unmarshal(raw, &payload))

	// Each element wraps one entity next to a "timestamp" sibling, so the entity
	// type is the other key.
	counts := map[string]int{}
	for _, entity := range payload.Entities {
		for kind := range entity {
			if kind == "timestamp" {
				continue
			}
			counts[kind]++
		}
	}
	// 4 prefixes, 3 VLANs, 2 addresses.
	assert.Equal(t, 4, counts["prefix"])
	assert.Equal(t, 3, counts["vlan"])
	assert.Equal(t, 2, counts["ip_address"])

	body := string(raw)
	// The grandchild match sets the mask, so the address is not a /24 or a /16.
	assert.Contains(t, body, `"10.10.20.200/25"`)
	// An unmatched address keeps the target mask, as it did before subnet_map.
	assert.Contains(t, body, `"198.51.100.9/32"`)
	assert.Contains(t, body, `"10.10.20.128/25"`)
	assert.Contains(t, body, `"LAB-AUS-01-VLANS"`)
	assert.Contains(t, body, `"discovery_agent"`)
	assert.Contains(t, body, `"lab-agent-01"`)
	assert.Contains(t, body, `"2026-09-14T10:30:00Z"`)
	assert.Contains(t, body, `"discovery_zone"`)
}
