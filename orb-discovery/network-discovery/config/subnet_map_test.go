package config_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
}

func bufferedLogger() (*slog.Logger, *bytes.Buffer) {
	buf := bytes.NewBuffer(nil)
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

// A policy written before subnet_map existed must still decode with the new
// fields at zero.
func TestParsePolicyWithoutSubnetMap(t *testing.T) {
	var policies config.Policies
	require.NoError(t, yaml.Unmarshal([]byte(`
policies:
  legacy:
    config:
      defaults: {vrf: LAB-A, tenant: LAB-A}
    scope:
      targets: [192.0.2.0/24]
`), &policies))
	policy := policies.Policies["legacy"]
	assert.Empty(t, policy.Scope.SubnetMap)
	assert.Equal(t, config.PrefixDefaults{}, policy.Config.Defaults.Prefix)
}

func TestParsePolicyWithSubnetMap(t *testing.T) {
	var policies config.Policies
	require.NoError(t, yaml.Unmarshal([]byte(`
policies:
  lab_a_scan:
    config:
      defaults:
        vrf: LAB-A
        prefix:
          status: active
          role: lab-data
          is_pool: false
    scope:
      targets: [192.0.2.0/24]
      subnet_map:
        - prefix: 192.0.2.0/24
          status: container
          role: lab-aggregate
        - prefix: 192.0.2.0/25
          role: lab-servers
          custom_fields:
            lab_id: "312"
`), &policies))

	policy := policies.Policies["lab_a_scan"]
	assert.Equal(t, "lab-data", policy.Config.Defaults.Prefix.Role)
	require.NotNil(t, policy.Config.Defaults.Prefix.IsPool)
	assert.False(t, *policy.Config.Defaults.Prefix.IsPool, "an explicit false must stay distinguishable from an omitted key")
	require.Len(t, policy.Scope.SubnetMap, 2)
	assert.Equal(t, "container", policy.Scope.SubnetMap[0].Status)
	assert.Equal(t, "312", policy.Scope.SubnetMap[1].CustomFields["lab_id"])
}

// A typo inside a subnet_map entry is an error, not a dropped attribute:
// WarnUnknownPolicyKeys deliberately leaves scope alone.
func TestSubnetMapRejectsUnknownKeys(t *testing.T) {
	var scope config.Scope
	err := yaml.Unmarshal([]byte("subnet_map:\n  - prefix: 192.0.2.0/24\n    roles: nope\n"), &scope)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key roles")
}

func TestValidateSubnetMap(t *testing.T) {
	tests := []struct {
		name    string
		entries []config.SubnetMapEntry
		wantErr string
	}{
		{
			name: "nested entries are valid",
			entries: []config.SubnetMapEntry{
				{Prefix: "192.0.2.0/24"}, {Prefix: "192.0.2.0/25"}, {Prefix: "192.0.2.128/26"},
			},
		},
		{name: "missing prefix", entries: []config.SubnetMapEntry{{}}, wantErr: "prefix is required"},
		{name: "bad cidr", entries: []config.SubnetMapEntry{{Prefix: "192.0.2.0/33"}}, wantErr: "invalid prefix"},
		{
			name:    "duplicate prefix",
			entries: []config.SubnetMapEntry{{Prefix: "192.0.2.0/24"}, {Prefix: "192.0.2.0/24"}},
			wantErr: "duplicate prefix",
		},
		{
			name:    "host bits normalize onto the same network and collide",
			entries: []config.SubnetMapEntry{{Prefix: "192.0.2.0/24"}, {Prefix: "192.0.2.5/24"}},
			wantErr: "duplicate prefix",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := config.ValidateSubnetMap(tt.entries, discardLogger())
			if tt.wantErr == "" {
				require.NoError(t, err)
				for i := range tt.entries {
					assert.NotNil(t, tt.entries[i].Network(), "validation must fill in the parsed network")
				}
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// Validation normalizes a host-bearing CIDR onto its network address, which is
// the form NetBox stores.
func TestValidateSubnetMapNormalizesHostBits(t *testing.T) {
	entries := []config.SubnetMapEntry{{Prefix: "192.0.2.5/24"}}
	logger, buf := bufferedLogger()
	require.NoError(t, config.ValidateSubnetMap(entries, logger))
	assert.Equal(t, "192.0.2.0/24", entries[0].Network().String())
	assert.Equal(t, 24, entries[0].MaskBits())
	assert.Contains(t, buf.String(), "host bits")
}

// An entry covering nothing scanned is a warning, never a failure: the map
// defines IPAM while the targets define what nmap touches.
func TestWarnSubnetMapCoverage(t *testing.T) {
	entries := []config.SubnetMapEntry{{Prefix: "192.0.2.0/25"}, {Prefix: "203.0.113.0/24"}}
	require.NoError(t, config.ValidateSubnetMap(entries, discardLogger()))

	logger, buf := bufferedLogger()
	config.WarnSubnetMapCoverage(entries, []string{"192.0.2.0/24"}, logger)
	out := buf.String()
	assert.Contains(t, out, "203.0.113.0/24")
	assert.NotContains(t, out, "192.0.2.0/25")
}

// A per-entry custom field extends the policy block without mutating it.
func TestMergeCustomFields(t *testing.T) {
	base := map[string]any{"discovery_source": "network_discovery"}
	merged := config.MergeCustomFields(base, map[string]any{"lab_id": "312"})
	assert.Equal(t, "network_discovery", merged["discovery_source"])
	assert.Equal(t, "312", merged["lab_id"])
	assert.NotContains(t, base, "lab_id", "the base map must not be mutated")

	assert.Equal(t, base, config.MergeCustomFields(base, nil))
}

// rd and vrf_tenant describe the VRF named alongside them. On an entry with no
// vrf of its own they would be silently dropped, and a dropped rd is the
// difference between matching a prebuilt VRF and Diode creating a second one.
func TestSubnetMapRejectsVrfFieldsWithoutVrf(t *testing.T) {
	err := config.ValidateSubnetMap([]config.SubnetMapEntry{
		{Prefix: "192.0.2.0/24", Rd: "65000:9"},
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rd is set without vrf")

	err = config.ValidateSubnetMap([]config.SubnetMapEntry{
		{Prefix: "192.0.2.0/24", VrfTenant: "Labs"},
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vrf_tenant is set without vrf")

	// With a vrf of its own, both are what make the reference match.
	require.NoError(t, config.ValidateSubnetMap([]config.SubnetMapEntry{
		{Prefix: "192.0.2.0/24", Vrf: "LAB", Rd: "65000:9", VrfTenant: "Labs"},
	}, nil))
}

// The same CIDR really can exist in two VRFs, but a scan cannot tell which one
// answered, so one policy cannot carry both.
func TestSubnetMapRejectsDuplicateAcrossVrfs(t *testing.T) {
	err := config.ValidateSubnetMap([]config.SubnetMapEntry{
		{Prefix: "192.0.2.0/24", Vrf: "CORP"},
		{Prefix: "192.0.2.0/24", Vrf: "LAB"},
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "give each VRF its own policy")
}

// Per-entry placement keys are known keys, so a config using them is not
// rejected by the unknown-key guard.
func TestSubnetMapAcceptsPlacementKeys(t *testing.T) {
	var entries []config.SubnetMapEntry
	require.NoError(t, yaml.Unmarshal([]byte(`
- prefix: 192.0.2.0/24
  vrf: CORP
  rd: "65000:1"
  vrf_tenant: Corp
  tenant: Corp
  tenant_group: Internal
`), &entries))
	require.Len(t, entries, 1)
	assert.Equal(t, "CORP", entries[0].Vrf)
	assert.Equal(t, "65000:1", entries[0].Rd)
	assert.Equal(t, "Corp", entries[0].VrfTenant)
	assert.Equal(t, "Corp", entries[0].Tenant)
	assert.Equal(t, "Internal", entries[0].TenantGroup)
}
