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

// bufferedLogger returns a logger and the buffer its records land in, so a test
// can assert on a warning that is deliberately not an error.
func bufferedLogger() (*slog.Logger, *bytes.Buffer) {
	buf := bytes.NewBuffer(nil)
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

// A policy written before any of the IPAM keys existed must still decode, and
// must leave every new field at its zero value.
func TestParsePolicyWithoutNewKeys(t *testing.T) {
	var policies config.Policies
	require.NoError(t, yaml.Unmarshal([]byte(`
policies:
  legacy:
    config:
      schedule: "* * * * *"
      timeout: 10
      defaults:
        vrf: LAB
        tenant: LAB
        role: host
        tags: [orb]
    scope:
      targets: [192.0.2.0/24]
`), &policies))

	policy := policies.Policies["legacy"]
	assert.Equal(t, []string{"192.0.2.0/24"}, policy.Scope.Targets)
	assert.Equal(t, "LAB", policy.Config.Defaults.Vrf)
	assert.Empty(t, policy.Scope.SubnetMap)
	assert.Empty(t, policy.Config.CustomFields)
	assert.Empty(t, policy.Config.Defaults.Site)
	assert.Equal(t, config.PrefixDefaults{}, policy.Config.Defaults.Prefix)
	assert.Equal(t, config.VlanDefaults{}, policy.Config.Defaults.Vlan)
}

// The full new surface decodes into the shapes the entity builders expect.
func TestParsePolicyWithNewKeys(t *testing.T) {
	var policies config.Policies
	require.NoError(t, yaml.Unmarshal([]byte(`
policies:
  lab_scan:
    config:
      defaults:
        site: LAB-AUS-01
        tenant: LAB-AUS-01
        vrf: LAB-AUS-01
        prefix:
          status: active
          role: lab-data
          is_pool: false
        vlan:
          status: active
          group: LAB-AUS-01-VLANS
      custom_fields:
        discovery_source: network_discovery
        discovery_retention_days: 30
    scope:
      targets: [10.10.0.0/16]
      subnet_map:
        - prefix: 10.10.0.0/16
          status: container
          role: lab-aggregate
        - prefix: 10.10.20.0/24
          role: lab-servers
          vlan: {vid: 20, name: SERVERS}
          custom_fields:
            discovery_zone: servers
`), &policies))

	policy := policies.Policies["lab_scan"]
	defaults := policy.Config.Defaults
	assert.Equal(t, "LAB-AUS-01", defaults.Site)
	assert.Equal(t, "lab-data", defaults.Prefix.Role)
	require.NotNil(t, defaults.Prefix.IsPool)
	assert.False(t, *defaults.Prefix.IsPool, "an explicit false must stay distinguishable from an omitted key")
	assert.Equal(t, "LAB-AUS-01-VLANS", defaults.Vlan.Group.Name)
	assert.Equal(t, "network_discovery", policy.Config.CustomFields["discovery_source"])
	assert.Equal(t, 30, policy.Config.CustomFields["discovery_retention_days"])

	require.Len(t, policy.Scope.SubnetMap, 2)
	assert.Equal(t, "container", policy.Scope.SubnetMap[0].Status)
	assert.Nil(t, policy.Scope.SubnetMap[0].Vlan)
	require.NotNil(t, policy.Scope.SubnetMap[1].Vlan)
	assert.Equal(t, 20, *policy.Scope.SubnetMap[1].Vlan.Vid)
	assert.Equal(t, "servers", policy.Scope.SubnetMap[1].CustomFields["discovery_zone"])
}

// vlan.group takes either form, and the bare string leaves the scope to
// defaults.site.
func TestVlanGroupAcceptsScalarAndMapping(t *testing.T) {
	var scalar config.VlanDefaults
	require.NoError(t, yaml.Unmarshal([]byte("group: LAB-VLANS\n"), &scalar))
	assert.Equal(t, "LAB-VLANS", scalar.Group.Name)
	assert.Empty(t, scalar.Group.ScopeSite)

	var mapping config.VlanDefaults
	require.NoError(t, yaml.Unmarshal([]byte("group:\n  name: LAB-VLANS\n  scope_site: OTHER\n"), &mapping))
	assert.Equal(t, "OTHER", mapping.Group.ScopeSite)
}

func TestVlanGroupRejectsBadMappings(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown key":  "group:\n  name: G\n  scope_zone: Z\n",
		"missing name": "group:\n  scope_site: S\n",
		"two scopes":   "group:\n  name: G\n  scope_site: S\n  scope_region: R\n",
	} {
		t.Run(name, func(t *testing.T) {
			var defaults config.VlanDefaults
			assert.Error(t, yaml.Unmarshal([]byte(doc), &defaults))
		})
	}
}

// A typo inside a subnet_map entry is an error, not a dropped attribute:
// WarnUnknownPolicyKeys deliberately leaves scope alone.
func TestSubnetMapRejectsUnknownKeys(t *testing.T) {
	var scope config.Scope
	err := yaml.Unmarshal([]byte("subnet_map:\n  - prefix: 10.0.0.0/8\n    roles: nope\n"), &scope)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key roles")

	err = yaml.Unmarshal([]byte("subnet_map:\n  - prefix: 10.0.0.0/8\n    vlan: {vid: 10, nmae: X}\n"), &scope)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key nmae")
}

func TestValidateSubnetMap(t *testing.T) {
	vid := func(v int) *int { return &v }

	tests := []struct {
		name    string
		entries []config.SubnetMapEntry
		wantErr string
	}{
		{
			name: "nested entries are valid",
			entries: []config.SubnetMapEntry{
				{Prefix: "10.10.0.0/16"},
				{Prefix: "10.10.20.0/24"},
				{Prefix: "10.10.20.128/25"},
			},
		},
		{
			name:    "missing prefix",
			entries: []config.SubnetMapEntry{{}},
			wantErr: "prefix is required",
		},
		{
			name:    "bad cidr",
			entries: []config.SubnetMapEntry{{Prefix: "10.10.20.0/33"}},
			wantErr: "invalid prefix",
		},
		{
			name: "duplicate prefix",
			entries: []config.SubnetMapEntry{
				{Prefix: "10.10.20.0/24"},
				{Prefix: "10.10.20.0/24"},
			},
			wantErr: "duplicate prefix",
		},
		{
			name: "host bits normalize onto the same network and collide",
			entries: []config.SubnetMapEntry{
				{Prefix: "10.10.20.0/24"},
				{Prefix: "10.10.20.5/24"},
			},
			wantErr: "duplicate prefix",
		},
		{
			name:    "vlan without vid",
			entries: []config.SubnetMapEntry{{Prefix: "10.10.20.0/24", Vlan: &config.SubnetVlan{Name: "SERVERS"}}},
			wantErr: "vlan.vid is required",
		},
		{
			name:    "vid too low",
			entries: []config.SubnetMapEntry{{Prefix: "10.10.20.0/24", Vlan: &config.SubnetVlan{Vid: vid(0)}}},
			wantErr: "out of range",
		},
		{
			name:    "vid too high",
			entries: []config.SubnetMapEntry{{Prefix: "10.10.20.0/24", Vlan: &config.SubnetVlan{Vid: vid(4095)}}},
			wantErr: "out of range",
		},
		{
			name:    "vid at the upper bound is valid",
			entries: []config.SubnetMapEntry{{Prefix: "10.10.20.0/24", Vlan: &config.SubnetVlan{Vid: vid(4094)}}},
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
	entries := []config.SubnetMapEntry{{Prefix: "10.10.20.5/24"}}
	logger, buf := bufferedLogger()
	require.NoError(t, config.ValidateSubnetMap(entries, logger))
	assert.Equal(t, "10.10.20.0/24", entries[0].Network().String())
	assert.Equal(t, 24, entries[0].MaskBits())
	assert.Contains(t, buf.String(), "host bits")
}

// An entry covering nothing that is scanned is a warning, never a failure: the
// map defines IPAM while the targets define what nmap touches.
func TestWarnSubnetMapCoverage(t *testing.T) {
	entries := []config.SubnetMapEntry{
		{Prefix: "10.10.20.0/24"},
		{Prefix: "192.168.99.0/24"},
	}
	require.NoError(t, config.ValidateSubnetMap(entries, discardLogger()))

	logger, buf := bufferedLogger()
	config.WarnSubnetMapCoverage(entries, []string{"10.10.0.0/16"}, logger)
	out := buf.String()
	assert.Contains(t, out, "192.168.99.0/24")
	assert.NotContains(t, out, "10.10.20.0/24")
}

// A subnet_map entry wider than the targets still overlaps them, so it is not
// warned about.
func TestWarnSubnetMapCoverageAcceptsWiderEntries(t *testing.T) {
	entries := []config.SubnetMapEntry{{Prefix: "10.0.0.0/8"}}
	require.NoError(t, config.ValidateSubnetMap(entries, discardLogger()))

	logger, buf := bufferedLogger()
	config.WarnSubnetMapCoverage(entries, []string{"10.10.20.0/24"}, logger)
	assert.Empty(t, buf.String())
}
