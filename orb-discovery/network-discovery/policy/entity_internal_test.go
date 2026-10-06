package policy

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/Ullaakut/nmap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

func scannedHost(name string) nmap.Host {
	return nmap.Host{
		Hostnames: []nmap.Hostname{{Name: name, Type: "PTR"}},
		Ports:     []nmap.Port{{ID: 22, Protocol: "tcp", Service: nmap.Service{Name: "ssh"}, State: nmap.State{State: "open"}}},
	}
}

func commentsOf(t *testing.T, comments *string) config.HostMetadata {
	t.Helper()
	require.NotNil(t, comments)
	var metadata config.HostMetadata
	require.NoError(t, json.Unmarshal([]byte(*comments), &metadata))
	return metadata
}

// With scan_details_in_comments opted in and no comments of the policy's own,
// a replaced name is kept in them as nmap gave it, next to the ports, and a
// clean name leaves the hostnames list empty as it always was.
func TestIPAddressEntityKeepsAReplacedNameInTheComments(t *testing.T) {
	r := &Runner{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: config.PolicyConfig{ScanDetailsInComments: true},
	}
	ip, outcome := r.ipAddressEntity(scannedHost("abc1234-vendor*model*unit.example.net"), "192.0.2.10/24", "192.0.2.10", nil, "p", nil)
	assert.Equal(t, hostnameReplaced, outcome)
	assert.Equal(t, "abc1234-vendor-model-unit.example.net", *ip.DnsName)
	metadata := commentsOf(t, ip.Comments)
	require.Len(t, metadata.Hostnames, 1)
	assert.Equal(t, "abc1234-vendor*model*unit.example.net", metadata.Hostnames[0].Name)
	require.Len(t, metadata.Ports, 1)
	assert.Equal(t, 22, metadata.Ports[0].Number)

	ip, outcome = r.ipAddressEntity(scannedHost("clean.example.net"), "192.0.2.11/24", "192.0.2.11", nil, "p", nil)
	assert.Equal(t, hostnameUnchanged, outcome)
	assert.Nil(t, commentsOf(t, ip.Comments).Hostnames)
}

// When the policy sets its own comments they go out untouched, and the
// replaced name is not recorded anywhere in the entity.
func TestIPAddressEntityLeavesThePolicysCommentsAlone(t *testing.T) {
	r := &Runner{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), config: config.PolicyConfig{Defaults: config.Defaults{Comments: "owned by the policy"}}}
	ip, outcome := r.ipAddressEntity(scannedHost("abc*unit.example.net"), "192.0.2.12/24", "192.0.2.12", nil, "p", nil)
	assert.Equal(t, hostnameReplaced, outcome)
	assert.Equal(t, "abc-unit.example.net", *ip.DnsName)
	require.NotNil(t, ip.Comments)
	assert.Equal(t, "owned by the policy", *ip.Comments)
}

// By default the scan never writes comments: they are often hand-written and a
// scan must not overwrite them.
func TestIPAddressEntityLeavesCommentsUnsetByDefault(t *testing.T) {
	r := &Runner{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ip, outcome := r.ipAddressEntity(scannedHost("abc*unit.example.net"), "192.0.2.13/24", "192.0.2.13", nil, "p", nil)
	assert.Equal(t, hostnameReplaced, outcome)
	assert.Equal(t, "abc-unit.example.net", *ip.DnsName)
	assert.Nil(t, ip.Comments)
}

// ${SCAN_DETAILS} puts the per-host scan document in a json custom field
// instead, with every reverse name nmap reported.
func TestIPAddressEntityScanDetailsToken(t *testing.T) {
	r := &Runner{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	fields := map[string]any{"scan_details": config.ScanDetailsToken{}, "discovery_source": "nd"}
	ip, _ := r.ipAddressEntity(scannedHost("clean.example.net"), "192.0.2.14/24", "192.0.2.14", nil, "p", fields)
	assert.Nil(t, ip.Comments)
	require.Contains(t, ip.CustomFields, "scan_details")
	require.Contains(t, ip.CustomFields, "discovery_source")
	raw, err := json.Marshal(ip.CustomFields["scan_details"])
	require.NoError(t, err)
	assert.Contains(t, string(raw), "clean.example.net")
	assert.Contains(t, string(raw), "ssh")
}

// address_tags reach the addresses inside the entry, merged after defaults.tags.
func TestIPAddressEntityAddressTags(t *testing.T) {
	r := &Runner{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: config.PolicyConfig{Defaults: config.Defaults{Tags: []string{"discovered"}}},
	}
	entry := &config.SubnetMapEntry{Prefix: "192.0.2.0/24", Tags: []string{"prefix-only"}, AddressTags: []string{"servers", "discovered"}}
	ip, _ := r.ipAddressEntity(scannedHost("a.example.net"), "192.0.2.15/24", "192.0.2.15", entry, "p", nil)
	var names []string
	for _, tag := range ip.Tags {
		names = append(names, *tag.Name)
	}
	assert.Equal(t, []string{"discovered", "servers"}, names)
}
