package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
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

func runnerWithCustomFields(fields map[string]any, precision string) *Runner {
	return &Runner{
		logger:    testLogger(),
		agentName: "lab-agent-01",
		config: config.PolicyConfig{
			CustomFields:       fields,
			TimestampPrecision: precision,
		},
	}
}

// Every custom field must reach the IP address on the variant NetBox expects.
func TestIPAddressEntityCarriesCustomFields(t *testing.T) {
	r := runnerWithCustomFields(nil, "")
	scanTime := config.TruncateScanTime(
		time.Date(2026, 9, 15, 10, 30, 45, 0, time.UTC), config.PrecisionDay)

	resolved, err := config.ResolveCustomFields(map[string]any{
		"discovery_agent":     "${AGENT_NAME}",
		"discovery_policy":    "${POLICY_NAME}",
		"discovery_last_seen": "${SCAN_TIMESTAMP}",
		"discovery_source":    "network_discovery",
	}, config.CustomFieldTokens{AgentName: "lab-agent-01", PolicyName: "lab_scan", ScanTime: scanTime})
	require.NoError(t, err)

	ip, _ := r.ipAddressEntity(scannedHost("host.example.net"), "192.0.2.10/24", "192.0.2.10", "lab_scan", resolved)

	require.Len(t, ip.CustomFields, 4)
	assert.Equal(t, diode.CustomFieldValueText("lab-agent-01"), ip.CustomFields["discovery_agent"].Value)
	assert.Equal(t, diode.CustomFieldValueText("lab_scan"), ip.CustomFields["discovery_policy"].Value)
	assert.Equal(t, diode.CustomFieldValueText("network_discovery"), ip.CustomFields["discovery_source"].Value)
	// Datetime, not text: a NetBox datetime custom field rejects a string.
	assert.IsType(t, diode.CustomFieldValueDatetime{}, ip.CustomFields["discovery_last_seen"].Value)
}

// A policy with no custom_fields must produce an entity identical to the one the
// backend emitted before the feature existed.
func TestIPAddressEntityUnchangedWithoutCustomFields(t *testing.T) {
	r := runnerWithCustomFields(nil, "")
	ip, _ := r.ipAddressEntity(scannedHost("host.example.net"), "192.0.2.10/24", "192.0.2.10", "lab_scan", nil)
	assert.Nil(t, ip.CustomFields)
	assert.Equal(t, "192.0.2.10/24", *ip.Address)
}

// A value the SDK rejects is logged and skipped; the address still goes out.
func TestIPAddressEntitySurvivesABadCustomFieldValue(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	r := &Runner{logger: slog.New(slog.NewTextHandler(buf, nil))}

	ip, _ := r.ipAddressEntity(scannedHost("host.example.net"), "192.0.2.10/24", "192.0.2.10", "lab_scan",
		map[string]any{"ok_field": "fine", "bad_field": struct{ X int }{1}})

	assert.Equal(t, "192.0.2.10/24", *ip.Address)
	assert.Contains(t, ip.CustomFields, "ok_field")
	assert.NotContains(t, ip.CustomFields, "bad_field")
	assert.Contains(t, buf.String(), "skipping custom field")
}

// Every address in one run shares one ${SCAN_TIMESTAMP}. Resolving per address
// would stamp hosts discovered seconds apart differently, and at scale that
// alone makes every entity differ from what NetBox holds.
func TestScanTimestampIsSharedAcrossARun(t *testing.T) {
	scanTime := config.TruncateScanTime(time.Now(), config.PrecisionDay)
	tokens := config.CustomFieldTokens{AgentName: "a", PolicyName: "p", ScanTime: scanTime}
	resolved, err := config.ResolveCustomFields(map[string]any{"discovery_last_seen": "${SCAN_TIMESTAMP}"}, tokens)
	require.NoError(t, err)

	r := runnerWithCustomFields(nil, "")
	first, _ := r.ipAddressEntity(scannedHost("a.example.net"), "192.0.2.1/24", "192.0.2.1", "p", resolved)
	second, _ := r.ipAddressEntity(scannedHost("b.example.net"), "192.0.2.2/24", "192.0.2.2", "p", resolved)

	assert.Equal(t,
		first.CustomFields["discovery_last_seen"].Value,
		second.CustomFields["discovery_last_seen"].Value)
}

// Walks the documented sample through the real dry-run client, which is the same
// path `dry_run: true` takes in production. nmap is not available in CI, so the
// discovered address is synthesized while everything downstream of it is the
// production code path.
func TestDryRunGolden(t *testing.T) {
	outputDir := os.Getenv("NETWORK_DISCOVERY_DRYRUN_DIR")
	if outputDir == "" {
		outputDir = t.TempDir()
	}
	client, err := diode.NewDryRunClient("network-discovery", outputDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	cfg := config.PolicyConfig{
		Defaults: config.Defaults{Vrf: "LAB-AUS-01", Tenant: "LAB-AUS-01"},
		CustomFields: map[string]any{
			"discovery_agent":     "${AGENT_NAME}",
			"discovery_policy":    "${POLICY_NAME}",
			"discovery_last_seen": "${SCAN_TIMESTAMP}",
			"discovery_source":    "network_discovery",
		},
	}
	r := &Runner{logger: testLogger(), agentName: "lab-agent-01", client: client, config: cfg}

	resolved, err := config.ResolveCustomFields(cfg.CustomFields, config.CustomFieldTokens{
		AgentName:  r.agentName,
		PolicyName: "lab_scan",
		ScanTime: config.TruncateScanTime(
			time.Date(2026, 9, 15, 10, 30, 45, 0, time.UTC), cfg.ResolvedTimestampPrecision()),
	})
	require.NoError(t, err)

	ip, _ := r.ipAddressEntity(scannedHost("host.example.net"), "192.0.2.200/24", "192.0.2.200", "lab_scan", resolved)
	_, err = client.Ingest(context.Background(), []diode.Entity{ip})
	require.NoError(t, err)

	files, err := filepath.Glob(filepath.Join(outputDir, "*.json"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	t.Logf("dry-run output: %s", files[0])

	body, err := os.ReadFile(files[0])
	require.NoError(t, err)

	// Asserted structurally rather than by substring: the dry-run writer
	// pretty-prints, so the spacing of the serialized form is not the contract.
	var payload struct {
		Entities []struct {
			IPAddress struct {
				Address      string                       `json:"address"`
				CustomFields map[string]map[string]string `json:"custom_fields"`
			} `json:"ip_address"`
		} `json:"entities"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))
	require.Len(t, payload.Entities, 1)

	entity := payload.Entities[0].IPAddress
	assert.Equal(t, "192.0.2.200/24", entity.Address)
	assert.Equal(t, "lab-agent-01", entity.CustomFields["discovery_agent"]["text"])
	assert.Equal(t, "lab_scan", entity.CustomFields["discovery_policy"]["text"])
	assert.Equal(t, "network_discovery", entity.CustomFields["discovery_source"]["text"])
	// Truncated to the day, and carried on the datetime variant rather than text.
	assert.Equal(t, "2026-09-15T00:00:00Z", entity.CustomFields["discovery_last_seen"]["datetime"])
}
