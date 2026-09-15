package config_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

func testTokens() config.CustomFieldTokens {
	return config.CustomFieldTokens{
		AgentName:  "lab-agent-01",
		PolicyName: "lab_scan",
		ScanTime:   time.Date(2026, 9, 15, 10, 30, 45, 123456789, time.UTC),
	}
}

// A policy written before custom_fields existed must still decode, with the new
// fields left at their zero values.
func TestParsePolicyWithoutCustomFields(t *testing.T) {
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
        tags: [orb]
    scope:
      targets: [192.0.2.0/24]
`), &policies))

	policy := policies.Policies["legacy"]
	assert.Equal(t, []string{"192.0.2.0/24"}, policy.Scope.Targets)
	assert.Equal(t, "LAB", policy.Config.Defaults.Vrf)
	assert.Empty(t, policy.Config.CustomFields)
	assert.Empty(t, policy.Config.TimestampPrecision)
	assert.Equal(t, config.PrecisionDay, policy.Config.ResolvedTimestampPrecision())
}

func TestParsePolicyWithCustomFields(t *testing.T) {
	var policies config.Policies
	require.NoError(t, yaml.Unmarshal([]byte(`
policies:
  lab_scan:
    config:
      timestamp_precision: hour
      custom_fields:
        discovery_source: network_discovery
        discovery_retention_days: 30
    scope:
      targets: [192.0.2.0/24]
`), &policies))

	cfg := policies.Policies["lab_scan"].Config
	assert.Equal(t, "network_discovery", cfg.CustomFields["discovery_source"])
	assert.Equal(t, 30, cfg.CustomFields["discovery_retention_days"])
	assert.Equal(t, config.PrecisionHour, cfg.ResolvedTimestampPrecision())
}

// Each YAML scalar type must land on the CustomFieldValue variant NetBox
// expects for the matching custom field type.
func TestResolveCustomFieldsTypeDetection(t *testing.T) {
	var raw map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(`
a_text: hello
an_integer: 42
a_negative: -7
a_boolean: true
a_decimal: 1.5
a_datetime: 2026-09-15T10:30:00Z
a_json:
  zone: management
  vids: [10, 20]
`), &raw))

	resolved, err := config.ResolveCustomFields(raw, testTokens())
	require.NoError(t, err)

	assert.Equal(t, "hello", resolved["a_text"])
	assert.Equal(t, int64(42), resolved["an_integer"], "an int must widen to int64, the only integer variant the SDK maps")
	assert.Equal(t, int64(-7), resolved["a_negative"])
	assert.Equal(t, true, resolved["a_boolean"])
	assert.Equal(t, 1.5, resolved["a_decimal"])
	assert.IsType(t, time.Time{}, resolved["a_datetime"])

	require.IsType(t, json.RawMessage{}, resolved["a_json"])
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(resolved["a_json"].(json.RawMessage), &decoded))
	assert.Equal(t, "management", decoded["zone"])
}

func TestResolveCustomFieldsTokens(t *testing.T) {
	raw := map[string]any{
		"discovery_agent":     "${AGENT_NAME}",
		"discovery_policy":    "${POLICY_NAME}",
		"discovery_last_seen": "${SCAN_TIMESTAMP}",
		"discovery_source":    "network_discovery",
	}
	resolved, err := config.ResolveCustomFields(raw, testTokens())
	require.NoError(t, err)

	assert.Equal(t, "lab-agent-01", resolved["discovery_agent"])
	assert.Equal(t, "lab_scan", resolved["discovery_policy"])
	assert.Equal(t, "network_discovery", resolved["discovery_source"])
	// The scan timestamp resolves to a time, not a string, so it reaches a
	// NetBox datetime field rather than a text one.
	assert.Equal(t, testTokens().ScanTime, resolved["discovery_last_seen"])
}

// Substitution stays whole-value, matching the convention the backend already
// applies to its flags. A token inside a longer string is literal text.
func TestResolveCustomFieldsLeavesEmbeddedTokensAlone(t *testing.T) {
	resolved, err := config.ResolveCustomFields(
		map[string]any{"discovery_agent": "lab-${AGENT_NAME}"}, testTokens())
	require.NoError(t, err)
	assert.Equal(t, "lab-${AGENT_NAME}", resolved["discovery_agent"])
}

func TestResolveCustomFieldsEnvVars(t *testing.T) {
	t.Setenv("DISCOVERY_ZONE", "management")
	resolved, err := config.ResolveCustomFields(
		map[string]any{"discovery_zone": "${DISCOVERY_ZONE}"}, testTokens())
	require.NoError(t, err)
	assert.Equal(t, "management", resolved["discovery_zone"])

	_, err = config.ResolveCustomFields(
		map[string]any{"discovery_zone": "${DISCOVERY_ZONE_NOT_SET}"}, testTokens())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "custom_fields.discovery_zone")
	assert.Contains(t, err.Error(), "DISCOVERY_ZONE_NOT_SET")
}

// An unconfigured agent name is reported rather than written through as "",
// which would look populated in NetBox but identify nothing.
func TestResolveCustomFieldsRejectsEmptyAgentName(t *testing.T) {
	tokens := testTokens()
	tokens.AgentName = ""
	_, err := config.ResolveCustomFields(map[string]any{"discovery_agent": "${AGENT_NAME}"}, tokens)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AGENT_NAME")
}

// A null value is dropped rather than sent: a null custom field clears whatever
// NetBox already holds.
func TestResolveCustomFieldsDropsNulls(t *testing.T) {
	var raw map[string]any
	require.NoError(t, yaml.Unmarshal([]byte("a_text: hello\na_null:\n"), &raw))
	resolved, err := config.ResolveCustomFields(raw, testTokens())
	require.NoError(t, err)
	assert.Len(t, resolved, 1)
	assert.NotContains(t, resolved, "a_null")
}

func TestResolveCustomFieldsEmptyIsNil(t *testing.T) {
	resolved, err := config.ResolveCustomFields(nil, testTokens())
	require.NoError(t, err)
	assert.Nil(t, resolved)
}

// The precision is what stops every scan rewriting every address in NetBox, so
// each step has to actually truncate.
func TestTruncateScanTime(t *testing.T) {
	scanTime := time.Date(2026, 9, 15, 10, 30, 45, 123456789, time.UTC)

	tests := map[string]time.Time{
		config.PrecisionNanosecond: scanTime,
		config.PrecisionSecond:     time.Date(2026, 9, 15, 10, 30, 45, 0, time.UTC),
		config.PrecisionMinute:     time.Date(2026, 9, 15, 10, 30, 0, 0, time.UTC),
		config.PrecisionHour:       time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC),
		config.PrecisionDay:        time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC),
	}
	for precision, want := range tests {
		t.Run(precision, func(t *testing.T) {
			assert.Equal(t, want, config.TruncateScanTime(scanTime, precision))
		})
	}
}

// Two scans within the same day produce the same value, which is what lets an
// otherwise unchanged address reconcile to a no-op.
func TestTruncateScanTimeIsStableWithinThePeriod(t *testing.T) {
	first := time.Date(2026, 9, 15, 2, 0, 0, 0, time.UTC)
	second := time.Date(2026, 9, 15, 22, 45, 12, 0, time.UTC)
	assert.Equal(t,
		config.TruncateScanTime(first, config.PrecisionDay),
		config.TruncateScanTime(second, config.PrecisionDay))
	assert.NotEqual(t,
		config.TruncateScanTime(first, config.PrecisionHour),
		config.TruncateScanTime(second, config.PrecisionHour))
}

func TestValidateTimestampPrecision(t *testing.T) {
	for _, ok := range []string{"", "nanosecond", "second", "minute", "hour", "day"} {
		assert.NoError(t, config.ValidateTimestampPrecision(ok), ok)
	}
	err := config.ValidateTimestampPrecision("fortnight")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fortnight")
}
