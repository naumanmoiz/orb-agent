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
		ScanTime:   time.Date(2026, 9, 14, 10, 30, 0, 0, time.UTC),
	}
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
a_datetime: 2026-09-14T10:30:00Z
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

	// A json custom field takes a serialized document; a bare map has no variant.
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
// applies to its flags. A token embedded in a longer string is literal text.
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

func TestMergeCustomFields(t *testing.T) {
	base := map[string]any{"discovery_source": "network_discovery", "discovery_zone": "default"}
	override := map[string]any{"discovery_zone": "management"}

	merged := config.MergeCustomFields(base, override)
	assert.Equal(t, "network_discovery", merged["discovery_source"])
	assert.Equal(t, "management", merged["discovery_zone"], "an entry value must win over the policy value")
	assert.Equal(t, "default", base["discovery_zone"], "the base map must not be mutated")

	assert.Nil(t, config.MergeCustomFields(nil, nil))
}
