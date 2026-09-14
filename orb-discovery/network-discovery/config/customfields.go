package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Substitution tokens resolved by the agent rather than from the environment.
// Anything else wrapped in ${} follows the environment-variable scheme the
// backend already uses for its command-line flags.
const (
	// TokenAgentName is replaced by the configured agent name, which reaches the
	// backend as --diode-app-name-prefix.
	TokenAgentName = "AGENT_NAME"
	// TokenPolicyName is replaced by the policy key the entity was emitted under.
	TokenPolicyName = "POLICY_NAME"
	// TokenScanTimestamp is replaced by the start time of the scan run. It
	// resolves to a time.Time, not a string, so it lands in a NetBox datetime
	// custom field rather than a text one.
	TokenScanTimestamp = "SCAN_TIMESTAMP"
)

// CustomFieldTokens are the per-run values the substitution tokens resolve to.
type CustomFieldTokens struct {
	AgentName  string
	PolicyName string
	ScanTime   time.Time
}

// ResolveCustomFields returns a copy of raw with every value substituted and
// normalized to a type the Diode SDK maps onto a NetBox custom field:
//
//	string     -> text        integer   -> integer
//	bool       -> boolean     float     -> decimal
//	time.Time  -> datetime    map/slice -> json
//
// Only a value that is exactly ${NAME} is substituted, matching the whole-value
// convention the backend already applies to its flags; "lab-${NAME}" is left
// alone. A nil value is dropped rather than sent, because a null custom field
// would clear whatever NetBox already holds.
func ResolveCustomFields(raw map[string]any, tokens CustomFieldTokens) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(raw))
	for _, key := range sortedKeys(raw) {
		value, err := resolveCustomFieldValue(raw[key], tokens)
		if err != nil {
			return nil, fmt.Errorf("custom_fields.%s: %w", key, err)
		}
		if value == nil {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// MergeCustomFields overlays override onto base, returning a new map. Used for
// the per-entry custom_fields of a subnet_map entry, which extend rather than
// replace the policy-level block.
func MergeCustomFields(base, override map[string]any) map[string]any {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}
	out := make(map[string]any, len(base)+len(override))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}

// resolveCustomFieldValue substitutes and normalizes a single value.
func resolveCustomFieldValue(value any, tokens CustomFieldTokens) (any, error) {
	switch v := value.(type) {
	case nil:
		return nil, nil
	case string:
		return resolveCustomFieldString(v, tokens)
	case bool, float32, float64, time.Time:
		return v, nil
	case int:
		return int64(v), nil
	case int8:
		return int64(v), nil
	case int16:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case uint, uint8, uint16, uint32, uint64:
		return normalizeUint(v)
	case map[string]any, []any:
		// NetBox json custom fields take a serialized document. The SDK maps
		// json.RawMessage onto CustomFieldValueJson; a bare map has no variant.
		data, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("cannot serialize as json: %w", err)
		}
		return json.RawMessage(data), nil
	default:
		return nil, fmt.Errorf("unsupported value type %T", v)
	}
}

// resolveCustomFieldString substitutes a whole-value ${NAME} reference.
func resolveCustomFieldString(value string, tokens CustomFieldTokens) (any, error) {
	name, ok := bracketedName(value)
	if !ok {
		return value, nil
	}
	switch name {
	case TokenAgentName:
		return tokens.AgentName, nil
	case TokenPolicyName:
		return tokens.PolicyName, nil
	case TokenScanTimestamp:
		return tokens.ScanTime.UTC(), nil
	}
	if resolved := os.Getenv(name); resolved != "" {
		return resolved, nil
	}
	return nil, fmt.Errorf("environment variable %s is not set or is empty", name)
}

// bracketedName returns the NAME in a value that is exactly ${NAME}.
func bracketedName(value string) (string, bool) {
	if !strings.HasPrefix(value, "${") || !strings.HasSuffix(value, "}") {
		return "", false
	}
	name := value[2 : len(value)-1]
	if name == "" {
		return "", false
	}
	return name, true
}

// normalizeUint widens an unsigned value to int64, the only integer variant
// NetBox custom fields have. yaml.v3 only produces one for a value above
// math.MaxInt64, which cannot be represented and is rejected rather than
// silently wrapped negative.
func normalizeUint(value any) (any, error) {
	switch v := value.(type) {
	case uint:
		return uintToInt64(uint64(v))
	case uint8:
		return int64(v), nil
	case uint16:
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case uint64:
		return uintToInt64(v)
	}
	return nil, fmt.Errorf("unsupported value type %T", value)
}

func uintToInt64(v uint64) (any, error) {
	const maxInt64 = 1<<63 - 1
	if v > maxInt64 {
		return nil, fmt.Errorf("integer %d exceeds the maximum NetBox custom field integer", v)
	}
	return int64(v), nil
}

// sortedKeys keeps resolution order deterministic so an error names the same
// field on every run.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
