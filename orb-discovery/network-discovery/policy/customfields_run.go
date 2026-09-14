package policy

import (
	"log/slog"
	"time"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

// runCustomFields holds the custom field values for one scan run, already
// substituted and type-normalized.
//
// Resolution happens once per run rather than once per entity because
// ${SCAN_TIMESTAMP} must be identical across every entity the run emits:
// resolving per entity would stamp addresses discovered seconds apart with
// different values and make "last seen" useless for grouping a run.
type runCustomFields struct {
	policy  map[string]any
	byEntry map[*config.SubnetMapEntry]map[string]any
}

// resolveRunCustomFields substitutes the policy-level block and every
// subnet_map entry's own block, merging each entry's over the policy's.
//
// A value that cannot be resolved is reported once and the affected block is
// dropped, leaving the rest of the run to proceed: an unset environment
// variable should not cost a scan's worth of discovered addresses.
func resolveRunCustomFields(cfg config.PolicyConfig, entries []config.SubnetMapEntry,
	tokens config.CustomFieldTokens, logger *slog.Logger,
) runCustomFields {
	resolved := runCustomFields{byEntry: make(map[*config.SubnetMapEntry]map[string]any)}

	policyFields, err := config.ResolveCustomFields(cfg.CustomFields, tokens)
	if err != nil {
		if logger != nil {
			logger.Error("skipping policy custom fields", "error", err, "policy", tokens.PolicyName)
		}
	} else {
		resolved.policy = policyFields
	}

	for i := range entries {
		entry := &entries[i]
		if len(entry.CustomFields) == 0 {
			continue
		}
		entryFields, err := config.ResolveCustomFields(entry.CustomFields, tokens)
		if err != nil {
			if logger != nil {
				logger.Error("skipping subnet_map custom fields", "error", err,
					"prefix", entry.Prefix, "policy", tokens.PolicyName)
			}
			continue
		}
		resolved.byEntry[entry] = config.MergeCustomFields(resolved.policy, entryFields)
	}
	return resolved
}

// forEntry returns the fields for a subnet_map entry, falling back to the
// policy-level block for an entry that declares none of its own and for a
// discovered address that matched no entry at all.
func (r runCustomFields) forEntry(entry *config.SubnetMapEntry) map[string]any {
	if entry != nil {
		if fields, ok := r.byEntry[entry]; ok {
			return fields
		}
	}
	return r.policy
}

// scanTokens builds the substitution tokens for one run.
func scanTokens(agentName, policyName string, scanTime time.Time) config.CustomFieldTokens {
	return config.CustomFieldTokens{
		AgentName:  agentName,
		PolicyName: policyName,
		ScanTime:   scanTime,
	}
}
