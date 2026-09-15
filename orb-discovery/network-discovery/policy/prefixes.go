package policy

import (
	"log/slog"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

// prefixBuilder turns validated subnet_map entries into Prefix entities, deduped
// so each network is sent once per scan run.
//
// Nothing here defaults an unset field. Diode leaves an absent optional field
// out of the changeset, so NetBox keeps the value it already holds; filling in
// "active" for a missing status would make every scan re-assert it over an
// operator-set one.
type prefixBuilder struct {
	defaults   config.Defaults
	logger     *slog.Logger
	policyName string

	seen  map[string]struct{}
	order []diode.Entity
}

func newPrefixBuilder(defaults config.Defaults, logger *slog.Logger, policyName string) *prefixBuilder {
	return &prefixBuilder{
		defaults:   defaults,
		logger:     logger,
		policyName: policyName,
		seen:       make(map[string]struct{}),
	}
}

// add emits one Prefix for the entry the first time its network is seen.
func (b *prefixBuilder) add(entry *config.SubnetMapEntry, customFields map[string]any) {
	cidr := entry.Network().String()
	if _, done := b.seen[cidr]; done {
		return
	}

	prefix := &diode.Prefix{Prefix: diode.String(cidr)}
	if vrf := vrfReference(b.defaults.Vrf, b.defaults.Rd); vrf != nil {
		prefix.Vrf = vrf
	}
	if tenant := firstNonEmpty(entry.Tenant, b.defaults.Prefix.Tenant, b.defaults.Tenant); tenant != "" {
		prefix.Tenant = &diode.Tenant{Name: diode.String(tenant)}
	}
	if status := firstNonEmpty(entry.Status, b.defaults.Prefix.Status); status != "" {
		prefix.Status = diode.String(status)
	}
	if role := firstNonEmpty(entry.Role, b.defaults.Prefix.Role); role != "" {
		// Prefix.Role is an ipam.Role object, unlike IPAddress.Role which is a
		// fixed choice string. The plugin generates the slug from the name.
		prefix.Role = &diode.Role{Name: diode.String(role)}
	}
	if isPool := firstNonNilBool(entry.IsPool, b.defaults.Prefix.IsPool); isPool != nil {
		prefix.IsPool = isPool
	}
	if markUtilized := firstNonNilBool(entry.MarkUtilized, b.defaults.Prefix.MarkUtilized); markUtilized != nil {
		prefix.MarkUtilized = markUtilized
	}
	if description := firstNonEmpty(entry.Description, b.defaults.Prefix.Description); description != "" {
		prefix.Description = diode.String(description)
	}
	if tags := toTags(mergeTags(b.defaults.Tags, b.defaults.Prefix.Tags, entry.Tags)); len(tags) > 0 {
		prefix.Tags = tags
	}
	for key, value := range customFields {
		if err := prefix.SetCustomField(key, value); err != nil && b.logger != nil {
			// One bad value should not cost the prefix.
			b.logger.Error("skipping custom field on prefix", "error", err,
				"custom_field", key, "prefix", cidr, "policy", b.policyName)
		}
	}

	b.seen[cidr] = struct{}{}
	b.order = append(b.order, prefix)
}

// entities returns the built prefixes in subnet_map order.
func (b *prefixBuilder) entities() []diode.Entity { return b.order }

// vrfReference builds the VRF every emitted entity points at.
//
// The reference carries the name and nothing else on purpose. The Diode NetBox
// plugin matches an existing VRF on name alone, and only while its rd and
// tenant are both null; a reference that adds either one stops matching a
// prebuilt VRF that lacks them and makes Diode create a second VRF with the
// same name. Tenant belongs on the prefix and the address, not on the VRF.
//
// rd is honoured when set, because a deployment whose prebuilt VRFs do carry an
// RD needs it to match, but it is the operator's job to make it exact.
func vrfReference(name, rd string) *diode.VRF {
	if name == "" {
		return nil
	}
	vrf := &diode.VRF{Name: diode.String(name)}
	if rd != "" {
		vrf.Rd = diode.String(rd)
	}
	return vrf
}

// firstNonEmpty returns the first non-empty string, which is how the
// entry -> typed defaults -> policy defaults precedence is applied.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// firstNonNilBool returns the first value that was actually set. The pointers
// keep an explicit false distinguishable from an omitted key, so `is_pool: false`
// is sent and an absent is_pool is not.
func firstNonNilBool(values ...*bool) *bool {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

// mergeTags concatenates tag lists, dropping empties and repeats while keeping
// first-seen order.
func mergeTags(lists ...[]string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, list := range lists {
		for _, tag := range list {
			if tag == "" {
				continue
			}
			if _, dup := seen[tag]; dup {
				continue
			}
			seen[tag] = struct{}{}
			out = append(out, tag)
		}
	}
	return out
}

// toTags converts tag names to Diode tags.
func toTags(names []string) []*diode.Tag {
	if len(names) == 0 {
		return nil
	}
	tags := make([]*diode.Tag, 0, len(names))
	for _, name := range names {
		tags = append(tags, &diode.Tag{Name: diode.String(name)})
	}
	return tags
}
