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
	// The entry decides the VRF and tenant, so a policy can declare subnets
	// belonging to several of each. The addresses discovered inside this prefix
	// resolve through the same entry, which is what keeps them together.
	place := prefixPlacement(b.defaults, entry)
	if place.vrf != nil {
		prefix.Vrf = place.vrf
	}
	if place.tenant != nil {
		prefix.Tenant = place.tenant
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
// The reference has to mirror the prebuilt VRF's own shape, because the Diode
// NetBox plugin chooses its matcher from the fields the payload carries and
// then restricts the search by them:
//
//	reference        matcher            searches
//	name             (name)             VRFs with rd IS NULL and tenant IS NULL
//	name + tenant    (name, tenant)     VRFs with rd IS NULL and tenant set
//	name + rd        NetBox's rd unique constraint
//
// A criterion whose fields are not all present in the payload is skipped
// entirely, so a name-only reference can only ever find a VRF that has neither
// an rd nor a tenant. Point it at a VRF that has either and nothing matches:
// Diode then creates a second, empty VRF of the same name and reconciles into
// it, which reads as success while splitting the lab's address space in two.
//
// Hence vrf_tenant, which is deliberately separate from defaults.tenant. That
// one describes the address and the prefix; this one exists only to make the
// reference match.
func vrfReference(name, rd, tenant, tenantGroup string) *diode.VRF {
	if name == "" {
		return nil
	}
	vrf := &diode.VRF{Name: diode.String(name)}
	if rd != "" {
		vrf.Rd = diode.String(rd)
	}
	if t := tenantReference(tenant, tenantGroup); t != nil {
		vrf.Tenant = t
	}
	return vrf
}

// tenantReference builds a Tenant the plugin can match against a prebuilt one.
//
// NetBox makes Tenant unique on (group, name) with nulls_distinct=False, and
// the plugin turns that into a matcher where an absent group is not "any group"
// but "group IS NULL". A reference without a group therefore only ever finds a
// group-less tenant; against one that sits in a group nothing matches and Diode
// creates a second tenant of the same name outside it.
//
// The same trap as the VRF reference, one level down, and it bites in the same
// silent way: the ingest succeeds and the objects hang off the wrong tenant.
func tenantReference(name, group string) *diode.Tenant {
	if name == "" {
		return nil
	}
	tenant := &diode.Tenant{Name: diode.String(name)}
	if group != "" {
		tenant.Group = &diode.TenantGroup{Name: diode.String(group)}
	}
	return tenant
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
