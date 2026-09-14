package policy

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

// ipamBuilder turns validated subnet_map entries into Prefix and VLAN entities,
// deduped so each network and each VLAN is sent once per scan run.
//
// Nothing here defaults an unset field. Diode leaves an absent optional field
// out of the changeset, so NetBox keeps the value it already holds; filling in
// "active" for a missing status would make every scan re-assert it over an
// operator-set one.
type ipamBuilder struct {
	defaults   config.Defaults
	logger     *slog.Logger
	policyName string

	prefixes map[string]*diode.Prefix
	vlans    map[string]*diode.VLAN
	order    []diode.Entity
}

func newIPAMBuilder(defaults config.Defaults, logger *slog.Logger, policyName string) *ipamBuilder {
	return &ipamBuilder{
		defaults:   defaults,
		logger:     logger,
		policyName: policyName,
		prefixes:   make(map[string]*diode.Prefix),
		vlans:      make(map[string]*diode.VLAN),
	}
}

// add emits the entry's VLAN (when declared) and Prefix, in that order, the
// first time each is seen. Returning early on a repeat keeps one entity per
// network across a run even though entries are walked once per policy.
func (b *ipamBuilder) add(entry *config.SubnetMapEntry, customFields map[string]any) {
	cidr := entry.Network().String()
	if _, done := b.prefixes[cidr]; done {
		return
	}

	var vlan *diode.VLAN
	if entry.Vlan != nil {
		vlan = b.vlan(entry.Vlan)
	}

	prefix := &diode.Prefix{Prefix: diode.String(cidr)}
	if vrf := b.vrf(); vrf != nil {
		prefix.Vrf = vrf
	}
	if tenant := firstNonEmpty(entry.Tenant, b.defaults.Prefix.Tenant, b.defaults.Tenant); tenant != "" {
		prefix.Tenant = &diode.Tenant{Name: diode.String(tenant)}
	}
	if vlan != nil {
		prefix.Vlan = vlan
	}
	if status := firstNonEmpty(entry.Status, b.defaults.Prefix.Status); status != "" {
		prefix.Status = diode.String(status)
	}
	if role := firstNonEmpty(entry.Role, b.defaults.Prefix.Role); role != "" {
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
	b.applyCustomFields(prefix, customFields, cidr)

	b.prefixes[cidr] = prefix
	b.order = append(b.order, prefix)
}

// vlan returns the shared VLAN entity for a declaration, building it on first
// use. The same pointer is nested in the Prefix and emitted as a top-level
// entity, so the two can never describe the VLAN differently.
func (b *ipamBuilder) vlan(declared *config.SubnetVlan) *diode.VLAN {
	vid := int64(*declared.Vid)
	group := b.vlanGroup(declared.Group)
	key := vlanKey(vid, group)
	if existing, ok := b.vlans[key]; ok {
		return existing
	}

	name := strings.TrimSpace(declared.Name)
	if name == "" {
		// NetBox VLAN name is not optional. gnmi-discovery uses the same
		// placeholder when a device reports a VLAN with no name.
		name = "VLAN" + strconv.FormatInt(vid, 10)
	}
	vlan := &diode.VLAN{Vid: &vid, Name: diode.String(name)}
	if group != nil {
		vlan.Group = group
	}
	if site := b.defaults.Site; site != "" {
		vlan.Site = &diode.Site{Name: diode.String(site)}
	}
	if tenant := firstNonEmpty(declared.Tenant, b.defaults.Vlan.Tenant, b.defaults.Tenant); tenant != "" {
		vlan.Tenant = &diode.Tenant{Name: diode.String(tenant)}
	}
	if status := firstNonEmpty(declared.Status, b.defaults.Vlan.Status); status != "" {
		vlan.Status = diode.String(status)
	}
	if role := firstNonEmpty(declared.Role, b.defaults.Vlan.Role); role != "" {
		vlan.Role = &diode.Role{Name: diode.String(role)}
	}
	if description := firstNonEmpty(declared.Description, b.defaults.Vlan.Description); description != "" {
		vlan.Description = diode.String(description)
	}
	if tags := toTags(mergeTags(b.defaults.Tags, b.defaults.Vlan.Tags)); len(tags) > 0 {
		vlan.Tags = tags
	}

	b.vlans[key] = vlan
	b.order = append(b.order, vlan)
	return vlan
}

// vlanGroup builds the VLANGroup a VLAN belongs to, preferring the entry's own
// group over defaults.vlan.group.
//
// NetBox requires a non-empty slug, so a name with no [a-z0-9] runes yields no
// group at all; the VLANs are still emitted, just ungrouped. gnmi-discovery
// makes the same trade.
func (b *ipamBuilder) vlanGroup(entryGroup config.VlanGroupParameters) *diode.VLANGroup {
	group := entryGroup
	if group.Name == "" {
		group = b.defaults.Vlan.Group
	}
	if group.Name == "" {
		return nil
	}
	slug := slugify(group.Name)
	if slug == "" {
		if b.logger != nil {
			b.logger.Warn("vlan group name yields an empty slug; emitting VLANs without a group",
				"group", group.Name, "policy", b.policyName)
		}
		return nil
	}
	built := &diode.VLANGroup{Name: diode.String(group.Name), Slug: diode.String(slug)}
	setVLANGroupScope(built, group, b.defaults.Site)
	return built
}

// setVLANGroupScope attaches the configured scope to a VLAN group. An explicit
// scope_* wins; otherwise defaults.site applies, so the bare-string form of
// vlan.group is site-scoped when a site is configured.
//
// Scope is only ever assigned a real value: a typed-nil *diode.Site would make
// the interface non-nil and serialize as an empty site.
func setVLANGroupScope(g *diode.VLANGroup, params config.VlanGroupParameters, defaultSite string) {
	switch {
	case params.ScopeSiteGroup != "":
		g.Scope = &diode.SiteGroup{Name: diode.String(params.ScopeSiteGroup)}
	case params.ScopeRegion != "":
		g.Scope = &diode.Region{Name: diode.String(params.ScopeRegion)}
	case params.ScopeLocation != "":
		location := &diode.Location{Name: diode.String(params.ScopeLocation)}
		if defaultSite != "" {
			location.Site = &diode.Site{Name: diode.String(defaultSite)}
		}
		g.Scope = location
	case params.ScopeSite != "":
		g.Scope = &diode.Site{Name: diode.String(params.ScopeSite)}
	case defaultSite != "":
		g.Scope = &diode.Site{Name: diode.String(defaultSite)}
	}
}

// applyCustomFields sets the already-resolved custom fields on a prefix. A value
// the SDK rejects is logged and skipped rather than failing the run: the prefix
// itself is still worth ingesting.
func (b *ipamBuilder) applyCustomFields(prefix *diode.Prefix, fields map[string]any, cidr string) {
	for key, value := range fields {
		if err := prefix.SetCustomField(key, value); err != nil && b.logger != nil {
			b.logger.Error("skipping custom field on prefix", "error", err,
				"custom_field", key, "prefix", cidr, "policy", b.policyName)
		}
	}
}

// entities returns the built entities in emission order: each VLAN immediately
// before the prefix that references it, in subnet_map order.
func (b *ipamBuilder) entities() []diode.Entity {
	return b.order
}

// vrf builds the VRF shared by every emitted prefix. All subnet_map prefixes go
// into one VRF so NetBox can derive the parent/child hierarchy from containment.
func (b *ipamBuilder) vrf() *diode.VRF {
	if b.defaults.Vrf == "" {
		return nil
	}
	vrf := &diode.VRF{Name: diode.String(b.defaults.Vrf)}
	if b.defaults.Rd != "" {
		vrf.Rd = diode.String(b.defaults.Rd)
	}
	return vrf
}

// vlanKey identifies a VLAN the way NetBox does, by vid within its group. Two
// entries naming the same vid in the same group are the same VLAN and are
// emitted once.
func vlanKey(vid int64, group *diode.VLANGroup) string {
	name := ""
	if group != nil && group.Name != nil {
		name = *group.Name
	}
	return fmt.Sprintf("%d\x00%s", vid, name)
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

// slugify lower-cases and replaces each run of non-[a-z0-9] with a single
// hyphen, trimming trailing hyphens. NetBox requires a VLANGroup slug.
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevHyphen := false
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevHyphen = false
		case b.Len() > 0 && !prevHyphen:
			b.WriteByte('-')
			prevHyphen = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}
