package policy

import (
	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

// placement is where one entity is filed in NetBox: the VRF that scopes it and
// the tenant that owns it. Either may be nil, which leaves the field off the
// emitted entity so Diode omits it from the changeset and NetBox keeps what it
// already holds.
type placement struct {
	vrf    *diode.VRF
	tenant *diode.Tenant
}

// apply sets the resolved references on an IP address.
func (p placement) apply(ip *diode.IPAddress) {
	if p.vrf != nil {
		ip.Vrf = p.vrf
	}
	if p.tenant != nil {
		ip.Tenant = p.tenant
	}
}

// addressPlacement resolves where a discovered address is filed.
//
// entry is the most specific subnet_map entry containing the address, or nil
// when the address matched none. A nil entry reproduces the policy-wide
// behaviour exactly, which is what keeps a subnet_map-less policy unchanged.
func addressPlacement(defaults config.Defaults, entry *config.SubnetMapEntry) placement {
	group := tenantGroupFor(defaults, entry)
	return placement{
		vrf:    vrfFor(defaults, entry, group),
		tenant: tenantReference(tenantNameFor(defaults, entry), group),
	}
}

// prefixPlacement resolves where a declared prefix is filed.
//
// It differs from addressPlacement in one place only: defaults.prefix.tenant
// sits between the entry's tenant and defaults.tenant, so a deployment can own
// its prefixes and its addresses with different tenants.
func prefixPlacement(defaults config.Defaults, entry *config.SubnetMapEntry) placement {
	group := tenantGroupFor(defaults, entry)
	name := defaults.Prefix.Tenant
	if entry != nil && entry.Tenant != "" {
		name = entry.Tenant
	}
	if name == "" {
		name = defaults.Tenant
	}
	return placement{
		vrf:    vrfFor(defaults, entry, group),
		tenant: tenantReference(name, group),
	}
}

// vrfFor builds the VRF reference for an entry, falling back to the defaults'.
//
// The three identity fields are taken from one source or the other, never
// mixed. A VRF reference only matches when its shape mirrors the prebuilt VRF's
// (see vrfReference), so pairing an entry's name with the defaults' rd or
// vrf_tenant would describe a VRF that does not exist — and Diode answers that
// by creating one. ValidateSubnetMap rejects an entry carrying rd or vrf_tenant
// without a vrf for the same reason.
func vrfFor(defaults config.Defaults, entry *config.SubnetMapEntry, group string) *diode.VRF {
	if entry != nil && entry.Vrf != "" {
		return vrfReference(entry.Vrf, entry.Rd, entry.VrfTenant, group)
	}
	return vrfReference(defaults.Vrf, defaults.Rd, defaults.VrfTenant, defaults.TenantGroup)
}

// tenantNameFor returns the tenant owning an address: the entry's, else the
// policy default.
func tenantNameFor(defaults config.Defaults, entry *config.SubnetMapEntry) string {
	if entry != nil && entry.Tenant != "" {
		return entry.Tenant
	}
	return defaults.Tenant
}

// tenantGroupFor returns the group every tenant reference for this entry
// carries.
//
// Unlike the VRF triple, the group is inherited rather than taken atomically: a
// deployment's tenants almost always share one group, so requiring every entry
// that names a tenant to restate it would be noise. An entry whose tenant lives
// elsewhere sets tenant_group itself, and the preflight reports the pairing it
// cannot match.
func tenantGroupFor(defaults config.Defaults, entry *config.SubnetMapEntry) string {
	if entry != nil && entry.TenantGroup != "" {
		return entry.TenantGroup
	}
	return defaults.TenantGroup
}
