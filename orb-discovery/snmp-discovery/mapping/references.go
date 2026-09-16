package mapping

import (
	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// TenantRef builds a Tenant reference the Diode NetBox plugin can match against
// a tenant that already exists, or nil when no tenant is named.
//
// The group is the whole point. NetBox makes Tenant unique on (group, name)
// with nulls_distinct=False, and the plugin turns that into a matcher where an
// absent group means "group IS NULL", not "any group". A group-less reference
// therefore cannot find a tenant that sits in a group: nothing matches, and
// Diode creates a second tenant of the same name outside the group. The ingest
// reports success and the objects hang off a tenant nobody meant to create.
//
// fallbackGroup is defaults.tenant's group, used when this block names a tenant
// by bare name. See config.TenantParameters.GroupOr.
func TenantRef(params config.TenantParameters, fallbackGroup string) *diode.Tenant {
	if params.Name == "" {
		return nil
	}
	name := params.Name
	tenant := &diode.Tenant{Name: &name}
	if group := params.GroupOr(fallbackGroup); group != "" {
		groupName := group
		tenant.Group = &diode.TenantGroup{Name: &groupName}
	}
	if params.Description != "" {
		description := params.Description
		tenant.Description = &description
	}
	if params.Comments != "" {
		comments := params.Comments
		tenant.Comments = &comments
	}
	for i := range params.Tags {
		tenant.Tags = append(tenant.Tags, &diode.Tag{Name: &params.Tags[i]})
	}
	return tenant
}

// applyVrfTenant sets the tenant that decides whether a VRF reference matches a
// prebuilt VRF at all.
//
// The plugin chooses its VRF matcher from the fields the payload carries and
// then restricts the search by them:
//
//	reference        searches
//	name             VRFs with rd IS NULL and tenant IS NULL
//	name + tenant    VRFs with rd IS NULL and that tenant
//	name + rd        NetBox's own rd unique constraint
//
// So a name-only reference can only ever find a VRF that has neither an rd nor
// a tenant. Point it at a VRF that has either and nothing matches, and Diode
// creates a second, empty VRF of the same name and reconciles into it.
//
// vrf.tenant therefore mirrors what the prebuilt VRF already has. It is not a
// way to assign a tenant to a VRF, and leaving it unset on a VRF that has one
// is the failure that looks like success.
func applyVrfTenant(vrf *diode.VRF, params config.VrfParameters, fallbackGroup string) {
	if vrf == nil || params.Tenant == "" {
		return
	}
	vrf.Tenant = TenantRef(config.TenantParameters{
		Name:  params.Tenant,
		Group: params.TenantGroup,
	}, fallbackGroup)
}
