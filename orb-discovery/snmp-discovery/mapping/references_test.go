package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// A tenant named by bare name inherits defaults.tenant's group. Without the
// group the plugin searches for "group IS NULL" and finds nothing, so Diode
// creates a second tenant of the same name outside the group.
func TestTenantRefInheritsTheDefaultGroup(t *testing.T) {
	tenant := TenantRef(config.TenantParameters{Name: "network-ops"}, "infrastructure")
	require.NotNil(t, tenant)
	require.NotNil(t, tenant.Group)
	assert.Equal(t, "network-ops", *tenant.Name)
	assert.Equal(t, "infrastructure", *tenant.Group.Name)
}

// A tenant that names its own group keeps it, so a block whose tenant lives
// elsewhere is not dragged into the policy-wide one.
func TestTenantRefOwnGroupWins(t *testing.T) {
	tenant := TenantRef(config.TenantParameters{Name: "partner", Group: "external"}, "infrastructure")
	require.NotNil(t, tenant.Group)
	assert.Equal(t, "external", *tenant.Group.Name)
}

// No group anywhere stays group-less, which is right for a deployment whose
// tenants have none: NetBox holds them with group IS NULL and that is what the
// reference then searches for.
func TestTenantRefWithoutAnyGroup(t *testing.T) {
	tenant := TenantRef(config.TenantParameters{Name: "network-ops"}, "")
	require.NotNil(t, tenant)
	assert.Nil(t, tenant.Group)

	assert.Nil(t, TenantRef(config.TenantParameters{}, "infrastructure"), "no name, no reference")
}

// A VRF reference carrying a tenant is the only shape that finds a prebuilt VRF
// which has one; a name-only reference searches VRFs with tenant IS NULL and
// creates a duplicate when it finds none.
func TestApplyVrfTenant(t *testing.T) {
	name := "mgmt"
	vrf := &diode.VRF{Name: &name}
	applyVrfTenant(vrf, config.VrfParameters{Name: name, Tenant: "network-ops"}, "infrastructure")
	require.NotNil(t, vrf.Tenant)
	assert.Equal(t, "network-ops", *vrf.Tenant.Name)
	require.NotNil(t, vrf.Tenant.Group)
	assert.Equal(t, "infrastructure", *vrf.Tenant.Group.Name)

	// A VRF whose prebuilt form has no tenant must stay tenant-less, or the
	// reference stops matching it.
	plain := &diode.VRF{Name: &name}
	applyVrfTenant(plain, config.VrfParameters{Name: name}, "infrastructure")
	assert.Nil(t, plain.Tenant)
}

// The VRF's own tenant_group overrides the policy-wide one, for a VRF whose
// tenant sits somewhere else.
func TestApplyVrfTenantOwnGroup(t *testing.T) {
	name := "mgmt"
	vrf := &diode.VRF{Name: &name}
	applyVrfTenant(vrf, config.VrfParameters{
		Name: name, Tenant: "partner", TenantGroup: "external",
	}, "infrastructure")
	require.NotNil(t, vrf.Tenant.Group)
	assert.Equal(t, "external", *vrf.Tenant.Group.Name)
}
