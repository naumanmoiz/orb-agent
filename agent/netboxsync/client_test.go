package netboxsync

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizationHeader(t *testing.T) {
	for in, want := range map[string]string{
		"abc123":             "Token abc123",
		"  abc123  ":         "Token abc123",
		"nbt_key.secret":     "Bearer nbt_key.secret",
		"Token abc123":       "Token abc123",
		"Bearer nbt_k.s":     "Bearer nbt_k.s",
		"bearer something":   "bearer something",
		"token lowercase-v1": "token lowercase-v1",
	} {
		assert.Equal(t, want, AuthorizationHeader(in), in)
	}
}

func testClient(t *testing.T, url, token string, pageSize int) *Client {
	t.Helper()
	c, err := NewClient(ClientOptions{URL: url, Token: token, PageSize: pageSize, Retries: 2, Backoff: time.Millisecond})
	require.NoError(t, err)
	return c
}

func TestFetchInventoryPaginatesAndResolves(t *testing.T) {
	nb := newFakeNetBox(t)
	nb.addTenant(1, "Tenant A", "Group A")
	nb.addTenant(2, "Tenant V", "Group V")
	nb.addVRF(10, "VRF-A", "65000:1", 2)
	for i := 0; i < 7; i++ {
		nb.addPrefix(fakePrefix{
			id: 100 + i, prefix: "192.0.2." + itoa(i*16) + "/28", vrfID: 10, tenantID: 1,
			status: "active", role: "servers", tags: []string{"tag-a"}, site: "Site A",
		})
	}
	srv := nb.serve()
	c := testClient(t, srv.URL, "secret-v1", 3)

	inv, err := c.FetchInventory(context.Background(), map[string]any{"tag": []any{"x", "y"}, "site_id": 4})
	require.NoError(t, err)
	require.Len(t, inv.Prefixes, 7)
	assert.Equal(t, 3, nb.requests["/api/ipam/prefixes/"], "7 prefixes at page size 3 is three pages")
	assert.Equal(t, 1, nb.requests["/api/ipam/vrfs/"])
	assert.Equal(t, 1, nb.requests["/api/tenancy/tenants/"])
	assert.Contains(t, nb.queries[0], "tag=x&tag=y")
	assert.Contains(t, nb.queries[0], "site_id=4")

	p := inv.Prefixes[0]
	assert.Equal(t, "VRF-A", p.VRF)
	assert.Equal(t, "65000:1", p.RD)
	assert.Equal(t, "Tenant V", p.VRFTenant, "VRF tenant comes from the VRF list")
	assert.Equal(t, "Group V", p.VRFTenantGroup)
	assert.Equal(t, "Tenant A", p.Tenant)
	assert.Equal(t, "Group A", p.TenantGroup)
	assert.Equal(t, "servers", p.Role)
	assert.Equal(t, "active", p.Status)
	assert.Equal(t, []string{"tag-a"}, p.Tags)
	assert.Equal(t, "Site A", p.Site)
}

func TestFetchInventoryRetriesTransientErrors(t *testing.T) {
	nb := newFakeNetBox(t)
	nb.failNext = 2
	nb.addPrefix(fakePrefix{id: 1, prefix: "192.0.2.0/24", status: "active"})
	srv := nb.serve()
	inv, err := testClient(t, srv.URL, "secret-v1", 0).FetchInventory(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, inv.Prefixes, 1)
}

func TestFetchInventoryFailsOnAuthError(t *testing.T) {
	nb := newFakeNetBox(t)
	srv := nb.serve()
	_, err := testClient(t, srv.URL, "wrong", 0).FetchInventory(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	assert.Equal(t, 1, nb.requests["/api/ipam/prefixes/"], "a 4xx is not retried")
}

func TestFilterValuesRejectsPagingKeys(t *testing.T) {
	_, err := filterValues(map[string]any{"limit": 5})
	require.Error(t, err)
}

func TestNewClientValidates(t *testing.T) {
	_, err := NewClient(ClientOptions{URL: "netbox.example.com", Token: "x"})
	require.Error(t, err)
	_, err = NewClient(ClientOptions{URL: "https://netbox.example.com", Token: " "})
	require.Error(t, err)
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestFetchInventoryReadsBranch(t *testing.T) {
	nb := newFakeNetBox(t)
	nb.addBranch("Dev", "ab12cd34", "ready")
	nb.addBranch("Old", "ef56gh78", "merged")
	srv := nb.serve()

	for _, ref := range []string{"Dev", "ab12cd34"} {
		c, err := NewClient(ClientOptions{URL: srv.URL, Token: "secret-v1", Branch: ref, Backoff: time.Millisecond})
		require.NoError(t, err)
		_, err = c.FetchInventory(context.Background(), nil)
		require.NoError(t, err, ref)
	}
	for _, path := range []string{"/api/ipam/prefixes/", "/api/ipam/vrfs/", "/api/tenancy/tenants/"} {
		assert.Equal(t, []string{"ab12cd34", "ab12cd34"}, nb.headers[path], path)
	}
	for _, h := range nb.headers["/api/plugins/branching/branches/"] {
		assert.Empty(t, h, "the branch lookup itself reads main")
	}

	for ref, msg := range map[string]string{"Old": "not ready", "Nope": "not found"} {
		c, err := NewClient(ClientOptions{URL: srv.URL, Token: "secret-v1", Branch: ref, Backoff: time.Millisecond})
		require.NoError(t, err)
		_, err = c.FetchInventory(context.Background(), nil)
		require.Error(t, err, ref)
		assert.Contains(t, err.Error(), msg)
	}

	c := testClient(t, srv.URL, "secret-v1", 0)
	_, err := c.FetchInventory(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, "", nb.headers["/api/ipam/prefixes/"][2], "no branch reads main")
}
