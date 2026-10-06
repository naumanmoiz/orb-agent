package netboxsync

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

// fakeNetBox serves /api/ipam/prefixes/, /api/ipam/vrfs/ and
// /api/tenancy/tenants/ from in-memory lists, paged by limit and offset the
// way NetBox does.
type fakeNetBox struct {
	t        *testing.T
	token    string
	prefixes []map[string]any
	vrfs     []map[string]any
	tenants  []map[string]any

	mu       sync.Mutex
	requests map[string]int
	queries  []string
	failNext int // respond 503 this many times first
}

func newFakeNetBox(t *testing.T) *fakeNetBox {
	return &fakeNetBox{t: t, token: "Token secret-v1", requests: map[string]int{}}
}

func (f *fakeNetBox) serve() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	f.t.Cleanup(srv.Close)
	return srv
}

func (f *fakeNetBox) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests[r.URL.Path]++
	f.queries = append(f.queries, r.URL.RawQuery)
	fail := f.failNext > 0
	if fail {
		f.failNext--
	}
	f.mu.Unlock()
	if fail {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("Authorization") != f.token {
		http.Error(w, `{"detail":"Invalid token"}`, http.StatusForbidden)
		return
	}
	var all []map[string]any
	switch r.URL.Path {
	case "/api/ipam/prefixes/":
		all = f.prefixes
	case "/api/ipam/vrfs/":
		all = f.vrfs
	case "/api/tenancy/tenants/":
		all = f.tenants
	default:
		http.NotFound(w, r)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 50
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	results := []map[string]any{}
	if offset < len(all) {
		results = all[offset:end]
	}
	var next any
	if end < len(all) {
		next = "http://wrong-host.example.com/next" // must not be followed
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"count": len(all), "next": next, "previous": nil, "results": results,
	})
}

func (f *fakeNetBox) addTenant(id int, name, group string) {
	t := map[string]any{"id": id, "name": name, "slug": slugify(name), "group": nil}
	if group != "" {
		t["group"] = map[string]any{"id": id + 1000, "name": group, "slug": slugify(group)}
	}
	f.tenants = append(f.tenants, t)
}

func (f *fakeNetBox) addVRF(id int, name, rd string, tenantID int) {
	v := map[string]any{"id": id, "name": name, "rd": nil, "tenant": nil}
	if rd != "" {
		v["rd"] = rd
	}
	if tenantID != 0 {
		v["tenant"] = map[string]any{"id": tenantID, "name": f.tenantName(tenantID)}
	}
	f.vrfs = append(f.vrfs, v)
}

func (f *fakeNetBox) tenantName(id int) string {
	for _, t := range f.tenants {
		if t["id"] == id {
			return t["name"].(string)
		}
	}
	return ""
}

type fakePrefix struct {
	id       int
	prefix   string
	vrfID    int
	tenantID int
	status   string
	role     string
	tags     []string
	site     string
}

func (f *fakeNetBox) addPrefix(p fakePrefix) {
	m := map[string]any{
		"id": p.id, "prefix": p.prefix, "vrf": nil, "tenant": nil, "role": nil,
		"status":  map[string]any{"value": p.status, "label": p.status},
		"is_pool": false, "mark_utilized": false, "description": "",
		"tags":       []any{},
		"scope_type": nil, "scope": nil,
		"_depth": 0, "children": 0,
	}
	if p.vrfID != 0 {
		for _, v := range f.vrfs {
			if v["id"] == p.vrfID {
				// The nested VRF on a prefix has no tenant.
				m["vrf"] = map[string]any{"id": p.vrfID, "name": v["name"], "rd": v["rd"]}
			}
		}
	}
	if p.tenantID != 0 {
		m["tenant"] = map[string]any{"id": p.tenantID, "name": f.tenantName(p.tenantID)}
	}
	if p.role != "" {
		m["role"] = map[string]any{"id": 1, "name": p.role, "slug": slugify(p.role)}
	}
	tags := []any{}
	for _, tag := range p.tags {
		tags = append(tags, map[string]any{"id": 1, "name": tag, "slug": slugify(tag)})
	}
	m["tags"] = tags
	if p.site != "" {
		m["scope_type"] = "dcim.site"
		m["scope"] = map[string]any{"id": 7, "name": p.site, "slug": slugify(p.site)}
	}
	f.prefixes = append(f.prefixes, m)
}
