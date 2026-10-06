package configmgr

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/netboxsync"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// recordingPolicyManager records manages and removes.
type recordingPolicyManager struct {
	mu      sync.Mutex
	manages []config.PolicyPayload
	removes []string
}

func (r *recordingPolicyManager) ManagePolicy(p config.PolicyPayload) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manages = append(r.manages, p)
}

func (r *recordingPolicyManager) RemovePolicy(_ string, name string, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removes = append(r.removes, name)
	return nil
}

func (r *recordingPolicyManager) RemovePolicyDataset(string, string, string, backend.Backend) {}
func (r *recordingPolicyManager) GetPolicyState() ([]policies.PolicyData, error)              { return nil, nil }
func (r *recordingPolicyManager) GetRepo() policies.PolicyRepo                                { return nil }
func (r *recordingPolicyManager) ApplyBackendPolicies(context.Context, string, backend.Backend) error {
	return nil
}

func (r *recordingPolicyManager) RemoveBackendPolicies(string, backend.Backend, bool) error {
	return nil
}
func (r *recordingPolicyManager) SetStarter(policymgr.BackendStarter) {}

func (r *recordingPolicyManager) reset() ([]config.PolicyPayload, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, rm := r.manages, r.removes
	r.manages, r.removes = nil, nil
	return m, rm
}

// fakeRunner returns whatever result or error it is given.
type fakeRunner struct {
	res *netboxsync.Result
	err error
}

func (f *fakeRunner) Run(context.Context) (*netboxsync.Result, error) { return f.res, f.err }

func result(prefixes int, nd map[string]any) *netboxsync.Result {
	return &netboxsync.Result{
		Policies: map[string]map[string]any{netboxsync.NetworkDiscoveryBackend: nd},
		Summary:  netboxsync.Summary{Prefixes: prefixes},
	}
}

func ndPolicy(target string) map[string]any {
	return map[string]any{"config": map[string]any{"schedule": "0 */6 * * *"},
		"scope": map[string]any{"targets": []any{target}}}
}

func newTestNetBoxManager(t *testing.T, runner policyRunner, cfg config.NetBoxManager) (*netboxConfigManager, *recordingPolicyManager) {
	t.Helper()
	pm := &recordingPolicyManager{}
	nc := newNetBoxConfigManager(slog.New(slog.NewTextHandler(io.Discard, nil)), pm)
	nc.runner = runner
	full := config.Config{}
	full.OrbAgent.ConfigManager.Sources.NetBox = cfg
	backends := map[string]backend.Backend{netboxsync.NetworkDiscoveryBackend: nil}
	require.NoError(t, nc.Start(context.Background(), full, backends))
	t.Cleanup(func() { _ = nc.Stop(context.Background()) })
	return nc, pm
}

func names(ps []config.PolicyPayload) map[string]int32 {
	out := map[string]int32{}
	for _, p := range ps {
		out[p.Name] = p.Version
	}
	return out
}

func TestNetBoxManagerDiff(t *testing.T) {
	runner := &fakeRunner{res: result(3, map[string]any{
		"nb-nd-global-001": ndPolicy("192.0.2.0/25"),
		"nb-nd-global-002": ndPolicy("192.0.2.128/25"),
	})}
	nc, pm := newTestNetBoxManager(t, runner, config.NetBoxManager{URL: "https://netbox.example.com"})

	manages, removes := pm.reset()
	assert.Equal(t, map[string]int32{"nb-nd-global-001": 1, "nb-nd-global-002": 1}, names(manages))
	assert.Empty(t, removes)
	first := manages[0]
	assert.Equal(t, "manage", first.Action)
	assert.NotEmpty(t, first.DatasetID)

	// Unchanged: nothing is re-applied.
	require.NoError(t, nc.refresh())
	manages, removes = pm.reset()
	assert.Empty(t, manages)
	assert.Empty(t, removes)

	// One changed, one removed, one added.
	runner.res = result(3, map[string]any{
		"nb-nd-global-001": ndPolicy("192.0.2.0/26"),
		"nb-nd-global-003": ndPolicy("198.51.100.0/24"),
	})
	require.NoError(t, nc.refresh())
	manages, removes = pm.reset()
	assert.Equal(t, map[string]int32{"nb-nd-global-001": 2, "nb-nd-global-003": 1}, names(manages))
	assert.Equal(t, []string{"nb-nd-global-002"}, removes)

	// Policy ids are deterministic per name and backend.
	nc2, pm2 := newTestNetBoxManager(t, runner, config.NetBoxManager{URL: "https://netbox.example.com"})
	_ = nc2
	m2, _ := pm2.reset()
	ids := map[string]string{}
	for _, p := range m2 {
		ids[p.Name] = p.ID
	}
	for _, p := range manages {
		assert.Equal(t, ids[p.Name], p.ID, p.Name)
	}
}

func TestNetBoxManagerKeepsPoliciesOnError(t *testing.T) {
	runner := &fakeRunner{res: result(1, map[string]any{"nb-nd-global-001": ndPolicy("192.0.2.0/24")})}
	sched := "*/30 * * * *"
	nc, pm := newTestNetBoxManager(t, runner, config.NetBoxManager{Schedule: &sched})
	pm.reset()

	runner.res, runner.err = nil, errors.New("netbox unavailable")
	require.Error(t, nc.refresh())
	manages, removes := pm.reset()
	assert.Empty(t, manages)
	assert.Empty(t, removes, "a failed refresh never removes anything")

	// An empty answer is refused unless allow_empty is set.
	runner.res, runner.err = result(0, map[string]any{}), nil
	require.Error(t, nc.refresh())
	_, removes = pm.reset()
	assert.Empty(t, removes)

	nc.cfg.AllowEmpty = true
	require.NoError(t, nc.refresh())
	_, removes = pm.reset()
	assert.Equal(t, []string{"nb-nd-global-001"}, removes)
}

func TestNetBoxManagerStartFailsWithoutScheduleWhenNetBoxFails(t *testing.T) {
	pm := &recordingPolicyManager{}
	nc := newNetBoxConfigManager(slog.New(slog.NewTextHandler(io.Discard, nil)), pm)
	nc.runner = &fakeRunner{err: errors.New("boom")}
	err := nc.Start(context.Background(), config.Config{}, nil)
	require.Error(t, err)
}

func TestNetBoxManagerSkipsMissingBackend(t *testing.T) {
	res := result(1, map[string]any{"nb-nd-global-001": ndPolicy("192.0.2.0/24")})
	res.Policies[netboxsync.SNMPDiscoveryBackend] = map[string]any{"nb-snmp-global-001": map[string]any{}}
	_, pm := newTestNetBoxManager(t, &fakeRunner{res: res}, config.NetBoxManager{})
	manages, _ := pm.reset()
	assert.Equal(t, map[string]int32{"nb-nd-global-001": 1}, names(manages))
}

// End to end against a fake NetBox: the generated file is written and the
// policies are managed.
func TestNetBoxManagerAgainstFakeNetBox(t *testing.T) {
	page := func(results ...map[string]any) []byte {
		b, _ := json.Marshal(map[string]any{"count": len(results), "next": nil, "results": results})
		return b
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token v1-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/api/ipam/prefixes/":
			_, _ = w.Write(page(
				map[string]any{"id": 1, "prefix": "198.51.100.0/24", "status": map[string]any{"value": "container"},
					"vrf": map[string]any{"id": 5, "name": "VRF-A"}, "tags": []any{}},
				map[string]any{"id": 2, "prefix": "198.51.100.0/25", "status": map[string]any{"value": "active"},
					"vrf": map[string]any{"id": 5, "name": "VRF-A"}, "tags": []any{map[string]any{"name": "servers"}}},
			))
		case "/api/ipam/vrfs/":
			_, _ = w.Write(page(map[string]any{"id": 5, "name": "VRF-A", "rd": "65000:5"}))
		case "/api/tenancy/tenants/":
			_, _ = w.Write(page())
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "generated-policies.yaml")
	t.Setenv("TEST_NB_URL", srv.URL)
	t.Setenv("TEST_NB_TOKEN", "v1-token")
	cfg := config.NetBoxManager{
		URL: "${TEST_NB_URL}", Token: "${TEST_NB_TOKEN}", GeneratedConfigPath: out,
		NetworkDiscovery: config.NetBoxNetworkDiscovery{Enabled: true},
	}
	_, pm := newTestNetBoxManager(t, nil, cfg)
	manages, _ := pm.reset()
	assert.Equal(t, map[string]int32{"nb-nd-vrf-a-001": 1, "nb-nd-straggler-vrf-a-001": 1}, names(manages))

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	text := string(data)
	assert.True(t, strings.HasPrefix(text, "# Generated by the orb-agent netbox config manager"))
	assert.Contains(t, text, "nb-nd-vrf-a-001:")
	assert.Contains(t, text, "rd: \"65000:5\"")
	assert.Contains(t, text, "emit_prefix: false")
}
