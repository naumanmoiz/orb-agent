package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/netboxsync"
)

func configWithDebug(enable bool) config.Config {
	var c config.Config
	c.OrbAgent.Debug.Enable = enable
	return c
}

func TestNewRootLogger_FlagSetsDebugImmediately(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, true)
	assert.Equal(t, slog.LevelDebug, level.Level())
	assert.True(t, logger.Enabled(context.Background(), slog.LevelDebug))
}

func TestNewRootLogger_DefaultIsInfo(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, false)
	assert.Equal(t, slog.LevelInfo, level.Level())
	assert.False(t, logger.Enabled(context.Background(), slog.LevelDebug))
}

func TestApplyConfigDebug_YAMLOnlyEnablesDebug(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, false)

	effective := applyConfigDebug(logger, level, false, configWithDebug(true))

	assert.True(t, effective)
	assert.Equal(t, slog.LevelDebug, level.Level())
	assert.True(t, logger.Enabled(context.Background(), slog.LevelDebug))
	// The switch itself must be visible in the (now debug-enabled) output.
	assert.Contains(t, buf.String(), "debug logging enabled via config file")
}

func TestApplyConfigDebug_FlagOnlyStaysDebugNoDuplicateAnnounce(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, true)

	effective := applyConfigDebug(logger, level, true, configWithDebug(false))

	assert.True(t, effective)
	assert.Equal(t, slog.LevelDebug, level.Level())
	assert.NotContains(t, buf.String(), "debug logging enabled via config file")
}

func TestApplyConfigDebug_BothOff(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, false)

	effective := applyConfigDebug(logger, level, false, configWithDebug(false))

	assert.False(t, effective)
	assert.Equal(t, slog.LevelInfo, level.Level())
	assert.False(t, logger.Enabled(context.Background(), slog.LevelDebug))
}

func TestApplyConfigDebug_BothOnNoDuplicateAnnounce(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, true)

	effective := applyConfigDebug(logger, level, true, configWithDebug(true))

	assert.True(t, effective)
	assert.Equal(t, slog.LevelDebug, level.Level())
	assert.NotContains(t, buf.String(), "debug logging enabled via config file",
		"flag already enabled debug; config adds nothing to announce")
}

// init registers every bundled backend; snmp_telemetry must be among them.
func TestInitRegistersSnmpTelemetry(t *testing.T) {
	assert.True(t, backend.HaveBackend("snmp_telemetry"))
}

// gnmi_telemetry ships in the image and is registered the same way.
func TestInitRegistersGnmiTelemetry(t *testing.T) {
	assert.True(t, backend.HaveBackend("gnmi_telemetry"))
}

func TestNetBoxRenderWritesPolicies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		results := []any{}
		if r.URL.Path == "/api/ipam/prefixes/" {
			results = append(results, map[string]any{"id": 1, "prefix": "192.0.2.0/24",
				"status": map[string]any{"value": "active"}, "tags": []any{}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"count": len(results), "next": nil, "results": results})
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`orb:
  config_manager:
    active: netbox
    sources:
      netbox:
        url: ${TEST_RENDER_NB_URL}
        token: abc
        network_discovery:
          enabled: true
          straggler:
            enabled: false
`), 0o600))
	t.Setenv("TEST_RENDER_NB_URL", srv.URL)

	cfgFiles, renderOut, renderTime = []string{cfgPath}, filepath.Join(dir, "out.yaml"), time.Minute
	t.Cleanup(func() { cfgFiles, renderOut = nil, "" })
	var stdout, stderr bytes.Buffer
	require.NoError(t, netboxRender(context.Background(), &stdout, &stderr))
	data, err := os.ReadFile(renderOut)
	require.NoError(t, err)
	assert.Contains(t, string(data), "nb-nd-global-001:")
	assert.Contains(t, string(data), "192.0.2.0/24")

	renderOut = ""
	stdout.Reset()
	require.NoError(t, netboxRender(context.Background(), &stdout, &stderr))
	assert.Contains(t, stdout.String(), "nb-nd-global-001:")
}

// The shipped example and the rendered template must stay loadable.
func TestNetBoxSyncExampleAndTemplateLoad(t *testing.T) {
	render := map[string]string{
		"ORB_AGENT_NAME": "agent-01", "NETBOX_SCHEDULE": "*/30 * * * *", "NETBOX_STATUSES": "[container, active]",
		"NETBOX_FILTERS": "{tag: [discover]}", "GENERATED_POLICIES_PATH": "/opt/orb/generated-policies.yaml",
		"ND_SCHEDULE": "0 */6 * * *", "ND_STRAGGLER_DELAY_MINUTES": "30", "ND_STAGGER_MINUTES": "60",
		"ND_TIMEOUT_MINUTES": "60", "ND_MAX_TARGETS_PER_POLICY": "256", "ND_MAX_HOSTS_PER_POLICY": "65536",
		"ND_MAX_BLOCK_PREFIX_LEN_V4": "16", "ND_MAX_BLOCK_PREFIX_LEN_V6": "112", "ND_TOP_PORTS": "100",
		"ND_STRAGGLER_ENABLED": "true", "ND_STRAGGLER_MAX_BLOCK_PREFIX_LEN_V4": "20",
		"ND_STRAGGLER_MAX_BLOCK_PREFIX_LEN_V6": "116", "ND_STRAGGLER_MAX_HOSTS_PER_PARENT": "16384",
		"SNMP_ENABLED": "true", "SNMP_SCHEDULE": "15 */6 * * *", "SNMP_STAGGER_MINUTES": "60",
		"SNMP_MAX_TARGETS_PER_POLICY": "256",
	}
	raw, err := os.ReadFile("../agent.netbox-sync.template.yaml")
	require.NoError(t, err)
	rendered := os.Expand(string(raw), func(name string) string {
		if v, ok := render[name]; ok {
			return v
		}
		return "${" + name + "}" // runtime placeholders and scan tokens stay
	})
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "agent.yaml")
	require.NoError(t, os.WriteFile(tmpl, []byte(rendered), 0o600))

	for _, path := range []string{"../agent.netbox-sync.example.yaml", tmpl} {
		cfg, err := config.Load([]string{path}, slog.Default())
		require.NoError(t, err, path)
		nb := cfg.OrbAgent.ConfigManager.Sources.NetBox
		assert.Equal(t, "netbox", cfg.OrbAgent.ConfigManager.Active)
		assert.Equal(t, "${NETBOX_TOKEN}", nb.Token, "secrets stay placeholders")
		_, err = netboxsync.NewSettings(nb)
		require.NoError(t, err, path)
	}
	assert.Contains(t, rendered, `discovery_policy: "${POLICY_NAME}"`)
	assert.Contains(t, rendered, "community: ${SNMP_COMMUNITY}")
}
