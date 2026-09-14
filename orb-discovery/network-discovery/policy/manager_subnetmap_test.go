package policy_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/policy"
)

// An invalid subnet_map fails that policy alone. The manager reports it and
// every other policy, and the agent itself, keeps running.
func TestStartPolicyRejectsInvalidSubnetMap(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	manager := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(buf, nil)), nil)

	bad := config.Policy{
		Scope: config.Scope{
			Targets:   []string{"10.10.0.0/16"},
			SubnetMap: []config.SubnetMapEntry{{Prefix: "10.10.20.0/33"}},
		},
	}
	err := manager.StartPolicy("bad_policy", bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad_policy")
	assert.Contains(t, err.Error(), "invalid prefix")
	assert.False(t, manager.HasPolicy("bad_policy"), "a rejected policy must not be registered")
	assert.Contains(t, buf.String(), "policy rejected")
}

// Validation fills in each entry's parsed network, which is what the runner
// matches against, so a valid map leaves the policy startable.
func TestStartPolicyAcceptsNestedSubnetMap(t *testing.T) {
	entries := []config.SubnetMapEntry{
		{Prefix: "10.10.0.0/16"},
		{Prefix: "10.10.20.0/24"},
		{Prefix: "10.10.20.128/25"},
	}
	require.NoError(t, config.ValidateSubnetMap(entries, slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))))
	assert.Equal(t, 25, entries[2].MaskBits())
}

// The agent name option is what ${AGENT_NAME} resolves against.
func TestManagerAcceptsAgentName(t *testing.T) {
	manager := policy.NewManager(context.Background(),
		slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)), nil, policy.WithAgentName("lab-agent-01"))
	require.NotNil(t, manager)
}
