package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

// Manager represents the policy manager
type Manager struct {
	policies  map[string]*Runner
	client    diode.Client
	logger    *slog.Logger
	ctx       context.Context
	agentName string
	runStore  *RunStore
}

// ManagerOption configures a Manager at construction.
type ManagerOption func(*Manager)

// WithAgentName sets the agent name that ${AGENT_NAME} resolves to in a policy's
// custom_fields block. It is the same value the agent passes as
// --diode-app-name-prefix.
func WithAgentName(name string) ManagerOption {
	return func(m *Manager) { m.agentName = name }
}

// NewManager returns a new policy manager
func NewManager(ctx context.Context, logger *slog.Logger, client diode.Client, opts ...ManagerOption) *Manager {
	m := &Manager{
		ctx:      ctx,
		client:   client,
		logger:   logger,
		policies: make(map[string]*Runner),
		runStore: NewRunStore(),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// ParsePolicies parses the policies from the request
func (m *Manager) ParsePolicies(data []byte) (map[string]config.Policy, error) {
	var payload config.Policies
	if err := yaml.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	config.WarnUnknownPolicyKeys(data, m.logger)

	if len(payload.Policies) == 0 {
		return nil, errors.New("no policies found in the request")
	}

	return payload.Policies, nil
}

// HasPolicy checks if the policy exists
func (m *Manager) HasPolicy(name string) bool {
	_, ok := m.policies[name]
	return ok
}

// StartPolicy starts the policy
func (m *Manager) StartPolicy(name string, policy config.Policy) error {
	if len(policy.Scope.Targets) == 0 {
		return fmt.Errorf("%s : no targets found in the policy", name)
	}

	if err := config.ValidateSubnetMap(policy.Scope.SubnetMap, m.logger); err != nil {
		m.logger.Error("policy rejected: invalid subnet_map", "error", err, "policy", name)
		return fmt.Errorf("%s : %w", name, err)
	}
	config.WarnSubnetMapCoverage(policy.Scope.SubnetMap, policy.Scope.Targets, m.logger)

	// A prefix with no VRF is matched globally by its CIDR, so two labs sharing
	// address space would collapse onto one NetBox prefix. The VRF is what keeps
	// them apart, and these VRFs are prebuilt, so a missing one is a config error.
	if len(policy.Scope.SubnetMap) > 0 && policy.Config.Defaults.Vrf == "" {
		m.logger.Warn("subnet_map declared without defaults.vrf; prefixes will be matched globally by CIDR "+
			"and overlapping labs will collide on one NetBox prefix", "policy", name)
	}

	if err := config.ValidateTimestampPrecision(policy.Config.TimestampPrecision); err != nil {
		m.logger.Error("policy rejected", "error", err, "policy", name)
		return fmt.Errorf("%s : %w", name, err)
	}

	if !m.HasPolicy(name) {
		r, err := NewRunner(m.ctx, m.logger, name, policy, m.client, m.runStore)
		if err != nil {
			return err
		}
		r.agentName = m.agentName

		r.Start()
		m.policies[name] = r
	}
	return nil
}

// StopPolicy stops the policy
func (m *Manager) StopPolicy(name string) error {
	if m.HasPolicy(name) {
		if err := m.policies[name].Stop(); err != nil {
			return err
		}
		delete(m.policies, name)
	}
	return nil
}

// Stop stops the policy manager
func (m *Manager) Stop() error {
	for name := range m.policies {
		if err := m.StopPolicy(name); err != nil {
			return err
		}
	}
	return nil
}

// GetCapabilities returns the capabilities of network-discovery
func (m *Manager) GetCapabilities() []string {
	return []string{"targets, ports, exclude_ports, timing, fast_mode, ping_scan, top_ports, scan_types, max_retries, subnet_map"}
}

// Status represents the status of a policy with its runs
type Status struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "unknown" if there are no runs, "running" if any run is in-flight, otherwise the latest run's status
	Runs   []*Run `json:"runs"`
}

// deriveStatus returns "unknown" when runs is empty, "running" if any run is still running,
// and otherwise the latest run's status. Expects runs in chronological order (oldest first),
// as stored by RunStore.CreateRun.
func deriveStatus(runs []*Run) string {
	if len(runs) == 0 {
		return "unknown"
	}
	for _, r := range runs {
		if r.Status == RunStatusRunning {
			return string(RunStatusRunning)
		}
	}
	// Last element is the most recent run (append order = chronological)
	return string(runs[len(runs)-1].Status)
}

// GetPolicyStatuses returns all policies with their status and runs
func (m *Manager) GetPolicyStatuses() []Status {
	allRuns := m.runStore.GetAllPoliciesWithRuns()

	statuses := make([]Status, 0)

	// Get statuses for all policies that have runners
	for name := range m.policies {
		runs := m.runStore.GetRunsForPolicy(name)
		statuses = append(statuses, Status{
			Name:   name,
			Status: deriveStatus(runs),
			Runs:   runs,
		})
	}

	// Also include policies that have runs but no active runner
	for name, runs := range allRuns {
		if !m.HasPolicy(name) {
			statuses = append(statuses, Status{
				Name:   name,
				Status: deriveStatus(runs),
				Runs:   runs,
			})
		}
	}

	return statuses
}
