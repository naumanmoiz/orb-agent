package configmgr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/netboxsync"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

var _ Manager = (*netboxConfigManager)(nil)

// netboxRefreshTimeout bounds one refresh: fetch, render and apply.
const netboxRefreshTimeout = 10 * time.Minute

// policyRunner fetches and generates one policy set. *netboxsync.Syncer
// satisfies it; tests substitute a fake.
type policyRunner interface {
	Run(ctx context.Context) (*netboxsync.Result, error)
}

type appliedPolicy struct {
	id      string
	hash    string
	version int32
}

// netboxConfigManager generates policies from NetBox IPAM prefixes and keeps
// the applied set in step with them, the way the git config manager keeps it
// in step with a repository: on every refresh it computes the desired set,
// diffs it against what it last applied, and adds, updates or removes.
//
// It only ever touches the policies it generated itself. A failed refresh
// changes nothing, so a NetBox outage never removes running policies.
type netboxConfigManager struct {
	logger    *slog.Logger
	pMgr      policymgr.PolicyManager
	cfg       config.NetBoxManager
	runner    policyRunner
	scheduler gocron.Scheduler
	namespace uuid.UUID
	datasetID string
	backends  map[string]backend.Backend

	mu      sync.Mutex
	applied map[policyKey]appliedPolicy

	ctx    context.Context
	cancel context.CancelFunc
}

func newNetBoxConfigManager(logger *slog.Logger, pMgr policymgr.PolicyManager) *netboxConfigManager {
	return &netboxConfigManager{logger: logger, pMgr: pMgr, applied: map[policyKey]appliedPolicy{}}
}

func (nc *netboxConfigManager) Start(ctx context.Context, cfg config.Config, backends map[string]backend.Backend) error {
	nc.cfg = cfg.OrbAgent.ConfigManager.Sources.NetBox
	nc.backends = backends
	if nc.runner == nil {
		syncer, err := netboxsync.NewSyncer(nc.cfg, nc.logger)
		if err != nil {
			return err
		}
		nc.runner = syncer
	}
	nc.namespace = uuid.NewSHA1(uuid.Nil, []byte("netbox:"+nc.cfg.URL))
	nc.datasetID = uuid.NewSHA1(nc.namespace, []byte("dataset")).String()
	nc.ctx, nc.cancel = context.WithCancel(context.WithoutCancel(ctx))

	if err := nc.refresh(); err != nil {
		if nc.cfg.Schedule == nil {
			return err
		}
		nc.logger.Error("initial netbox refresh failed; the scheduler will retry",
			"schedule", *nc.cfg.Schedule, "error", err)
	}

	if nc.cfg.Schedule != nil {
		s, err := gocron.NewScheduler()
		if err != nil {
			return err
		}
		nc.scheduler = s
		task := gocron.NewTask(func() {
			if err := nc.refresh(); err != nil {
				nc.logger.Error("netbox refresh failed; keeping the last applied policies", "error", err)
			}
		})
		if _, err = s.NewJob(gocron.CronJob(*nc.cfg.Schedule, false), task,
			gocron.WithSingletonMode(gocron.LimitModeReschedule)); err != nil {
			return err
		}
		s.Start()
	}
	return nil
}

// refresh fetches, renders, writes and applies one policy set.
func (nc *netboxConfigManager) refresh() error {
	ctx, cancel := context.WithTimeout(nc.ctx, netboxRefreshTimeout)
	defer cancel()

	res, err := nc.runner.Run(ctx)
	if err != nil {
		return err
	}
	res.Summary.Log(nc.logger)

	if nc.cfg.GeneratedConfigPath != "" {
		data, err := netboxsync.Render(res)
		if err != nil {
			return err
		}
		if err := netboxsync.WriteFileAtomic(nc.cfg.GeneratedConfigPath, data, 0o644); err != nil {
			nc.logger.Error("failed to write the generated policies", "path", nc.cfg.GeneratedConfigPath, "error", err)
		} else {
			nc.logger.Info("wrote the generated policies", "path", nc.cfg.GeneratedConfigPath)
		}
	}

	if res.Summary.Prefixes == 0 && !nc.cfg.AllowEmpty {
		nc.mu.Lock()
		n := len(nc.applied)
		nc.mu.Unlock()
		if n > 0 {
			return errors.New("netbox returned no prefixes; keeping the applied policies (set allow_empty to permit removing them)")
		}
	}
	nc.apply(res.Policies)
	return nil
}

func hashPolicy(data any) (string, error) {
	b, err := yaml.Marshal(data)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// apply diffs the desired set against the last applied one. A new policy is
// managed at version 1, a changed one at the next version, and one no longer
// desired is removed. An unchanged policy is not touched.
func (nc *netboxConfigManager) apply(desired map[string]map[string]any) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	keep := map[policyKey]bool{}
	var added, updated, removed int
	beNames := make([]string, 0, len(desired))
	for be := range desired {
		beNames = append(beNames, be)
	}
	sort.Strings(beNames)
	for _, beName := range beNames {
		policies := desired[beName]
		if _, ok := nc.backends[beName]; !ok {
			nc.logger.Error("generated policies need a backend that is not configured; skipping them",
				"backend", beName, "policies", len(policies))
			continue
		}
		names := make([]string, 0, len(policies))
		for name := range policies {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			data := policies[name]
			key := policyKey{Backend: beName, Name: name}
			hash, err := hashPolicy(data)
			if err != nil {
				nc.logger.Error("failed to hash generated policy", "policy", name, "error", err)
				continue
			}
			keep[key] = true
			prev, exists := nc.applied[key]
			if exists && prev.hash == hash {
				continue
			}
			ap := appliedPolicy{
				id:      uuid.NewSHA1(nc.namespace, []byte(name+beName)).String(),
				hash:    hash,
				version: 1,
			}
			if exists {
				ap.version = prev.version + 1
				updated++
			} else {
				added++
			}
			nc.pMgr.ManagePolicy(config.PolicyPayload{
				ID:        ap.id,
				Action:    "manage",
				Name:      name,
				DatasetID: nc.datasetID,
				Backend:   beName,
				Version:   ap.version,
				Data:      data,
			})
			nc.applied[key] = ap
		}
	}

	for key, ap := range nc.applied {
		if keep[key] || !strings.HasPrefix(key.Name, netboxsync.PolicyNamePrefix) {
			continue
		}
		if err := nc.pMgr.RemovePolicy(ap.id, key.Name, key.Backend); err != nil {
			nc.logger.Error("failed to remove policy", "policy", key.Name, "backend", key.Backend, "error", err)
			continue
		}
		delete(nc.applied, key)
		removed++
	}
	nc.logger.Info("netbox policies applied", "added", added, "updated", updated, "removed", removed,
		"total", len(nc.applied))
}

// GetContext returns the context unchanged.
func (nc *netboxConfigManager) GetContext(ctx context.Context) context.Context {
	return ctx
}

// Stop stops the refresh schedule.
func (nc *netboxConfigManager) Stop(_ context.Context) error {
	if nc.cancel != nil {
		nc.cancel()
	}
	if nc.scheduler != nil {
		return nc.scheduler.Shutdown()
	}
	return nil
}
