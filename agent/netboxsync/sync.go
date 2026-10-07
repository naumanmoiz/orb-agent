package netboxsync

import (
	"context"
	"log/slog"
	"time"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// Syncer fetches prefixes from NetBox and generates the policy set.
type Syncer struct {
	client   *Client
	settings Settings
	filters  map[string]any
}

// NewSyncer resolves ${VAR} in the url and token from the environment,
// validates the configuration and builds the NetBox client.
func NewSyncer(cfg config.NetBoxManager, logger *slog.Logger) (*Syncer, error) {
	url, err := config.ResolveEnv(cfg.URL)
	if err != nil {
		return nil, err
	}
	token, err := config.ResolveEnv(cfg.Token)
	if err != nil {
		return nil, err
	}
	settings, err := NewSettings(cfg)
	if err != nil {
		return nil, err
	}
	opts := ClientOptions{
		URL:           url,
		Token:         token,
		SkipTLSVerify: cfg.SkipTLSVerify,
		Branch:        cfg.Branch,
		Retries:       intOr(cfg.Retries, defaultRetries),
		PageSize:      cfg.PageSize,
		Logger:        logger,
	}
	if cfg.Timeout != nil {
		opts.Timeout = time.Duration(*cfg.Timeout) * time.Second
	}
	client, err := NewClient(opts)
	if err != nil {
		return nil, err
	}
	return &Syncer{client: client, settings: settings, filters: cfg.Filters}, nil
}

// Client returns the underlying NetBox client.
func (s *Syncer) Client() *Client { return s.client }

// Run fetches the current prefixes and generates the policy set. Any error
// means nothing was generated; callers keep what they last applied.
func (s *Syncer) Run(ctx context.Context) (*Result, error) {
	inv, err := s.client.FetchInventory(ctx, s.filters)
	if err != nil {
		return nil, err
	}
	return Generate(inv.Prefixes, s.settings), nil
}
