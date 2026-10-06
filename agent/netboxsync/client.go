// Package netboxsync reads IPAM prefixes from NetBox and turns them into
// network_discovery and snmp_discovery policies. It is used by the netbox
// config manager and by the netbox-render command.
package netboxsync

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout  = 30 * time.Second
	defaultRetries  = 3
	defaultPageSize = 1000
	maxPageSize     = 1000
	maxPages        = 100000
)

// ClientOptions configures a Client.
type ClientOptions struct {
	URL           string
	Token         string
	SkipTLSVerify bool
	Timeout       time.Duration
	Retries       int
	PageSize      int
	// Backoff is the delay before the first retry; it doubles each time.
	Backoff time.Duration
	Logger  *slog.Logger
}

// Client is a minimal read-only NetBox REST client.
type Client struct {
	base     *url.URL
	auth     string
	http     *http.Client
	retries  int
	pageSize int
	backoff  time.Duration
	logger   *slog.Logger
}

// NewClient builds a client. The URL must be absolute.
func NewClient(opts ClientOptions) (*Client, error) {
	if strings.TrimSpace(opts.URL) == "" {
		return nil, errors.New("netbox url is required")
	}
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(opts.URL), "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("netbox url %q is not an absolute URL", opts.URL)
	}
	if strings.TrimSpace(opts.Token) == "" {
		return nil, errors.New("netbox token is required")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	retries := opts.Retries
	if retries < 0 {
		retries = 0
	}
	pageSize := opts.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	backoff := opts.Backoff
	if backoff <= 0 {
		backoff = time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // operator opt-in
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Client{
		base:     base,
		auth:     AuthorizationHeader(opts.Token),
		http:     &http.Client{Timeout: timeout, Transport: transport},
		retries:  retries,
		pageSize: pageSize,
		backoff:  backoff,
		logger:   logger,
	}, nil
}

// AuthorizationHeader returns the Authorization header value for a token.
//
// A value that already names its scheme ("Token ..." or "Bearer ...") is sent
// as is. A bare token is sent as "Bearer" when it is a NetBox v2 token (nbt_
// prefix) and as "Token" otherwise, which is what v1 tokens expect.
func AuthorizationHeader(token string) string {
	token = strings.TrimSpace(token)
	lower := strings.ToLower(token)
	if strings.HasPrefix(lower, "token ") || strings.HasPrefix(lower, "bearer ") {
		return token
	}
	if strings.HasPrefix(token, "nbt_") {
		return "Bearer " + token
	}
	return "Token " + token
}

// page is a NetBox list response.
type page struct {
	Count   int               `json:"count"`
	Next    *string           `json:"next"`
	Results []json.RawMessage `json:"results"`
}

// list fetches every object at path, paging with limit/offset. Offsets are
// computed locally rather than following "next", which behind a TLS-
// terminating proxy often points at the wrong scheme or host.
func (c *Client) list(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
	var all []json.RawMessage
	for pageNo := 0; pageNo < maxPages; pageNo++ {
		q := url.Values{}
		for k, v := range query {
			q[k] = append([]string(nil), v...)
		}
		q.Set("limit", strconv.Itoa(c.pageSize))
		q.Set("offset", strconv.Itoa(pageNo*c.pageSize))
		var p page
		if err := c.getJSON(ctx, path, q, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Results...)
		if len(p.Results) == 0 || p.Next == nil || len(all) >= p.Count {
			return all, nil
		}
	}
	return nil, fmt.Errorf("netbox %s: more than %d pages", path, maxPages)
}

// getJSON performs one GET with retries on transport errors, 429 and 5xx.
func (c *Client) getJSON(ctx context.Context, path string, query url.Values, out any) error {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = query.Encode()
	delay := c.backoff
	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			c.logger.Warn("retrying netbox request", "path", path, "attempt", attempt, "error", lastErr)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			delay *= 2
		}
		retry, err := c.do(ctx, u.String(), out)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retry {
			break
		}
	}
	return lastErr
}

func (c *Client) do(ctx context.Context, rawURL string, out any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return true, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return true, err
	}
	if resp.StatusCode != http.StatusOK {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return retry, fmt.Errorf("netbox %s: HTTP %d: %s", req.URL.Path, resp.StatusCode, snippet)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return false, fmt.Errorf("netbox %s: invalid JSON: %w", req.URL.Path, err)
	}
	return false, nil
}

// Wire types: only the fields used are decoded.

type nbRef struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type nbChoice struct {
	Value string `json:"value"`
}

type nbVRF struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	RD     string `json:"rd"`
	Tenant *nbRef `json:"tenant"`
}

type nbTenant struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Group *nbRef `json:"group"`
}

type nbPrefix struct {
	ID           int       `json:"id"`
	Prefix       string    `json:"prefix"`
	VRF          *nbVRF    `json:"vrf"`
	Tenant       *nbRef    `json:"tenant"`
	Status       *nbChoice `json:"status"`
	Role         *nbRef    `json:"role"`
	IsPool       bool      `json:"is_pool"`
	MarkUtilized bool      `json:"mark_utilized"`
	Description  string    `json:"description"`
	Tags         []nbRef   `json:"tags"`
	ScopeType    *string   `json:"scope_type"`
	Scope        *nbRef    `json:"scope"`
	// Site is the NetBox < 4.2 field, replaced by scope there.
	Site *nbRef `json:"site"`
}

// Inventory is everything one refresh read from NetBox.
type Inventory struct {
	Prefixes []*Prefix
}

// FetchInventory reads all prefixes (with filters), VRFs and tenants, and
// resolves each prefix's VRF tenant and tenant groups from the cached lists.
// Three paginated list calls in total, never one per prefix.
func (c *Client) FetchInventory(ctx context.Context, filters map[string]any) (*Inventory, error) {
	query, err := filterValues(filters)
	if err != nil {
		return nil, err
	}
	rawPrefixes, err := c.list(ctx, "/api/ipam/prefixes/", query)
	if err != nil {
		return nil, err
	}
	rawVRFs, err := c.list(ctx, "/api/ipam/vrfs/", nil)
	if err != nil {
		return nil, err
	}
	rawTenants, err := c.list(ctx, "/api/tenancy/tenants/", nil)
	if err != nil {
		return nil, err
	}

	vrfs := make(map[int]nbVRF, len(rawVRFs))
	for _, raw := range rawVRFs {
		var v nbVRF
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("netbox vrf: %w", err)
		}
		vrfs[v.ID] = v
	}
	tenants := make(map[int]nbTenant, len(rawTenants))
	for _, raw := range rawTenants {
		var t nbTenant
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("netbox tenant: %w", err)
		}
		tenants[t.ID] = t
	}

	inv := &Inventory{Prefixes: make([]*Prefix, 0, len(rawPrefixes))}
	for _, raw := range rawPrefixes {
		var np nbPrefix
		if err := json.Unmarshal(raw, &np); err != nil {
			return nil, fmt.Errorf("netbox prefix: %w", err)
		}
		p, err := convertPrefix(np, vrfs, tenants)
		if err != nil {
			c.logger.Warn("skipping netbox prefix", "id", np.ID, "prefix", np.Prefix, "error", err)
			continue
		}
		inv.Prefixes = append(inv.Prefixes, p)
	}
	return inv, nil
}

func convertPrefix(np nbPrefix, vrfs map[int]nbVRF, tenants map[int]nbTenant) (*Prefix, error) {
	network, err := parsePrefix(np.Prefix)
	if err != nil {
		return nil, err
	}
	p := &Prefix{
		ID:           np.ID,
		Network:      network,
		IsPool:       np.IsPool,
		MarkUtilized: np.MarkUtilized,
		Description:  np.Description,
	}
	if np.Status != nil {
		p.Status = np.Status.Value
	}
	if np.Role != nil {
		p.Role = np.Role.Name
	}
	for _, tag := range np.Tags {
		if tag.Name != "" {
			p.Tags = append(p.Tags, tag.Name)
		}
	}
	if np.Tenant != nil {
		p.Tenant = np.Tenant.Name
		if t, ok := tenants[np.Tenant.ID]; ok && t.Group != nil {
			p.TenantGroup = t.Group.Name
		}
	}
	if np.VRF != nil {
		p.VRFID = np.VRF.ID
		p.VRF = np.VRF.Name
		p.RD = np.VRF.RD
		// The nested VRF on a prefix carries no tenant; the VRF list does.
		if v, ok := vrfs[np.VRF.ID]; ok {
			if v.Name != "" {
				p.VRF = v.Name
			}
			if v.RD != "" {
				p.RD = v.RD
			}
			if v.Tenant != nil {
				p.VRFTenant = v.Tenant.Name
				if t, ok := tenants[v.Tenant.ID]; ok && t.Group != nil {
					p.VRFTenantGroup = t.Group.Name
				}
			}
		}
	}
	switch {
	case np.ScopeType != nil && *np.ScopeType == "dcim.site" && np.Scope != nil:
		p.Site = np.Scope.Name
	case np.Site != nil:
		p.Site = np.Site.Name
	}
	return p, nil
}

// filterValues turns the configured filters into query values. Lists become
// repeated parameters; limit and offset are reserved for paging.
func filterValues(filters map[string]any) (url.Values, error) {
	q := url.Values{}
	keys := make([]string, 0, len(filters))
	for k := range filters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "limit" || k == "offset" {
			return nil, fmt.Errorf("netbox filters: %q is reserved for paging", k)
		}
		switch v := filters[k].(type) {
		case nil:
		case []any:
			for _, item := range v {
				q.Add(k, fmt.Sprint(item))
			}
		case []string:
			for _, item := range v {
				q.Add(k, item)
			}
		default:
			q.Add(k, fmt.Sprint(v))
		}
	}
	return q, nil
}
