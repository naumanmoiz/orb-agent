package netboxsync

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// Backend names the generated policies are filed under.
const (
	NetworkDiscoveryBackend = "network_discovery"
	SNMPDiscoveryBackend    = "snmp_discovery"
)

// Policy name prefixes. Every generated name starts with PolicyNamePrefix, so
// the config manager never touches a policy it did not generate.
const (
	PolicyNamePrefix    = "nb-"
	scanPolicyPrefix    = "nb-nd-"
	stragglerPrefix     = "nb-nd-straggler-"
	snmpPolicyPrefix    = "nb-snmp-"
	statusContainer     = "container"
	defaultStatusActive = "active"
)

// Settings is the NetBox source configuration with every default applied.
type Settings struct {
	Statuses map[string]bool
	ND       NDSettings
	SNMP     SNMPSettings
}

// NDSettings are the network_discovery generation settings.
type NDSettings struct {
	Enabled             bool
	Schedule            string
	StragglerSchedule   string
	StaggerMinutes      int
	Timeout             int
	MaxTargets          int
	MaxHosts            uint64
	MinBitsV4           int
	MinBitsV6           int
	Config              map[string]any
	Scope               map[string]any
	Straggler           bool
	StragglerMinBitsV4  int
	StragglerMinBitsV6  int
	StragglerMaxPerPar  uint64
	StragglerPingOnly   bool
	StragglerMaxTargets int
	StragglerMaxHosts   uint64
	StragglerScope      map[string]any
}

// SNMPSettings are the snmp_discovery generation settings.
type SNMPSettings struct {
	Enabled           bool
	Schedule          string
	StaggerMinutes    int
	IncludeStragglers bool
	MaxTargets        int
	MaxHosts          uint64
	Authentication    map[string]any
	Config            map[string]any
}

func intOr(v *int, def int) int {
	if v == nil {
		return def
	}
	return *v
}

func boolOr(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func positiveOr(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// NewSettings validates cfg and applies the defaults.
func NewSettings(cfg config.NetBoxManager) (Settings, error) {
	s := Settings{Statuses: map[string]bool{}}
	statuses := cfg.Statuses
	if len(statuses) == 0 {
		statuses = []string{statusContainer, defaultStatusActive}
	}
	for _, st := range statuses {
		s.Statuses[strings.ToLower(strings.TrimSpace(st))] = true
	}

	nd := cfg.NetworkDiscovery
	s.ND = NDSettings{
		Enabled:             nd.Enabled,
		Schedule:            nd.Schedule,
		StaggerMinutes:      nd.StaggerMinutes,
		Timeout:             nd.Timeout,
		MaxTargets:          positiveOr(nd.MaxTargetsPerPolicy, 256),
		MaxHosts:            uint64(positiveOr(nd.MaxHostsPerPolicy, 65536)),
		MinBitsV4:           intOr(nd.MaxBlockPrefixLenV4, 16),
		MinBitsV6:           intOr(nd.MaxBlockPrefixLenV6, 112),
		Config:              nd.Config,
		Scope:               nd.Scope,
		Straggler:           boolOr(nd.Straggler.Enabled, true),
		StragglerMinBitsV4:  intOr(nd.Straggler.MaxBlockPrefixLenV4, 20),
		StragglerMinBitsV6:  intOr(nd.Straggler.MaxBlockPrefixLenV6, 116),
		StragglerMaxPerPar:  uint64(positiveOr(nd.Straggler.MaxHostsPerParent, 16384)),
		StragglerPingOnly:   boolOr(nd.Straggler.PingOnly, true),
		StragglerMaxTargets: positiveOr(nd.Straggler.MaxTargetsPerPolicy, positiveOr(nd.MaxTargetsPerPolicy, 256)),
		StragglerMaxHosts:   uint64(positiveOr(nd.Straggler.MaxHostsPerPolicy, positiveOr(nd.MaxHostsPerPolicy, 65536))),
		StragglerScope:      nd.Straggler.Scope,
	}
	if s.ND.Schedule == "" {
		s.ND.Schedule = "0 */6 * * *"
	}
	if s.ND.Timeout <= 0 {
		s.ND.Timeout = 30
	}
	if s.ND.Enabled && s.ND.Straggler {
		if nd.StragglerSchedule != "" {
			s.ND.StragglerSchedule = nd.StragglerSchedule
		} else {
			shifted, err := ShiftCron(s.ND.Schedule, intOr(nd.StragglerDelayMinutes, 30))
			if err != nil {
				return Settings{}, fmt.Errorf("network_discovery: cannot derive the straggler schedule (%w); set straggler_schedule explicitly", err)
			}
			s.ND.StragglerSchedule = shifted
		}
	}

	sn := cfg.SNMPDiscovery
	s.SNMP = SNMPSettings{
		Enabled:           sn.Enabled,
		Schedule:          sn.Schedule,
		StaggerMinutes:    sn.StaggerMinutes,
		IncludeStragglers: sn.IncludeStragglers,
		MaxTargets:        positiveOr(sn.MaxTargetsPerPolicy, 256),
		MaxHosts:          uint64(positiveOr(sn.MaxHostsPerPolicy, 65536)),
		Authentication:    sn.Authentication,
		Config:            sn.Config,
	}
	if s.SNMP.Schedule == "" {
		s.SNMP.Schedule = "15 */6 * * *"
	}
	if !s.ND.Enabled && !s.SNMP.Enabled {
		return Settings{}, fmt.Errorf("netbox source: neither network_discovery nor snmp_discovery is enabled")
	}
	for name, bits := range map[string]int{
		"max_block_prefix_len_v4": s.ND.MinBitsV4, "straggler.max_block_prefix_len_v4": s.ND.StragglerMinBitsV4,
	} {
		if bits < 0 || bits > 32 {
			return Settings{}, fmt.Errorf("network_discovery.%s must be between 0 and 32", name)
		}
	}
	for name, bits := range map[string]int{
		"max_block_prefix_len_v6": s.ND.MinBitsV6, "straggler.max_block_prefix_len_v6": s.ND.StragglerMinBitsV6,
	} {
		if bits < 0 || bits > 128 {
			return Settings{}, fmt.Errorf("network_discovery.%s must be between 0 and 128", name)
		}
	}
	return s, nil
}

// Skip records a prefix or block left out of the generated policies.
type Skip struct {
	PrefixID int
	Block    string
	VRF      string
	Reason   string
}

// Summary describes one generation.
type Summary struct {
	Prefixes          int
	ScanPrefixes      int
	ScanPolicies      int
	Parents           int
	StragglerBlocks   int
	StragglerPolicies int
	SNMPTargets       int
	SNMPPolicies      int
	Skipped           []Skip
	Warnings          []string
}

// Result is the generated policy set: backend -> policy name -> policy data,
// the same shape as orb.policies.
type Result struct {
	Policies map[string]map[string]any
	Summary  Summary
}

// Log logs the counts, warnings and every skip.
func (s Summary) Log(logger *slog.Logger) {
	logger.Info("netbox prefix sync generated policies",
		"prefixes", s.Prefixes,
		"scan_prefixes", s.ScanPrefixes, "scan_policies", s.ScanPolicies,
		"parents_with_leftover", s.Parents, "straggler_blocks", s.StragglerBlocks,
		"straggler_policies", s.StragglerPolicies,
		"snmp_targets", s.SNMPTargets, "snmp_policies", s.SNMPPolicies,
		"skipped", len(s.Skipped))
	for _, w := range s.Warnings {
		logger.Warn(w)
	}
	for _, sk := range s.Skipped {
		logger.Warn("netbox prefix sync skipped a block", "prefix_id", sk.PrefixID, "block", sk.Block, "vrf", sk.VRF, "reason", sk.Reason)
	}
}

// vrfGroup is one VRF's prefixes. Groups are output with the global table
// first, then VRFs by name and id.
type vrfGroup struct {
	id       int
	name     string
	slug     string
	prefixes []*Prefix
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 40 {
		s = strings.TrimRight(s[:40], "-")
	}
	if s == "" {
		s = "vrf"
	}
	return s
}

// groupByVRF orders the VRF groups and gives each a slug that is unique and
// stable: the slug of the VRF name, with "-v<id>" appended only when two VRFs
// would otherwise share it.
func groupByVRF(byVRF map[int][]*Prefix) []*vrfGroup {
	groups := make([]*vrfGroup, 0, len(byVRF))
	for id, prefixes := range byVRF {
		g := &vrfGroup{id: id, prefixes: prefixes}
		if id == 0 {
			g.slug = "global"
		} else {
			g.name = prefixes[0].VRF
			g.slug = slugify(g.name)
			if g.slug == "global" {
				g.slug = "vrf-global"
			}
		}
		groups = append(groups, g)
	}
	count := map[string]int{}
	for _, g := range groups {
		count[g.slug]++
	}
	for _, g := range groups {
		if g.id != 0 && count[g.slug] > 1 {
			g.slug = fmt.Sprintf("%s-v%d", g.slug, g.id)
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if (a.id == 0) != (b.id == 0) {
			return a.id == 0
		}
		if a.name != b.name {
			return a.name < b.name
		}
		return a.id < b.id
	})
	return groups
}

// item is one scan target with the prefix whose attributes it takes.
type item struct {
	block netip.Prefix
	owner *Prefix
}

// batch splits items into chunks of at most maxTargets targets and maxHosts
// addresses, whichever is reached first. An item larger than maxHosts on its
// own gets a chunk to itself.
func batch(items []item, maxTargets int, maxHosts uint64) [][]item {
	var out [][]item
	var cur []item
	var hosts uint64
	for _, it := range items {
		h := hostCount(it.block)
		if len(cur) > 0 && (len(cur) >= maxTargets || hosts+h > maxHosts) {
			out = append(out, cur)
			cur, hosts = nil, 0
		}
		cur = append(cur, it)
		hosts += h
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

func tooLarge(p netip.Prefix, minV4, minV6 int) bool {
	if p.Addr().Is4() {
		return p.Bits() < minV4
	}
	return p.Bits() < minV6
}

// Generate builds the policy set from the fetched prefixes.
func Generate(prefixes []*Prefix, s Settings) *Result {
	res := &Result{Policies: map[string]map[string]any{}}
	res.Summary.Prefixes = len(prefixes)
	groups := groupByVRF(BuildTree(prefixes))

	type named struct {
		name  string
		chunk []item
	}
	var scan, straggle, snmp []named

	for _, g := range groups {
		var leaves, blocks []item
		for _, p := range g.prefixes {
			eligible := s.Statuses[strings.ToLower(p.Status)]
			if !eligible {
				continue
			}
			isParent := len(p.Children) > 0 || p.Status == statusContainer
			if !isParent {
				if tooLarge(p.Network, s.ND.MinBitsV4, s.ND.MinBitsV6) {
					res.Summary.Skipped = append(res.Summary.Skipped, Skip{p.ID, p.Network.String(), p.VRF,
						"leaf prefix larger than max_block_prefix_len"})
					continue
				}
				leaves = append(leaves, item{p.Network, p})
				continue
			}
			if !s.ND.Straggler && !(s.SNMP.Enabled && s.SNMP.IncludeStragglers) {
				continue
			}
			children := make([]netip.Prefix, len(p.Children))
			for i, c := range p.Children {
				children[i] = c.Network
			}
			left := Leftover(p.Network, children)
			if len(left) == 0 {
				continue
			}
			res.Summary.Parents++
			var used uint64
			for _, b := range left {
				if tooLarge(b, s.ND.StragglerMinBitsV4, s.ND.StragglerMinBitsV6) {
					res.Summary.Skipped = append(res.Summary.Skipped, Skip{p.ID, b.String(), p.VRF,
						"leftover block larger than straggler.max_block_prefix_len"})
					continue
				}
				h := hostCount(b)
				if used+h > s.ND.StragglerMaxPerPar {
					res.Summary.Skipped = append(res.Summary.Skipped, Skip{p.ID, b.String(), p.VRF,
						"parent exceeded straggler.max_hosts_per_parent"})
					continue
				}
				used += h
				blocks = append(blocks, item{b, p})
			}
		}
		// Address order keeps a parent's blocks next to the leaves around them
		// and makes batches stable as prefixes come and go elsewhere.
		sort.SliceStable(blocks, func(i, j int) bool {
			return blocks[i].block.Addr().Less(blocks[j].block.Addr())
		})
		res.Summary.ScanPrefixes += len(leaves)
		res.Summary.StragglerBlocks += len(blocks)

		if s.ND.Enabled {
			for i, chunk := range batch(leaves, s.ND.MaxTargets, s.ND.MaxHosts) {
				scan = append(scan, named{fmt.Sprintf("%s%s-%03d", scanPolicyPrefix, g.slug, i+1), chunk})
			}
			if s.ND.Straggler {
				for i, chunk := range batch(blocks, s.ND.StragglerMaxTargets, s.ND.StragglerMaxHosts) {
					straggle = append(straggle, named{fmt.Sprintf("%s%s-%03d", stragglerPrefix, g.slug, i+1), chunk})
				}
			}
		}
		if s.SNMP.Enabled {
			targets := leaves
			if s.SNMP.IncludeStragglers {
				targets = append(append([]item(nil), leaves...), blocks...)
			}
			for i, chunk := range batch(targets, s.SNMP.MaxTargets, s.SNMP.MaxHosts) {
				snmp = append(snmp, named{fmt.Sprintf("%s%s-%03d", snmpPolicyPrefix, g.slug, i+1), chunk})
			}
		}
	}

	if len(scan)+len(straggle) > 0 {
		nd := map[string]any{}
		for i, n := range scan {
			sched := staggered(s.ND.Schedule, i, len(scan), s.ND.StaggerMinutes, &res.Summary)
			nd[n.name] = networkPolicy(n.chunk, sched, s, false, &res.Summary)
		}
		for i, n := range straggle {
			sched := staggered(s.ND.StragglerSchedule, i, len(straggle), s.ND.StaggerMinutes, &res.Summary)
			nd[n.name] = networkPolicy(n.chunk, sched, s, true, &res.Summary)
		}
		res.Policies[NetworkDiscoveryBackend] = nd
	}
	if len(snmp) > 0 {
		sp := map[string]any{}
		for i, n := range snmp {
			sched := staggered(s.SNMP.Schedule, i, len(snmp), s.SNMP.StaggerMinutes, &res.Summary)
			sp[n.name] = snmpPolicy(n.chunk, sched, s, &res.Summary)
			res.Summary.SNMPTargets += len(n.chunk)
		}
		res.Policies[SNMPDiscoveryBackend] = sp
	}
	res.Summary.ScanPolicies = len(scan)
	res.Summary.StragglerPolicies = len(straggle)
	res.Summary.SNMPPolicies = len(snmp)
	res.Summary.Warnings = dedupe(res.Summary.Warnings)
	return res
}

// staggered spreads n policies evenly over window minutes.
func staggered(base string, i, n, window int, sum *Summary) string {
	if window <= 0 || n <= 1 {
		return base
	}
	offset := i * window / n
	shifted, err := ShiftCron(base, offset)
	if err != nil {
		sum.Warnings = append(sum.Warnings, fmt.Sprintf("stagger_minutes ignored for schedule %q: %v", base, err))
		return base
	}
	return shifted
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// placementKeys are the defaults the generated subnet_map decides per prefix.
// A template value would leak onto prefixes in the global table, which have
// no VRF or tenant of their own to override it with.
var ndPlacementKeys = []string{"vrf", "rd", "vrf_tenant", "vrf_tenant_group", "tenant", "tenant_group"}

// pingOnlyDrops are the scope keys that ask for a port scan.
var pingOnlyDrops = []string{"ports", "exclude_ports", "top_ports", "scan_types", "os_detection", "fast_mode"}

func networkPolicy(chunk []item, schedule string, s Settings, straggler bool, sum *Summary) map[string]any {
	cfg := deepCopyMap(s.ND.Config)
	if defaults, ok := cfg["defaults"].(map[string]any); ok {
		for _, k := range ndPlacementKeys {
			if _, set := defaults[k]; set {
				sum.Warnings = append(sum.Warnings, fmt.Sprintf(
					"network_discovery.config.defaults.%s is ignored: VRF and tenant come from each NetBox prefix", k))
				delete(defaults, k)
			}
		}
	}
	cfg["schedule"] = schedule
	cfg["timeout"] = s.ND.Timeout

	scope := deepCopyMap(s.ND.Scope)
	for _, k := range []string{"targets", "subnet_map"} {
		if _, set := scope[k]; set {
			sum.Warnings = append(sum.Warnings, fmt.Sprintf("network_discovery.scope.%s is ignored: it is generated", k))
		}
	}
	if straggler {
		for k, v := range deepCopyMap(s.ND.StragglerScope) {
			scope[k] = v
		}
		if s.ND.StragglerPingOnly {
			for _, k := range pingOnlyDrops {
				delete(scope, k)
			}
			scope["ping_scan"] = true
		}
	}

	targets := make([]any, 0, len(chunk))
	var entries []any
	seen := map[*Prefix]bool{}
	for _, it := range chunk {
		targets = append(targets, it.block.String())
		if !seen[it.owner] {
			seen[it.owner] = true
			entries = append(entries, subnetMapEntry(it.owner))
		}
	}
	scope["targets"] = targets
	scope["subnet_map"] = entries
	return map[string]any{"config": cfg, "scope": scope}
}

// subnetMapEntry describes p so that every address found inside it is filed
// with exactly p's VRF (name, rd, tenant) and tenant, matching the existing
// NetBox objects. emit_prefix is false: the prefix already exists in NetBox.
func subnetMapEntry(p *Prefix) map[string]any {
	e := map[string]any{"prefix": p.Network.String(), "emit_prefix": false}
	if p.VRF != "" {
		e["vrf"] = p.VRF
		if p.RD != "" {
			e["rd"] = p.RD
		}
		if p.VRFTenant != "" {
			e["vrf_tenant"] = p.VRFTenant
			if p.VRFTenantGroup != "" {
				e["vrf_tenant_group"] = p.VRFTenantGroup
			}
		}
	}
	if p.Tenant != "" {
		e["tenant"] = p.Tenant
		if p.TenantGroup != "" {
			e["tenant_group"] = p.TenantGroup
		}
	}
	if p.Status != "" {
		e["status"] = p.Status
	}
	if p.Role != "" {
		e["role"] = p.Role
	}
	if len(p.Tags) > 0 {
		e["tags"] = stringsToAny(p.Tags)
		e["address_tags"] = stringsToAny(p.Tags)
	}
	if p.IsPool {
		e["is_pool"] = true
	}
	if p.MarkUtilized {
		e["mark_utilized"] = true
	}
	if p.Description != "" {
		e["description"] = p.Description
	}
	return e
}

var snmpStripped = map[string][]string{
	"":           {"tenant"},
	"ip_address": {"vrf", "vrf_ipv4", "vrf_ipv6", "tenant"},
	"prefix":     {"vrf", "vrf_ipv4", "vrf_ipv6", "tenant"},
}

func snmpPolicy(chunk []item, schedule string, s Settings, sum *Summary) map[string]any {
	cfg := deepCopyMap(s.SNMP.Config)
	if defaults, ok := cfg["defaults"].(map[string]any); ok {
		for section, keys := range snmpStripped {
			target := defaults
			if section != "" {
				sub, ok := defaults[section].(map[string]any)
				if !ok {
					continue
				}
				target = sub
			}
			for _, k := range keys {
				if _, set := target[k]; set {
					sum.Warnings = append(sum.Warnings, fmt.Sprintf(
						"snmp_discovery.config.defaults.%s is ignored: it comes from each NetBox prefix",
						strings.TrimPrefix(section+"."+k, ".")))
					delete(target, k)
				}
			}
		}
	}
	cfg["schedule"] = schedule
	options, _ := cfg["options"].(map[string]any)
	if options == nil {
		options = map[string]any{}
	}
	// Keep hand-written NetBox descriptions unless the template opts back in.
	for _, k := range []string{"device_description_from_sysdescr", "interface_description_from_ifalias"} {
		if _, set := options[k]; !set {
			options[k] = false
		}
	}
	cfg["options"] = options

	targets := make([]any, 0, len(chunk))
	for _, it := range chunk {
		t := map[string]any{"host": it.block.String()}
		if od := snmpOverrides(it.owner); len(od) > 0 {
			t["override_defaults"] = od
		}
		targets = append(targets, t)
	}
	scope := map[string]any{"targets": targets}
	if len(s.SNMP.Authentication) > 0 {
		scope["authentication"] = deepCopyMap(s.SNMP.Authentication)
	}
	return map[string]any{"config": cfg, "scope": scope}
}

func snmpOverrides(p *Prefix) map[string]any {
	od := map[string]any{}
	if p.Site != "" {
		od["site"] = p.Site
	}
	var tenant map[string]any
	if p.Tenant != "" {
		tenant = map[string]any{"name": p.Tenant}
		if p.TenantGroup != "" {
			tenant["group"] = p.TenantGroup
		}
		od["tenant"] = tenant
	}
	var vrf map[string]any
	if p.VRF != "" {
		vrf = map[string]any{"name": p.VRF}
		if p.RD != "" {
			vrf["rd"] = p.RD
		}
		if p.VRFTenant != "" {
			vrf["tenant"] = p.VRFTenant
			if p.VRFTenantGroup != "" {
				vrf["tenant_group"] = p.VRFTenantGroup
			}
		}
	}
	for _, section := range []string{"ip_address", "prefix"} {
		sec := map[string]any{}
		if vrf != nil {
			sec["vrf"] = deepCopyMap(vrf)
		}
		if tenant != nil {
			sec["tenant"] = deepCopyMap(tenant)
		}
		if len(p.Tags) > 0 {
			sec["tags"] = stringsToAny(p.Tags)
		}
		if len(sec) > 0 {
			od[section] = sec
		}
	}
	return od
}

func stringsToAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func deepCopyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = deepCopy(v)
	}
	return out
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return deepCopyMap(t)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = deepCopy(x)
		}
		return out
	default:
		return v
	}
}

// Render marshals the policies as YAML, the same shape as orb.policies, with a
// header saying where they came from.
func Render(res *Result) ([]byte, error) {
	body, err := yaml.Marshal(res.Policies)
	if err != nil {
		return nil, err
	}
	header := fmt.Sprintf("# Generated by the orb-agent netbox config manager. Do not edit: it is\n"+
		"# rewritten on every refresh.\n"+
		"# prefixes=%d scan_policies=%d straggler_policies=%d snmp_policies=%d skipped=%d\n",
		res.Summary.Prefixes, res.Summary.ScanPolicies, res.Summary.StragglerPolicies,
		res.Summary.SNMPPolicies, len(res.Summary.Skipped))
	return append([]byte(header), body...), nil
}

// WriteFileAtomic writes data to path through a temporary file in the same
// directory and a rename, so a reader never sees a partial file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp.Name(), perm); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
