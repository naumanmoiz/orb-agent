package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// VLAN ID bounds defined by 802.1Q and enforced by NetBox.
const (
	minVID = 1
	maxVID = 4094
)

// VlanGroupParameters names the VLAN group the declared VLANs are attached to
// and the NetBox object the group is scoped to. A bare string is the group name;
// the mapping form adds at most one scope_* field. With no scope the group falls
// back to defaults.site, as the string form does.
//
// The shape mirrors gnmi-discovery's VlanGroupParameters so policy YAML is
// portable between the two backends.
type VlanGroupParameters struct {
	Name           string `yaml:"name,omitempty"`
	ScopeSite      string `yaml:"scope_site,omitempty"`
	ScopeSiteGroup string `yaml:"scope_site_group,omitempty"`
	ScopeRegion    string `yaml:"scope_region,omitempty"`
	ScopeLocation  string `yaml:"scope_location,omitempty"`
}

// UnmarshalYAML accepts a scalar group name or a mapping.
//
// An unknown key in the mapping is an error rather than the warning the rest of
// the policy gets: WarnUnknownPolicyKeys cannot see inside a custom decoder, and
// a misspelled scope would otherwise fall back silently to a site-scoped group
// that then persists in NetBox.
func (g *VlanGroupParameters) UnmarshalYAML(node *yaml.Node) error {
	*g = VlanGroupParameters{}
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag == "!!null" {
			return nil
		}
		g.Name = node.Value
		return nil
	case yaml.MappingNode:
		if err := rejectUnknownKeys(node, reflect.TypeFor[VlanGroupParameters](), "vlan.group"); err != nil {
			return err
		}
		type alias VlanGroupParameters
		var a alias
		if err := node.Decode(&a); err != nil {
			return err
		}
		if a.Name == "" {
			return errors.New("vlan.group: name is required")
		}
		scopes := 0
		for _, v := range []string{a.ScopeSite, a.ScopeSiteGroup, a.ScopeRegion, a.ScopeLocation} {
			if v != "" {
				scopes++
			}
		}
		if scopes > 1 {
			return errors.New("vlan.group: only one scope may be set (scope_site, scope_site_group, scope_region, scope_location)")
		}
		*g = VlanGroupParameters(a)
		return nil
	default:
		return fmt.Errorf("vlan.group: expected string or mapping, got node kind %d", node.Kind)
	}
}

// SubnetVlan is the VLAN a subnet_map entry attaches to its prefix. Vid is
// required; the remaining fields override the matching defaults.vlan value.
type SubnetVlan struct {
	Vid         *int                `yaml:"vid,omitempty"`
	Name        string              `yaml:"name,omitempty"`
	Status      string              `yaml:"status,omitempty"`
	Role        string              `yaml:"role,omitempty"`
	Tenant      string              `yaml:"tenant,omitempty"`
	Group       VlanGroupParameters `yaml:"group,omitempty"`
	Description string              `yaml:"description,omitempty"`
}

// UnmarshalYAML rejects unknown keys for the same reason VlanGroupParameters
// does: a misspelled key here silently drops a VLAN attribute.
func (v *SubnetVlan) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("subnet_map: vlan must be a mapping, got node kind %d", node.Kind)
	}
	if err := rejectUnknownKeys(node, reflect.TypeFor[SubnetVlan](), "subnet_map: vlan"); err != nil {
		return err
	}
	type alias SubnetVlan
	var a alias
	if err := node.Decode(&a); err != nil {
		return err
	}
	*v = SubnetVlan(a)
	return nil
}

// SubnetMapEntry maps one CIDR onto a NetBox prefix, and optionally a VLAN.
//
// Entries may be parents, children or grandchildren of one another. NetBox
// derives the hierarchy itself from containment within a VRF, so no parent
// reference is set here; the agent only has to emit every entry in the same VRF.
// A discovered address takes its mask, role, VLAN and custom fields from the
// most specific entry that contains it, and inherits nothing from a wider one.
type SubnetMapEntry struct {
	Prefix       string         `yaml:"prefix"`
	Status       string         `yaml:"status,omitempty"`
	Role         string         `yaml:"role,omitempty"`
	Tenant       string         `yaml:"tenant,omitempty"`
	Description  string         `yaml:"description,omitempty"`
	IsPool       *bool          `yaml:"is_pool,omitempty"`
	MarkUtilized *bool          `yaml:"mark_utilized,omitempty"`
	Tags         []string       `yaml:"tags,omitempty"`
	Vlan         *SubnetVlan    `yaml:"vlan,omitempty"`
	CustomFields map[string]any `yaml:"custom_fields,omitempty"`

	// network is the parsed, mask-normalized form of Prefix, filled in by
	// ValidateSubnetMap. Entries are matched and emitted through it so that a
	// host-bearing CIDR such as 10.10.20.5/24 becomes the 10.10.20.0/24 network
	// NetBox expects.
	network *net.IPNet `yaml:"-"`
}

// UnmarshalYAML rejects unknown keys in a subnet_map entry. WarnUnknownPolicyKeys
// deliberately leaves scope alone, so without this a typo such as `roles:` would
// decode cleanly and the prefix would reach NetBox with no role at all.
func (e *SubnetMapEntry) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("subnet_map: entry must be a mapping, got node kind %d", node.Kind)
	}
	if err := rejectUnknownKeys(node, reflect.TypeFor[SubnetMapEntry](), "subnet_map"); err != nil {
		return err
	}
	type alias SubnetMapEntry
	var a alias
	if err := node.Decode(&a); err != nil {
		return err
	}
	*e = SubnetMapEntry(a)
	return nil
}

// Network returns the entry's normalized network, or nil before validation.
func (e *SubnetMapEntry) Network() *net.IPNet { return e.network }

// MaskBits returns the entry's prefix length, or -1 before validation.
func (e *SubnetMapEntry) MaskBits() int {
	if e.network == nil {
		return -1
	}
	bits, _ := e.network.Mask.Size()
	return bits
}

// rejectUnknownKeys reports the first key of a mapping node that is not a yaml
// field of t.
func rejectUnknownKeys(node *yaml.Node, t reflect.Type, context string) error {
	known := yamlFieldNames(t)
	for i := 0; i+1 < len(node.Content); i += 2 {
		if key := node.Content[i].Value; !known[key] {
			return fmt.Errorf("%s: unknown key %s", context, key)
		}
	}
	return nil
}

// ValidateSubnetMap checks every entry and fills in its normalized network.
// It is called once at policy load so a malformed map fails that policy alone,
// leaving the rest of the agent running.
//
// Overlapping parent and child entries are valid and expected: they are how the
// hierarchy is declared. Two entries covering the identical network are not,
// because the second would silently win the longest-prefix match.
func ValidateSubnetMap(entries []SubnetMapEntry, logger *slog.Logger) error {
	seen := make(map[string]int, len(entries))
	for i := range entries {
		entry := &entries[i]
		if strings.TrimSpace(entry.Prefix) == "" {
			return fmt.Errorf("subnet_map[%d]: prefix is required", i)
		}
		ip, network, err := net.ParseCIDR(entry.Prefix)
		if err != nil {
			return fmt.Errorf("subnet_map[%d]: invalid prefix %q: %w", i, entry.Prefix, err)
		}
		entry.network = network
		if logger != nil && !ip.Equal(network.IP) {
			logger.Warn("subnet_map prefix carries host bits; using its network address",
				"configured", entry.Prefix, "prefix", network.String())
		}
		key := network.String()
		if first, dup := seen[key]; dup {
			return fmt.Errorf("subnet_map[%d]: duplicate prefix %s, already declared at subnet_map[%d]", i, key, first)
		}
		seen[key] = i

		if entry.Vlan == nil {
			continue
		}
		if entry.Vlan.Vid == nil {
			return fmt.Errorf("subnet_map[%d] (%s): vlan.vid is required when a vlan is declared", i, key)
		}
		if vid := *entry.Vlan.Vid; vid < minVID || vid > maxVID {
			return fmt.Errorf("subnet_map[%d] (%s): vlan.vid %d out of range %d-%d", i, key, vid, minVID, maxVID)
		}
	}
	return nil
}

// WarnSubnetMapCoverage logs an entry that overlaps none of the scan targets.
// Such an entry is still emitted, because the map defines IPAM while the targets
// define what nmap scans, but it is far more often a typo than an intent.
func WarnSubnetMapCoverage(entries []SubnetMapEntry, targets []string, logger *slog.Logger) {
	if logger == nil || len(entries) == 0 {
		return
	}
	nets := make([]*net.IPNet, 0, len(targets))
	for _, target := range targets {
		if _, network, err := net.ParseCIDR(target); err == nil {
			nets = append(nets, network)
		}
	}
	for i := range entries {
		entry := &entries[i]
		if entry.network == nil {
			continue
		}
		covered := false
		for _, target := range nets {
			if networksOverlap(entry.network, target) {
				covered = true
				break
			}
		}
		if !covered {
			logger.Warn("subnet_map entry overlaps no scan target; its prefix is emitted but nothing in it is scanned",
				"prefix", entry.network.String(), "targets", targets)
		}
	}
}

// networksOverlap reports whether either network contains the other's base
// address, which for CIDRs is equivalent to the two overlapping at all.
func networksOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}
