package config

import (
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// SubnetMapEntry declares one subnet as a NetBox prefix.
//
// Entries may be parents, children or grandchildren of one another, and of
// prefixes that already exist in NetBox. No parent reference is set here:
// NetBox derives the hierarchy from containment within a VRF, so emitting an
// entry into the right VRF is all that is needed for it to nest.
//
// The map also gives every discovered address the mask of the most specific
// entry containing it, so the address lands inside the prefix rather than as a
// loose /32.
//
// An entry also decides where that prefix and those addresses live. Its vrf and
// tenant override defaults.vrf and defaults.tenant for everything inside it, so
// one policy can scan subnets spread across several prebuilt VRFs and tenants
// instead of needing one policy per VRF.
type SubnetMapEntry struct {
	Prefix string `yaml:"prefix"`
	// Vrf places this subnet, and every address discovered inside it, in a VRF
	// other than defaults.vrf. It is what lets one policy scan subnets belonging
	// to several VRFs.
	//
	// The three VRF identity fields travel together: setting vrf here means rd
	// and vrf_tenant are read from this entry too, never inherited from
	// defaults. They describe one prebuilt VRF, and pairing this entry's name
	// with the defaults' rd would build a reference matching neither. An entry
	// with no vrf inherits all three from defaults, unchanged.
	Vrf       string `yaml:"vrf,omitempty"`
	Rd        string `yaml:"rd,omitempty"`
	VrfTenant string `yaml:"vrf_tenant,omitempty"`
	// Tenant owns this subnet: it lands on the prefix and on every address
	// discovered inside it. TenantGroup is inherited from defaults.tenant_group
	// unless set here, since a deployment's tenants usually share one group.
	Tenant       string         `yaml:"tenant,omitempty"`
	TenantGroup  string         `yaml:"tenant_group,omitempty"`
	Status       string         `yaml:"status,omitempty"`
	Role         string         `yaml:"role,omitempty"`
	Description  string         `yaml:"description,omitempty"`
	IsPool       *bool          `yaml:"is_pool,omitempty"`
	MarkUtilized *bool          `yaml:"mark_utilized,omitempty"`
	Tags         []string       `yaml:"tags,omitempty"`
	CustomFields map[string]any `yaml:"custom_fields,omitempty"`

	// network is the parsed, mask-normalized form of Prefix, filled in by
	// ValidateSubnetMap. Entries are matched and emitted through it so a
	// host-bearing CIDR such as 10.1.2.5/24 becomes the 10.1.2.0/24 network
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
	known := yamlFieldNames(reflect.TypeFor[SubnetMapEntry]())
	for i := 0; i+1 < len(node.Content); i += 2 {
		if key := node.Content[i].Value; !known[key] {
			return fmt.Errorf("subnet_map: unknown key %s", key)
		}
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

// PrefixDefaults holds NetBox defaults applied to the prefixes declared in
// scope.subnet_map. Every field is optional, and an unset field is left off the
// emitted entity rather than defaulted: Diode omits absent optional fields from
// the changeset, so NetBox keeps whatever the prefix already carries.
// Defaulting status here would make every scan re-assert it over an
// operator-set value.
type PrefixDefaults struct {
	Status       string   `yaml:"status,omitempty"`
	Role         string   `yaml:"role,omitempty"`
	Tenant       string   `yaml:"tenant,omitempty"`
	IsPool       *bool    `yaml:"is_pool,omitempty"`
	MarkUtilized *bool    `yaml:"mark_utilized,omitempty"`
	Tags         []string `yaml:"tags,omitempty"`
	Description  string   `yaml:"description,omitempty"`
}

// ValidateSubnetMap checks every entry and fills in its normalized network.
// Called once at policy load so a malformed map fails that policy alone,
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
		// rd and vrf_tenant describe the VRF named alongside them. On an entry
		// with no vrf of its own they would be silently dropped, since the
		// defaults' VRF is referenced with the defaults' own rd and vrf_tenant.
		if entry.Vrf == "" {
			if entry.Rd != "" {
				return fmt.Errorf("subnet_map[%d]: rd is set without vrf; rd describes this entry's own vrf, "+
					"and defaults.vrf is referenced with defaults.rd", i)
			}
			if entry.VrfTenant != "" {
				return fmt.Errorf("subnet_map[%d]: vrf_tenant is set without vrf; vrf_tenant describes this entry's "+
					"own vrf, and defaults.vrf is referenced with defaults.vrf_tenant", i)
			}
		}

		key := network.String()
		if first, dup := seen[key]; dup {
			// Deliberately keyed on the network alone, not on (vrf, network).
			// The same CIDR really can exist in two VRFs, but a scan cannot tell
			// which one answered, so the second entry would only ever win the
			// longest-prefix match. Overlapping VRFs need one policy each.
			return fmt.Errorf("subnet_map[%d]: duplicate prefix %s, already declared at subnet_map[%d]; "+
				"if the same CIDR exists in two VRFs, give each VRF its own policy", i, key, first)
		}
		seen[key] = i
	}
	return nil
}

// WarnSubnetMapCoverage logs an entry that overlaps none of the scan targets.
// Such an entry is still emitted, because the map defines IPAM while the
// targets define what nmap scans, but it is far more often a typo than an
// intent.
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
			if entry.network.Contains(target.IP) || target.Contains(entry.network.IP) {
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
