package policy

import (
	"net"
	"sort"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

// subnetMatcher resolves a discovered address to the most specific subnet_map
// entry containing it.
//
// Entries are held longest-mask-first so the first containing entry is the
// answer: 10.10.20.200 resolves to 10.10.20.128/25 rather than the 10.10.20.0/24
// or 10.10.0.0/16 that also contain it. Ties on mask length cannot happen, since
// ValidateSubnetMap rejects duplicate networks, and two distinct networks of the
// same length never overlap.
type subnetMatcher struct {
	entries []*config.SubnetMapEntry
}

// newSubnetMatcher builds a matcher over validated entries. Entries whose
// network is unset (never validated) are skipped rather than matched against a
// nil network.
func newSubnetMatcher(entries []config.SubnetMapEntry) *subnetMatcher {
	ordered := make([]*config.SubnetMapEntry, 0, len(entries))
	for i := range entries {
		if entries[i].Network() != nil {
			ordered = append(ordered, &entries[i])
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].MaskBits() > ordered[j].MaskBits()
	})
	return &subnetMatcher{entries: ordered}
}

// match returns the most specific entry containing ip, or nil when none does.
func (m *subnetMatcher) match(ip net.IP) *config.SubnetMapEntry {
	if m == nil || ip == nil {
		return nil
	}
	for _, entry := range m.entries {
		if entry.Network().Contains(ip) {
			return entry
		}
	}
	return nil
}

// empty reports whether the matcher holds no entries, which is the untouched
// upstream case.
func (m *subnetMatcher) empty() bool {
	return m == nil || len(m.entries) == 0
}
