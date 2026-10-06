package netboxsync

import (
	"fmt"
	"net/netip"
	"sort"
)

// Prefix is one NetBox prefix with the attributes the generated policies need,
// already resolved: VRF name, RD and tenant, and the groups of both tenants.
type Prefix struct {
	ID             int
	Network        netip.Prefix
	VRFID          int // 0 is the global table
	VRF            string
	RD             string
	VRFTenant      string
	VRFTenantGroup string
	Tenant         string
	TenantGroup    string
	Status         string
	Role           string
	Tags           []string
	IsPool         bool
	MarkUtilized   bool
	Description    string
	Site           string

	// Parent and Children are filled in by BuildTree. Children are the direct
	// children only, in address order.
	Parent   *Prefix
	Children []*Prefix
}

func parsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid prefix %q: %w", s, err)
	}
	return p.Masked(), nil
}

// comparePrefixes orders by family, network address, then shorter mask first,
// then id. Under that order every prefix comes after all of its ancestors.
func comparePrefixes(a, b *Prefix) int {
	if c := a.Network.Addr().Compare(b.Network.Addr()); c != 0 {
		return c
	}
	if a.Network.Bits() != b.Network.Bits() {
		return a.Network.Bits() - b.Network.Bits()
	}
	return a.ID - b.ID
}

// contains reports whether outer contains inner (or equals it).
func contains(outer, inner netip.Prefix) bool {
	return outer.Addr().BitLen() == inner.Addr().BitLen() &&
		outer.Bits() <= inner.Bits() &&
		outer.Contains(inner.Addr())
}

// BuildTree links every prefix to its parent and direct children, within its
// own VRF only (VRF id 0 is the global table). Prefixes in different VRFs are
// never related, even when one's network contains the other's. A duplicate of
// a network in the same VRF becomes a child of the first one (lowest id), so
// the duplicate pair is scanned once.
//
// It returns the prefixes grouped by VRF id, each group in address order. The
// sweep is O(n log n).
func BuildTree(prefixes []*Prefix) map[int][]*Prefix {
	byVRF := make(map[int][]*Prefix)
	for _, p := range prefixes {
		p.Parent = nil
		p.Children = nil
		byVRF[p.VRFID] = append(byVRF[p.VRFID], p)
	}
	for _, group := range byVRF {
		sort.Slice(group, func(i, j int) bool { return comparePrefixes(group[i], group[j]) < 0 })
		var stack []*Prefix
		for _, p := range group {
			for len(stack) > 0 && !contains(stack[len(stack)-1].Network, p.Network) {
				stack = stack[:len(stack)-1]
			}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				p.Parent = parent
				parent.Children = append(parent.Children, p)
			}
			stack = append(stack, p)
		}
	}
	return byVRF
}

// lastAddr returns the last address in p.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	bytes := a.AsSlice()
	hostBits := a.BitLen() - p.Bits()
	for i := len(bytes) - 1; i >= 0 && hostBits > 0; i-- {
		if hostBits >= 8 {
			bytes[i] = 0xff
			hostBits -= 8
		} else {
			bytes[i] |= byte(1<<hostBits) - 1
			hostBits = 0
		}
	}
	out, _ := netip.AddrFromSlice(bytes)
	if a.Is4() {
		return out.Unmap()
	}
	return out
}

// Leftover returns the part of parent not covered by any of children, as the
// minimal list of CIDR blocks in address order. Children must lie inside
// parent and be disjoint, which direct children from BuildTree are.
func Leftover(parent netip.Prefix, children []netip.Prefix) []netip.Prefix {
	parent = parent.Masked()
	sorted := append([]netip.Prefix(nil), children...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Addr().Less(sorted[j].Addr()) })
	var out []netip.Prefix
	cur := parent.Addr()
	end := lastAddr(parent)
	for _, child := range sorted {
		child = child.Masked()
		if !contains(parent, child) {
			continue
		}
		if cur.Less(child.Addr()) {
			out = append(out, RangeToPrefixes(cur, child.Addr().Prev())...)
		}
		childEnd := lastAddr(child)
		if !childEnd.Less(end) {
			return out // the child reaches the end of the parent
		}
		if next := childEnd.Next(); cur.Less(next) {
			cur = next
		}
	}
	return append(out, RangeToPrefixes(cur, end)...)
}

// RangeToPrefixes splits the inclusive range [from, to] into the minimal list
// of CIDR blocks. Both ends must be of the same family.
func RangeToPrefixes(from, to netip.Addr) []netip.Prefix {
	if !from.IsValid() || !to.IsValid() || from.BitLen() != to.BitLen() || to.Less(from) {
		return nil
	}
	var out []netip.Prefix
	bitLen := from.BitLen()
	for {
		bits := bitLen
		for bits > 0 {
			candidate := netip.PrefixFrom(from, bits-1)
			if candidate.Masked().Addr() != from || to.Less(lastAddr(candidate)) {
				break
			}
			bits--
		}
		block := netip.PrefixFrom(from, bits)
		out = append(out, block)
		last := lastAddr(block)
		if last == to {
			return out
		}
		from = last.Next()
	}
}

// hostCount returns the number of addresses in p, saturating at 1<<62.
func hostCount(p netip.Prefix) uint64 {
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits >= 62 {
		return 1 << 62
	}
	return 1 << uint(hostBits)
}
