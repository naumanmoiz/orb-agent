package netboxsync

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pfx(id, vrf int, cidr, status string) *Prefix {
	return &Prefix{ID: id, VRFID: vrf, Network: netip.MustParsePrefix(cidr), Status: status}
}

func strs(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func TestBuildTreeThreeLevels(t *testing.T) {
	container := pfx(1, 0, "198.51.100.0/24", "container")
	child := pfx(2, 0, "198.51.100.0/25", "active")
	grand1 := pfx(3, 0, "198.51.100.0/27", "active")
	grand2 := pfx(4, 0, "198.51.100.64/26", "reserved")
	sibling := pfx(5, 0, "198.51.100.192/26", "active")
	// Input order must not matter.
	BuildTree([]*Prefix{grand2, sibling, grand1, container, child})

	assert.Nil(t, container.Parent)
	assert.Equal(t, container, child.Parent)
	assert.Equal(t, child, grand1.Parent)
	assert.Equal(t, child, grand2.Parent)
	assert.Equal(t, container, sibling.Parent)
	assert.Equal(t, []*Prefix{child, sibling}, container.Children, "direct children only")
	assert.Equal(t, []*Prefix{grand1, grand2}, child.Children)
	assert.Empty(t, grand1.Children)
}

func TestBuildTreeKeepsVRFsApart(t *testing.T) {
	// The same address space in two VRFs and in the global table: none of them
	// is a parent of another.
	a := pfx(1, 10, "198.51.100.0/24", "container")
	aChild := pfx(2, 10, "198.51.100.0/25", "active")
	b := pfx(3, 20, "198.51.100.0/25", "active")
	g := pfx(4, 0, "198.51.100.0/26", "active")
	byVRF := BuildTree([]*Prefix{a, aChild, b, g})
	assert.Len(t, byVRF, 3)
	assert.Equal(t, a, aChild.Parent)
	assert.Nil(t, b.Parent)
	assert.Nil(t, g.Parent)
	assert.Equal(t, []*Prefix{aChild}, a.Children)
}

func TestBuildTreeDuplicateNetworkNestsUnderFirst(t *testing.T) {
	first := pfx(1, 0, "192.0.2.0/24", "active")
	dup := pfx(2, 0, "192.0.2.0/24", "active")
	BuildTree([]*Prefix{dup, first})
	assert.Equal(t, first, dup.Parent)
	assert.Empty(t, dup.Children)
}

func TestLeftover(t *testing.T) {
	p := netip.MustParsePrefix
	cases := []struct {
		name     string
		parent   string
		children []string
		want     []string
	}{
		{"no children is the whole parent", "192.0.2.0/24", nil, []string{"192.0.2.0/24"}},
		{"first half", "192.0.2.0/24", []string{"192.0.2.0/25"}, []string{"192.0.2.128/25"}},
		{
			"middle hole", "192.0.2.0/24",
			[]string{"192.0.2.64/26"},
			[]string{"192.0.2.0/26", "192.0.2.128/25"},
		},
		{"fully covered", "192.0.2.0/24", []string{"192.0.2.0/25", "192.0.2.128/25"}, nil},
		{"child equal to parent", "192.0.2.0/24", []string{"192.0.2.0/24"}, nil},
		{
			"unaligned gap", "192.0.2.0/24",
			[]string{"192.0.2.0/30", "192.0.2.12/30", "192.0.2.128/25"},
			[]string{"192.0.2.4/30", "192.0.2.8/30", "192.0.2.16/28", "192.0.2.32/27", "192.0.2.64/26"},
		},
		{
			"last child at the end of the address space", "255.255.255.0/24",
			[]string{"255.255.255.128/25"},
			[]string{"255.255.255.0/25"},
		},
		{
			"children outside the parent are ignored", "192.0.2.0/25",
			[]string{"198.51.100.0/24"},
			[]string{"192.0.2.0/25"},
		},
		{"ipv6", "2001:db8::/120", []string{"2001:db8::80/121"}, []string{"2001:db8::/121"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var children []netip.Prefix
			for _, c := range tc.children {
				children = append(children, p(c))
			}
			got := strs(Leftover(p(tc.parent), children))
			if tc.want == nil {
				assert.Empty(t, got)
			} else {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestRangeToPrefixes(t *testing.T) {
	a := netip.MustParseAddr
	assert.Equal(t, []string{"192.0.2.1/32", "192.0.2.2/31", "192.0.2.4/32"},
		strs(RangeToPrefixes(a("192.0.2.1"), a("192.0.2.4"))))
	assert.Equal(t, []string{"0.0.0.0/0"}, strs(RangeToPrefixes(a("0.0.0.0"), a("255.255.255.255"))))
	assert.Nil(t, RangeToPrefixes(a("192.0.2.4"), a("192.0.2.1")))
	assert.Nil(t, RangeToPrefixes(a("192.0.2.4"), a("2001:db8::1")))
	assert.Equal(t, []string{"2001:db8::/127"}, strs(RangeToPrefixes(a("2001:db8::"), a("2001:db8::1"))))
}

func TestHostCount(t *testing.T) {
	assert.Equal(t, uint64(256), hostCount(netip.MustParsePrefix("192.0.2.0/24")))
	assert.Equal(t, uint64(1), hostCount(netip.MustParsePrefix("192.0.2.1/32")))
	assert.Equal(t, uint64(1<<62), hostCount(netip.MustParsePrefix("2001:db8::/32")))
	require.Equal(t, uint64(4096), hostCount(netip.MustParsePrefix("2001:db8::/116")))
}
