package main

import "net/netip"

// Destinations no allow rule can reach (design.md §7.2, security.md S5). The
// check runs on every resolved address, and the address dialled is the
// address checked, so an allowed name that resolves inward is refused.
var deniedRanges = []struct {
	prefix netip.Prefix
	reason string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), "this_network"},
	{netip.MustParsePrefix("10.0.0.0/8"), "private"},
	{netip.MustParsePrefix("100.64.0.0/10"), "shared_address"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link_local"},
	{netip.MustParsePrefix("172.16.0.0/12"), "private"},
	{netip.MustParsePrefix("192.0.0.0/24"), "protocol_assignment"},
	{netip.MustParsePrefix("192.0.2.0/24"), "documentation"},
	{netip.MustParsePrefix("192.168.0.0/16"), "private"},
	{netip.MustParsePrefix("198.18.0.0/15"), "benchmark"},
	{netip.MustParsePrefix("198.51.100.0/24"), "documentation"},
	{netip.MustParsePrefix("203.0.113.0/24"), "documentation"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved"},
	{netip.MustParsePrefix("::/128"), "unspecified"},
	{netip.MustParsePrefix("::1/128"), "loopback"},
	{netip.MustParsePrefix("::ffff:0:0/96"), "ipv4_mapped"},
	{netip.MustParsePrefix("64:ff9b::/96"), "nat64"},
	{netip.MustParsePrefix("2001:db8::/32"), "documentation"},
	{netip.MustParsePrefix("fc00::/7"), "private"},
	{netip.MustParsePrefix("fe80::/10"), "link_local"},
	{netip.MustParsePrefix("ff00::/8"), "multicast"},
}

// deniedReason names why addr may not be dialled, or returns "" if it may.
func deniedReason(addr netip.Addr) string {
	// A zoned or invalid address matches no prefix, so it would otherwise pass.
	if !addr.IsValid() || addr.Zone() != "" {
		return "invalid_address"
	}
	for _, d := range deniedRanges {
		if d.prefix.Contains(addr) {
			return d.reason
		}
	}
	return ""
}
