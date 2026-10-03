package main

import (
	"net/netip"
	"testing"
)

func TestDeniedRanges(t *testing.T) {
	for addr, want := range map[string]string{
		"0.0.0.0":                 "this_network",
		"10.1.2.3":                "private",
		"100.64.0.1":              "shared_address",
		"127.0.0.1":               "loopback",
		"169.254.169.254":         "link_local",
		"172.16.0.1":              "private",
		"172.31.255.255":          "private",
		"192.0.0.8":               "protocol_assignment",
		"192.0.2.1":               "documentation",
		"192.168.1.1":             "private",
		"198.18.0.1":              "benchmark",
		"198.51.100.1":            "documentation",
		"203.0.113.7":             "documentation",
		"224.0.0.1":               "multicast",
		"240.0.0.1":               "reserved",
		"255.255.255.255":         "reserved",
		"::":                      "unspecified",
		"::1":                     "loopback",
		"::ffff:10.0.0.1":         "ipv4_mapped",
		"::ffff:8.8.8.8":          "ipv4_mapped",
		"64:ff9b::a9fe:a9fe":      "nat64",
		"2001:db8::1":             "documentation",
		"fc00::1":                 "private",
		"fd00::1":                 "private",
		"fe80::1":                 "link_local",
		"ff02::1":                 "multicast",
		"8.8.8.8":                 "",
		"172.32.0.1":              "",
		"151.101.0.223":           "",
		"2606:4700:10::ac42:9ded": "",
	} {
		if got := deniedReason(netip.MustParseAddr(addr)); got != want {
			t.Errorf("deniedReason(%s) = %q, want %q", addr, got, want)
		}
	}
}

func TestDeniedRefusesUncheckableAddresses(t *testing.T) {
	if got := deniedReason(netip.Addr{}); got != "invalid_address" {
		t.Errorf("zero Addr = %q", got)
	}
	if got := deniedReason(netip.MustParseAddr("2606:4700::1%eth0")); got != "invalid_address" {
		t.Errorf("zoned address = %q", got)
	}
}
