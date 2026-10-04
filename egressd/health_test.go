package main

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestHealthcheckPassesAgainstServingListeners(t *testing.T) {
	s, out := testServer(t, "pypi.org")
	s.self = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		_ = s.serveDNSUDP(udp)
		close(served)
	}()
	tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()

	dns := udp.LocalAddr().(*net.UDPAddr).AddrPort()
	tls := tcp.Addr().(*net.TCPAddr).AddrPort()
	if err := healthcheck(dns, tls); err != nil {
		t.Fatal(err)
	}
	// The DNS goroutine wrote the log; wait for it before reading.
	udp.Close()
	<-served
	if logged := events(t, out, "dns")[0]; logged["source_kind"] != "self" {
		t.Errorf("probe logged as %v", logged["source_kind"])
	}
}

func TestHealthcheckFailsWithoutListeners(t *testing.T) {
	closed := netip.MustParseAddrPort("127.0.0.1:1")
	if err := healthcheck(closed, closed); err == nil {
		t.Fatal("healthcheck passed with nothing listening")
	}
}

func TestProbeRejectsAReplyToAnotherQuery(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 512)
		_, from, err := udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		stray := dnsmessage.Message{Header: dnsmessage.Header{ID: probeID + 1, Response: true}}
		packed, _ := stray.Pack()
		_, _ = udp.WriteToUDPAddrPort(packed, from)
	}()
	if err := probeDNS(udp.LocalAddr().(*net.UDPAddr).AddrPort()); err == nil {
		t.Fatal("accepted a reply with the wrong ID")
	}
}
