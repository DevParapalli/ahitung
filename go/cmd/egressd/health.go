package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// healthTimeout bounds each probe, below Podman's own healthcheck timeout.
const healthTimeout = 2 * time.Second

const probeID = 0xe9d5

// healthcheck probes a running egressd's DNS and TLS listeners. The scratch
// image has no shell, so Podman's HealthCmd runs the binary itself in this
// mode; a nil error means both listeners are serving.
func healthcheck(dns, tls netip.AddrPort) error {
	if err := probeDNS(dns); err != nil {
		return fmt.Errorf("dns %s: %w", dns, err)
	}
	conn, err := net.DialTimeout("tcp", tls.String(), healthTimeout)
	if err != nil {
		return fmt.Errorf("tls %s: %w", tls, err)
	}
	return conn.Close()
}

// probeDNS sends one query and accepts any reply to it. REFUSED proves the
// server is answering as well as an answer would.
func probeDNS(at netip.AddrPort) error {
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(at))
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(healthTimeout)); err != nil {
		return err
	}

	query := dnsmessage.Message{
		Header: dnsmessage.Header{ID: probeID},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName("healthcheck.invalid."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := query.Pack()
	if err != nil {
		return err
	}
	if _, err := conn.Write(packed); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(buf[:n])
	if err != nil {
		return err
	}
	if !header.Response || header.ID != probeID {
		return errors.New("reply does not answer the probe")
	}
	return nil
}
