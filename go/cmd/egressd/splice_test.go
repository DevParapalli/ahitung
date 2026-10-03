package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// spliceOnce accepts one connection on a local port and splices it. done
// closes when the splice, and so its logging, has finished.
func spliceOnce(t *testing.T, s *server) (addr string, port uint16, done chan struct{}) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done = make(chan struct{})
	port = uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		defer close(done)
		conn, err := ln.AcceptTCP()
		ln.Close()
		if err == nil {
			s.splice(conn, port)
		}
	}()
	return ln.Addr().String(), port, done
}

func wait(t *testing.T, done chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("splice did not finish")
	}
}

// resolveTo answers every lookup with addrs and counts the lookups.
func resolveTo(calls *int, addrs ...string) func(context.Context, string) ([]netip.Addr, error) {
	return func(context.Context, string) ([]netip.Addr, error) {
		*calls++
		var parsed []netip.Addr
		for _, a := range addrs {
			parsed = append(parsed, netip.MustParseAddr(a))
		}
		return parsed, nil
	}
}

// dialInstead connects to target whatever address egressd asks for, and
// records the address asked for.
func dialInstead(target string, dialled *[]string) func(context.Context, string) (*net.TCPConn, error) {
	return func(ctx context.Context, address string) (*net.TCPConn, error) {
		*dialled = append(*dialled, address)
		return dialTCP(ctx, target)
	}
}

func TestSpliceAllowed(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello through egressd")
	}))
	defer upstream.Close()

	s, out := testServer(t, "example.com")
	var lookups int
	var dialled []string
	s.resolve = resolveTo(&lookups, "8.8.8.8")
	s.dial = dialInstead(upstream.Listener.Addr().String(), &dialled)
	addr, port, done := spliceOnce(t, s)

	// The client trusts only the upstream's certificate, so success proves the
	// TLS session is end to end and egressd terminated nothing.
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
	resp, err := client.Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	client.CloseIdleConnections()
	if err != nil || string(body) != "hello through egressd" {
		t.Fatalf("body %q, err %v", body, err)
	}
	wait(t, done)

	want := fmt.Sprintf("8.8.8.8:%d", port)
	if lookups != 1 || len(dialled) != 1 || dialled[0] != want {
		t.Errorf("lookups %d, dialled %v; want one lookup and %s", lookups, dialled, want)
	}
	decided := events(t, out, "conn")[0]
	if decided["decision"] != "allow" || decided["rule"] != "example.com" || decided["sni"] != "example.com" || decided["dial_ip"] != "8.8.8.8" {
		t.Errorf("decision logged %v", decided)
	}
	closed := events(t, out, "conn")[1]
	if closed["close"] != "eof" || closed["bytes_up"].(float64) == 0 || closed["bytes_down"].(float64) == 0 {
		t.Errorf("close logged %v", closed)
	}
}

func TestSpliceDeniedHost(t *testing.T) {
	s, out := testServer(t, "pypi.org")
	var lookups int
	var dialled []string
	s.resolve = resolveTo(&lookups, "8.8.8.8")
	s.dial = dialInstead("127.0.0.1:1", &dialled)
	addr, _, done := spliceOnce(t, s)

	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "example.com"})
	if err == nil {
		conn.Close()
		t.Fatal("handshake succeeded for a host not on the allowlist")
	}
	if !strings.Contains(err.Error(), "unrecognized name") {
		t.Errorf("err = %v, want the unrecognized_name alert", err)
	}
	wait(t, done)

	if lookups != 0 || len(dialled) != 0 {
		t.Errorf("denied host was resolved %d times and dialled %v", lookups, dialled)
	}
	if decided := events(t, out, "conn")[0]; decided["decision"] != "deny" || decided["rule"] != "egress.deny.not_allowed" {
		t.Errorf("logged %v", decided)
	}
}

// DNS rebinding: an allowed name resolving even partly inward is refused, and
// nothing is dialled, so no second lookup can pick a different address.
func TestSpliceRefusesInwardResolution(t *testing.T) {
	s, out := testServer(t, "example.com")
	var lookups int
	var dialled []string
	s.resolve = resolveTo(&lookups, "8.8.8.8", "169.254.169.254")
	s.dial = dialInstead("127.0.0.1:1", &dialled)
	addr, _, done := spliceOnce(t, s)

	if _, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "example.com"}); err == nil {
		t.Fatal("handshake succeeded")
	}
	wait(t, done)

	if lookups != 1 || len(dialled) != 0 {
		t.Errorf("lookups %d, dialled %v", lookups, dialled)
	}
	decided := events(t, out, "conn")[0]
	if decided["decision"] != "deny" || decided["rule"] != "egress.deny.link_local" || decided["dial_ip"] != "169.254.169.254" {
		t.Errorf("logged %v", decided)
	}
}

func TestSpliceRefusesPlainHTTP(t *testing.T) {
	s, out := testServer(t, "example.com")
	addr, _, done := spliceOnce(t, s)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if n, _ := conn.Read(make([]byte, 1)); n != 0 {
		t.Error("plain HTTP got a response")
	}
	wait(t, done)

	if decided := events(t, out, "conn")[0]; decided["rule"] != "egress.deny.no_client_hello" {
		t.Errorf("logged %v", decided)
	}
}

func TestSpliceClientHelloTimeout(t *testing.T) {
	t.Parallel()
	s, out := testServer(t, "example.com")
	addr, _, done := spliceOnce(t, s)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	started := time.Now()
	wait(t, done)

	if elapsed := time.Since(started); elapsed < helloTimeout-time.Second {
		t.Errorf("silent client dropped after %v", elapsed)
	}
	if decided := events(t, out, "conn")[0]; decided["rule"] != "egress.deny.no_client_hello" {
		t.Errorf("logged %v", decided)
	}
}

func TestSpliceClosesIdleConnection(t *testing.T) {
	upstream, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(io.Discard, conn) // reads the replayed hello, then waits
		}
	}()

	s, out := testServer(t, "example.com")
	s.idle = 200 * time.Millisecond
	var lookups int
	var dialled []string
	s.resolve = resolveTo(&lookups, "8.8.8.8")
	s.dial = dialInstead(upstream.Addr().String(), &dialled)
	addr, _, done := spliceOnce(t, s)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(clientHello(t, "example.com")); err != nil {
		t.Fatal(err)
	}
	wait(t, done)

	if closed := events(t, out, "conn")[1]; closed["close"] != "idle" {
		t.Errorf("logged %v", closed)
	}
}
