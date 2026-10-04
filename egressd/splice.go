package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	helloTimeout   = 5 * time.Second // egressd.md §8
	resolveTimeout = 5 * time.Second
	dialTimeout    = 10 * time.Second
	alertTimeout   = 5 * time.Second
	dnsTCPTimeout  = 5 * time.Second
	// Matches the workspace idle stop. SSE and WebSocket idle legitimately,
	// so this is a backstop for abandoned connections, not a request timeout.
	idleTimeout = 15 * time.Minute
)

// unrecognizedName is a fatal TLS alert 112, the refusal for a denied SNI.
var unrecognizedName = []byte{21, 3, 3, 0, 2, 2, 112}

type server struct {
	policy atomic.Pointer[Policy]
	answer netip.Addr // egressd's address on the sandbox, returned for allowed names
	worker netip.Addr
	self   []netip.Addr // egressd's own addresses: traffic from them is the health check
	log    *logger
	idle   time.Duration

	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	dial    func(ctx context.Context, address string) (*net.TCPConn, error)

	connID atomic.Uint64
}

func (s *server) source(ev string, ip netip.Addr) source {
	kind := "workspace"
	switch {
	case ip == s.worker:
		kind = "worker"
	case slices.Contains(s.self, ip):
		kind = "self"
	}
	return source{TS: timestamp(), Ev: ev, SourceKind: kind}
}

// serveTLS splices every connection accepted on ln until ln fails.
func (s *server) serveTLS(ln *net.TCPListener, port uint16) error {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			return err
		}
		go s.splice(conn, port)
	}
}

// splice applies the policy to one connection and, if allowed, copies bytes
// between it and the checked upstream address (egressd.md §4).
func (s *server) splice(client *net.TCPConn, port uint16) {
	defer client.Close()
	started := time.Now()
	src := client.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
	decide := connDecide{
		source: s.source("conn", src),
		ConnID: fmt.Sprintf("c%d", s.connID.Add(1)),
		SrcIP:  src.String(),
		Policy: "splice",
		Port:   port,
	}

	upstream, hello, rule := s.decide(client, &decide)
	decide.Rule = rule
	s.log.emit(decide)
	if upstream == nil {
		return
	}
	defer upstream.Close()

	closed := connClose{source: decide.source, ConnID: decide.ConnID}
	if _, err := upstream.Write(hello); err != nil {
		closed.Close = "error"
	} else {
		closed.BytesUp, closed.BytesDown, closed.Close = pipe(client, upstream, s.idle)
		closed.BytesUp += int64(len(hello))
	}
	closed.TS = timestamp()
	closed.DurMs = time.Since(started).Milliseconds()
	s.log.emit(closed)
}

// decide reads the ClientHello, checks the SNI and every resolved address,
// and dials. It fills in decide and returns the rule name to log; upstream is
// nil when the connection is refused.
func (s *server) decide(client *net.TCPConn, decide *connDecide) (upstream *net.TCPConn, hello []byte, rule string) {
	decide.Decision = "deny"
	if err := client.SetReadDeadline(time.Now().Add(helloTimeout)); err != nil {
		return nil, nil, "egress.deny.no_client_hello"
	}
	hello, sni, err := readClientHello(client)
	if err != nil {
		// Not TLS, or too slow to say what it is: close without an alert.
		return nil, nil, "egress.deny.no_client_hello"
	}
	decide.SNI = sni
	if sni == "" {
		s.refuse(client)
		return nil, nil, "egress.deny.no_sni"
	}
	host, err := normalise(sni)
	if err != nil {
		s.refuse(client)
		return nil, nil, "egress.deny.invalid_name"
	}
	allowed := s.policy.Load().match(host, decide.Port)
	if allowed == nil {
		s.refuse(client)
		return nil, nil, "egress.deny.not_allowed"
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	addrs, err := s.resolve(ctx, host)
	cancel()
	if err != nil || len(addrs) == 0 {
		decide.Decision = "error"
		return nil, nil, "egress.error.resolve"
	}
	// Every address must pass: a name that resolves even partly inward is
	// refused outright rather than filtered, since rebinding can pick either.
	for _, addr := range addrs {
		if reason := deniedReason(addr); reason != "" {
			ip := addr.String()
			decide.DialIP = &ip
			s.refuse(client)
			return nil, nil, "egress.deny." + reason
		}
	}

	if err := client.SetReadDeadline(time.Time{}); err != nil {
		decide.Decision = "error"
		return nil, nil, "egress.error.client"
	}
	for _, addr := range addrs {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		conn, err := s.dial(ctx, netip.AddrPortFrom(addr, decide.Port).String())
		cancel()
		if err == nil {
			ip := addr.String()
			decide.DialIP = &ip
			decide.Decision = "allow"
			return conn, hello, allowed.Name
		}
	}
	decide.Decision = "error"
	return nil, nil, "egress.error.dial"
}

// refuse sends the unrecognized_name alert; the caller closes the connection.
func (s *server) refuse(client net.Conn) {
	if err := client.SetWriteDeadline(time.Now().Add(alertTimeout)); err == nil {
		// The client may already be gone; the decision is logged either way.
		_, _ = client.Write(unrecognizedName)
	}
}

// pipe copies both directions until both have ended or the connection has
// carried no bytes either way for idle. A direction ending cleanly half-closes
// the other side, so request-then-response protocols still complete.
func pipe(client, upstream *net.TCPConn, idle time.Duration) (up, down int64, reason string) {
	var lastActive atomic.Int64
	lastActive.Store(time.Now().UnixNano())
	var idled atomic.Bool
	closeBoth := func() {
		client.Close()
		upstream.Close()
	}

	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(idle / 4)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, lastActive.Load())) > idle {
					idled.Store(true)
					closeBoth()
					return
				}
			}
		}
	}()

	var failed atomic.Bool
	run := func(dst, src *net.TCPConn, n *int64) {
		var err error
		*n, err = copyActive(dst, src, &lastActive)
		if err != nil {
			failed.Store(true)
			closeBoth()
			return
		}
		_ = dst.CloseWrite()
	}
	var wg sync.WaitGroup
	wg.Go(func() { run(upstream, client, &up) })
	wg.Go(func() { run(client, upstream, &down) })
	wg.Wait()
	close(done)

	switch {
	case idled.Load():
		return up, down, "idle"
	case failed.Load():
		return up, down, "error"
	default:
		return up, down, "eof"
	}
}

func copyActive(dst io.Writer, src io.Reader, lastActive *atomic.Int64) (int64, error) {
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			lastActive.Store(time.Now().UnixNano())
			written, werr := dst.Write(buf[:n])
			total += int64(written)
			if werr != nil {
				return total, werr
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}
