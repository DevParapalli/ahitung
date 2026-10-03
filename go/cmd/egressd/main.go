// Command egressd is the only path from ahitung containers to the internet
// (egressd.md). It answers DNS for workspaces and splices TLS connections to
// allowlisted hosts, refusing everything else.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

type config struct {
	policy string
	listen []netip.Addr
	answer netip.Addr
	worker netip.Addr
}

func main() {
	healthcheckMode := flag.Bool("healthcheck", false, "probe the running egressd's listeners and exit")
	flag.Parse()
	run := serve
	if *healthcheckMode {
		run = probe
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "egressd:", err)
		os.Exit(1)
	}
}

func probe() error {
	cfg, err := configFromEnv()
	if err != nil {
		return err
	}
	at := cfg.listen[0]
	return healthcheck(netip.AddrPortFrom(at, 53), netip.AddrPortFrom(at, 443))
}

func serve() error {
	cfg, err := configFromEnv()
	if err != nil {
		return err
	}
	policy, err := loadPolicy(cfg.policy)
	if err != nil {
		return err
	}
	s := &server{
		answer:  cfg.answer,
		worker:  cfg.worker,
		self:    cfg.listen,
		log:     newLogger(os.Stdout),
		idle:    idleTimeout,
		resolve: lookup,
		dial:    dialTCP,
	}
	s.policy.Store(policy)

	l := &listeners{server: s, ips: cfg.listen, open: map[netip.AddrPort]bool{}, errs: make(chan error)}
	if err := l.openDNS(); err != nil {
		return err
	}
	if err := l.openTLS(policy.ports()); err != nil {
		return err
	}
	s.log.emit(notice{TS: timestamp(), Ev: "start", Msg: fmt.Sprintf("listening on %v, %d rules", cfg.listen, len(policy.Rules))})

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case err := <-l.errs:
			return err
		case sig := <-signals:
			if sig != syscall.SIGHUP {
				return nil
			}
			l.reload(cfg.policy)
		}
	}
}

func configFromEnv() (config, error) {
	cfg := config{policy: os.Getenv("EGRESSD_POLICY")}
	if cfg.policy == "" {
		return cfg, errors.New("EGRESSD_POLICY must be set")
	}
	var err error
	if cfg.answer, err = ipv4FromEnv("EGRESSD_DNS_ANSWER"); err != nil {
		return cfg, err
	}
	if cfg.worker, err = ipv4FromEnv("EGRESSD_WORKER_IP"); err != nil {
		return cfg, err
	}
	for field := range strings.SplitSeq(os.Getenv("EGRESSD_LISTEN"), ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(field))
		if err != nil {
			return cfg, fmt.Errorf("EGRESSD_LISTEN: %w", err)
		}
		cfg.listen = append(cfg.listen, addr)
	}
	return cfg, nil
}

func ipv4FromEnv(name string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(os.Getenv(name))
	if err != nil {
		return addr, fmt.Errorf("%s: %w", name, err)
	}
	if !addr.Is4() {
		return addr, fmt.Errorf("%s: %s is not an IPv4 address", name, addr)
	}
	return addr, nil
}

func lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func dialTCP(ctx context.Context, address string) (*net.TCPConn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

// listeners owns every socket egressd serves. TLS ports can grow on reload
// when a new host:port rule appears; they never shrink, since a port with no
// matching rule refuses every connection anyway.
type listeners struct {
	server *server
	ips    []netip.Addr
	open   map[netip.AddrPort]bool
	errs   chan error
}

func (l *listeners) openDNS() error {
	for _, ip := range l.ips {
		at := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 53))
		udp, err := net.ListenUDP("udp", at)
		if err != nil {
			return err
		}
		tcp, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, 53)))
		if err != nil {
			return err
		}
		go func() { l.errs <- l.server.serveDNSUDP(udp) }()
		go func() { l.errs <- l.server.serveDNSTCP(tcp) }()
	}
	return nil
}

func (l *listeners) openTLS(ports []uint16) error {
	for _, port := range ports {
		for _, ip := range l.ips {
			at := netip.AddrPortFrom(ip, port)
			if l.open[at] {
				continue
			}
			ln, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(at))
			if err != nil {
				return err
			}
			l.open[at] = true
			go func() { l.errs <- l.server.serveTLS(ln, port) }()
		}
	}
	return nil
}

// reload swaps in a new policy on SIGHUP. A policy that fails to load or
// needs a port that cannot be opened is refused, and the old one stays.
func (l *listeners) reload(path string) {
	policy, err := loadPolicy(path)
	if err == nil {
		err = l.openTLS(policy.ports())
	}
	if err != nil {
		l.server.log.emit(notice{TS: timestamp(), Ev: "config", Msg: "reload refused, previous policy kept: " + err.Error()})
		return
	}
	l.server.policy.Store(policy)
	l.server.log.emit(notice{TS: timestamp(), Ev: "config", Msg: fmt.Sprintf("reloaded, %d rules", len(policy.Rules))})
}
