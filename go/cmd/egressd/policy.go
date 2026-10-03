package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Policy is the allowlist. A host no rule matches is refused.
type Policy struct {
	Rules []Rule `json:"rules"`
}

// Rule allows one host pattern, optionally on one port (design.md §7.2).
type Rule struct {
	Name  string `json:"name"`
	Allow string `json:"allow"`

	host string
	kind matchKind
	port uint16 // 0 allows any port egressd listens on
}

type matchKind int

const (
	exact     matchKind = iota
	oneLabel            // *.host: exactly one label in front of host
	manyLabel           // **.host: one or more labels in front of host
)

// Hosts where one name serves many tenants, so a hostname rule cannot tell
// them apart (egressd.md §4). Wildcards touching them are refused until
// inspect mode exists.
var sharedSuffixes = []string{
	"akamaized.net",
	"appspot.com",
	"azureedge.net",
	"cloudfront.net",
	"fastly.net",
	"githubusercontent.com",
	"herokuapp.com",
	"netlify.app",
	"pages.dev",
	"s3.amazonaws.com",
	"storage.googleapis.com",
	"vercel.app",
	"workers.dev",
}

// Hosts that separate tenants by path, so even an exact rule admits all of them.
var sharedByPath = []string{
	"raw.githubusercontent.com",
	"s3.amazonaws.com",
	"storage.googleapis.com",
}

func loadPolicy(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	// A misspelt key is a rule that silently does nothing; refuse it.
	decoder.DisallowUnknownFields()
	var p Policy
	if err := decoder.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range p.Rules {
		if err := p.Rules[i].compile(); err != nil {
			return nil, fmt.Errorf("%s: rule %d: %w", path, i, err)
		}
	}
	return &p, nil
}

func (r *Rule) compile() error {
	pattern := r.Allow
	if host, port, found := strings.Cut(pattern, ":"); found {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return fmt.Errorf("invalid port in %q", r.Allow)
		}
		pattern, r.port = host, uint16(n)
	}
	if rest, found := strings.CutPrefix(pattern, "**."); found {
		pattern, r.kind = rest, manyLabel
	} else if rest, found := strings.CutPrefix(pattern, "*."); found {
		pattern, r.kind = rest, oneLabel
	}
	host, err := normalise(pattern)
	if err != nil {
		return err
	}
	r.host = host
	if r.Name == "" {
		r.Name = r.Allow
	}
	return r.lint()
}

func (r *Rule) lint() error {
	if r.kind == exact {
		for _, shared := range sharedByPath {
			if r.host == shared {
				return fmt.Errorf("%q serves many tenants by path; a host rule cannot confine it", r.Allow)
			}
		}
		return nil
	}
	for _, shared := range sharedSuffixes {
		if within(r.host, shared) || within(shared, r.host) {
			return fmt.Errorf("%q spans the multi-tenant suffix %q", r.Allow, shared)
		}
	}
	return nil
}

// within reports whether host is name or a subdomain of it.
func within(host, name string) bool {
	return host == name || strings.HasSuffix(host, "."+name)
}

func (r *Rule) matches(host string, port uint16) bool {
	if r.port != 0 && port != 0 && r.port != port {
		return false
	}
	if r.kind == exact {
		return host == r.host
	}
	prefix, found := strings.CutSuffix(host, "."+r.host)
	if !found || prefix == "" {
		return false
	}
	return r.kind == manyLabel || !strings.Contains(prefix, ".")
}

// match returns the first rule allowing host on port, or nil. Port 0 asks
// whether any rule allows the host at all, which is the DNS question.
func (p *Policy) match(host string, port uint16) *Rule {
	for i := range p.Rules {
		if p.Rules[i].matches(host, port) {
			return &p.Rules[i]
		}
	}
	return nil
}

// ports lists every port egressd must listen on: 443 and each rule's own.
func (p *Policy) ports() []uint16 {
	ports := []uint16{443}
	for _, r := range p.Rules {
		if r.port != 0 && !slices.Contains(ports, r.port) {
			ports = append(ports, r.port)
		}
	}
	return ports
}

// normalise lowercases an ASCII host name and strips one trailing dot. It
// refuses anything else, including IP literals in any spelling: a final label
// that is all digits (127.0.0.1, 2130706433, 0x7f.1) is never a host name.
func normalise(name string) (string, error) {
	for i := 0; i < len(name); i++ {
		// Checked before lowercasing: some non-ASCII letters lowercase to ASCII.
		if name[i] >= 0x80 {
			return "", fmt.Errorf("host name %q is not ASCII", name)
		}
	}
	host := strings.ToLower(strings.TrimSuffix(name, "."))
	if host == "" || len(host) > 253 {
		return "", fmt.Errorf("invalid host name %q", name)
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !validLabel(label) {
			return "", fmt.Errorf("invalid host name %q", name)
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", fmt.Errorf("%q is an address, not a host name", name)
	}
	return host, nil
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
