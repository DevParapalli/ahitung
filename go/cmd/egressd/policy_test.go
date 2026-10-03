package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func compiled(t *testing.T, patterns ...string) *Policy {
	t.Helper()
	p := &Policy{}
	for _, pattern := range patterns {
		r := Rule{Allow: pattern}
		if err := r.compile(); err != nil {
			t.Fatalf("compile %q: %v", pattern, err)
		}
		p.Rules = append(p.Rules, r)
	}
	return p
}

func TestWildcardMatrix(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "a.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "a.b.c.d.example.com", false},
		{"**.example.com", "example.com", false},
		{"**.example.com", "a.example.com", true},
		{"**.example.com", "a.b.example.com", true},
		{"**.example.com", "a.b.c.d.example.com", true},
		{"*.example.com", "aexample.com", false},
		{"**.example.com", "evil-example.com", false},
		{"Example.COM.", "example.com", true},
	}
	for _, c := range cases {
		if got := compiled(t, c.pattern).match(c.host, 443) != nil; got != c.want {
			t.Errorf("%q matching %q = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestPorts(t *testing.T) {
	p := compiled(t, "scm.parapalli.dev:8008", "pypi.org")
	if p.match("scm.parapalli.dev", 8008) == nil {
		t.Error("host:port rule refused its own port")
	}
	if p.match("scm.parapalli.dev", 8001) != nil {
		t.Error("host:port rule allowed another port")
	}
	if p.match("scm.parapalli.dev", 443) != nil {
		t.Error("host:port rule allowed 443")
	}
	if p.match("pypi.org", 8008) == nil {
		t.Error("bare host refused a listened port")
	}
	if p.match("scm.parapalli.dev", 0) == nil {
		t.Error("DNS question refused a host allowed on some port")
	}
	if got := p.ports(); !slices.Equal(got, []uint16{443, 8008}) {
		t.Errorf("ports = %v", got)
	}
}

func TestFirstMatchingRuleNamesTheDecision(t *testing.T) {
	p := compiled(t, "**.example.com", "a.example.com")
	if got := p.match("a.example.com", 443).Name; got != "**.example.com" {
		t.Errorf("rule = %q", got)
	}
}

func TestNormaliseRefuses(t *testing.T) {
	for _, name := range []string{
		"",
		".",
		"exa mple.com",
		"under_score.com",
		"-lead.com",
		"trail-.com",
		"a..com",
		"münchen.de",
		"Kelvin.com", // KELVIN SIGN lowercases to ASCII "k"
		"127.0.0.1",
		"2130706433",
		"0x7f.1",
		"017700000001",
		"[::1]",
	} {
		if host, err := normalise(name); err == nil {
			t.Errorf("normalise(%q) = %q, want error", name, host)
		}
	}
}

func TestNormaliseAccepts(t *testing.T) {
	for name, want := range map[string]string{
		"PyPI.org.":         "pypi.org",
		"xn--mnchen-3ya.de": "xn--mnchen-3ya.de",
		"a-b.c0m":           "a-b.c0m",
	} {
		if got, err := normalise(name); err != nil || got != want {
			t.Errorf("normalise(%q) = %q, %v; want %q", name, got, err, want)
		}
	}
}

func TestLintRefusesSharedHosts(t *testing.T) {
	for _, pattern := range []string{
		"*.cloudfront.net",
		"**.s3.amazonaws.com",
		"*.amazonaws.com", // one label in front of it is s3.amazonaws.com itself
		"**.net",
		"raw.githubusercontent.com",
		"storage.googleapis.com",
	} {
		r := Rule{Allow: pattern}
		if err := r.compile(); err == nil {
			t.Errorf("%q passed the lint", pattern)
		}
	}
	for _, pattern := range []string{"d111111abcdef8.cloudfront.net", "**.github.com"} {
		r := Rule{Allow: pattern}
		if err := r.compile(); err != nil {
			t.Errorf("%q refused: %v", pattern, err)
		}
	}
}

func TestLoadPolicy(t *testing.T) {
	write := func(body string) string {
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	p, err := loadPolicy(write(`{"rules": [{"allow": "pypi.org", "name": "python"}, {"allow": "x.dev:8443"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Rules[0].Name != "python" || p.Rules[1].Name != "x.dev:8443" {
		t.Errorf("names = %q, %q", p.Rules[0].Name, p.Rules[1].Name)
	}

	for _, body := range []string{
		`{"rules": [{"allow": "pypi.org", "inspect": true}]}`,
		`{"rule": []}`,
		`{"rules": [{"allow": "x.dev:0"}]}`,
		`{"rules": [{"allow": "x.dev:65536"}]}`,
		`{"rules": [{"allow": "x.dev:+443"}]}`,
		`{"rules": [{"allow": "10.0.0.1"}]}`,
		`not json`,
	} {
		if _, err := loadPolicy(write(body)); err == nil {
			t.Errorf("loaded %s", body)
		}
	}
}
