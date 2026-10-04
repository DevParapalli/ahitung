package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

var (
	sandboxIP = netip.MustParseAddr("10.89.0.2")
	workerIP  = netip.MustParseAddr("10.89.1.3")
)

// testServer builds a server over the given allow patterns whose decision
// log is returned for inspection. resolve and dial are left for each test.
func testServer(t *testing.T, patterns ...string) (*server, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	s := &server{
		answer: sandboxIP,
		worker: workerIP,
		log:    newLogger(&out),
		idle:   idleTimeout,
	}
	s.policy.Store(compiled(t, patterns...))
	return s, &out
}

// events decodes every logged line whose ev is kind.
func events(t *testing.T, out *bytes.Buffer, kind string) []map[string]any {
	t.Helper()
	var found []map[string]any
	for line := range strings.Lines(out.String()) {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if event["ev"] == kind {
			found = append(found, event)
		}
	}
	return found
}
