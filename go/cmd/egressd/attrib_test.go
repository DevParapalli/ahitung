package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeAttribution(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAttribution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attribution.json")
	a := &attribution{path: path}
	ip := netip.MustParseAddr("10.89.0.14")

	if wsid, err := a.lookup(ip); wsid != nil || err != nil {
		t.Fatalf("missing file: %v, %v", wsid, err)
	}

	writeAttribution(t, path, `{"10.89.0.14": "ws-1"}`)
	if wsid, err := a.lookup(ip); err != nil || wsid == nil || *wsid != "ws-1" {
		t.Fatalf("first map: %v, %v", wsid, err)
	}

	writeAttribution(t, path, `{"10.89.0.14": "ws-2"}`)
	// Force a distinct mtime: two writes can land in the same clock tick.
	later := time.Now().Add(time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if wsid, _ := a.lookup(ip); wsid == nil || *wsid != "ws-2" {
		t.Fatalf("rewritten map not picked up: %v", wsid)
	}

	writeAttribution(t, path, `{"not an ip": "ws-3"}`)
	evenLater := later.Add(time.Second)
	if err := os.Chtimes(path, evenLater, evenLater); err != nil {
		t.Fatal(err)
	}
	if _, err := a.lookup(ip); err == nil {
		t.Fatal("malformed map accepted")
	}
}
