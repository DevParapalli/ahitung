package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"sync"
	"time"
)

// attribution maps a workspace container IP to its wsid, from a JSON object
// the executor writes (egressd.md §7). It labels log events only; policy is
// never selected by it, because model code can influence its own source.
type attribution struct {
	path string

	mu    sync.Mutex
	mtime time.Time
	byIP  map[netip.Addr]string
}

// lookup returns the wsid for ip, or nil. The file is re-read when its
// modification time changes, so the executor needs no signal to update it.
func (a *attribution) lookup(ip netip.Addr) (*string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	info, err := os.Stat(a.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// No file yet means the executor has started no workspace.
		a.byIP, a.mtime = nil, time.Time{}
	case err != nil:
		return nil, err
	case !info.ModTime().Equal(a.mtime):
		byIP, err := readAttribution(a.path)
		if err != nil {
			return nil, err
		}
		a.byIP, a.mtime = byIP, info.ModTime()
	}
	if wsid, found := a.byIP[ip]; found {
		return &wsid, nil
	}
	return nil, nil
}

func readAttribution(path string) (map[netip.Addr]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	byIP := make(map[netip.Addr]string, len(raw))
	for ip, wsid := range raw {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		byIP[addr] = wsid
	}
	return byIP, nil
}
