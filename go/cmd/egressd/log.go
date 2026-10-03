package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// logger writes the decision log (egressd.md §9): one JSON object per line.
type logger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func newLogger(w io.Writer) *logger {
	return &logger{enc: json.NewEncoder(w)}
}

func (l *logger) emit(event any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.enc.Encode(event); err != nil {
		// An unrecorded decision breaks the log's one guarantee; stop instead.
		fmt.Fprintln(os.Stderr, "egressd: decision log write failed:", err)
		os.Exit(1)
	}
}

func timestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// notice reports egressd's own state: start, config, error.
type notice struct {
	TS  string `json:"ts"`
	Ev  string `json:"ev"`
	Msg string `json:"msg"`
}

// source is common to every event about traffic.
type source struct {
	TS         string `json:"ts"`
	Ev         string `json:"ev"`
	SourceKind string `json:"source_kind"`
}

type dnsEvent struct {
	source
	QName    string  `json:"qname"`
	QType    string  `json:"qtype"`
	Answer   *string `json:"answer"`
	Decision string  `json:"decision"`
	Rule     string  `json:"rule"`
}

type connDecide struct {
	source
	ConnID   string  `json:"conn_id"`
	SrcIP    string  `json:"src_ip"`
	Policy   string  `json:"policy"`
	SNI      string  `json:"sni"`
	Port     uint16  `json:"port"`
	DialIP   *string `json:"dial_ip"`
	Decision string  `json:"decision"`
	Rule     string  `json:"rule"`
}

type connClose struct {
	source
	ConnID    string `json:"conn_id"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
	DurMs     int64  `json:"dur_ms"`
	Close     string `json:"close"`
}
