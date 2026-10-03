package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"testing"
)

// clientHello captures the ClientHello crypto/tls sends for serverName.
func clientHello(t testing.TB, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		conn := tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: serverName == ""})
		_ = conn.Handshake() // fails once the pipe closes; only the first flight matters
	}()
	raw, _, err := readClientHello(server)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	server.Close()
	return raw
}

func TestReadClientHello(t *testing.T) {
	raw := clientHello(t, "pypi.org")
	got, sni, err := readClientHello(bytes.NewReader(raw))
	if err != nil || sni != "pypi.org" {
		t.Fatalf("sni = %q, err = %v", sni, err)
	}
	if !bytes.Equal(got, raw) {
		t.Error("returned bytes differ from the bytes read, so replay would corrupt the stream")
	}
}

func TestReadClientHelloWithoutSNI(t *testing.T) {
	_, sni, err := readClientHello(bytes.NewReader(clientHello(t, "")))
	if err != nil || sni != "" {
		t.Fatalf("sni = %q, err = %v", sni, err)
	}
}

// A ClientHello split across records is legal (RFC 8446 §5.1).
func TestReadClientHelloAcrossRecords(t *testing.T) {
	raw := clientHello(t, "files.pythonhosted.org")
	body := raw[5:]
	var split []byte
	for chunk := range slices.Chunk(body, 100) {
		split = append(split, recordHandshake, raw[1], raw[2], byte(len(chunk)>>8), byte(len(chunk)))
		split = append(split, chunk...)
	}
	got, sni, err := readClientHello(bytes.NewReader(split))
	if err != nil || sni != "files.pythonhosted.org" {
		t.Fatalf("sni = %q, err = %v", sni, err)
	}
	if !bytes.Equal(got, split) {
		t.Error("returned bytes differ from the records read")
	}
}

func TestReadClientHelloRefuses(t *testing.T) {
	raw := clientHello(t, "pypi.org")
	cases := map[string][]byte{
		"plain HTTP":       []byte("GET / HTTP/1.1\r\nHost: pypi.org\r\n\r\n"),
		"alert record":     {21, 3, 3, 0, 2, 2, 40},
		"empty record":     {recordHandshake, 3, 3, 0, 0},
		"oversized record": {recordHandshake, 3, 3, 0x40, 0x01},
		"server hello":     append([]byte{recordHandshake, 3, 3, 0, 4}, 2, 0, 0, 0),
	}
	for name, input := range cases {
		if _, _, err := readClientHello(bytes.NewReader(input)); !errors.Is(err, errNotClientHello) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, _, err := readClientHello(bytes.NewReader(raw[:len(raw)-1])); err == nil {
		t.Error("truncated ClientHello accepted")
	}
}

func FuzzParseClientHello(f *testing.F) {
	f.Add(clientHello(f, "pypi.org")[5:])
	f.Add(clientHello(f, "")[5:])
	f.Fuzz(func(t *testing.T, msg []byte) {
		sni, err := parseClientHello(msg)
		if err != nil && sni != "" {
			t.Errorf("returned %q alongside %v", sni, err)
		}
	})
}
