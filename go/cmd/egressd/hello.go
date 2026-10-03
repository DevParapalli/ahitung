package main

import (
	"errors"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

const (
	recordHandshake    = 22
	handshakeHello     = 1
	extensionSNI       = 0
	maxRecordLength    = 16384    // RFC 8446 §5.1
	maxClientHelloSize = 64 << 10 // far above any real ClientHello
)

var errNotClientHello = errors.New("not a TLS ClientHello")

// readClientHello reads the records carrying the ClientHello and returns
// them verbatim, for replay upstream, with the SNI host name ("" if absent).
// A ClientHello may span several records, so records are read until the
// handshake message is complete.
func readClientHello(r io.Reader) (raw []byte, sni string, err error) {
	var handshake []byte
	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(r, header); err != nil {
			return nil, "", err
		}
		length := int(header[3])<<8 | int(header[4])
		if header[0] != recordHandshake || length == 0 || length > maxRecordLength {
			return nil, "", errNotClientHello
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, "", err
		}
		raw = append(append(raw, header...), body...)
		handshake = append(handshake, body...)

		if len(handshake) < 4 {
			continue
		}
		size := 4 + (int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3]))
		if handshake[0] != handshakeHello || size > maxClientHelloSize {
			return nil, "", errNotClientHello
		}
		if len(handshake) >= size {
			sni, err := parseClientHello(handshake[:size])
			return raw, sni, err
		}
	}
}

// parseClientHello extracts the first host_name from the server_name
// extension of a ClientHello handshake message (RFC 8446 §4.1.2, RFC 6066 §3).
func parseClientHello(msg []byte) (string, error) {
	s := cryptobyte.String(msg)
	var msgType uint8
	var body cryptobyte.String
	if !s.ReadUint8(&msgType) || msgType != handshakeHello || !s.ReadUint24LengthPrefixed(&body) || !s.Empty() {
		return "", errNotClientHello
	}
	var sessionID, cipherSuites, compression cryptobyte.String
	if !body.Skip(2+32) || // legacy_version, random
		!body.ReadUint8LengthPrefixed(&sessionID) ||
		!body.ReadUint16LengthPrefixed(&cipherSuites) ||
		!body.ReadUint8LengthPrefixed(&compression) {
		return "", errNotClientHello
	}
	if body.Empty() {
		return "", nil
	}
	var extensions cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&extensions) || !body.Empty() {
		return "", errNotClientHello
	}
	for !extensions.Empty() {
		var extType uint16
		var ext cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&ext) {
			return "", errNotClientHello
		}
		if extType != extensionSNI {
			continue
		}
		var names cryptobyte.String
		if !ext.ReadUint16LengthPrefixed(&names) || !ext.Empty() {
			return "", errNotClientHello
		}
		for !names.Empty() {
			var nameType uint8
			var name cryptobyte.String
			if !names.ReadUint8(&nameType) || !names.ReadUint16LengthPrefixed(&name) {
				return "", errNotClientHello
			}
			if nameType == 0 {
				return string(name), nil
			}
		}
	}
	return "", nil
}
