package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsTTL is short so a policy reload takes effect in clients quickly.
const dnsTTL = 30

// answerDNS answers one query (egressd.md §2). An allowed name resolves to
// egressd itself; everything else is REFUSED. It returns nil for a packet
// too malformed to answer.
func (s *server) answerDNS(query []byte, src netip.Addr) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil || header.Response {
		return nil
	}
	reply := dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		OpCode:             header.OpCode,
		RecursionDesired:   header.RecursionDesired,
		RecursionAvailable: true,
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || header.OpCode != 0 {
		reply.RCode = dnsmessage.RCodeFormatError
		return s.buildReply(reply, nil, nil)
	}
	q := questions[0]

	event := dnsEvent{
		source:   s.source("dns", src),
		QName:    q.Name.String(),
		QType:    q.Type.String(),
		Decision: "deny",
	}
	var answer *dnsmessage.AResource
	host, err := normalise(q.Name.String())
	var rule *Rule
	if err == nil {
		rule = s.policy.Load().match(host, 0)
	}
	switch {
	case err != nil:
		event.Rule = "egress.deny.invalid_name"
		reply.RCode = dnsmessage.RCodeRefused
	case rule == nil || q.Class != dnsmessage.ClassINET:
		event.Rule = "egress.deny.not_allowed"
		reply.RCode = dnsmessage.RCodeRefused
	case q.Type == dnsmessage.TypeA:
		ip := s.answer.String()
		event.Decision, event.Rule, event.Answer = "allow", rule.Name, &ip
		answer = &dnsmessage.AResource{A: s.answer.As4()}
	default:
		// AAAA, HTTPS, and the rest get NODATA. Withholding HTTPS records
		// keeps ECH configs from clients, so the SNI stays readable.
		event.Decision, event.Rule = "allow", rule.Name
	}
	s.log.emit(event)
	return s.buildReply(reply, &q, answer)
}

func (s *server) buildReply(header dnsmessage.Header, q *dnsmessage.Question, a *dnsmessage.AResource) []byte {
	msg, err := encodeReply(header, q, a)
	if err != nil {
		s.log.emit(notice{TS: timestamp(), Ev: "error", Msg: "dns reply: " + err.Error()})
		return nil
	}
	return msg
}

func encodeReply(header dnsmessage.Header, q *dnsmessage.Question, a *dnsmessage.AResource) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, header)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if q != nil {
		if err := b.Question(*q); err != nil {
			return nil, err
		}
	}
	if a != nil {
		if err := b.StartAnswers(); err != nil {
			return nil, err
		}
		rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: dnsTTL}
		if err := b.AResource(rh, *a); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// serveDNSUDP answers queries on a UDP socket until it fails.
func (s *server) serveDNSUDP(conn *net.UDPConn) error {
	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		if reply := s.answerDNS(buf[:n], from.Addr().Unmap()); reply != nil {
			if _, err := conn.WriteToUDPAddrPort(reply, from); err != nil {
				return err
			}
		}
	}
}

// serveDNSTCP answers length-prefixed queries on each accepted connection.
func (s *server) serveDNSTCP(ln *net.TCPListener) error {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			return err
		}
		go s.dnsTCPConn(conn)
	}
}

func (s *server) dnsTCPConn(conn *net.TCPConn) {
	defer conn.Close()
	src := conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
	for {
		if err := conn.SetDeadline(time.Now().Add(dnsTCPTimeout)); err != nil {
			return
		}
		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			return
		}
		query := make([]byte, length)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		reply := s.answerDNS(query, src)
		if reply == nil {
			return
		}
		if err := binary.Write(conn, binary.BigEndian, uint16(len(reply))); err != nil {
			return
		}
		if _, err := conn.Write(reply); err != nil {
			return
		}
	}
}
