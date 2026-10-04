package main

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(name),
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

func reply(t *testing.T, packed []byte) dnsmessage.Message {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(packed); err != nil {
		t.Fatal(err)
	}
	if msg.ID != 7 || !msg.Response || len(msg.Questions) != 1 {
		t.Fatalf("malformed reply header: %+v", msg.Header)
	}
	return msg
}

func TestDNSAllowedNameResolvesToEgressd(t *testing.T) {
	s, out := testServer(t, "pypi.org")
	msg := reply(t, s.answerDNS(query(t, "PyPI.org.", dnsmessage.TypeA), netip.MustParseAddr("10.89.0.14")))
	if msg.RCode != dnsmessage.RCodeSuccess || len(msg.Answers) != 1 {
		t.Fatalf("rcode %v, %d answers", msg.RCode, len(msg.Answers))
	}
	if a := msg.Answers[0].Body.(*dnsmessage.AResource).A; netip.AddrFrom4(a) != sandboxIP {
		t.Errorf("answer %v, want egressd's own address", a)
	}
	logged := events(t, out, "dns")[0]
	if logged["decision"] != "allow" || logged["rule"] != "pypi.org" || logged["answer"] != "10.89.0.2" || logged["qtype"] != "A" {
		t.Errorf("logged %v", logged)
	}
}

func TestDNSNoDataForOtherTypes(t *testing.T) {
	s, _ := testServer(t, "pypi.org")
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeHTTPS, dnsmessage.TypeSVCB, dnsmessage.TypeTXT} {
		msg := reply(t, s.answerDNS(query(t, "pypi.org.", qtype), sandboxIP))
		if msg.RCode != dnsmessage.RCodeSuccess || len(msg.Answers) != 0 {
			t.Errorf("%v: rcode %v, %d answers; want NODATA", qtype, msg.RCode, len(msg.Answers))
		}
	}
}

func TestDNSRefused(t *testing.T) {
	s, out := testServer(t, "pypi.org")
	for name, rule := range map[string]string{
		"evil.example.":    "egress.deny.not_allowed",
		"a.pypi.org.":      "egress.deny.not_allowed",
		"169.254.169.254.": "egress.deny.invalid_name",
	} {
		out.Reset()
		msg := reply(t, s.answerDNS(query(t, name, dnsmessage.TypeA), sandboxIP))
		if msg.RCode != dnsmessage.RCodeRefused || len(msg.Answers) != 0 {
			t.Errorf("%s: rcode %v, %d answers", name, msg.RCode, len(msg.Answers))
		}
		if logged := events(t, out, "dns")[0]; logged["decision"] != "deny" || logged["rule"] != rule {
			t.Errorf("%s: logged %v", name, logged)
		}
	}
}

func TestDNSLabelsSourceKind(t *testing.T) {
	s, out := testServer(t, "pypi.org")
	s.answerDNS(query(t, "pypi.org.", dnsmessage.TypeA), netip.MustParseAddr("10.89.0.14"))
	s.answerDNS(query(t, "pypi.org.", dnsmessage.TypeA), workerIP)
	logged := events(t, out, "dns")
	if logged[0]["source_kind"] != "workspace" {
		t.Errorf("workspace query logged %v", logged[0])
	}
	if logged[1]["source_kind"] != "worker" {
		t.Errorf("worker query logged %v", logged[1])
	}
}

func TestDNSMalformed(t *testing.T) {
	s, _ := testServer(t, "pypi.org")
	if got := s.answerDNS([]byte{1, 2, 3}, sandboxIP); got != nil {
		t.Error("answered a packet with no header")
	}
	twoQuestions := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 7},
		Questions: []dnsmessage.Question{
			{Name: dnsmessage.MustNewName("pypi.org."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			{Name: dnsmessage.MustNewName("pypi.org."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		},
	}
	packed, err := twoQuestions.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(s.answerDNS(packed, sandboxIP)); err != nil || msg.RCode != dnsmessage.RCodeFormatError {
		t.Errorf("rcode %v, err %v; want FORMERR", msg.RCode, err)
	}
}
