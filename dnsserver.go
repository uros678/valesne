package main

import (
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsServer is a DNS server from the config that is queried directly
// (bypassing the system resolver and its cache).
type dnsServer struct {
	Name   string `toml:"name"`
	Server string `toml:"server"`
	Query  string `toml:"query"`
}

// The default query is the root zone (". NS"): every recursive DNS server can
// answer it, regardless of which domains it knows.
const defaultDNSQuery = "."

var rcodeText = map[dnsmessage.RCode]string{
	dnsmessage.RCodeSuccess:        "NOERROR",
	dnsmessage.RCodeFormatError:    "FORMERR",
	dnsmessage.RCodeServerFailure:  "SERVFAIL",
	dnsmessage.RCodeNameError:      "NXDOMAIN",
	dnsmessage.RCodeNotImplemented: "NOTIMP",
	dnsmessage.RCodeRefused:        "REFUSED",
}

func rcodeString(rc dnsmessage.RCode) string {
	if s, ok := rcodeText[rc]; ok {
		return s
	}
	return fmt.Sprintf("RCODE %d", rc)
}

// checkDNSServer sends a single UDP query directly to the server.
//   - NOERROR or NXDOMAIN: the server works (it answered the question properly)
//   - REFUSED, SERVFAIL ...: the server is alive but not working right (Warn)
//   - no answer: the server is unreachable
func checkDNSServer(server, query string, timeout time.Duration) probe {
	p := probe{CheckedAt: time.Now().Format(time.RFC3339)}

	name := query
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	qtype := dnsmessage.TypeA
	if name == "." {
		qtype = dnsmessage.TypeNS
	}

	id := uint16(rand.Uint32())
	req, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: qname, Type: qtype, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		p.Error = err.Error()
		return p
	}

	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		p.Error = shortNetError(err)
		return p
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	start := time.Now()
	if _, err := conn.Write(req); err != nil {
		p.Error = shortNetError(err)
		return p
	}

	buf := make([]byte, 4096)
	var resp dnsmessage.Message
	for {
		n, err := conn.Read(buf)
		if err != nil {
			// "timeout", or e.g. "connection refused" when nothing listens
			// on the port (instead of "read udp ...->...: recvfrom: ...").
			p.LatencyMS = time.Since(start).Milliseconds()
			p.Error = shortNetError(err)
			return p
		}
		// Skip foreign or malformed packets and keep waiting.
		if resp.Unpack(buf[:n]) == nil && resp.Header.ID == id && resp.Header.Response {
			break
		}
	}
	p.LatencyMS = time.Since(start).Milliseconds()

	rc := resp.Header.RCode
	switch rc {
	case dnsmessage.RCodeSuccess:
		p.OK = true
		p.Detail = "NOERROR · " + answerSummary(resp.Answers)
	case dnsmessage.RCodeNameError:
		p.OK = true
		p.Detail = "NXDOMAIN"
	default:
		p.Warn = true
		p.Error = rcodeString(rc)
	}
	return p
}

func answerSummary(answers []dnsmessage.Resource) string {
	for _, a := range answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			return net.IP(r.A[:]).String()
		}
	}
	switch len(answers) {
	case 0:
		return "no records"
	case 1:
		return "1 record"
	default:
		return fmt.Sprintf("%d records", len(answers))
	}
}
