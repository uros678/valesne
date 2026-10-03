package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// closedAddr returns a local address that nothing listens on.
func closedAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// TestShortErrors: HTTP and DNS server checks show short error texts like
// Docker and certificates, not "Get \"http://...\": dial tcp ...".
func TestShortErrors(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer slow.Close()

	check := func(name, got, want string) {
		t.Helper()
		// Windows words system errors differently ("actively refused"), so
		// only the key word is checked, and that no raw prefix is left.
		if !strings.Contains(got, want) || strings.Contains(got, "Get ") || strings.Contains(got, "dial ") || strings.Contains(got, "read udp") {
			t.Errorf("%s: got %q, want a short text with %q", name, got, want)
		}
	}
	http := func(url string) string {
		return checkHTTP(target{URL: url, okRanges: []statusRange{{200, 399}}}, 300*time.Millisecond).Error
	}
	check("HTTP refused", http("http://"+closedAddr(t)+"/"), "refused")
	check("HTTP timeout", http(slow.URL), "timeout")
	check("HTTP unknown host", http("http://no-such-host.invalid/"), "DNS: ")

	// A DNS server that never answers.
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	p := checkDNSServer(silent.LocalAddr().String(), ".", 300*time.Millisecond)
	if p.Error != "timeout" {
		t.Errorf("DNS server timeout: got %q", p.Error)
	}
}
