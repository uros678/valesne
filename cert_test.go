package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// serveCert starts a TLS server with a certificate for host, signed by a test
// CA, valid from now+from to now+to. It returns the address and the CA pool.
func serveCert(t *testing.T, host string, from, to time.Duration) (string, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.Add(-1000 * 24 * time.Hour),
		NotAfter:              now.Add(1000 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(from),
		NotAfter:     now.Add(to),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return ln.Addr().String(), pool
}

func TestCheckCert(t *testing.T) {
	const day = 24 * time.Hour
	cases := []struct {
		name     string
		certHost string // name on the certificate
		checkAs  string // host in the config
		from, to time.Duration
		want     string // OK, WARN or FAIL
		text     string // part of the detail or error
		expiry   bool   // WARN/FAIL from the expiry (alerts)
	}{
		{"90-day cert, 60 days left", "example.test", "example.test", -30 * day, 60 * day, "OK", "59 days", false},
		{"90-day cert, 25 days left (renewal due, not overdue)", "example.test", "example.test", -65 * day, 25 * day, "OK", "24 days", false},
		{"90-day cert, 20 days left: renewal overdue", "example.test", "example.test", -70 * day, 20 * day, "WARN", "renewal overdue", true},
		{"45-day cert, 10 days left: renewal overdue", "example.test", "example.test", -35 * day, 10 * day, "WARN", "renewal overdue", true},
		{"45-day cert, 15 days left", "example.test", "example.test", -30 * day, 15 * day, "OK", "14 days", false},
		{"397-day cert, 58 days left (cap: not yet)", "example.test", "example.test", -339 * day, 58 * day, "OK", "57 days", false},
		{"397-day cert, 25 days left: renew soon (cap 30 days)", "example.test", "example.test", -372 * day, 25 * day, "WARN", "renew soon", true},
		{"5 days left", "example.test", "example.test", -85 * day, 5 * day, "FAIL", "only 4 days left", true},
		{"expired 3 days ago", "example.test", "example.test", -93 * day, -3 * day, "FAIL", "expired 3 days ago", true},
		{"wrong name: only shown", "other.test", "example.test", -30 * day, 60 * day, "WARN", "not valid for example.test", false},
		{"wrong name, 5 days left: the expiry counts", "other.test", "example.test", -85 * day, 5 * day, "FAIL", "only 4 days left", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr, pool := serveCert(t, c.certHost, c.from, c.to)
			certRoots = pool
			defer func() { certRoots = nil }()
			r := checkCert(certTarget{Name: "x", Host: c.checkAs, Address: addr}, 3*time.Second)
			got := "FAIL"
			switch {
			case r.Probe.OK:
				got = "OK"
			case r.Probe.Warn:
				got = "WARN"
			}
			if r.Subject != c.certHost || len(r.SANs) != 1 || r.SANs[0] != c.certHost {
				t.Errorf("got CN %q SANs %v, want %q", r.Subject, r.SANs, c.certHost)
			}
			text := r.Probe.Detail + r.Probe.Error
			if got != c.want || !strings.Contains(text, c.text) || r.Expiry != c.expiry {
				t.Errorf("got %s %q expiry=%v, want %s containing %q expiry=%v", got, text, r.Expiry, c.want, c.text, c.expiry)
			}
			t.Logf("%-4s %s | expires %s", got, text, r.Expires)
		})
	}
}

func TestCheckCertUnknownCA(t *testing.T) {
	addr, _ := serveCert(t, "example.test", -30*24*time.Hour, 60*24*time.Hour)
	r := checkCert(certTarget{Host: "example.test", Address: addr}, 3*time.Second)
	if !r.Probe.Warn || r.Expiry || !strings.Contains(r.Probe.Error, "unknown issuer") {
		t.Errorf("got warn=%v expiry=%v %q, want WARN unknown issuer", r.Probe.Warn, r.Expiry, r.Probe.Error)
	}
}

func TestCheckCertNoTLS(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Read the whole ClientHello first, like a real HTTP server reads the
		// request before it answers 400: closing with unread data sends a
		// reset, and on Windows the client then often gets "connection
		// aborted" instead of the reply.
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		hdr := make([]byte, 5) // TLS record header, length in bytes 3-4
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		if _, err := io.ReadFull(c, make([]byte, int(hdr[3])<<8|int(hdr[4]))); err != nil {
			return
		}
		c.Write([]byte("HTTP/1.0 400 plain http\r\n\r\n"))
	}()
	r := checkCert(certTarget{Host: "example.test", Address: ln.Addr().String()}, 3*time.Second)
	if !r.Probe.Warn || r.Expiry || r.Probe.Error != "no TLS on this address" {
		t.Errorf("got warn=%v expiry=%v %q, want WARN \"no TLS on this address\"", r.Probe.Warn, r.Expiry, r.Probe.Error)
	}
}

func TestCheckCertRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens there any more, like a stopped nginx
	r := checkCert(certTarget{Host: "example.test", Address: addr}, 3*time.Second)
	// Linux: "connection refused"; Windows: "No connection could be made
	// because the target machine actively refused it."
	if !r.Probe.Warn || r.Expiry || !strings.Contains(r.Probe.Error, "refused") || strings.Contains(r.Probe.Error, "dial tcp") {
		t.Errorf("got warn=%v expiry=%v %q, want WARN connection refused", r.Probe.Warn, r.Expiry, r.Probe.Error)
	}
}

func TestWithDefaultPort(t *testing.T) {
	for _, c := range []struct{ in, port, want string }{
		{"example.com", "443", "example.com:443"},
		{"example.com:8443", "443", "example.com:8443"},
		{" 192.168.1.10 ", "443", "192.168.1.10:443"},
		{"192.168.1.10:993", "443", "192.168.1.10:993"},
		{"2001:db8::1", "443", "[2001:db8::1]:443"},
		{"[2001:db8::1]", "443", "[2001:db8::1]:443"},
		{"[2001:db8::1]:8443", "443", "[2001:db8::1]:8443"},
		{"1.1.1.1", "53", "1.1.1.1:53"},
		{"9.9.9.9:5353", "53", "9.9.9.9:5353"},
		{"2606:4700:4700::1111", "53", "[2606:4700:4700::1111]:53"},
	} {
		if got := withDefaultPort(c.in, c.port); got != c.want {
			t.Errorf("withDefaultPort(%q, %q) = %q, want %q", c.in, c.port, got, c.want)
		}
	}
}

func TestShortIssuer(t *testing.T) {
	for _, c := range []struct {
		cn, org, want string
	}{
		{"R11", "Let's Encrypt", "R11"},
		{"YE1", "Let's Encrypt", "YE1"},
		{"WE2", "Google Trust Services", "WE2"},
		{"DigiCert Global G2 TLS RSA SHA256 2020 CA1", "DigiCert Inc", "DigiCert"},
		{"Sectigo RSA Domain Validation Secure Server CA", "Sectigo Limited", "Sectigo"},
		{"Amazon RSA 2048 M02", "Amazon", "Amazon"},
		{"A very long CA name without org", "", "A very long CA name without org"},
		{"", "Some CA, Inc.", "Some CA"},
	} {
		n := pkix.Name{CommonName: c.cn}
		if c.org != "" {
			n.Organization = []string{c.org}
		}
		if got := shortIssuer(n); got != c.want {
			t.Errorf("shortIssuer(%q, %q) = %q, want %q", c.cn, c.org, got, c.want)
		}
	}
}
