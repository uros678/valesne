package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"
	"time"
)

// certTarget is a TLS certificate from the config ([[certs]]).
type certTarget struct {
	Name    string `toml:"name"`
	Host    string `toml:"host"`    // name on the certificate: SNI and verification
	Address string `toml:"address"` // where to connect, default host:443 (e.g. the origin behind Cloudflare)
}

// certFailDays: fewer days left than this is FAIL, whatever the lifetime.
const certFailDays = 7

// certWarnMaxDays caps the WARN threshold (1/4 of the lifetime): a long
// certificate (e.g. 397 days from a commercial CA, renewed by hand) would
// otherwise warn 99 days before expiry.
const certWarnMaxDays = 30

// certRoots are the trusted root CAs for the verification; nil means the
// system's CAs. Only the tests set it (to a test CA).
var certRoots *x509.CertPool

// certCheck is the result of one check of a certificate; certResult embeds it.
type certCheck struct {
	Issuer   string   `json:"issuer,omitempty"`  // issuer CN, e.g. "R11"
	Subject  string   `json:"subject,omitempty"` // the certificate's own CN, e.g. "*.example.com" (may be empty)
	SANs     []string `json:"sans,omitempty"`    // names (and IPs) the certificate is valid for
	Expires  string   `json:"expires,omitempty"` // expiry date, YYYY-MM-DD
	DaysLeft int      `json:"daysLeft"`          // may be negative (expired)
	// Expiry: the WARN/FAIL comes from the expiry thresholds. Only these
	// alert; an unreachable address or an invalid certificate does not.
	Expiry bool  `json:"-"`
	Probe  probe `json:"probe"`
}

// checkCert connects to the address, reads the certificate that is actually
// served (not the files of certbot), and judges its expiry:
//
//	OK   = enough time left
//	WARN = less than 1/4 of the lifetime left, at most certWarnMaxDays: certbot
//	       renews at ~1/3, so the renewal should already have happened
//	       (relative, because certificate lifetimes get shorter; 90 days ->
//	       22.5 days, 45 days -> ~11 days; capped so a 397-day certificate
//	       warns at 30 days, not 99)
//	FAIL = fewer than certFailDays days left, or expired
//
// Only the expiry is this check's job: a server that cannot be reached (or
// has no TLS on the port) and a certificate that is not valid (hostname,
// chain; checked by hand) are WARN with the error text and do not alert
// (Expiry = false). Whether the server is up is for the ping/HTTP checks.
func checkCert(t certTarget, timeout time.Duration) certCheck {
	now := time.Now()
	res := certCheck{Probe: probe{CheckedAt: now.Format(time.RFC3339)}}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	// Verification is done below, so the dates can be read even from an
	// expired or otherwise invalid certificate.
	dialer := &tls.Dialer{Config: &tls.Config{ServerName: t.Host, InsecureSkipVerify: true}}
	conn, err := dialer.DialContext(ctx, "tcp", t.Address)
	res.Probe.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Probe.Warn = true
		var recErr tls.RecordHeaderError
		if errors.As(err, &recErr) {
			res.Probe.Error = "no TLS on this address"
		} else {
			res.Probe.Error = shortNetError(err)
		}
		return res
	}
	state := conn.(*tls.Conn).ConnectionState()
	conn.Close()
	if len(state.PeerCertificates) == 0 {
		res.Probe.Warn = true
		res.Probe.Error = "no certificate"
		return res
	}
	leaf := state.PeerCertificates[0]

	left := leaf.NotAfter.Sub(now)
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	res.Subject = leaf.Subject.CommonName
	res.SANs = append(res.SANs, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		res.SANs = append(res.SANs, ip.String())
	}
	res.Issuer = shortIssuer(leaf.Issuer)
	res.Expires = leaf.NotAfter.Local().Format("2006-01-02")
	// Whole days, rounded toward zero: 59.9 days left is "59 days", expired
	// 3.1 days ago is "expired 3 days ago".
	res.DaysLeft = int(left.Hours() / 24)

	days := plural(res.DaysLeft, "day")
	if left <= 0 {
		res.Expiry = true
		res.Probe.Error = "expired today"
		if res.DaysLeft < 0 {
			res.Probe.Error = fmt.Sprintf("expired %s ago", plural(-res.DaysLeft, "day"))
		}
		return res
	}

	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       t.Host,
		Roots:         certRoots,
		Intermediates: intermediates,
		CurrentTime:   now,
	})

	// The expiry is judged first, so it alerts even on a certificate that
	// is not valid.
	warnAt := min(lifetime/4, certWarnMaxDays*24*time.Hour)
	switch {
	case left < certFailDays*24*time.Hour:
		res.Expiry = true
		res.Probe.Error = "only " + days + " left"
	case left < warnAt:
		res.Expiry = true
		// Only a warning: the certificate still works. With the relative
		// threshold (short, auto-renewed certificates) the renewal is late;
		// with the cap (long certificates) it is due.
		res.Probe.Warn = true
		if warnAt < certWarnMaxDays*24*time.Hour {
			res.Probe.Error = days + " · renewal overdue"
		} else {
			res.Probe.Error = days + " · renew soon"
		}
	case verifyErr != nil:
		res.Probe.Warn = true
		res.Probe.Error = shortCertError(verifyErr, t.Host)
	default:
		res.Probe.OK = true
		res.Probe.Detail = days
		if res.Issuer != "" {
			res.Probe.Detail += " · " + res.Issuer
		}
	}
	return res
}

// issuerMaxLen: a longer issuer CN is replaced by the organization, e.g.
// "DigiCert Global G2 TLS RSA SHA256 2020 CA1" -> "DigiCert".
const issuerMaxLen = 16

// shortIssuer returns a short name of the issuer for the page: the CN when it
// is short (e.g. "R11"), otherwise the organization without a legal suffix.
func shortIssuer(n pkix.Name) string {
	org := ""
	if len(n.Organization) > 0 {
		org = strings.TrimSpace(n.Organization[0])
		for _, suffix := range []string{", Inc.", " Inc", " Limited"} {
			if s := strings.TrimSuffix(org, suffix); s != "" && s != org {
				org = s
				break
			}
		}
	}
	switch {
	case n.CommonName == "":
		return org
	case len(n.CommonName) > issuerMaxLen && org != "":
		return org
	}
	return n.CommonName
}

// shortCertError turns the long x509 errors into a short text for the page.
func shortCertError(err error, host string) string {
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	var invErr x509.CertificateInvalidError
	switch {
	case errors.As(err, &hostErr):
		return "not valid for " + host
	case errors.As(err, &authErr):
		return "unknown issuer (self-signed?)"
	case errors.As(err, &invErr):
		return "invalid: " + strings.TrimPrefix(invErr.Error(), "x509: ")
	}
	return strings.TrimPrefix(err.Error(), "x509: ")
}

func plural(n int, word string) string {
	if n == 1 || n == -1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
