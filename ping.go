package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// checkPing resolves the host and sends a single ICMP echo. The ICMP part
// (pingIP) is OS-specific: ping_windows.go (IcmpSendEcho) and ping_unix.go (x/net/icmp).
// There is no separate DNS check for hosts: when the name does not resolve,
// ping fails with "DNS: ..." (the DNS servers box checks the servers).
func checkPing(host string, timeout time.Duration) probe {
	p := probe{CheckedAt: time.Now().Format(time.RFC3339)}

	ip, err := resolvePingIP(host, timeout)
	if err != nil {
		p.Error = "DNS: " + shortDNSError(err)
		return p
	}
	p.Detail = ip.String()

	rtt, err := pingIP(ip, timeout)
	p.LatencyMS = rtt.Milliseconds()
	if err != nil {
		p.Error = err.Error()
		return p
	}
	p.OK = true
	return p
}

// resolvePingIP returns the host's first IPv4 address, otherwise the first IPv6.
func resolvePingIP(host string, timeout time.Duration) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return pickIP(ips)
}

// shortDNSError turns "lookup x on 127.0.0.53:53: no such host" into
// "no such host".
func shortDNSError(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		if de.IsTimeout {
			return "timeout"
		}
		return de.Err
	}
	return err.Error()
}

// pickIP returns the first IPv4 address, otherwise the first IPv6.
func pickIP(ips []net.IP) (net.IP, error) {
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	if len(ips) > 0 {
		return ips[0], nil
	}
	return nil, fmt.Errorf("no A/AAAA records")
}
