//go:build !windows

package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var pingSeq atomic.Uint32

// pingIP first tries an unprivileged ICMP socket ("udp4"/"udp6"), which works
// on Linux when net.ipv4.ping_group_range allows it. Otherwise it
// falls back to a raw socket, which needs root or CAP_NET_RAW.
func pingIP(ip net.IP, timeout time.Duration) (time.Duration, error) {
	v4 := ip.To4() != nil

	network, rawNetwork, listenAddr, proto := "udp6", "ip6:ipv6-icmp", "::", 58
	var echoType, replyType icmp.Type = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	if v4 {
		network, rawNetwork, listenAddr, proto = "udp4", "ip4:icmp", "0.0.0.0", 1
		echoType, replyType = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	}

	privileged := false
	conn, err := icmp.ListenPacket(network, listenAddr)
	if err != nil {
		var rawErr error
		conn, rawErr = icmp.ListenPacket(rawNetwork, listenAddr)
		if rawErr != nil {
			return 0, fmt.Errorf("ICMP socket: %v (raw: %v)", err, rawErr)
		}
		privileged = true
	}
	defer conn.Close()

	// On Linux the unprivileged socket rewrites the ID, so the reply is matched
	// by its content (payload with a sequence number).
	seq := int(pingSeq.Add(1) & 0xffff)
	payload := []byte(fmt.Sprintf("valesne-ping-%d-%d", os.Getpid(), seq))
	msg := icmp.Message{
		Type: echoType,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: seq, Data: payload},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}

	var dst net.Addr = &net.UDPAddr{IP: ip}
	if privileged {
		dst = &net.IPAddr{IP: ip}
	}

	deadline := time.Now().Add(timeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return 0, err
	}

	start := time.Now()
	if _, err := conn.WriteTo(wb, dst); err != nil {
		return time.Since(start), err
	}

	rb := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(rb)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return time.Since(start), fmt.Errorf("timeout")
			}
			return time.Since(start), err
		}
		rm, err := icmp.ParseMessage(proto, rb[:n])
		if err != nil || rm.Type != replyType {
			continue
		}
		if echo, ok := rm.Body.(*icmp.Echo); ok && bytes.Equal(echo.Data, payload) {
			return time.Since(start), nil
		}
	}
}
