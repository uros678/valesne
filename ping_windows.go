//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IcmpSendEcho from iphlpapi.dll is the same call ping.exe uses: it needs no
// administrator rights and returns the RTT as a number.
var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

// icmpEchoReply matches ICMP_ECHO_REPLY (with IP_OPTION_INFORMATION inlined).
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Ttl           uint8
	Tos           uint8
	Flags         uint8
	OptionsSize   uint8
	OptionsData   uintptr
}

const ipSuccess = 0

var icmpStatusText = map[uint32]string{
	11002: "network unreachable",
	11003: "host unreachable",
	11004: "protocol unreachable",
	11005: "port unreachable",
	11010: "timeout",
	11013: "TTL expired",
	11050: "general failure",
}

func icmpStatusError(status uint32) error {
	if s, ok := icmpStatusText[status]; ok {
		return fmt.Errorf("%s", s)
	}
	return fmt.Errorf("ICMP status %d", status)
}

func pingIP(ip net.IP, timeout time.Duration) (time.Duration, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("IPv6 ping is not supported on Windows (%s)", ip)
	}

	h, _, err := procIcmpCreateFile.Call()
	if windows.Handle(h) == windows.InvalidHandle {
		return 0, fmt.Errorf("IcmpCreateFile: %w", err)
	}
	defer procIcmpCloseHandle.Call(h)

	payload := []byte("valesne-ping")
	// Room for the reply + data + a possible ICMP error message.
	var buf struct {
		reply icmpEchoReply
		extra [64]byte
	}

	// IPAddr is in network byte order, i.e. just the bytes a.b.c.d in memory.
	addr := binary.LittleEndian.Uint32(ip4)
	start := time.Now()
	n, _, err := procIcmpSendEcho.Call(
		h,
		uintptr(addr),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		0,
		uintptr(unsafe.Pointer(&buf)),
		unsafe.Sizeof(buf),
		uintptr(timeout.Milliseconds()),
	)
	elapsed := time.Since(start)

	if n == 0 {
		if errno, ok := err.(windows.Errno); ok && errno != 0 {
			return elapsed, icmpStatusError(uint32(errno))
		}
		return elapsed, fmt.Errorf("no reply")
	}
	if buf.reply.Status != ipSuccess {
		return elapsed, icmpStatusError(buf.reply.Status)
	}
	return time.Duration(buf.reply.RoundTripTime) * time.Millisecond, nil
}
