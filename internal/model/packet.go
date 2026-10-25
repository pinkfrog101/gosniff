package model

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

type Packet struct {
	Number   int
	Time     time.Time
	Length   int
	SrcAddr  string
	DstAddr  string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
	Info     string
	Raw      []byte
}

func (p Packet) Source() string { return endpoint(p.SrcAddr, p.SrcPort) }

func (p Packet) Destination() string { return endpoint(p.DstAddr, p.DstPort) }

func endpoint(addr string, port uint16) string {
	if port == 0 {
		return addr
	}
	return net.JoinHostPort(addr, strconv.Itoa(int(port)))
}

func (p Packet) Summary() string {
	return fmt.Sprintf("%-5d %s  %-22s -> %-22s %-5s %5d  %s",
		p.Number,
		p.Time.Format("15:04:05.000"),
		p.Source(),
		p.Destination(),
		p.Protocol,
		p.Length,
		p.Info)
}
