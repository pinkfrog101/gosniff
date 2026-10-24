package decode

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
	EtherTypeIPv6 = 0x86DD
)

type Ethernet struct {
	Dst, Src  net.HardwareAddr
	EtherType uint16
}

func ParseEthernet(b []byte) (Ethernet, []byte, error) {
	if len(b) < 14 {
		return Ethernet{}, nil, fmt.Errorf("ethernet: need 14 bytes, got %d", len(b))
	}
	return Ethernet{
		Dst:       net.HardwareAddr(b[0:6]),
		Src:       net.HardwareAddr(b[6:12]),
		EtherType: binary.BigEndian.Uint16(b[12:14]),
	}, b[14:], nil
}

const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

type IPv4 struct {
	TTL      uint8
	Protocol uint8
	Src, Dst net.IP
}

func ParseIPv4(b []byte) (IPv4, []byte, error) {
	if len(b) < 20 {
		return IPv4{}, nil, fmt.Errorf("ipv4: need 20 bytes, got %d", len(b))
	}
	if version := b[0] >> 4; version != 4 {
		return IPv4{}, nil, fmt.Errorf("ipv4: bad version %d", version)
	}
	headerLen := int(b[0]&0x0F) * 4
	if headerLen < 20 || len(b) < headerLen {
		return IPv4{}, nil, fmt.Errorf("ipv4: bad header length %d", headerLen)
	}
	totalLen := int(binary.BigEndian.Uint16(b[2:4]))
	end := len(b)
	if totalLen >= headerLen && totalLen <= len(b) {
		end = totalLen
	}
	return IPv4{
		TTL:      b[8],
		Protocol: b[9],
		Src:      net.IP(b[12:16]),
		Dst:      net.IP(b[16:20]),
	}, b[headerLen:end], nil
}

type TCP struct {
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	Flags            uint8
}

func ParseTCP(b []byte) (TCP, []byte, error) {
	if len(b) < 20 {
		return TCP{}, nil, fmt.Errorf("tcp: need 20 bytes, got %d", len(b))
	}
	headerLen := int(b[12]>>4) * 4
	if headerLen < 20 || len(b) < headerLen {
		return TCP{}, nil, fmt.Errorf("tcp: bad header length %d", headerLen)
	}
	return TCP{
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
		Seq:     binary.BigEndian.Uint32(b[4:8]),
		Ack:     binary.BigEndian.Uint32(b[8:12]),
		Flags:   b[13],
	}, b[headerLen:], nil
}

func (t TCP) FlagString() string {
	names := []struct {
		bit  uint8
		name string
	}{
		{0x02, "SYN"}, {0x10, "ACK"}, {0x01, "FIN"},
		{0x04, "RST"}, {0x08, "PSH"}, {0x20, "URG"},
	}
	var set []string
	for _, f := range names {
		if t.Flags&f.bit != 0 {
			set = append(set, f.name)
		}
	}
	return strings.Join(set, ",")
}

type UDP struct {
	SrcPort, DstPort uint16
	Length           uint16
}

func ParseUDP(b []byte) (UDP, []byte, error) {
	if len(b) < 8 {
		return UDP{}, nil, fmt.Errorf("udp: need 8 bytes, got %d", len(b))
	}
	return UDP{
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
		Length:  binary.BigEndian.Uint16(b[4:6]),
	}, b[8:], nil
}

func Describe(data []byte) string {
	eth, l3, err := ParseEthernet(data)
	if err != nil {
		return "malformed: " + err.Error()
	}

	switch eth.EtherType {
	case EtherTypeIPv4:
		ip, l4, err := ParseIPv4(l3)
		if err != nil {
			return "malformed: " + err.Error()
		}
		switch ip.Protocol {
		case ProtoTCP:
			tcp, _, err := ParseTCP(l4)
			if err != nil {
				return "malformed: " + err.Error()
			}
			return fmt.Sprintf("TCP  %s:%d -> %s:%d [%s]",
				ip.Src, tcp.SrcPort, ip.Dst, tcp.DstPort, tcp.FlagString())
		case ProtoUDP:
			udp, _, err := ParseUDP(l4)
			if err != nil {
				return "malformed: " + err.Error()
			}
			return fmt.Sprintf("UDP  %s:%d -> %s:%d len=%d",
				ip.Src, udp.SrcPort, ip.Dst, udp.DstPort, udp.Length)
		default:
			return fmt.Sprintf("IPv4 %s -> %s proto=%d", ip.Src, ip.Dst, ip.Protocol)
		}
	case EtherTypeARP:
		return "ARP"
	case EtherTypeIPv6:
		return "IPv6 (not decoded yet)"
	default:
		return fmt.Sprintf("EtherType 0x%04x", eth.EtherType)
	}
}
