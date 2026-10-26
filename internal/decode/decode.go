package decode

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"gosniff/internal/model"
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
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
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

func Decode(data []byte) model.Packet {
	p := model.Packet{Length: len(data), Raw: data}

	eth, l3, err := ParseEthernet(data)
	if err != nil {
		p.Protocol, p.Info = "ERR", err.Error()
		return p
	}
	p.SrcAddr = eth.Src.String()
	p.DstAddr = eth.Dst.String()

	switch eth.EtherType {
	case EtherTypeIPv4:
		decodeIPv4(&p, l3)
	case EtherTypeARP:
		p.Protocol = "ARP"
	case EtherTypeIPv6:
		decodeIPv6(&p, l3)
	default:
		p.Protocol = "ETH"
		p.Info = fmt.Sprintf("EtherType 0x%04x", eth.EtherType)
	}
	return p
}

func decodeIPv4(p *model.Packet, b []byte) {
	ip, l4, err := ParseIPv4(b)
	if err != nil {
		p.Protocol, p.Info = "ERR", err.Error()
		return
	}
	p.SrcAddr, p.DstAddr = ip.Src.String(), ip.Dst.String()
	decodeTransport(p, ip.Protocol, l4, false)
}

func decodeIPv6(p *model.Packet, b []byte) {
	ip, l4, err := ParseIPv6(b)
	if err != nil {
		p.Protocol, p.Info = "ERR", err.Error()
		return
	}
	p.SrcAddr, p.DstAddr = ip.Src.String(), ip.Dst.String()
	decodeTransport(p, ip.NextHeader, l4, true)
}

// decodeTransport handles the layer above IP. It is shared by IPv4 and IPv6.
func decodeTransport(p *model.Packet, proto uint8, b []byte, v6 bool) {
	switch proto {
	case ProtoTCP:
		tcp, _, err := ParseTCP(b)
		if err != nil {
			p.Protocol, p.Info = "ERR", err.Error()
			return
		}
		p.Protocol = "TCP"
		p.SrcPort, p.DstPort = tcp.SrcPort, tcp.DstPort
		p.Info = fmt.Sprintf("%d -> %d [%s] seq=%d ack=%d",
			tcp.SrcPort, tcp.DstPort, tcp.FlagString(), tcp.Seq, tcp.Ack)

	case ProtoUDP:
		udp, _, err := ParseUDP(b)
		if err != nil {
			p.Protocol, p.Info = "ERR", err.Error()
			return
		}
		p.Protocol = "UDP"
		p.SrcPort, p.DstPort = udp.SrcPort, udp.DstPort
		p.Info = fmt.Sprintf("%d -> %d len=%d", udp.SrcPort, udp.DstPort, udp.Length)

	case ProtoICMP, ProtoICMPv6:
		icmp, _, err := ParseICMP(b)
		if err != nil {
			p.Protocol, p.Info = "ERR", err.Error()
			return
		}
		if proto == ProtoICMPv6 {
			p.Protocol, p.Info = "ICMPv6", ICMPv6TypeName(icmp.Type)
		} else {
			p.Protocol, p.Info = "ICMP", ICMPv4TypeName(icmp.Type)
		}

	default:
		p.Protocol = "IPv4"
		if v6 {
			p.Protocol = "IPv6"
		}
		p.Info = fmt.Sprintf("protocol %d", proto)
	}
}

type IPv6 struct {
	HopLimit   uint8
	NextHeader uint8
	Src, Dst   net.IP
}

func ParseIPv6(b []byte) (IPv6, []byte, error) {
	if len(b) < 40 {
		return IPv6{}, nil, fmt.Errorf("ipv6: need 40 bytes, got %d", len(b))
	}
	if version := b[0] >> 4; version != 6 {
		return IPv6{}, nil, fmt.Errorf("ipv6: bad version %d", version)
	}
	payloadLen := int(binary.BigEndian.Uint16(b[4:6]))
	next := b[6]
	payload := b[40:]
	if payloadLen > 0 && payloadLen <= len(payload) {
		payload = payload[:payloadLen]
	}
	for {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(payload) < 8 {
				return IPv6{}, nil, fmt.Errorf("ipv6: truncated extension header")
			}
			hdrLen := (int(payload[1]) + 1) * 8 // length is in 8-byte units, not counting the first 8
			if len(payload) < hdrLen {
				return IPv6{}, nil, fmt.Errorf("ipv6: truncated extension header")
			}
			next = payload[0]
			payload = payload[hdrLen:]
		case 44: // fragment header: always 8 bytes
			if len(payload) < 8 {
				return IPv6{}, nil, fmt.Errorf("ipv6: truncated fragment header")
			}
			next = payload[0]
			payload = payload[8:]
		default:
			return IPv6{
				HopLimit:   b[7],
				NextHeader: next,
				Src:        net.IP(b[8:24]),
				Dst:        net.IP(b[24:40]),
			}, payload, nil
		}
	}
}

type ICMP struct {
	Type, Code uint8
}

func ParseICMP(b []byte) (ICMP, []byte, error) {
	if len(b) < 4 {
		return ICMP{}, nil, fmt.Errorf("icmp: need 4 bytes, got %d", len(b))
	}
	return ICMP{Type: b[0], Code: b[1]}, b[4:], nil
}

func ICMPv4TypeName(t uint8) string {
	switch t {
	case 0:
		return "Echo reply"
	case 3:
		return "Destination unreachable"
	case 8:
		return "Echo request"
	case 11:
		return "Time exceeded"
	default:
		return fmt.Sprintf("type %d", t)
	}
}

func ICMPv6TypeName(t uint8) string {
	switch t {
	case 128:
		return "Echo request"
	case 129:
		return "Echo reply"
	case 130, 131, 132, 143:
		return "Multicast listener"
	case 133:
		return "Router solicitation"
	case 134:
		return "Router advertisement"
	case 135:
		return "Neighbor solicitation"
	case 136:
		return "Neighbor advertisement"
	default:
		return fmt.Sprintf("type %d", t)
	}
}
