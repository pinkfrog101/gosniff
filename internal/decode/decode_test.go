package decode

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseEthernet(t *testing.T) {
	b := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		0xAA, 0xBB,
	}
	eth, rest, err := ParseEthernet(b)
	if err != nil {
		t.Fatal(err)
	}
	if eth.EtherType != EtherTypeIPv4 {
		t.Errorf("ethertype = %#x, want 0x0800", eth.EtherType)
	}
	if eth.Src.String() != "00:11:22:33:44:55" {
		t.Errorf("src = %s", eth.Src)
	}
	if len(rest) != 2 {
		t.Errorf("payload len = %d, want 2", len(rest))
	}
}

func TestParseEthernetTooShort(t *testing.T) {
	if _, _, err := ParseEthernet(make([]byte, 5)); err == nil {
		t.Error("expected error for short input")
	}
}

func TestParseIPv4(t *testing.T) {
	b := []byte{
		0x45, 0x00, 0x00, 0x14,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		192, 168, 1, 5,
		142, 250, 1, 1,
	}
	ip, rest, err := ParseIPv4(b)
	if err != nil {
		t.Fatal(err)
	}
	if ip.TTL != 64 || ip.Protocol != ProtoTCP {
		t.Errorf("got ttl=%d proto=%d", ip.TTL, ip.Protocol)
	}
	if ip.Src.String() != "192.168.1.5" || ip.Dst.String() != "142.250.1.1" {
		t.Errorf("got %s -> %s", ip.Src, ip.Dst)
	}
	if len(rest) != 0 {
		t.Errorf("payload len = %d, want 0", len(rest))
	}
}
func TestParseTCP(t *testing.T) {
	b := []byte{
		0xC8, 0x22, 0x01, 0xBB,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x12,
		0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		0xDE, 0xAD,
	}
	tcp, rest, err := ParseTCP(b)
	if err != nil {
		t.Fatal(err)
	}
	if tcp.SrcPort != 51234 || tcp.DstPort != 443 {
		t.Errorf("ports = %d -> %d, want 51234 -> 443", tcp.SrcPort, tcp.DstPort)
	}
	if tcp.Seq != 1 || tcp.Ack != 0 {
		t.Errorf("seq=%d ack=%d, want 1 and 0", tcp.Seq, tcp.Ack)
	}
	if got := tcp.FlagString(); got != "SYN,ACK" {
		t.Errorf("flags = %q, want SYN,ACK", got)
	}
	if len(rest) != 2 {
		t.Errorf("payload len = %d, want 2", len(rest))
	}
}

func TestParseTCPErrors(t *testing.T) {
	if _, _, err := ParseTCP(make([]byte, 10)); err == nil {
		t.Error("expected error for short input")
	}

	if _, _, err := ParseTCP(make([]byte, 20)); err == nil {
		t.Error("expected error for bad header length")
	}
}

func TestTCPFlagString(t *testing.T) {
	tests := []struct {
		name  string
		flags uint8
		want  string
	}{
		{"syn", 0x02, "SYN"},
		{"syn-ack", 0x12, "SYN,ACK"},
		{"fin-ack", 0x11, "ACK,FIN"},
		{"rst", 0x04, "RST"},
		{"psh-ack", 0x18, "ACK,PSH"},
		{"none", 0x00, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (TCP{Flags: tt.flags}).FlagString(); got != tt.want {
				t.Errorf("FlagString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseUDP(t *testing.T) {
	b := []byte{
		0xC7, 0x38, 0x00, 0x35,
		0x00, 0x0C, 0x00, 0x00,
		0x01, 0x02, 0x03, 0x04,
	}
	udp, rest, err := ParseUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	if udp.SrcPort != 51000 || udp.DstPort != 53 || udp.Length != 12 {
		t.Errorf("got %+v", udp)
	}
	if len(rest) != 4 {
		t.Errorf("payload len = %d, want 4", len(rest))
	}
}

func TestParseUDPTooShort(t *testing.T) {
	if _, _, err := ParseUDP(make([]byte, 7)); err == nil {
		t.Error("expected error for short input")
	}
}
func TestDecodeTCPPacket(t *testing.T) {
	eth := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
	}
	ip := []byte{
		0x45, 0x00, 0x00, 0x28,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		192, 168, 1, 5,
		142, 250, 1, 1,
	}
	tcp := []byte{
		0xC8, 0x22, 0x01, 0xBB,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x02,
		0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
	}
	data := bytes.Join([][]byte{eth, ip, tcp}, nil)

	p := Decode(data)

	if p.Protocol != "TCP" {
		t.Errorf("protocol = %q, want TCP", p.Protocol)
	}
	if p.SrcAddr != "192.168.1.5" || p.DstAddr != "142.250.1.1" {
		t.Errorf("addrs = %s -> %s", p.SrcAddr, p.DstAddr)
	}
	if p.SrcPort != 51234 || p.DstPort != 443 {
		t.Errorf("ports = %d -> %d", p.SrcPort, p.DstPort)
	}
	if !strings.Contains(p.Info, "SYN") {
		t.Errorf("info = %q, want it to mention SYN", p.Info)
	}
}

func TestDecodeGarbage(t *testing.T) {
	p := Decode([]byte{1, 2, 3})
	if p.Protocol != "ERR" {
		t.Errorf("protocol = %q, want ERR", p.Protocol)
	}
}
