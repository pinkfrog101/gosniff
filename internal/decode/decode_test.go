package decode

import "testing"

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
