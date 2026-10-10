package capture

import "github.com/google/gopacket/pcap"

func ListDevices() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}
