package capture

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

func ListDevices() error {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}
	for _, d := range devs {
		fmt.Println(d.Name, "-", d.Description)
		for _, a := range d.Addresses {
			fmt.Println("     ", a.IP)
		}
	}
	return nil
}
