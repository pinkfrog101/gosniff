package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"gosniff/internal/capture"
	"gosniff/internal/decode"
)

func main() {
	iface := flag.String("i", "", "interface to capture on")
	file := flag.String("r", "", "read packets from a .pcap file instead of live capture")
	list := flag.Bool("list", false, "list interfaces and exit")
	flag.Parse()

	if *list {
		if err := capture.ListDevices(); err != nil {
			log.Fatal(err)
		}
		return
	}

	var handle *pcap.Handle
	var err error

	switch {
	case *file != "":
		handle, err = pcap.OpenOffline(*file)
	case *iface != "":
		handle, err = pcap.OpenLive(*iface, 1600, false, time.Second) // false = not promiscuous
	default:
		log.Fatal("usage: gosniff -i <interface> | -r <file.pcap> | -list")
	}
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	fmt.Println("link type:", handle.LinkType(), "- capturing, press Ctrl+C to stop")

	if handle.LinkType() != layers.LinkTypeEthernet {
		log.Fatalf("unsupported link type %v (this tool only decodes Ethernet)", handle.LinkType())
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	n := 0
	for packet := range source.Packets() {
		n++
		fmt.Printf("#%d  %s  %s\n",
			n,
			packet.Metadata().Timestamp.Format("15:04:05.000"),
			decode.Describe(packet.Data()))
	}
}
