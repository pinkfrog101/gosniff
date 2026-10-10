package main

import (
	"fmt"
	"gosniff/internal/capture"
	"log"
)

func main() {
	devices, err := capture.ListDevices()
	if err != nil {
		log.Fatalf("Could not list interfaces: %v", err)
	}
	fmt.Println("===goSniff===")
	for i, device := range devices {
		fmt.Printf("\n[%d] %s\n", i+1, device.Name)
		fmt.Printf("Description: %s\n", device.Description)
		for _, address := range device.Addresses {
			fmt.Printf("IP Address: %s\n", address.IP)
		}
	}

}
