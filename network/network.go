package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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

func GetAllIPs(attackerIP net.IP) []net.IP {
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

func Ping(ips []net.IP) []net.IP {
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

func MapIPstoMAC(ips []net.IP) ([]*DeviceInfo, error) {
	Ping(ips)

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

func GetWindowsInterface(ifaceArg string) (string, error) {
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

func getAttackerInfo(ifaceArg string) (*DeviceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var info DeviceInfo
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

func checkIPs(ips ...string) error {
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			msg := ip + " not in the correct ipv4 format: x.x.x.x"
			return errors.New(msg)
		}
	}
	return nil
}

func GetAttackerIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	str := strings.Split(conn.LocalAddr().String(), ":")[0]

	ip := net.ParseIP(str)
	if ip == nil {
		msg := "err: failed to parse IP: " + str
		return nil, errors.New(msg)
	}

	return ip, nil
}

func GetMAC(netInterface string) (net.HardwareAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var mac net.HardwareAddr
	for _, iface := range ifaces {
		if iface.Name == netInterface {
			mac = iface.HardwareAddr
			break
		}
	}

	return mac, nil
}
