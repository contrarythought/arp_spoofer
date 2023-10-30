package main

import (
	"arp_spoof/network"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket"
)

func TestSerializeBuffer(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()

	fmt.Println("1: ", buf.Bytes())

	bytes, _ := buf.PrependBytes(3)

	copy(bytes, []byte{1, 2, 4})

	fmt.Println("2: ", buf.Bytes())

	bytes, _ = buf.PrependBytes(1)

	fmt.Println("3: ", buf.Bytes())
}

func TestOutboundIP(t *testing.T) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	fmt.Println(conn.LocalAddr().String())
}

func TestGenIPRange(t *testing.T) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	ipv4 := net.ParseIP(strings.Split(conn.LocalAddr().String(), ":")[0])
	if ipv4 == nil {
		t.Error(err)
	}

	ipnet := net.IPNet{
		IP:   ipv4,
		Mask: ipv4.DefaultMask(),
	}

	num := binary.BigEndian.Uint32(ipnet.IP.To4())
	fmt.Println(num)

	mask := binary.BigEndian.Uint32(ipnet.Mask)
	fmt.Println(mask)

	orignetwork := num & mask
	fmt.Println(orignetwork)
	b4 := uint8((orignetwork >> 24) & 0xff)
	b3 := uint8((orignetwork >> 16) & 0xff)
	b2 := uint8((orignetwork >> 8) & 0xff)
	b1 := uint8(orignetwork & 0xff)

	numOfOffBits := 0

	for i := 0; i < 32; i++ {
		tmp := (1 << i) & mask
		if tmp == 0 {
			numOfOffBits += 1
		}
	}

	fmt.Println("num of 0s: ", numOfOffBits)
	numHosts := 1<<numOfOffBits - 2
	fmt.Println("numHosts: ", numHosts)

	networkPortion := net.IPv4(b4, b3, b2, b1)
	fmt.Println(networkPortion.String())

	var orignet [4]byte
	binary.BigEndian.PutUint32(orignet[:], orignetwork)
	broadcast := orignetwork | ^mask

	startHost := binary.BigEndian.Uint32(networkPortion.To4())
	b1 = uint8(startHost & 0xff)
	b2 = uint8((startHost >> 8) & 0xff)
	b3 = uint8((startHost >> 16) & 0xff)
	b4 = uint8((startHost >> 24) & 0xff)

	sh := net.IPv4(b1, b2, b3, b4)
	fmt.Println("uin32 to ip: ", sh.String())

	fmt.Println("br: ", broadcast)
	fmt.Println("st:", startHost)

	defmask := binary.BigEndian.Uint32(ipnet.IP.DefaultMask())

	shost := startHost & ^defmask
	b1 = uint8(shost & 0xff)
	b2 = uint8((shost >> 8) & 0xff)
	b3 = uint8((shost >> 16) & 0xff)
	b4 = uint8((shost >> 24) & 0xff)

	sip := net.IPv4(b4, b3, b2, b1)
	fmt.Println(sip.String())

	for startHost++; startHost < broadcast; startHost++ {
		b1 = uint8(startHost & 0xff)
		b2 = uint8((startHost >> 8) & 0xff)
		b3 = uint8((startHost >> 16) & 0xff)
		b4 = uint8((startHost >> 24) & 0xff)

		theip := net.IPv4(b4, b3, b2, b1)
		fmt.Println(theip.String())
	}
}

func TestGetAllIPs(t *testing.T) {
	ip := "10.0.0.0"

	addresses := network.GetAllIPs(net.ParseIP(ip).To4())

	for _, address := range addresses {
		fmt.Println(address.String())
	}
}
