package main

import (
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

func TestGetAllIPs(t *testing.T) {
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

	for network := orignetwork + 1; network < broadcast; network++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], network)

		//ip := net.IPv4(buf[0], buf[1], buf[2], buf[3])

		//fmt.Println(ip.String())
	}
}
