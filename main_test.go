package main

import (
	"fmt"
	"net"
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
