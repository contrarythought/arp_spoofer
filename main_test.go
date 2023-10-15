package main

import (
	"fmt"
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
