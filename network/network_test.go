package network

import (
	"fmt"
	"testing"
)

func TestGetMAC(t *testing.T) {
	mac, err := GetMAC("Wi-Fi")
	if err != nil {
		t.Error(err)
	}

	fmt.Println(mac.String())
}

func TestGetAttackerIP(t *testing.T) {
	myIP, err := GetAttackerIP()
	if err != nil {
		t.Error(err)
	}

	fmt.Println(myIP.String())
}
