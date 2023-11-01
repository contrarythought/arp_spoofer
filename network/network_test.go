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

func TestEnableIPForwarding(t *testing.T) {
	if err := EnableIPForwarding("Wi-Fi"); err != nil {
		t.Error(err)
	}
}

func TestDisableIPForwarding(t *testing.T) {
	if err := DisableIPForwarding("Wi-Fi"); err != nil {
		t.Error(err)
	}
}
