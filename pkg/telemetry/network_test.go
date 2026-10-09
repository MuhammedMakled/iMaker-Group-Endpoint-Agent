package telemetry

import (
	"reflect"
	"testing"
)

func TestNormalizeMAC(t *testing.T) {
	for _, in := range []string{"A8:5E:45:12:34:56", "a8-5e-45-12-34-56", "a85e.4512.3456"} {
		if NormalizeMAC(in) != "A85E45123456" {
			t.Errorf("%q normalised wrong: %q", in, NormalizeMAC(in))
		}
	}
}

func TestAdapterType(t *testing.T) {
	cases := []struct {
		name, desc string
		id         int32
		hasID      bool
		want       string
	}{
		{"Wi-Fi", "Intel(R) Wi-Fi 6 AX201", 9, true, "Wireless"},
		{"Ethernet 3", "Realtek PCIe GbE Family Controller", 0, true, "Ethernet"},
		{"Wi-Fi", "some adapter", 0, false, "Wireless"},
		{"Ethernet", "Intel(R) Ethernet Connection", 0, false, "Ethernet"},
		{"vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", 0, false, "Virtual"},
		{"Local Area Connection", "TAP-Windows Adapter V9", 0, false, "Virtual"},
		{"Bluetooth Network", "Bluetooth Device (PAN)", 0, false, "Other"},
	}
	for _, c := range cases {
		if got := AdapterType(c.name, c.desc, c.id, c.hasID); got != c.want {
			t.Errorf("%q/%q => %q, want %q", c.name, c.desc, got, c.want)
		}
	}
}

func TestSplitIPVersions(t *testing.T) {
	v4, v6 := SplitIPVersions([]string{
		"192.168.1.20", "fe80::1%eth0", "2001:db8::5", "10.0.0.5/24", "bad",
	})
	if !reflect.DeepEqual(v4, []string{"192.168.1.20", "10.0.0.5"}) {
		t.Errorf("v4: %v", v4)
	}
	if !reflect.DeepEqual(v6, []string{"2001:db8::5"}) { // link-local dropped
		t.Errorf("v6: %v", v6)
	}
	if !IsPrivateIPv4("192.168.1.20") || IsPrivateIPv4("8.8.8.8") {
		t.Error("private detection")
	}
}

func TestNetConnectionStatusName(t *testing.T) {
	if NetConnectionStatusName(2) != "Connected" || NetConnectionStatusName(7) != "Media disconnected" {
		t.Error("status names")
	}
}
