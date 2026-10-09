package telemetry

import (
	"net"
	"strings"
)

// NormalizeMAC upper-cases and strips separators so MACs from different
// sources (Go's net, WMI) can be matched.
func NormalizeMAC(mac string) string {
	r := strings.NewReplacer(":", "", "-", "", ".", "", " ", "")
	return strings.ToUpper(r.Replace(strings.TrimSpace(mac)))
}

// AdapterType classifies an interface from its names and the WMI AdapterTypeID.
//
// AdapterTypeID: 0 = Ethernet 802.3, 9 = Wireless. Many drivers leave it unset,
// so we also match keywords in the connection name / description.
func AdapterType(name, description string, adapterTypeID int32, hasTypeID bool) string {
	n := strings.ToLower(name + " " + description)
	switch {
	case strings.Contains(n, "virtual"), strings.Contains(n, "vmware"), strings.Contains(n, "hyper-v"),
		strings.Contains(n, "vethernet"), strings.Contains(n, "loopback"), strings.Contains(n, "vpn"),
		strings.Contains(n, "tap-"), strings.Contains(n, "tunnel"), strings.Contains(n, "wan miniport"):
		return "Virtual"
	}
	if hasTypeID {
		switch adapterTypeID {
		case 9:
			return "Wireless"
		case 0:
			return "Ethernet"
		}
	}
	switch {
	case strings.Contains(n, "wi-fi"), strings.Contains(n, "wifi"), strings.Contains(n, "wireless"),
		strings.Contains(n, "wlan"), strings.Contains(n, "802.11"):
		return "Wireless"
	case strings.Contains(n, "ethernet"), strings.Contains(n, "gigabit"), strings.Contains(n, "gbe"),
		strings.Contains(n, " lan"), strings.Contains(n, "realtek pcie"), strings.Contains(n, "intel(r) ethernet"):
		return "Ethernet"
	}
	return "Other"
}

// NetConnectionStatusName maps Win32_NetworkAdapter.NetConnectionStatus.
func NetConnectionStatusName(v uint16) string {
	names := map[uint16]string{
		0: "Disconnected", 1: "Connecting", 2: "Connected", 3: "Disconnecting",
		4: "Hardware not present", 5: "Hardware disabled", 6: "Hardware malfunction",
		7: "Media disconnected", 8: "Authenticating", 9: "Authentication succeeded",
		10: "Authentication failed", 11: "Invalid address", 12: "Credentials required",
	}
	if n, ok := names[v]; ok {
		return n
	}
	return "Unknown"
}

// SplitIPVersions separates a mixed address list into IPv4 and IPv6, dropping
// link-local IPv6 (fe80::) which is rarely useful in an inventory.
func SplitIPVersions(addrs []string) (v4, v6 []string) {
	for _, a := range addrs {
		host := a
		if i := strings.IndexByte(host, '/'); i >= 0 { // strip CIDR suffix
			host = host[:i]
		}
		if p := strings.IndexByte(host, '%'); p >= 0 { // strip zone id
			host = host[:p]
		}
		ip := net.ParseIP(strings.TrimSpace(host))
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, host)
		} else {
			if ip.IsLinkLocalUnicast() {
				continue
			}
			v6 = append(v6, host)
		}
	}
	return v4, v6
}

// IsPrivateIPv4 reports whether s is an RFC1918 private address.
func IsPrivateIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && ip.IsPrivate()
}
