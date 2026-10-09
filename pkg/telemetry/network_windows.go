//go:build windows

package telemetry

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

type win32NetworkAdapter struct {
	MACAddress          string
	NetConnectionID     string
	Name                string
	AdapterTypeID       int32
	Speed               uint64
	NetConnectionStatus uint16
	PhysicalAdapter     bool
	NetEnabled          bool
}

type win32NetworkAdapterConfig struct {
	MACAddress           string
	Description          string
	DHCPEnabled          bool
	DHCPServer           string
	IPAddress            []string
	DefaultIPGateway     []string
	DNSServerSearchOrder []string
	DNSDomain            string
}

// collectNetwork builds a full per-adapter view. WMI gives names, type, speed,
// status, DHCP and DNS; Go's net package gives reliable address/MAC data. The
// two are joined on the normalised MAC.
func collectNetwork(s *protocol.TelemetrySnapshot) error {
	// Hardware adapters (names, type, speed, status) keyed by MAC.
	hw := map[string]win32NetworkAdapter{}
	var adapters []win32NetworkAdapter
	if err := query(nsCIMV2, "SELECT MACAddress, NetConnectionID, Name, AdapterTypeID, Speed, NetConnectionStatus, PhysicalAdapter, NetEnabled FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL", &adapters); err == nil {
		for _, a := range adapters {
			hw[NormalizeMAC(a.MACAddress)] = a
		}
	} else {
		s.Errors = append(s.Errors, "network: adapters: "+err.Error())
	}

	// IP configuration (DHCP, DNS, gateway) keyed by MAC.
	cfgByMAC := map[string]win32NetworkAdapterConfig{}
	var cfgs []win32NetworkAdapterConfig
	if err := query(nsCIMV2, "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE MACAddress IS NOT NULL", &cfgs); err == nil {
		for _, c := range cfgs {
			cfgByMAC[NormalizeMAC(c.MACAddress)] = c
		}
	} else {
		s.Errors = append(s.Errors, "network: config: "+err.Error())
	}

	ifaces, _ := net.Interfaces()
	seen := map[string]bool{}
	for _, ifi := range ifaces {
		mac := NormalizeMAC(ifi.HardwareAddr.String())
		if mac == "" {
			continue // skip loopback / interfaces without a MAC
		}
		seen[mac] = true
		a := protocol.NetworkAdapter{MACAddress: ifi.HardwareAddr.String()}

		var addrStrings []string
		if addrs, err := ifi.Addrs(); err == nil {
			for _, ad := range addrs {
				addrStrings = append(addrStrings, ad.String())
			}
		}
		a.IPv4Addresses, a.IPv6Addresses = SplitIPVersions(addrStrings)

		hwi, hasHW := hw[mac]
		cfg := cfgByMAC[mac]
		a.Name = firstNonEmpty(hwi.NetConnectionID, ifi.Name)
		a.Description = firstNonEmpty(cfg.Description, hwi.Name)
		a.Type = AdapterType(a.Name, a.Description, hwi.AdapterTypeID, hasHW)
		a.IsPhysical = hwi.PhysicalAdapter
		if hwi.NetConnectionStatus != 0 || hasHW {
			a.Status = NetConnectionStatusName(hwi.NetConnectionStatus)
		}
		if ifi.Flags&net.FlagUp != 0 && a.Status == "" {
			a.Status = "Connected"
		}
		if hwi.Speed > 0 {
			a.LinkSpeedMbps = hwi.Speed / 1_000_000
		}
		a.DHCPEnabled = cfg.DHCPEnabled
		a.DHCPServer = cfg.DHCPServer
		a.Gateways = cfg.DefaultIPGateway
		a.DNSServers = cfg.DNSServerSearchOrder
		a.DNSDomain = cfg.DNSDomain

		// Skip adapters that are down and have no addresses and aren't physical.
		if len(a.IPv4Addresses) == 0 && len(a.IPv6Addresses) == 0 && !a.IsPhysical {
			continue
		}
		s.Network = append(s.Network, a)
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// detectPublicIP fetches the machine's public IP from a configured endpoint.
// Best-effort and time-bounded; returns the IP or an error string.
func detectPublicIP(endpoint string, timeout time.Duration) (string, string) {
	if endpoint == "" {
		return "", ""
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err.Error()
	}
	req.Header.Set("User-Agent", "ImakerEndpointAgent")
	resp, err := client.Do(req)
	if err != nil {
		return "", err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "public IP service returned " + resp.Status
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err.Error()
	}
	ipStr := strings.TrimSpace(string(body))
	if net.ParseIP(ipStr) == nil {
		return "", "public IP service returned a non-IP response"
	}
	return ipStr, ""
}

func collectPublicIP(s *protocol.TelemetrySnapshot, endpoint string) error {
	ip, errStr := detectPublicIP(endpoint, 5*time.Second)
	s.PublicIP = ip
	s.PublicIPError = errStr
	return nil
}
