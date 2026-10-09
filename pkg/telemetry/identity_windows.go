//go:build windows

package telemetry

import (
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// AgentRegistryKey holds machine-level agent settings written by IT.
const AgentRegistryKey = `SOFTWARE\Imaker\Agent`

type win32SystemEnclosure struct {
	SerialNumber   string
	SMBIOSAssetTag string
	ChassisTypes   []int32
}

type win32BaseBoard struct {
	SerialNumber string
	Manufacturer string
	Product      string
}

type win32ComputerSystemProduct struct {
	UUID string
}

type win32DiskPartitionBoot struct {
	DiskIndex     uint32
	BootPartition bool
}

type win32DiskDriveSerial struct {
	Index        uint32
	SerialNumber string
}

type win32NetworkAdapterPhys struct {
	MACAddress  string
	PNPDeviceID string
}

// CollectIdentity gathers every hardware identifier and picks the best
// serial number. It never fails outright: missing sources are skipped.
func CollectIdentity() protocol.AssetIdentity {
	var c IdentityCandidates

	var bios []win32BIOS
	if query(nsCIMV2, "SELECT * FROM Win32_BIOS", &bios) == nil && len(bios) > 0 {
		c.BIOSSerial = bios[0].SerialNumber
	}
	var enc []win32SystemEnclosure
	if query(nsCIMV2, "SELECT * FROM Win32_SystemEnclosure", &enc) == nil && len(enc) > 0 {
		c.EnclosureSerial = enc[0].SerialNumber
		c.EnclosureAssetTag = enc[0].SMBIOSAssetTag
		c.ChassisTypes = enc[0].ChassisTypes
	}
	var bb []win32BaseBoard
	if query(nsCIMV2, "SELECT * FROM Win32_BaseBoard", &bb) == nil && len(bb) > 0 {
		c.BaseboardSerial, c.BaseboardManufacturer, c.BaseboardProduct = bb[0].SerialNumber, bb[0].Manufacturer, bb[0].Product
	}
	var csp []win32ComputerSystemProduct
	if query(nsCIMV2, "SELECT UUID FROM Win32_ComputerSystemProduct", &csp) == nil && len(csp) > 0 {
		c.SMBIOSUUID = csp[0].UUID
	}
	c.BootDiskSerial = bootDiskSerial()
	c.PrimaryMAC = onboardMAC()
	c.MachineGUID = machineGUID()
	c.RegistryAssetTag = GetAssetTag()

	return ChooseIdentity(c)
}

// bootDiskSerial returns the serial of the disk holding the boot/EFI partition.
func bootDiskSerial() string {
	var parts []win32DiskPartitionBoot
	if query(nsCIMV2, "SELECT DiskIndex, BootPartition FROM Win32_DiskPartition WHERE BootPartition = TRUE", &parts) != nil || len(parts) == 0 {
		return ""
	}
	var disks []win32DiskDriveSerial
	q := "SELECT Index, SerialNumber FROM Win32_DiskDrive WHERE Index = " + strconv.FormatUint(uint64(parts[0].DiskIndex), 10)
	if query(nsCIMV2, q, &disks) != nil || len(disks) == 0 {
		return ""
	}
	return strings.TrimSpace(disks[0].SerialNumber)
}

// onboardMAC returns the MAC of the first physical PCI network adapter
// (onboard Ethernet/Wi-Fi), ignoring USB dongles, VPN and virtual adapters.
func onboardMAC() string {
	var nics []win32NetworkAdapterPhys
	if query(nsCIMV2, "SELECT MACAddress, PNPDeviceID FROM Win32_NetworkAdapter WHERE PhysicalAdapter = TRUE", &nics) != nil {
		return ""
	}
	best := ""
	for _, n := range nics {
		if n.MACAddress == "" || !strings.HasPrefix(strings.ToUpper(n.PNPDeviceID), "PCI\\") {
			continue
		}
		if best == "" || n.MACAddress < best { // deterministic choice
			best = n.MACAddress
		}
	}
	return best
}

func machineGUID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("MachineGuid")
	return v
}

// GetAssetTag reads IT's asset tag from HKLM\SOFTWARE\Imaker\Agent\AssetTag.
func GetAssetTag() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, AgentRegistryKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("AssetTag")
	return strings.TrimSpace(v)
}

// SetAssetTag writes (or clears, when tag is empty) IT's asset tag. Requires admin.
func SetAssetTag(tag string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, AgentRegistryKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	tag = strings.TrimSpace(tag)
	if tag == "" {
		err := k.DeleteValue("AssetTag")
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}
	return k.SetStringValue("AssetTag", tag)
}

// ---- collector sections ----

func collectAsset(s *protocol.TelemetrySnapshot) error {
	s.Asset = CollectIdentity()
	return nil
}

type wmiMonitorID struct {
	InstanceName      string
	Active            bool
	ManufacturerName  []int32
	UserFriendlyName  []int32
	SerialNumberID    []int32
	ProductCodeID     []int32
	YearOfManufacture int32
}

func collectMonitors(s *protocol.TelemetrySnapshot) error {
	var mons []wmiMonitorID
	if err := query(nsWMI, "SELECT * FROM WmiMonitorID", &mons); err != nil {
		return err
	}
	for _, m := range mons {
		s.Monitors = append(s.Monitors, protocol.MonitorInfo{
			Manufacturer:      PNPVendorName(EDIDString(m.ManufacturerName)),
			Model:             EDIDString(m.UserFriendlyName),
			SerialNumber:      EDIDString(m.SerialNumberID),
			ProductCode:       EDIDString(m.ProductCodeID),
			YearOfManufacture: int(m.YearOfManufacture),
			Active:            m.Active,
		})
	}
	return nil
}

type win32NetworkAdapterConfiguration struct {
	Description      string
	MACAddress       string
	IPAddress        []string
	DefaultIPGateway []string
	DNSDomain        string
	DHCPEnabled      bool
}

func collectNetwork(s *protocol.TelemetrySnapshot) error {
	var cfgs []win32NetworkAdapterConfiguration
	if err := query(nsCIMV2, "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE", &cfgs); err != nil {
		return err
	}
	for _, c := range cfgs {
		s.Network = append(s.Network, protocol.NetworkAdapter{
			Description: c.Description,
			MACAddress:  c.MACAddress,
			IPAddresses: c.IPAddress,
			Gateways:    c.DefaultIPGateway,
			DNSDomain:   c.DNSDomain,
			DHCPEnabled: c.DHCPEnabled,
		})
	}
	return nil
}
