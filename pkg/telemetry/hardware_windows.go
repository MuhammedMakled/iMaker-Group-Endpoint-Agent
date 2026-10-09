//go:build windows

package telemetry

import (
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

type win32ComputerSystem struct {
	Name                string
	Manufacturer        string
	Model               string
	Domain              string
	PartOfDomain        bool
	UserName            string
	TotalPhysicalMemory uint64
}

type win32OperatingSystem struct {
	Caption            string
	Version            string
	BuildNumber        string
	OSArchitecture     string
	InstallDate        time.Time
	LastBootUpTime     time.Time
	FreePhysicalMemory uint64 // KB
}

type win32BIOS struct {
	SerialNumber      string
	SMBIOSBIOSVersion string
}

type win32Processor struct {
	Name                      string
	Manufacturer              string
	NumberOfCores             uint32
	NumberOfLogicalProcessors uint32
	MaxClockSpeed             uint32
}

type win32VideoController struct {
	Name           string
	DriverVersion  string
	VideoProcessor string
	Status         string
	AdapterRAM     int64 // uint32 in WMI, may arrive as a negative VT_I4
	PNPDeviceID    string
}

func collectSystem(s *protocol.TelemetrySnapshot) error {
	var cs []win32ComputerSystem
	if err := query(nsCIMV2, "SELECT * FROM Win32_ComputerSystem", &cs); err != nil {
		return err
	}
	if len(cs) > 0 {
		c := cs[0]
		s.System.Manufacturer = cleanString(c.Manufacturer)
		s.System.Model = cleanString(c.Model)
		s.System.Domain = c.Domain
		s.System.PartOfDomain = c.PartOfDomain
		s.System.LoggedOnUser = c.UserName
		s.Memory.TotalBytes = c.TotalPhysicalMemory
		s.Memory.TotalGB = gb(c.TotalPhysicalMemory)
	}

	var osv []win32OperatingSystem
	if err := query(nsCIMV2, "SELECT * FROM Win32_OperatingSystem", &osv); err != nil {
		return err
	}
	if len(osv) > 0 {
		o := osv[0]
		s.OS = protocol.OSInfo{
			Caption:        cleanString(o.Caption),
			Version:        o.Version,
			BuildNumber:    o.BuildNumber,
			Architecture:   o.OSArchitecture,
			InstallDate:    o.InstallDate,
			LastBootUpTime: o.LastBootUpTime,
		}
		if !o.LastBootUpTime.IsZero() {
			s.OS.UptimeHours = round2(time.Since(o.LastBootUpTime).Hours())
		}
		s.OS.BuildNumber = displayBuild(o.BuildNumber)
		s.Memory.AvailableBytes = o.FreePhysicalMemory * 1024
		if s.Memory.TotalBytes > 0 {
			used := s.Memory.TotalBytes - min(s.Memory.AvailableBytes, s.Memory.TotalBytes)
			s.Memory.UsedPercent = round2(float64(used) / float64(s.Memory.TotalBytes) * 100)
		}
	}

	var bios []win32BIOS
	if err := query(nsCIMV2, "SELECT * FROM Win32_BIOS", &bios); err == nil && len(bios) > 0 {
		s.System.SerialNumber = cleanString(bios[0].SerialNumber)
		s.System.BIOSVersion = cleanString(bios[0].SMBIOSBIOSVersion)
	}
	return nil
}

// displayBuild appends the UBR (e.g. 22631.4317) so patch level is visible.
func displayBuild(build string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return build
	}
	defer k.Close()
	if ubr, _, err := k.GetIntegerValue("UBR"); err == nil && build != "" {
		return build + "." + strconv.FormatUint(ubr, 10)
	}
	return build
}

func collectCPU(s *protocol.TelemetrySnapshot) error {
	var cpus []win32Processor
	if err := query(nsCIMV2, "SELECT * FROM Win32_Processor", &cpus); err != nil {
		return err
	}
	for _, c := range cpus {
		s.CPU = append(s.CPU, protocol.CPUInfo{
			Name:              cleanString(c.Name),
			Manufacturer:      c.Manufacturer,
			PhysicalCores:     c.NumberOfCores,
			LogicalProcessors: c.NumberOfLogicalProcessors,
			MaxClockMHz:       c.MaxClockSpeed,
		})
	}
	return nil
}

func collectGPU(s *protocol.TelemetrySnapshot) error {
	var vcs []win32VideoController
	if err := query(nsCIMV2, "SELECT * FROM Win32_VideoController", &vcs); err != nil {
		return err
	}
	vram := gpuMemoryFromRegistry()
	for _, v := range vcs {
		ram := uint64(uint32(v.AdapterRAM))
		if r, ok := vram[strings.ToLower(cleanString(v.Name))]; ok && r > ram {
			ram = r // true 64-bit size (WMI caps at 4 GB)
		}
		s.GPUs = append(s.GPUs, protocol.GPUInfo{
			Name:            cleanString(v.Name),
			DriverVersion:   v.DriverVersion,
			AdapterRAMBytes: ram,
			VideoProcessor:  v.VideoProcessor,
			Status:          v.Status,
		})
	}
	return nil
}

// gpuMemoryFromRegistry reads HardwareInformation.qwMemorySize from the
// display adapter class key, keyed by lower-case DriverDesc.
func gpuMemoryFromRegistry() map[string]uint64 {
	const class = `SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}`
	out := map[string]uint64{}
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, class, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return out
	}
	defer root.Close()
	subs, _ := root.ReadSubKeyNames(-1)
	for _, sub := range subs {
		k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		desc, _, _ := k.GetStringValue("DriverDesc")
		if size, _, err := k.GetIntegerValue("HardwareInformation.qwMemorySize"); err == nil && desc != "" {
			out[strings.ToLower(strings.TrimSpace(desc))] = size
		}
		k.Close()
	}
	return out
}
