//go:build windows

package telemetry

import (
	"strconv"
	"strings"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

type win32DiskDrive struct {
	Index         uint32
	Model         string
	SerialNumber  string
	Size          uint64
	InterfaceType string
	Status        string
	PNPDeviceID   string
}

type msftPhysicalDisk struct {
	DeviceId          string
	FriendlyName      string
	SerialNumber      string
	MediaType         uint16
	BusType           uint16
	HealthStatus      uint16
	OperationalStatus []uint16
	Size              uint64
}

// msftStorageReliabilityCounter is the SMART/NVMe health log as surfaced by
// the Windows storage stack (same data as Get-StorageReliabilityCounter).
type msftStorageReliabilityCounter struct {
	DeviceId         string
	Temperature      *uint64
	Wear             *uint64
	PowerOnHours     *uint64
	ReadErrorsTotal  *uint64
	WriteErrorsTotal *uint64
}

// msStorageDriverFailurePredictStatus is the legacy ATA SMART verdict.
type msStorageDriverFailurePredictStatus struct {
	InstanceName   string
	PredictFailure bool
	Active         bool
}

type win32LogicalDisk struct {
	DeviceID   string
	VolumeName string
	FileSystem string
	Size       uint64
	FreeSpace  uint64
}

func collectPhysicalDisks(s *protocol.TelemetrySnapshot) error {
	var drives []win32DiskDrive
	if err := query(nsCIMV2, "SELECT * FROM Win32_DiskDrive", &drives); err != nil {
		return err
	}

	// Storage-stack health (Windows 8+). Keyed by DeviceId == Win32_DiskDrive.Index.
	phys := map[string]msftPhysicalDisk{}
	var pds []msftPhysicalDisk
	if err := query(nsStorage, "SELECT * FROM MSFT_PhysicalDisk", &pds); err == nil {
		for _, p := range pds {
			phys[p.DeviceId] = p
		}
	} else {
		s.Errors = append(s.Errors, "disks: MSFT_PhysicalDisk: "+err.Error())
	}

	rel := map[string]msftStorageReliabilityCounter{}
	var rcs []msftStorageReliabilityCounter
	if err := query(nsStorage, "SELECT * FROM MSFT_StorageReliabilityCounter", &rcs); err == nil {
		for _, r := range rcs {
			rel[r.DeviceId] = r
		}
	}

	var smart []msStorageDriverFailurePredictStatus
	_ = query(nsWMI, "SELECT * FROM MSStorageDriver_FailurePredictStatus", &smart) // ATA only; NVMe returns none

	for _, d := range drives {
		pd := protocol.PhysicalDisk{
			Index:         d.Index,
			Model:         cleanString(d.Model),
			SerialNumber:  cleanString(d.SerialNumber),
			SizeBytes:     d.Size,
			SizeGB:        gb(d.Size),
			InterfaceType: d.InterfaceType,
			WMIStatus:     d.Status,
			Health:        "Unknown",
			MediaType:     "Unspecified",
			BusType:       "Unknown",
		}
		id := strconv.FormatUint(uint64(d.Index), 10)
		if p, ok := phys[id]; ok {
			pd.BusType = BusTypeName(p.BusType)
			pd.MediaType = MediaTypeName(p.MediaType)
			pd.Health = HealthStatusName(p.HealthStatus)
			for _, o := range p.OperationalStatus {
				pd.OperationalStatus = append(pd.OperationalStatus, OperationalStatusName(o))
			}
			if pd.SerialNumber == "" {
				pd.SerialNumber = cleanString(p.SerialNumber)
			}
		}
		if r, ok := rel[id]; ok {
			pd.TemperatureC = u32(r.Temperature)
			pd.WearPercentUsed = u32(r.Wear)
			pd.PowerOnHours = u32(r.PowerOnHours)
			pd.ReadErrorsTotal = r.ReadErrorsTotal
			pd.WriteErrorsTotal = r.WriteErrorsTotal
		}
		pnp := strings.ToUpper(d.PNPDeviceID)
		for _, sm := range smart {
			if pnp != "" && strings.HasPrefix(strings.ToUpper(sm.InstanceName), pnp) {
				v := sm.PredictFailure
				pd.SmartPredictFailure = &v
				if v {
					pd.Health = "Unhealthy"
				}
			}
		}
		s.PhysicalDisks = append(s.PhysicalDisks, pd)
	}
	return nil
}

func collectVolumes(s *protocol.TelemetrySnapshot) error {
	var lds []win32LogicalDisk
	// DriveType 3 = local fixed disk.
	if err := query(nsCIMV2, "SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3", &lds); err != nil {
		return err
	}
	for _, l := range lds {
		v := protocol.LogicalVolume{
			DriveLetter: l.DeviceID,
			Label:       l.VolumeName,
			FileSystem:  l.FileSystem,
			SizeBytes:   l.Size,
			FreeBytes:   l.FreeSpace,
			SizeGB:      gb(l.Size),
			FreeGB:      gb(l.FreeSpace),
			LowSpace:    IsLowSpace(l.Size, l.FreeSpace),
		}
		if l.Size > 0 {
			v.UsedPercent = round2(float64(l.Size-l.FreeSpace) / float64(l.Size) * 100)
		}
		s.Volumes = append(s.Volumes, v)
	}
	return nil
}

func u32(p *uint64) *uint32 {
	if p == nil {
		return nil
	}
	v := uint32(*p)
	return &v
}
