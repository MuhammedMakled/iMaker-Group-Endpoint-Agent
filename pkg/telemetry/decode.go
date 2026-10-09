// Package telemetry collects PC health and inventory data inside the SYSTEM
// service: hardware specs, disk health (SMART / Storage reliability
// counters), BitLocker, antivirus/Defender, Windows Update state and the
// installed-software inventory.
//
// This file holds the pure decoding helpers (unit-tested on any OS); the
// WMI/registry collectors are in *_windows.go.
package telemetry

import (
	"math"
	"strings"
	"time"
)

// gb converts bytes to GB rounded to 2 decimals (1 GB = 1024^3).
func gb(b uint64) float64 { return round2(float64(b) / (1 << 30)) }

func round2(f float64) float64 { return math.Round(f*100) / 100 }

// DecodeAVProductState decodes SecurityCenter2 AntivirusProduct.productState.
// Layout (hex 0xAABBCC): BB = scanner state (0x10/0x11 on, 0x00/0x01 off),
// CC = signature state (0x00 up to date, 0x10 out of date).
func DecodeAVProductState(state uint32) (enabled, upToDate bool) {
	scanner := (state >> 8) & 0xFF
	sigs := state & 0xFF
	return scanner&0x10 != 0, sigs == 0x00
}

// BitLocker enumerations (Win32_EncryptableVolume).
func ProtectionStatusName(v uint32) string {
	switch v {
	case 0:
		return "Off"
	case 1:
		return "On"
	}
	return "Unknown"
}

func ConversionStatusName(v uint32) string {
	switch v {
	case 0:
		return "FullyDecrypted"
	case 1:
		return "FullyEncrypted"
	case 2:
		return "EncryptionInProgress"
	case 3:
		return "DecryptionInProgress"
	case 4:
		return "EncryptionPaused"
	case 5:
		return "DecryptionPaused"
	}
	return "Unknown"
}

func EncryptionMethodName(v uint32) string {
	switch v {
	case 0:
		return "None"
	case 1:
		return "AES-128-Diffuser"
	case 2:
		return "AES-256-Diffuser"
	case 3:
		return "AES-128"
	case 4:
		return "AES-256"
	case 5:
		return "HardwareEncryption"
	case 6:
		return "XTS-AES-128"
	case 7:
		return "XTS-AES-256"
	}
	return "Unknown"
}

func VolumeTypeName(v uint32) string {
	switch v {
	case 0:
		return "OperatingSystem"
	case 1:
		return "FixedData"
	case 2:
		return "Removable"
	}
	return "Unknown"
}

// MSFT_PhysicalDisk enumerations.
func BusTypeName(v uint16) string {
	names := map[uint16]string{
		1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "IEEE1394", 5: "SSA", 6: "FibreChannel",
		7: "USB", 8: "RAID", 9: "iSCSI", 10: "SAS", 11: "SATA", 12: "SD", 13: "MMC",
		15: "FileBackedVirtual", 16: "StorageSpaces", 17: "NVMe", 18: "SCM", 19: "UFS",
	}
	if n, ok := names[v]; ok {
		return n
	}
	return "Unknown"
}

func MediaTypeName(v uint16) string {
	switch v {
	case 3:
		return "HDD"
	case 4:
		return "SSD"
	case 5:
		return "SCM"
	}
	return "Unspecified"
}

func HealthStatusName(v uint16) string {
	switch v {
	case 0:
		return "Healthy"
	case 1:
		return "Warning"
	case 2:
		return "Unhealthy"
	}
	return "Unknown"
}

func OperationalStatusName(v uint16) string {
	names := map[uint16]string{
		1: "Other", 2: "OK", 3: "Degraded", 4: "Stressed", 5: "Predictive Failure",
		6: "Error", 7: "Non-Recoverable Error", 8: "Starting", 9: "Stopping", 10: "Stopped",
		11: "In Service", 12: "No Contact", 13: "Lost Communication", 14: "Aborted",
		15: "Dormant", 16: "Supporting Entity in Error", 17: "Completed", 18: "Power Mode",
		0xD00D: "Transient Error", 0xD00E: "Unrecognized Metadata", 0xD00F: "Failed Media",
		0xD010: "Split", 0xD011: "Stale Metadata", 0xD012: "IO Error",
	}
	if n, ok := names[v]; ok {
		return n
	}
	return "Unknown"
}

// ParseInstallDate normalises registry InstallDate values ("20240115",
// "2024-01-15", "1/15/2024") to YYYY-MM-DD; unparseable input is returned as-is.
func ParseInstallDate(s string) string {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"20060102", "2006-01-02", "1/2/2006", "01/02/2006", "2006/01/02"} {
		if t, err := time.Parse(layout, s); err == nil {
			if t.Year() < 1990 || t.Year() > 2100 {
				return ""
			}
			return t.Format("2006-01-02")
		}
	}
	return s
}

// ParseHotfixDate parses Win32_QuickFixEngineering.InstalledOn, which is
// usually "M/D/YYYY" but on some builds is a hex FILETIME string.
func ParseHotfixDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"1/2/2006", "01/02/2006", "2006-01-02", "20060102"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// IsLowSpace flags volumes with < 10 % or < 20 GB free.
func IsLowSpace(size, free uint64) bool {
	if size == 0 {
		return false
	}
	return float64(free)/float64(size) < 0.10 || free < 20<<30
}

// cleanString trims whitespace and NULs that WMI sometimes pads serials with.
func cleanString(s string) string {
	return strings.TrimSpace(strings.Trim(s, "\x00 "))
}

// EDIDString decodes a WmiMonitorID character array (one char per element,
// zero-padded) into a string.
func EDIDString(chars []int32) string {
	var b strings.Builder
	for _, c := range chars {
		if c == 0 {
			break
		}
		if c > 31 && c < 127 {
			b.WriteRune(rune(c))
		}
	}
	return strings.TrimSpace(b.String())
}

// pnpVendors maps common 3-letter EDID manufacturer codes to names.
var pnpVendors = map[string]string{
	"DEL": "Dell", "HWP": "HP", "HPN": "HP", "LEN": "Lenovo", "SAM": "Samsung", "SEC": "Samsung",
	"GSM": "LG", "LGD": "LG Display", "ACR": "Acer", "AUS": "ASUS", "BNQ": "BenQ", "PHL": "Philips",
	"VSC": "ViewSonic", "AOC": "AOC", "MSI": "MSI", "GBT": "Gigabyte", "EIZ": "EIZO", "NEC": "NEC",
	"SNY": "Sony", "APP": "Apple", "AUO": "AU Optronics", "BOE": "BOE", "CMN": "Chimei Innolux",
	"SHP": "Sharp", "IVM": "iiyama", "HKC": "HKC", "XMI": "Xiaomi", "HUA": "Huawei",
}

// PNPVendorName expands a PNP vendor code; unknown codes are returned as-is.
func PNPVendorName(code string) string {
	if n, ok := pnpVendors[strings.ToUpper(code)]; ok {
		return n
	}
	return code
}
