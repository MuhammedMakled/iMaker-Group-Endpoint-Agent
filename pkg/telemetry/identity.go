package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// placeholderSerials are values motherboard vendors leave in SMBIOS when the
// system builder never programs a serial (typical for custom-built PCs).
var placeholderSerials = map[string]bool{
	"": true, "to be filled by o.e.m.": true, "to be filled by oem": true,
	"default string": true, "system serial number": true, "chassis serial number": true,
	"base board serial number": true, "baseboard serial number": true, "serial number": true,
	"none": true, "n/a": true, "na": true, "not applicable": true, "not specified": true,
	"not available": true, "unknown": true, "invalid": true, "empty": true, "default": true,
	"oem": true, "o.e.m.": true, "o.e.m": true, "0123456789": true, "123456789": true,
	"1234567890": true, "12345678": true, "abcdefghij": true, "x.x": true, "sn12345678": true,
	"type1productconfigid": true, "system product name": true,
}

// ValidSerial reports whether s looks like a real, unique serial number.
func ValidSerial(s string) bool {
	n := strings.ToLower(strings.TrimSpace(strings.Trim(s, "\x00")))
	if placeholderSerials[n] || len(n) < 4 {
		return false
	}
	// Reject strings made of one repeated character: "00000000", "FFFFFFFF", "........", "        ".
	stripped := strings.NewReplacer("-", "", " ", "", ".", "", "_", "").Replace(n)
	if stripped == "" {
		return false
	}
	same := true
	for i := 1; i < len(stripped); i++ {
		if stripped[i] != stripped[0] {
			same = false
			break
		}
	}
	return !same
}

// knownBadUUIDs are SMBIOS UUIDs shipped identically on many boards.
var knownBadUUIDs = map[string]bool{
	"03000200-0400-0500-0006-000700080009": true, // common AMI default
	"00020003-0004-0005-0006-000700080009": true,
	"12345678-1234-5678-90ab-cddeefaabbcc": true,
}

// ValidUUID reports whether an SMBIOS UUID is usable as an identifier.
func ValidUUID(u string) bool {
	n := strings.ToLower(strings.TrimSpace(u))
	if len(n) != 36 || knownBadUUIDs[n] {
		return false
	}
	return ValidSerial(n)
}

// IdentityCandidates are the raw values gathered from WMI and the registry.
type IdentityCandidates struct {
	BIOSSerial            string
	EnclosureSerial       string
	EnclosureAssetTag     string // SMBIOS asset tag (settable in some BIOSes)
	BaseboardSerial       string
	BaseboardManufacturer string
	BaseboardProduct      string
	SMBIOSUUID            string
	BootDiskSerial        string
	PrimaryMAC            string
	MachineGUID           string
	RegistryAssetTag      string // set by IT: ImakerAgentService set-asset-tag
	ChassisTypes          []int32
}

// ChooseIdentity picks the most trustworthy serial and builds the fingerprint.
//
// Priority: BIOS system serial → chassis/enclosure serial → motherboard
// serial → SMBIOS UUID → hardware fingerprint. A PC that needed anything past
// the BIOS serial is flagged as a custom build.
func ChooseIdentity(c IdentityCandidates) protocol.AssetIdentity {
	clean := func(s string) string { return strings.TrimSpace(strings.Trim(s, "\x00 ")) }
	id := protocol.AssetIdentity{
		BIOSSerial:            clean(c.BIOSSerial),
		EnclosureSerial:       clean(c.EnclosureSerial),
		BaseboardSerial:       clean(c.BaseboardSerial),
		BaseboardManufacturer: clean(c.BaseboardManufacturer),
		BaseboardProduct:      clean(c.BaseboardProduct),
		SMBIOSUUID:            strings.ToUpper(clean(c.SMBIOSUUID)),
		BootDiskSerial:        clean(c.BootDiskSerial),
		PrimaryMAC:            strings.ToUpper(clean(c.PrimaryMAC)),
		MachineGUID:           strings.ToLower(clean(c.MachineGUID)),
		ChassisType:           ChassisTypeName(c.ChassisTypes),
	}
	id.HardwareFingerprint = Fingerprint(c)

	switch {
	case ValidSerial(id.BIOSSerial):
		id.SerialNumber, id.SerialSource = id.BIOSSerial, "bios"
	case ValidSerial(id.EnclosureSerial):
		id.SerialNumber, id.SerialSource, id.IsCustomBuild = id.EnclosureSerial, "enclosure", true
	case ValidSerial(id.BaseboardSerial):
		id.SerialNumber, id.SerialSource, id.IsCustomBuild = id.BaseboardSerial, "baseboard", true
	case ValidUUID(id.SMBIOSUUID):
		id.SerialNumber, id.SerialSource, id.IsCustomBuild = id.SMBIOSUUID, "smbios_uuid", true
	default:
		id.SerialNumber, id.SerialSource, id.IsCustomBuild = id.HardwareFingerprint, "fingerprint", true
	}

	switch {
	case strings.TrimSpace(c.RegistryAssetTag) != "":
		id.AssetTag, id.AssetTagSource = strings.TrimSpace(c.RegistryAssetTag), "registry"
	case ValidSerial(c.EnclosureAssetTag) && !strings.EqualFold(clean(c.EnclosureAssetTag), "no asset tag"):
		id.AssetTag, id.AssetTagSource = clean(c.EnclosureAssetTag), "smbios"
	}
	return id
}

// Fingerprint hashes the hardware identifiers that survive an OS reinstall.
// Format: HW-XXXXXXXXXXXXXXXX (16 hex chars). Falls back to MachineGuid.
func Fingerprint(c IdentityCandidates) string {
	var parts []string
	if ValidSerial(c.BaseboardSerial) {
		parts = append(parts, "mb:"+strings.ToUpper(strings.TrimSpace(c.BaseboardSerial)))
	}
	if ValidUUID(c.SMBIOSUUID) {
		parts = append(parts, "uuid:"+strings.ToUpper(strings.TrimSpace(c.SMBIOSUUID)))
	}
	if ValidSerial(c.BootDiskSerial) {
		parts = append(parts, "disk:"+strings.ToUpper(strings.TrimSpace(c.BootDiskSerial)))
	}
	if mac := strings.ToUpper(strings.TrimSpace(c.PrimaryMAC)); len(mac) >= 12 {
		parts = append(parts, "mac:"+mac)
	}
	if len(parts) == 0 {
		if g := strings.TrimSpace(c.MachineGUID); g != "" {
			parts = append(parts, "guid:"+strings.ToLower(g))
		} else {
			return ""
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "HW-" + strings.ToUpper(hex.EncodeToString(sum[:8]))
}

// ChassisTypeName maps SMBIOS chassis types to a short label.
func ChassisTypeName(types []int32) string {
	for _, t := range types {
		switch t {
		case 3, 4, 5, 6, 7, 15, 16:
			return "Desktop"
		case 8, 9, 10, 14, 31, 32:
			return "Laptop"
		case 13:
			return "All-in-One"
		case 35, 36:
			return "Mini PC"
		case 17, 23, 28:
			return "Server"
		case 30:
			return "Tablet"
		}
	}
	return "Unknown"
}
