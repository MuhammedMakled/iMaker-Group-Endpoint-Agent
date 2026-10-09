package telemetry

import (
	"strings"
	"testing"
)

func TestValidSerial(t *testing.T) {
	good := []string{"5CD1234XYZ", "PF2ABCDE", "J7N0CV12345678", "MB-1234-5678"}
	bad := []string{"", "To be filled by O.E.M.", "Default string", "System Serial Number",
		"0123456789", "00000000", "FFFFFFFF", "........", "N/A", "123", "  \x00"}
	for _, s := range good {
		if !ValidSerial(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range bad {
		if ValidSerial(s) {
			t.Errorf("%q should be rejected", s)
		}
	}
	if ValidUUID("03000200-0400-0500-0006-000700080009") || ValidUUID("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF") {
		t.Error("placeholder UUIDs must be rejected")
	}
	if !ValidUUID("4C4C4544-0042-3510-8052-B3C04F4B3332") {
		t.Error("real UUID rejected")
	}
}

func TestChooseIdentityBrandedPC(t *testing.T) {
	id := ChooseIdentity(IdentityCandidates{BIOSSerial: "5CD1234XYZ", BaseboardSerial: "PXXXX123", ChassisTypes: []int32{10}})
	if id.SerialNumber != "5CD1234XYZ" || id.SerialSource != "bios" || id.IsCustomBuild || id.ChassisType != "Laptop" {
		t.Fatalf("%+v", id)
	}
}

func TestChooseIdentityCustomPC(t *testing.T) {
	c := IdentityCandidates{
		BIOSSerial:      "To be filled by O.E.M.",
		EnclosureSerial: "Default string",
		BaseboardSerial: "201234567890123",
		SMBIOSUUID:      "03000200-0400-0500-0006-000700080009",
		BootDiskSerial:  "S5GXNF0R123456",
		PrimaryMAC:      "a8:5e:45:12:34:56",
		ChassisTypes:    []int32{3},
	}
	id := ChooseIdentity(c)
	if id.SerialNumber != "201234567890123" || id.SerialSource != "baseboard" || !id.IsCustomBuild {
		t.Fatalf("custom PC should use motherboard serial: %+v", id)
	}
	if !strings.HasPrefix(id.HardwareFingerprint, "HW-") || len(id.HardwareFingerprint) != 19 {
		t.Fatalf("fingerprint: %q", id.HardwareFingerprint)
	}
	// Fingerprint is stable and changes when hardware changes.
	if Fingerprint(c) != id.HardwareFingerprint {
		t.Fatal("fingerprint not deterministic")
	}
	c2 := c
	c2.BootDiskSerial = "OTHERDISK999"
	if Fingerprint(c2) == id.HardwareFingerprint {
		t.Fatal("fingerprint should change with the boot disk")
	}

	// Everything is a placeholder → fingerprint becomes the serial.
	none := ChooseIdentity(IdentityCandidates{BIOSSerial: "Default string", BaseboardSerial: "Default string",
		BootDiskSerial: "S5GXNF0R123456"})
	if none.SerialSource != "fingerprint" || none.SerialNumber != none.HardwareFingerprint || none.SerialNumber == "" {
		t.Fatalf("%+v", none)
	}
}

func TestAssetTagPriority(t *testing.T) {
	id := ChooseIdentity(IdentityCandidates{BIOSSerial: "ABC12345", EnclosureAssetTag: "DELL-TAG-77", RegistryAssetTag: "IMK-UAE-0042"})
	if id.AssetTag != "IMK-UAE-0042" || id.AssetTagSource != "registry" {
		t.Fatalf("registry tag should win: %+v", id)
	}
	id = ChooseIdentity(IdentityCandidates{BIOSSerial: "ABC12345", EnclosureAssetTag: "No Asset Tag"})
	if id.AssetTag != "" {
		t.Fatalf("placeholder asset tag should be ignored: %+v", id)
	}
}
