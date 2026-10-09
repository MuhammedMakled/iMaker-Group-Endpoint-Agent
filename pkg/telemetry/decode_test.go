package telemetry

import "testing"

func TestDecodeAVProductState(t *testing.T) {
	cases := []struct {
		state       uint32
		on, current bool
	}{
		{0x061100, true, true},  // Defender on, up to date (397568)
		{0x060100, false, true}, // Defender off
		{0x061110, true, false}, // on, out of date
		{0x041000, true, true},  // third-party on, up to date
		{0x040100, false, true}, // third-party snoozed
	}
	for _, c := range cases {
		on, cur := DecodeAVProductState(c.state)
		if on != c.on || cur != c.current {
			t.Errorf("%#x: got on=%v current=%v", c.state, on, cur)
		}
	}
}

func TestParseInstallDate(t *testing.T) {
	for in, want := range map[string]string{
		"20240115":   "2024-01-15",
		"2024-01-15": "2024-01-15",
		"1/15/2024":  "2024-01-15",
		"garbage":    "garbage",
		"19000101":   "",
	} {
		if got := ParseInstallDate(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestEnums(t *testing.T) {
	if BusTypeName(17) != "NVMe" || MediaTypeName(4) != "SSD" || HealthStatusName(1) != "Warning" {
		t.Error("storage enum mismatch")
	}
	if ProtectionStatusName(1) != "On" || EncryptionMethodName(7) != "XTS-AES-256" || VolumeTypeName(0) != "OperatingSystem" {
		t.Error("bitlocker enum mismatch")
	}
	if !IsLowSpace(500<<30, 10<<30) || IsLowSpace(500<<30, 200<<30) {
		t.Error("low space")
	}
}
