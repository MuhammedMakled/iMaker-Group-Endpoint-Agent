package sysctl

import "testing"

func TestNormalizeStartMode(t *testing.T) {
	if NormalizeStartMode("Auto", false) != "Automatic" || NormalizeStartMode("Auto", true) != "Automatic (Delayed)" {
		t.Error("auto")
	}
	if NormalizeStartMode("Disabled", false) != "Disabled" {
		t.Error("disabled")
	}
}

func TestStartupIDRoundTrip(t *testing.T) {
	id := EncodeStartupID(LocHKLMRun, "Dropbox")
	loc, name, err := DecodeStartupID(id)
	if err != nil || loc != LocHKLMRun || name != "Dropbox" {
		t.Fatalf("roundtrip: %q %q %v", loc, name, err)
	}
	if _, _, err := DecodeStartupID("!!!notbase64"); err == nil {
		t.Error("bad id should error")
	}
}

func TestCriticalService(t *testing.T) {
	for _, n := range []string{"RpcSs", "winmgmt", "ImakerAgentService", "Schedule"} {
		if !IsCriticalService(n) {
			t.Errorf("%s should be protected", n)
		}
	}
	if IsCriticalService("Spooler") {
		t.Error("Spooler should be controllable")
	}
	if err := ValidateServiceAction("nope"); err == nil {
		t.Error("invalid action accepted")
	}
}
