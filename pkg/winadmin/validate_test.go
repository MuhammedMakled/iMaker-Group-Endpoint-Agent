package winadmin

import "testing"

func TestValidateComputerName(t *testing.T) {
	ok := []string{"DXB-ARCH-07", "PC1", "a", "WS-123"}
	bad := []string{"", "this-name-is-too-long", "-lead", "trail-", "123456", "bad_name", "spa ce"}
	for _, n := range ok {
		if err := ValidateComputerName(n); err != nil {
			t.Errorf("%q should be valid: %v", n, err)
		}
	}
	for _, n := range bad {
		if ValidateComputerName(n) == nil {
			t.Errorf("%q should be rejected", n)
		}
	}
}

func TestValidateUsername(t *testing.T) {
	if err := ValidateUsername("ali.hassan"); err != nil {
		t.Errorf("valid username rejected: %v", err)
	}
	for _, n := range []string{"", "has space is ok but not trailing ", "bad\\slash", "a:b", "toolongusernameover20c", "ends."} {
		if ValidateUsername(n) == nil {
			t.Errorf("%q should be rejected", n)
		}
	}
}

func TestResetConfirm(t *testing.T) {
	if ResetConfirmToken("dxb-arch-07") != "RESET DXB-ARCH-07" {
		t.Fatal("token format")
	}
	if err := CheckResetConfirm("reset DXB-ARCH-07", "DXB-ARCH-07"); err != nil {
		t.Errorf("case-insensitive match should pass: %v", err)
	}
	if CheckResetConfirm("RESET OTHER-PC", "DXB-ARCH-07") == nil {
		t.Error("wrong hostname must be rejected")
	}
	if CheckResetConfirm("yes", "DXB-ARCH-07") == nil {
		t.Error("loose confirmation must be rejected")
	}
}

func TestValidatePassword(t *testing.T) {
	if ValidatePassword("Str0ngPass!") != nil {
		t.Error("strong password rejected")
	}
	if ValidatePassword("short") == nil {
		t.Error("short password accepted")
	}
}
