package usbctl

import (
	"testing"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

func TestDeriveStatus(t *testing.T) {
	if s := DeriveStatus(3, 0); s.Mode != protocol.USBAllow || !s.StorageEnabled || s.WriteProtected {
		t.Errorf("allow: %+v", s)
	}
	if s := DeriveStatus(3, 1); s.Mode != protocol.USBReadOnly || !s.WriteProtected {
		t.Errorf("read-only: %+v", s)
	}
	if s := DeriveStatus(4, 0); s.Mode != protocol.USBBlock || s.StorageEnabled {
		t.Errorf("block: %+v", s)
	}
	// Disabled takes priority over a stale write-protect flag.
	if s := DeriveStatus(4, 1); s.Mode != protocol.USBBlock {
		t.Errorf("block should win: %+v", s)
	}
}

func TestDesiredRegistry(t *testing.T) {
	cases := map[string][2]uint32{
		protocol.USBAllow:    {3, 0},
		protocol.USBReadOnly: {3, 1},
		protocol.USBBlock:    {4, 0},
	}
	for mode, want := range cases {
		s, w, err := DesiredRegistry(mode)
		if err != nil || s != want[0] || w != want[1] {
			t.Errorf("%s: got (%d,%d) err %v, want %v", mode, s, w, err, want)
		}
	}
	if _, _, err := DesiredRegistry("nope"); err == nil {
		t.Error("invalid mode should error")
	}
	if ValidateMode("block") != nil || ValidateMode("x") == nil {
		t.Error("ValidateMode")
	}
}
