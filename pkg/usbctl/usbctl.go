// Package usbctl controls removable USB storage access: allow (read/write),
// read-only (write-protected), or block (storage driver disabled). This
// prevents design-data leakage to personal USB drives.
//
// Two registry settings are used:
//   - HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Start
//     3 = enabled, 4 = disabled (blocks USB mass-storage entirely).
//   - HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect
//     1 = read-only, 0 = read/write (applies to removable media).
//
// Pure helpers here are unit-tested; the registry access is in usbctl_windows.go.
package usbctl

import (
	"errors"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

const (
	usbstorEnabled  = 3
	usbstorDisabled = 4
)

// ValidateMode checks a requested USB mode.
func ValidateMode(mode string) error {
	switch mode {
	case protocol.USBAllow, protocol.USBReadOnly, protocol.USBBlock:
		return nil
	}
	return errors.New("mode must be allow, read_only or block")
}

// DeriveStatus turns the two raw registry values into a USBStatus.
func DeriveStatus(usbstorStart uint32, writeProtect uint32) protocol.USBStatus {
	enabled := usbstorStart != usbstorDisabled
	wp := writeProtect == 1
	st := protocol.USBStatus{StorageEnabled: enabled, WriteProtected: wp}
	switch {
	case !enabled:
		st.Mode = protocol.USBBlock
		st.Detail = "USB mass-storage is disabled (USBSTOR Start=4)"
	case wp:
		st.Mode = protocol.USBReadOnly
		st.Detail = "USB storage is read-only (WriteProtect=1)"
	default:
		st.Mode = protocol.USBAllow
		st.Detail = "USB storage is allowed (read/write)"
	}
	return st
}

// DesiredRegistry returns the (USBSTOR Start, WriteProtect) values for a mode.
func DesiredRegistry(mode string) (usbstorStart uint32, writeProtect uint32, err error) {
	switch mode {
	case protocol.USBAllow:
		return usbstorEnabled, 0, nil
	case protocol.USBReadOnly:
		return usbstorEnabled, 1, nil
	case protocol.USBBlock:
		return usbstorDisabled, 0, nil
	}
	return 0, 0, errors.New("invalid mode")
}
