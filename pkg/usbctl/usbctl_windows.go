//go:build windows

package usbctl

import (
	"golang.org/x/sys/windows/registry"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

const (
	usbstorKey = `SYSTEM\CurrentControlSet\Services\USBSTOR`
	policyKey  = `SYSTEM\CurrentControlSet\Control\StorageDevicePolicies`
)

// Status reads the current USB storage access state.
func Status() (protocol.USBStatus, error) {
	start := uint32(usbstorEnabled)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, usbstorKey, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		if v, _, err := k.GetIntegerValue("Start"); err == nil {
			start = uint32(v)
		}
		k.Close()
	}
	wp := uint32(0)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, policyKey, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		if v, _, err := k.GetIntegerValue("WriteProtect"); err == nil {
			wp = uint32(v)
		}
		k.Close()
	}
	return DeriveStatus(start, wp), nil
}

// Set applies a USB access mode. Requires SYSTEM/admin. A reboot or device
// re-plug may be needed for USBSTOR Start changes to take full effect on
// already-connected devices.
func Set(mode string) (protocol.USBStatus, error) {
	start, wp, err := DesiredRegistry(mode)
	if err != nil {
		return protocol.USBStatus{}, err
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, usbstorKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return protocol.USBStatus{}, err
	}
	if err := k.SetDWordValue("Start", start); err != nil {
		k.Close()
		return protocol.USBStatus{}, err
	}
	k.Close()

	// StorageDevicePolicies may not exist; create it for WriteProtect.
	pk, _, err := registry.CreateKey(registry.LOCAL_MACHINE, policyKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return protocol.USBStatus{}, err
	}
	if err := pk.SetDWordValue("WriteProtect", wp); err != nil {
		pk.Close()
		return protocol.USBStatus{}, err
	}
	pk.Close()

	return Status()
}
