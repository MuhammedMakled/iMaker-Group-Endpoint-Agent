//go:build windows

package telemetry

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procNetUserGetInfo = modnetapi32.NewProc("NetUserGetInfo")

// userInfo1 mirrors the fields of USER_INFO_1 that we read.
type userInfo1 struct {
	name        *uint16
	password    *uint16
	passwordAge uint32
	priv        uint32
	homeDir     *uint16
	comment     *uint16
	flags       uint32
	scriptPath  *uint16
}

// netUserInfo1 reads a local user account's flags (level 1).
func netUserInfo1(user string) (userInfo1, error) {
	var zero userInfo1
	u, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return zero, err
	}
	var buf *byte
	r, _, _ := procNetUserGetInfo.Call(0, uintptr(unsafe.Pointer(u)), 1, uintptr(unsafe.Pointer(&buf)))
	if r != 0 {
		return zero, fmt.Errorf("NetUserGetInfo: error %d", r)
	}
	defer procNetAPIBufferFree.Call(uintptr(unsafe.Pointer(buf)))
	return *(*userInfo1)(unsafe.Pointer(buf)), nil
}
