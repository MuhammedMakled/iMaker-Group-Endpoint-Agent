//go:build windows

package winadmin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procSetComputerNameEx = kernel32.NewProc("SetComputerNameExW")

	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd              = netapi32.NewProc("NetUserAdd")
	procNetUserSetInfo          = netapi32.NewProc("NetUserSetInfo")
	procNetLocalGroupAddMembers = netapi32.NewProc("NetLocalGroupAddMembers")
)

// ComputerNamePhysicalDnsHostname selector for SetComputerNameExW.
const computerNamePhysicalDnsHostname = 5

// RenamePC changes the computer name. A reboot (scheduled separately) is
// required for it to take effect. Caller must be elevated/SYSTEM.
func RenamePC(newName string) error {
	if err := ValidateComputerName(newName); err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(newName)
	if err != nil {
		return err
	}
	r, _, e := procSetComputerNameEx.Call(computerNamePhysicalDnsHostname, uintptr(unsafe.Pointer(p)))
	if r == 0 {
		return fmt.Errorf("SetComputerNameEx failed: %w", e)
	}
	return nil
}

// userInfo1 mirrors USER_INFO_1 for NetUserAdd (level 1).
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

type userInfo1011 struct {
	fullName *uint16
}

type localGroupMembersInfo3 struct {
	domainAndName *uint16
}

const (
	userPrivUser       = 1
	ufScript           = 0x0001
	ufNormalAccount    = 0x0200
	ufDontExpirePasswd = 0x10000
)

// CreateLocalUser creates a local account and optionally adds it to the local
// Administrators group. The password is passed straight to Windows and is
// never logged. Caller must be elevated/SYSTEM.
func CreateLocalUser(username, password, fullName, comment string, admin, passwordNeverExpires bool) (sid string, addedToAdmins bool, err error) {
	if err = ValidateUsername(username); err != nil {
		return "", false, err
	}
	if err = ValidatePassword(password); err != nil {
		return "", false, err
	}

	uName, _ := windows.UTF16PtrFromString(username)
	uPass, _ := windows.UTF16PtrFromString(password)
	flags := uint32(ufScript | ufNormalAccount)
	if passwordNeverExpires {
		flags |= ufDontExpirePasswd
	}
	info := userInfo1{name: uName, password: uPass, priv: userPrivUser, flags: flags}
	var parmErr uint32
	r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr)))
	if r != 0 {
		return "", false, fmt.Errorf("NetUserAdd failed: %w", netError(r))
	}
	// Zero the in-memory password copy as soon as the account exists.
	zeroUTF16(uPass)

	if fullName != "" {
		if fn, e := windows.UTF16PtrFromString(fullName); e == nil {
			ui := userInfo1011{fullName: fn}
			procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(uName)), 1011, uintptr(unsafe.Pointer(&ui)), 0)
		}
	}

	if s, _, _, e := windows.LookupSID("", username); e == nil {
		sid = s.String()
	}

	if admin {
		if err = addToAdministrators(username); err != nil {
			return sid, false, fmt.Errorf("account created but adding to Administrators failed: %w", err)
		}
		addedToAdmins = true
	}
	return sid, addedToAdmins, nil
}

func addToAdministrators(username string) error {
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	group, _, _, err := adminSID.LookupAccount("")
	if err != nil || group == "" {
		group = "Administrators"
	}
	gName, _ := windows.UTF16PtrFromString(group)
	member, _ := windows.UTF16PtrFromString(username)
	entry := localGroupMembersInfo3{domainAndName: member}
	r, _, _ := procNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(gName)), 3, uintptr(unsafe.Pointer(&entry)), 1)
	if r != 0 {
		return netError(r)
	}
	return nil
}

// ResetArgs returns the exact systemreset.exe command that a given scope maps
// to. Exposed so the service can log (and dry-run print) precisely what will
// run before anything happens.
func ResetArgs(scope string) []string {
	switch scope {
	case "remove_everything_clean":
		// Reset, remove everything, clean the drive (slower; for devices
		// leaving the company).
		return []string{"-factoryreset", "-cleanPC"}
	default:
		return []string{"-factoryreset"}
	}
}

// RunReset launches Windows' own reset engine (systemreset.exe) with the args
// for scope. This is the real, OS-native "Reset this PC → Remove everything"
// flow; the agent never deletes files itself. Caller must be elevated/SYSTEM
// and must already have validated the confirmation token and logged the action.
func RunReset(scope string) (string, error) {
	sysreset := filepath.Join(os.Getenv("SystemRoot"), "System32", "systemreset.exe")
	if _, err := os.Stat(sysreset); err != nil {
		return "", fmt.Errorf("systemreset.exe not found (this Windows edition may require the MDM RemoteWipe path): %w", err)
	}
	args := ResetArgs(scope)
	cmd := exec.Command(sysreset, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("launch systemreset.exe: %w", err)
	}
	// Do not Wait: the reset engine takes over the machine.
	return sysreset + " " + strings.Join(args, " "), nil
}

func zeroUTF16(p *uint16) {
	if p == nil {
		return
	}
	for i := uintptr(0); ; i++ {
		c := (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + i*2))
		if *c == 0 {
			break
		}
		*c = 0
	}
}

func netError(code uintptr) error {
	return fmt.Errorf("NetAPI status %d", code)
}
