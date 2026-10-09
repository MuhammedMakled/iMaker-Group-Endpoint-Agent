//go:build windows

package telemetry

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

var (
	modnetapi32                 = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupGetMembers = modnetapi32.NewProc("NetLocalGroupGetMembers")
	procNetAPIBufferFree        = modnetapi32.NewProc("NetApiBufferFree")
)

// localGroupMembersInfo2 mirrors LOCALGROUP_MEMBERS_INFO_2.
type localGroupMembersInfo2 struct {
	Sid           *windows.SID
	SidUsage      uint32
	DomainAndName *uint16
}

const (
	sidTypeUser           = 1
	sidTypeGroup          = 2
	sidTypeDomain         = 3
	sidTypeWellKnownGroup = 5
	sidTypeAlias          = 4
)

// collectLocalAdmins lists the members of the built-in Administrators group.
// This is a read-only audit used to spot users who shouldn't have admin rights.
func collectLocalAdmins(s *protocol.TelemetrySnapshot) error {
	// Resolve BUILTIN\Administrators (S-1-5-32-544) to its (possibly localized) name.
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	name, _, _, err := adminSID.LookupAccount("")
	if err != nil || name == "" {
		name = "Administrators"
	}
	groupName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}

	var buf *byte
	var read, total uint32
	const level = 2
	const prefMaxLen = 0xFFFFFFFF // MAX_PREFERRED_LENGTH
	r, _, _ := procNetLocalGroupGetMembers.Call(
		0, uintptr(unsafe.Pointer(groupName)), level,
		uintptr(unsafe.Pointer(&buf)), prefMaxLen,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), 0,
	)
	if r != 0 {
		return fmt.Errorf("NetLocalGroupGetMembers: error %d", r)
	}
	defer procNetAPIBufferFree.Call(uintptr(unsafe.Pointer(buf)))

	entries := unsafe.Slice((*localGroupMembersInfo2)(unsafe.Pointer(buf)), int(read))
	for _, e := range entries {
		acc := protocol.LocalAccount{
			Name: windows.UTF16PtrToString(e.DomainAndName),
			Type: sidUsageName(e.SidUsage),
		}
		if e.Sid != nil {
			acc.SID = e.Sid.String()
			acc.Local = isLocalSID(acc.SID)
		}
		acc.Disabled = accountDisabled(acc.Name, acc.Local)
		s.LocalAdmins = append(s.LocalAdmins, acc)
	}
	return nil
}

func sidUsageName(u uint32) string {
	switch u {
	case sidTypeUser:
		return "User"
	case sidTypeGroup, sidTypeWellKnownGroup, sidTypeAlias:
		return "Group"
	case sidTypeDomain:
		return "Domain"
	}
	return "Other"
}

// isLocalSID is true for accounts in this machine's own SID domain.
func isLocalSID(sid string) bool {
	local, err := localMachineSID()
	if err != nil || local == "" {
		return false
	}
	return len(sid) > len(local) && sid[:len(local)] == local
}

var cachedMachineSID string

func localMachineSID() (string, error) {
	if cachedMachineSID != "" {
		return cachedMachineSID, nil
	}
	host, err := windows.ComputerName()
	if err != nil {
		return "", err
	}
	sid, _, _, err := lookupName(host)
	if err != nil {
		return "", err
	}
	cachedMachineSID = sid
	return sid, nil
}

func lookupName(name string) (sid string, domain string, use uint32, err error) {
	s, dom, u, e := windows.LookupSID("", name)
	if e != nil {
		return "", "", 0, e
	}
	return s.String(), dom, u, nil
}

// accountDisabled reports whether a local user account is disabled.
func accountDisabled(domainAndName string, local bool) bool {
	if !local {
		return false // can't cheaply check domain accounts
	}
	user := domainAndName
	if i := indexByte(domainAndName, '\\'); i >= 0 {
		user = domainAndName[i+1:]
	}
	info, err := netUserInfo1(user)
	if err != nil {
		return false
	}
	const ufAccountDisable = 0x0002
	return info.flags&ufAccountDisable != 0
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
