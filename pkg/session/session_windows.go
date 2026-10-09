//go:build windows

// Package session implements remote lock and sign-out of the interactive
// Windows user session. The service runs as LocalSystem in session 0, so it
// cannot lock the user's desktop directly; it launches the lock in the user's
// own session via CreateProcessAsUser, and signs a session out with
// WTSLogoffSession.
package session

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

var (
	wtsapi32             = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSLogoffSession = wtsapi32.NewProc("WTSLogoffSession")
	procWTSEnumerateW    = wtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSQuerySessionW = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory    = wtsapi32.NewProc("WTSFreeMemory")

	userenv                     = windows.NewLazySystemDLL("userenv.dll")
	procCreateEnvironmentBlock  = userenv.NewProc("CreateEnvironmentBlock")
	procDestroyEnvironmentBlock = userenv.NewProc("DestroyEnvironmentBlock")
)

const wtsCurrentServer = 0

// WTS_INFO_CLASS values.
const (
	wtsUserName    = 5
	wtsWinStaName  = 6
	wtsSessionInfo = 24
)

// ActiveSessionID returns the current physical-console session.
func ActiveSessionID() uint32 { return windows.WTSGetActiveConsoleSessionId() }

// LockSession locks the given session's desktop. If sessionID is 0 the active
// console session is used. It runs rundll32 user32,LockWorkStation inside the
// target user's session.
func LockSession(sessionID uint32) (uint32, string, error) {
	if sessionID == 0 {
		sessionID = ActiveSessionID()
	}
	if sessionID == 0xFFFFFFFF {
		return 0, "", fmt.Errorf("no active console session to lock")
	}
	user := sessionUser(sessionID)

	var userToken windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &userToken); err != nil {
		return sessionID, user, fmt.Errorf("WTSQueryUserToken(%d): %w", sessionID, err)
	}
	defer userToken.Close()

	cmd := windows.StringToUTF16Ptr(`C:\Windows\System32\rundll32.exe user32.dll,LockWorkStation`)
	desktop := windows.StringToUTF16Ptr(`winsta0\default`)

	var env *uint16
	if r, _, _ := procCreateEnvironmentBlock.Call(uintptr(unsafe.Pointer(&env)), uintptr(userToken), 0); r != 0 {
		defer procDestroyEnvironmentBlock.Call(uintptr(unsafe.Pointer(env)))
	}

	si := windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	err := windows.CreateProcessAsUser(userToken, nil, cmd, nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, env, nil, &si, &pi)
	if err != nil {
		return sessionID, user, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return sessionID, user, nil
}

// SignoutSession logs the given session off. sessionID 0 = active console.
func SignoutSession(sessionID uint32) (uint32, string, error) {
	if sessionID == 0 {
		sessionID = ActiveSessionID()
	}
	if sessionID == 0xFFFFFFFF {
		return 0, "", fmt.Errorf("no active console session to sign out")
	}
	user := sessionUser(sessionID)
	// WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, sessionId, bWait=TRUE)
	r, _, e := procWTSLogoffSession.Call(wtsCurrentServer, uintptr(sessionID), 1)
	if r == 0 {
		return sessionID, user, fmt.Errorf("WTSLogoffSession(%d): %w", sessionID, e)
	}
	return sessionID, user, nil
}

// wtsSessionInfoW mirrors WTS_SESSION_INFOW.
type wtsSessionInfoW struct {
	SessionID      uint32
	WinStationName *uint16
	State          uint32
}

// WTS connection states.
var wtsStateNames = map[uint32]string{
	0: "Active", 1: "Connected", 2: "ConnectQuery", 3: "Shadow", 4: "Disconnected",
	5: "Idle", 6: "Listen", 7: "Reset", 8: "Down", 9: "Init",
}

// ListSessions enumerates interactive sessions with a logged-on user.
func ListSessions() ([]protocol.UserSession, error) {
	var pinfo *wtsSessionInfoW
	var count uint32
	r, _, e := procWTSEnumerateW.Call(wtsCurrentServer, 0, 1,
		uintptr(unsafe.Pointer(&pinfo)), uintptr(unsafe.Pointer(&count)))
	if r == 0 {
		return nil, fmt.Errorf("WTSEnumerateSessions: %w", e)
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(pinfo)))

	infos := unsafe.Slice(pinfo, int(count))
	var out []protocol.UserSession
	for _, s := range infos {
		user := sessionUser(s.SessionID)
		if user == "" {
			continue // no interactive user (Services, listener)
		}
		out = append(out, protocol.UserSession{
			SessionID: s.SessionID,
			User:      user,
			State:     wtsStateNames[s.State],
			Station:   windows.UTF16PtrToString(s.WinStationName),
		})
	}
	return out, nil
}

// sessionUser returns DOMAIN\user for a session, or "".
func sessionUser(sessionID uint32) string {
	name := queryStr(sessionID, wtsUserName)
	if name == "" {
		return ""
	}
	if dom := queryStr(sessionID, 7 /* WTSDomainName */); dom != "" {
		return dom + `\` + name
	}
	return name
}

func queryStr(sessionID uint32, infoClass uint32) string {
	var buf *uint16
	var bytes uint32
	r, _, _ := procWTSQuerySessionW.Call(wtsCurrentServer, uintptr(sessionID), uintptr(infoClass),
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&bytes)))
	if r == 0 || buf == nil {
		return ""
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf)
}
