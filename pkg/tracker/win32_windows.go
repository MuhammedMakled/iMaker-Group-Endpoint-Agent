//go:build windows

package tracker

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetWindowTextW   = user32.NewProc("GetWindowTextW")
	procGetWindowTextLen = user32.NewProc("GetWindowTextLengthW")
	procGetLastInputInfo = user32.NewProc("GetLastInputInfo")
	procGetTickCount     = kernel32.NewProc("GetTickCount")
)

// lastInputInfo mirrors LASTINPUTINFO.
type lastInputInfo struct {
	cbSize uint32
	dwTime uint32
}

// Win32Platform implements Platform using user32/kernel32.
// It must run in the interactive user's session (the tray app): a service in
// session 0 cannot see the user's desktop or input.
type Win32Platform struct {
	// exeCache avoids re-opening the same process every 2 seconds.
	exeCache map[uint32]cachedExe
}

type cachedExe struct {
	path string
	at   time.Time
}

func NewWin32Platform() *Win32Platform {
	return &Win32Platform{exeCache: map[uint32]cachedExe{}}
}

// ForegroundWindow implements Platform.
func (p *Win32Platform) ForegroundWindow() (WindowInfo, bool, error) {
	hwnd := windows.GetForegroundWindow()
	if hwnd == 0 {
		return WindowInfo{}, false, nil // locked / secure desktop
	}
	var pid uint32
	if _, err := windows.GetWindowThreadProcessId(hwnd, &pid); err != nil {
		return WindowInfo{}, false, fmt.Errorf("GetWindowThreadProcessId: %w", err)
	}
	title := windowText(hwnd)
	exe, err := p.processImage(pid)
	if err != nil {
		return WindowInfo{}, false, err
	}
	return WindowInfo{Handle: uintptr(hwnd), PID: pid, Process: exe, Title: title}, true, nil
}

func windowText(hwnd windows.HWND) string {
	n, _, _ := procGetWindowTextLen.Call(uintptr(hwnd))
	if n == 0 {
		return ""
	}
	if n > 2048 {
		n = 2048
	}
	buf := make([]uint16, n+1)
	r, _, _ := procGetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf[:r])
}

func (p *Win32Platform) processImage(pid uint32) (string, error) {
	now := time.Now()
	if c, ok := p.exeCache[pid]; ok && now.Sub(c.at) < time.Minute {
		return c.path, nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		// Elevated processes may deny access to a standard-user tray app.
		return "", fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", fmt.Errorf("QueryFullProcessImageName: %w", err)
	}
	path := windows.UTF16ToString(buf[:size])
	if len(p.exeCache) > 512 {
		p.exeCache = map[uint32]cachedExe{}
	}
	p.exeCache[pid] = cachedExe{path: path, at: now}
	return path, nil
}

// IdleDuration implements Platform via GetLastInputInfo. Both values are
// 32-bit tick counts, so unsigned subtraction handles the 49.7-day wrap.
func (p *Win32Platform) IdleDuration() (time.Duration, error) {
	lii := lastInputInfo{cbSize: uint32(unsafe.Sizeof(lastInputInfo{}))}
	r, _, err := procGetLastInputInfo.Call(uintptr(unsafe.Pointer(&lii)))
	if r == 0 {
		return 0, fmt.Errorf("GetLastInputInfo: %w", err)
	}
	now, _, _ := procGetTickCount.Call()
	idleMs := uint32(now) - lii.dwTime
	return time.Duration(idleMs) * time.Millisecond, nil
}
