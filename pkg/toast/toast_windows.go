//go:build windows

package toast

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// Toaster shows notifications for the current (interactive) user.
type Toaster struct {
	AppID       string // e.g. IMAKER.EndpointAgent
	DisplayName string // shown as the toast's source, e.g. "IMAKER IT"
	IconPath    string // PNG on disk
}

// Register creates HKCU\Software\Classes\AppUserModelId\<AppID> so Windows
// shows our name and icon on toasts. Safe to call on every start.
func (t *Toaster) Register() error {
	if !ValidAppID(t.AppID) {
		return fmt.Errorf("invalid toast app id %q", t.AppID)
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\AppUserModelId\`+t.AppID, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue("DisplayName", t.DisplayName); err != nil {
		return err
	}
	if t.IconPath != "" {
		_ = k.SetStringValue("IconUri", t.IconPath)
	}
	return nil
}

const psTemplate = `$ErrorActionPreference='Stop'
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime]
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s')))
$t = New-Object Windows.UI.Notifications.ToastNotification $x
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('%s').Show($t)`

// Show raises a toast. For critical notifications, a failure falls back to a
// top-most dialog so the message is never silently lost.
func (t *Toaster) Show(n protocol.Notification) error {
	err := t.showToast(n)
	if err != nil && n.Severity == protocol.SeverityCritical {
		go MessageBox(n.Title, n.Message+urlSuffix(n), true)
		return nil
	}
	return err
}

func (t *Toaster) showToast(n protocol.Notification) error {
	if !ValidAppID(t.AppID) {
		return errors.New("invalid app id")
	}
	payload := base64.StdEncoding.EncodeToString([]byte(BuildXML(n, t.DisplayName)))
	script := fmt.Sprintf(psTemplate, payload, t.AppID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-EncodedCommand", encodePS(script))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("toast: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// encodePS encodes a script for powershell -EncodedCommand (UTF-16LE base64).
func encodePS(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func urlSuffix(n protocol.Notification) string {
	if n.URL == "" {
		return ""
	}
	return "\n\nMore info: " + n.URL
}

var (
	user32         = windows.NewLazySystemDLL("user32.dll")
	procMessageBox = user32.NewProc("MessageBoxW")
)

const (
	mbOK            = 0x00000000
	mbIconInfo      = 0x00000040
	mbIconWarning   = 0x00000030
	mbTopMost       = 0x00040000
	mbSetForeground = 0x00010000
)

// MessageBox shows a blocking, top-most dialog (call from a goroutine).
func MessageBox(title, text string, warning bool) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	flags := uintptr(mbOK | mbTopMost | mbSetForeground | mbIconInfo)
	if warning {
		flags = uintptr(mbOK | mbTopMost | mbSetForeground | mbIconWarning)
	}
	procMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), flags)
}
