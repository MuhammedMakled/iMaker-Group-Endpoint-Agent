//go:build windows

package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Process creation flags (winbase.h). Defined here so the code does not
// depend on which constants a given syscall package version exports.
const (
	createNoWindow         = 0x08000000
	detachedProcess        = 0x00000008
	createNewProcessGroup  = 0x00000200
	createBreakawayFromJob = 0x01000000
)

// WinOps implements Ops against the Service Control Manager and the file system.
type WinOps struct {
	ServiceName string // config.ServiceName
	TrayName    string // ImakerTrayApp.exe image name, for taskkill
}

// StopTray force-stops the tray so its executable can be replaced. A missing
// process is not an error for this purpose.
func (w WinOps) StopTray() error {
	cmd := exec.Command("taskkill.exe", "/F", "/IM", w.TrayName)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow, HideWindow: true}
	return cmd.Run()
}

// StopService stops the service and waits until it reports Stopped.
func (w WinOps) StopService(timeout time.Duration) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(w.ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		st, err = s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("service did not stop within %s", timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// StartService asks the SCM to start the service.
func (w WinOps) StartService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(w.ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

// CopyFile replaces dst with src. It writes a sibling temp file, flushes it,
// then renames it over dst, so a crash never leaves a half-written binary.
func (WinOps) CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// VerifySignature checks that path carries a valid Authenticode signature
// whose signer subject contains subject. Paths and the subject are passed
// through environment variables, never interpolated into the script.
func VerifySignature(path, subject string) error {
	if subject == "" {
		return errors.New("update_signer_subject is not set in agent.json")
	}
	const script = `$s = Get-AuthenticodeSignature -LiteralPath $env:IMK_UPD_PATH
if ($s.Status -eq 'Valid' -and $s.SignerCertificate -and $s.SignerCertificate.Subject.Contains($env:IMK_UPD_SUBJECT)) { 'OK' } else { 'BAD:' + $s.Status }`
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Env = append(os.Environ(), "IMK_UPD_PATH="+path, "IMK_UPD_SUBJECT="+subject)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow, HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("signature check failed for %s: %w", filepath.Base(path), err)
	}
	if got := string(out); got != "OK\r\n" && got != "OK\n" {
		return fmt.Errorf("signature check failed for %s: %s", filepath.Base(path), trimSpace(got))
	}
	return nil
}

// SpawnDetached starts exe with args in its own process group, outside the
// service's job object, so it keeps running after the service stops.
func SpawnDetached(exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: detachedProcess | createNewProcessGroup | createBreakawayFromJob | createNoWindow,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
