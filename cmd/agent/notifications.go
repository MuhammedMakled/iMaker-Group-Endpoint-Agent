//go:build windows

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/toast"
)

//go:embed assets/icon.png
var iconPNG []byte

const historySize = 20

// notifier polls the service for notifications and shows them as toasts.
type notifier struct {
	app     *app
	toaster *toast.Toaster
	path    string // history file

	mu      sync.Mutex
	history []protocol.Notification // newest first
	unread  int

	idMu     sync.Mutex
	identity *protocol.AssetIdentity
}

func newNotifier(a *app) *notifier {
	iconPath := filepath.Join(a.dataDir, "icon.png")
	_ = os.WriteFile(iconPath, iconPNG, 0o644)
	n := &notifier{
		app:     a,
		toaster: &toast.Toaster{AppID: a.cfg.ToastAppID, DisplayName: "IMAKER IT", IconPath: iconPath},
		path:    filepath.Join(a.dataDir, "notifications-history.json"),
	}
	if err := n.toaster.Register(); err != nil {
		a.log.Warn("toast registration failed", "err", err)
	}
	if b, err := os.ReadFile(n.path); err == nil {
		_ = json.Unmarshal(b, &n.history)
	}
	return n
}

// run polls until ctx is cancelled.
func (n *notifier) run(ctx context.Context) {
	t := time.NewTicker(n.app.cfg.NotificationPollInterval.D())
	defer t.Stop()
	// First poll shortly after logon so overnight messages appear promptly.
	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
	}
	for {
		n.pollOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (n *notifier) pollOnce(ctx context.Context) {
	var res protocol.NotifyPollResult
	if err := n.app.client.Call(ctx, protocol.MethodNotifyPoll, nil, &res); err != nil {
		n.app.log.Debug("notification poll failed", "err", err)
		return
	}
	if len(res.Notifications) == 0 {
		return
	}
	var ids []string
	for _, msg := range res.Notifications {
		if err := n.toaster.Show(msg); err != nil {
			n.app.log.Warn("toast failed; kept in tray history", "id", msg.ID, "err", err)
		} else {
			n.app.log.Info("notification shown", "id", msg.ID, "title", msg.Title)
		}
		n.remember(msg)
		ids = append(ids, msg.ID)
	}
	// Ack even if the toast failed: the message stays readable from the tray
	// menu, and we must not re-pop it every 30 seconds.
	if err := n.app.client.Call(ctx, protocol.MethodNotifyAck, protocol.NotifyAckParams{IDs: ids}, nil); err != nil {
		n.app.log.Warn("notification ack failed", "err", err)
	}
}

func (n *notifier) remember(msg protocol.Notification) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.history = append([]protocol.Notification{msg}, n.history...)
	if len(n.history) > historySize {
		n.history = n.history[:historySize]
	}
	n.unread++
	if b, err := json.MarshalIndent(n.history, "", "  "); err == nil {
		_ = os.WriteFile(n.path, b, 0o644)
	}
}

func (n *notifier) unreadCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.unread
}

// showHistory opens a dialog with the most recent notifications.
func (n *notifier) showHistory() {
	n.mu.Lock()
	n.unread = 0
	items := append([]protocol.Notification{}, n.history...)
	n.mu.Unlock()

	if len(items) == 0 {
		go toast.MessageBox("IMAKER IT — Notifications", "You have no notifications.", false)
		return
	}
	if len(items) > 5 {
		items = items[:5]
	}
	var b strings.Builder
	for i, m := range items {
		if i > 0 {
			b.WriteString("\n────────────────────\n")
		}
		fmt.Fprintf(&b, "%s  —  %s\n%s", m.CreatedAt.Local().Format("02 Jan 15:04"), m.Title, m.Message)
		if m.URL != "" {
			fmt.Fprintf(&b, "\n%s", m.URL)
		}
	}
	go toast.MessageBox("IMAKER IT — Recent notifications", b.String(), false)
}

// ---- PC identity (shown in the tray so users can quote it to IT) ----

func (n *notifier) loadIdentity(ctx context.Context) *protocol.AssetIdentity {
	n.idMu.Lock()
	defer n.idMu.Unlock()
	if n.identity != nil {
		return n.identity
	}
	var id protocol.AssetIdentity
	if err := n.app.client.Call(ctx, protocol.MethodIdentity, nil, &id); err != nil || id.SerialNumber == "" {
		return nil
	}
	n.identity = &id
	return n.identity
}

// identityLabel is the tray menu text, e.g. "PC: DXB-ARCH-07 · S/N 5CD1234XYZ".
func identityLabel(host string, id *protocol.AssetIdentity) string {
	if id == nil {
		return "PC: " + host
	}
	ref := id.AssetTag
	if ref == "" {
		ref = "S/N " + id.SerialNumber
	}
	return fmt.Sprintf("PC: %s · %s  (click to copy)", host, ref)
}

// identityText is what gets copied to the clipboard for IT tickets.
func identityText(host string, id *protocol.AssetIdentity) string {
	if id == nil {
		return host
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Computer: %s\r\n", host)
	if id.AssetTag != "" {
		fmt.Fprintf(&b, "Asset tag: %s\r\n", id.AssetTag)
	}
	fmt.Fprintf(&b, "Serial: %s (%s)\r\n", id.SerialNumber, id.SerialSource)
	fmt.Fprintf(&b, "Hardware ID: %s\r\n", id.HardwareFingerprint)
	return b.String()
}

// copyToClipboard uses the built-in clip.exe (no extra dependencies).
func copyToClipboard(text string) error {
	cmd := exec.Command("clip.exe")
	cmd.Stdin = strings.NewReader(text)
	hideWindow(cmd)
	return cmd.Run()
}

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}
