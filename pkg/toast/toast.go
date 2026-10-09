// Package toast shows Windows 10/11 toast notifications from the tray app.
//
// Toasts are raised through the WinRT ToastNotificationManager (via a hidden
// PowerShell host, which keeps the binary CGO-free) under the agent's own
// AppUserModelID, registered per user in HKCU so the toast shows "IMAKER IT"
// and the agent icon. Critical messages use the "reminder" scenario so they
// stay on screen, and fall back to a classic dialog if toasts fail.
package toast

import (
	"encoding/xml"
	"regexp"
	"strings"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// validAppID guards the value interpolated into the PowerShell script.
var validAppID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ValidAppID reports whether id is safe to use as an AppUserModelID.
func ValidAppID(id string) bool { return validAppID.MatchString(id) }

func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func attr(s string) string {
	return strings.ReplaceAll(esc(s), `"`, "&quot;")
}

// BuildXML renders the toast payload for a notification.
func BuildXML(n protocol.Notification, attribution string) string {
	var b strings.Builder
	b.WriteString(`<toast`)
	if n.URL != "" {
		b.WriteString(` activationType="protocol" launch="` + attr(n.URL) + `"`)
	}
	critical := n.Severity == protocol.SeverityCritical
	if critical {
		b.WriteString(` scenario="reminder"`)
	}
	b.WriteString(`><visual><binding template="ToastGeneric">`)
	title := n.Title
	if n.Severity == protocol.SeverityWarning {
		title = "⚠ " + title
	} else if critical {
		title = "⛔ " + title
	}
	b.WriteString(`<text>` + esc(title) + `</text>`)
	b.WriteString(`<text>` + esc(n.Message) + `</text>`)
	if attribution != "" {
		b.WriteString(`<text placement="attribution">` + esc(attribution) + `</text>`)
	}
	b.WriteString(`</binding></visual>`)

	if n.URL != "" || critical {
		b.WriteString(`<actions>`)
		if n.URL != "" {
			label := n.ButtonLabel
			if label == "" {
				label = "Open"
			}
			b.WriteString(`<action content="` + attr(label) + `" activationType="protocol" arguments="` + attr(n.URL) + `"/>`)
		}
		b.WriteString(`<action content="Dismiss" activationType="system" arguments="dismiss"/>`)
		b.WriteString(`</actions>`)
	}
	if critical {
		b.WriteString(`<audio src="ms-winsoundevent:Notification.Reminder"/>`)
	}
	b.WriteString(`</toast>`)
	return b.String()
}
