package protocol

import "time"

// Notification severities. Critical notifications stay on screen until the
// user dismisses them and fall back to a dialog if toasts are unavailable.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Notification categories (free text is allowed; these are the common ones).
const (
	CategoryUpdate = "update" // software / Windows / agent update
	CategoryIT     = "it"     // IT announcement, maintenance window
	CategoryHealth = "health" // automatic alert from the agent (disk full, restart needed)
	CategoryPolicy = "policy"
)

// Notification is a message shown to users as a Windows toast by the tray app.
type Notification struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	Severity  string    `json:"severity"`           // info | warning | critical
	Category  string    `json:"category,omitempty"` // update | it | health | policy
	// URL is opened when the user clicks the notification or its button.
	URL         string `json:"url,omitempty"`
	ButtonLabel string `json:"button_label,omitempty"`
	// Users limits delivery to these DOMAIN\user accounts; empty = everyone
	// who signs in to this PC.
	Users  []string `json:"users,omitempty"`
	Source string   `json:"source,omitempty"` // cli | dashboard | agent
}

// NotificationStatus adds delivery tracking for admins.
type NotificationStatus struct {
	Notification
	DeliveredTo []string `json:"delivered_to"`
	Expired     bool     `json:"expired"`
}

type NotifySendParams struct {
	Notification
	// TTL overrides ExpiresAt, e.g. "24h". Default 72h.
	TTL string `json:"ttl,omitempty"`
}

type NotifyPollResult struct {
	Notifications []Notification `json:"notifications"`
}

type NotifyAckParams struct {
	IDs []string `json:"ids"`
}

type NotifyListResult struct {
	Notifications []NotificationStatus `json:"notifications"`
}

// RPC methods for identity and notifications.
const (
	MethodIdentity   = "agent.identity"
	MethodNotifySend = "notify.send" // admin only
	MethodNotifyPoll = "notify.poll"
	MethodNotifyAck  = "notify.ack"
	MethodNotifyList = "notify.list" // admin only
)
