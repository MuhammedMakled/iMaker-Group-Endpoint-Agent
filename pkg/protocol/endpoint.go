package protocol

// ---- Remote lock & sign-out ----

const (
	MethodSessionLock    = "session.lock"    // privileged
	MethodSessionSignout = "session.signout" // privileged
	MethodSessionList    = "session.list"    // admin
)

type SessionActionParams struct {
	Reason string `json:"reason,omitempty"`
	// SessionID targets a specific session; 0 = the active console session.
	SessionID uint32 `json:"session_id,omitempty"`
}

type SessionActionResult struct {
	Action    string `json:"action"`
	SessionID uint32 `json:"session_id"`
	User      string `json:"user,omitempty"`
	Done      bool   `json:"done"`
}

type UserSession struct {
	SessionID uint32 `json:"session_id"`
	User      string `json:"user"`
	State     string `json:"state"` // Active | Disconnected | ...
	Station   string `json:"station,omitempty"`
}

type SessionListResult struct {
	Sessions []UserSession `json:"sessions"`
}

// ---- USB / removable storage control ----

const (
	MethodUSBStatus = "usb.status" // admin
	MethodUSBSet    = "usb.set"    // privileged
)

// USB access modes.
const (
	USBAllow    = "allow"     // USB storage enabled, read/write
	USBReadOnly = "read_only" // USB storage enabled, write-protected
	USBBlock    = "block"     // USB storage disabled
)

type USBStatus struct {
	Mode           string `json:"mode"`            // allow | read_only | block
	StorageEnabled bool   `json:"storage_enabled"` // USBSTOR service start != disabled
	WriteProtected bool   `json:"write_protected"`
	Detail         string `json:"detail,omitempty"`
}

type USBSetParams struct {
	Mode   string `json:"mode"` // allow | read_only | block
	Reason string `json:"reason,omitempty"`
}

// ---- IP allowlist (for the future dashboard uplink) ----

const (
	MethodIPAllowStatus = "ipallow.status" // admin
	MethodIPAllowCheck  = "ipallow.check"  // admin
)

type IPAllowStatus struct {
	Enabled bool     `json:"enabled"`
	Rules   []string `json:"rules"`
	// Active is false until the remote command uplink (Phase 3) is enabled;
	// everything is local-pipe only today.
	ActiveForRemote bool `json:"active_for_remote"`
}

type IPAllowCheckParams struct {
	IP string `json:"ip"`
}

type IPAllowCheckResult struct {
	IP      string `json:"ip"`
	Allowed bool   `json:"allowed"`
	Matched string `json:"matched,omitempty"`
}
