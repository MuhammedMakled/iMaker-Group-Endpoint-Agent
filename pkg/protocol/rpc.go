package protocol

import (
	"encoding/json"
	"time"
)

// JSON-RPC 2.0 envelope used over the local named pipe. Messages are
// newline-delimited JSON (one object per line).

const JSONRPCVersion = "2.0"

type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	// Auth carries a global-admin session token for privileged methods.
	Auth string `json:"auth,omitempty"`
}

type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string { return e.Message }

// Standard + application error codes.
const (
	ErrParse          = -32700
	ErrInvalidRequest = -32600
	ErrMethodNotFound = -32601
	ErrInvalidParams  = -32602
	ErrInternal       = -32603
	ErrUnauthorized   = -32001
	ErrRateLimited    = -32002
)

// RPC method names. Phase 3 (actions/deployment) will add admin-only methods.
const (
	MethodPing            = "agent.ping"
	MethodActivitySubmit  = "activity.submit"
	MethodActivityQuery   = "activity.query"
	MethodActivitySummary = "activity.summary"
	MethodTelemetryGet    = "telemetry.get"
	MethodSoftwareList    = "software.list"
)

// ---- Method payloads ----

type PingResult struct {
	AgentVersion  string    `json:"agent_version"`
	SchemaVersion int       `json:"schema_version"`
	Hostname      string    `json:"hostname"`
	StartedAt     time.Time `json:"started_at"`
	Caller        string    `json:"caller,omitempty"`
	CallerIsAdmin bool      `json:"caller_is_admin"`
}

type ActivitySubmitParams struct {
	Sessions   []WorkSession `json:"sessions"`
	FileEvents []FileEvent   `json:"file_events"`
}

type ActivitySubmitResult struct {
	AcceptedSessions   int `json:"accepted_sessions"`
	AcceptedFileEvents int `json:"accepted_file_events"`
}

type ActivityQueryParams struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// User filter; non-admin callers can only query themselves.
	User string `json:"user,omitempty"`
}

type ActivityQueryResult struct {
	Sessions   []WorkSession `json:"sessions"`
	FileEvents []FileEvent   `json:"file_events"`
}

type ActivitySummaryParams struct {
	Date string `json:"date"` // YYYY-MM-DD (local). Empty = today.
	User string `json:"user,omitempty"`
}

type ActivitySummaryResult struct {
	Suggestions []TimesheetSuggestion `json:"suggestions"`
}

type TelemetryGetParams struct {
	Refresh bool `json:"refresh"`
}

type SoftwareListParams struct {
	Refresh bool   `json:"refresh"`
	Filter  string `json:"filter,omitempty"` // case-insensitive substring on name/publisher
}
