// Package ipc implements newline-delimited JSON-RPC 2.0 over a Windows named
// pipe (\\.\pipe\imaker_agent_ipc) between the tray app and the service.
//
// The transport-independent dispatcher lives here so it can be unit-tested
// with net.Pipe on any OS; the named-pipe listener/dialer are Windows-only.
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// MaxMessageBytes bounds a single request/response line.
const MaxMessageBytes = 8 << 20

// Caller identifies the process on the other end of the pipe, as verified by
// the server from the client's process token (not from the payload).
type Caller struct {
	PID     uint32
	User    string // DOMAIN\user
	SID     string
	IsAdmin bool // elevated Administrators member, or LocalSystem
}

type callerKey struct{}

// CallerFrom returns the verified caller stored in ctx (zero value if unknown).
func CallerFrom(ctx context.Context) Caller {
	c, _ := ctx.Value(callerKey{}).(Caller)
	return c
}

// WithCaller attaches caller info to ctx.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// HandlerFunc handles one RPC method. Return *protocol.RPCError for typed errors.
type HandlerFunc func(ctx context.Context, params json.RawMessage) (any, error)

type route struct {
	h         HandlerFunc
	adminOnly bool
}

// Mux routes JSON-RPC methods to handlers.
type Mux struct {
	mu     sync.RWMutex
	routes map[string]route
	log    *slog.Logger
}

func NewMux(log *slog.Logger) *Mux {
	if log == nil {
		log = slog.Default()
	}
	return &Mux{routes: map[string]route{}, log: log}
}

// Handle registers a method available to any authenticated local user.
func (m *Mux) Handle(method string, h HandlerFunc) { m.add(method, h, false) }

// HandleAdmin registers a method that requires an elevated admin or SYSTEM
// caller. Phase 3 actions (restart, rename, deploy) must use this.
func (m *Mux) HandleAdmin(method string, h HandlerFunc) { m.add(method, h, true) }

func (m *Mux) add(method string, h HandlerFunc, admin bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[method] = route{h: h, adminOnly: admin}
}

// ServeConn reads requests from conn until EOF or ctx cancellation.
func (m *Mux) ServeConn(ctx context.Context, conn io.ReadWriteCloser, caller Caller) {
	defer conn.Close()
	ctx = WithCaller(ctx, caller)
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), MaxMessageBytes)
	enc := json.NewEncoder(conn)
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		resp := m.dispatch(ctx, sc.Bytes())
		if err := enc.Encode(resp); err != nil {
			m.log.Debug("ipc write failed", "err", err)
			return
		}
	}
}

func (m *Mux) dispatch(ctx context.Context, line []byte) (resp protocol.RPCResponse) {
	resp.JSONRPC = protocol.JSONRPCVersion
	var req protocol.RPCRequest
	if err := json.Unmarshal(line, &req); err != nil {
		resp.Error = &protocol.RPCError{Code: protocol.ErrParse, Message: "parse error"}
		return
	}
	resp.ID = req.ID
	if req.JSONRPC != protocol.JSONRPCVersion || req.Method == "" {
		resp.Error = &protocol.RPCError{Code: protocol.ErrInvalidRequest, Message: "invalid request"}
		return
	}
	m.mu.RLock()
	r, ok := m.routes[req.Method]
	m.mu.RUnlock()
	if !ok {
		resp.Error = &protocol.RPCError{Code: protocol.ErrMethodNotFound, Message: "method not found: " + req.Method}
		return
	}
	caller := CallerFrom(ctx)
	if r.adminOnly && !caller.IsAdmin {
		m.log.Warn("unauthorized ipc call", "method", req.Method, "user", caller.User, "pid", caller.PID)
		resp.Error = &protocol.RPCError{Code: protocol.ErrUnauthorized, Message: "administrator privileges required"}
		return
	}

	defer func() {
		if p := recover(); p != nil {
			m.log.Error("ipc handler panic", "method", req.Method, "panic", p)
			resp.Result = nil
			resp.Error = &protocol.RPCError{Code: protocol.ErrInternal, Message: "internal error"}
		}
	}()
	start := time.Now()
	res, err := r.h(ctx, req.Params)
	m.log.Debug("ipc call", "method", req.Method, "user", caller.User, "ms", time.Since(start).Milliseconds(), "err", err)
	if err != nil {
		var rpcErr *protocol.RPCError
		if errors.As(err, &rpcErr) {
			resp.Error = rpcErr
		} else {
			resp.Error = &protocol.RPCError{Code: protocol.ErrInternal, Message: err.Error()}
		}
		return
	}
	b, err := json.Marshal(res)
	if err != nil {
		resp.Error = &protocol.RPCError{Code: protocol.ErrInternal, Message: "marshal result: " + err.Error()}
		return
	}
	resp.Result = b
	return
}

// InvalidParams is a convenience constructor.
func InvalidParams(format string, a ...any) *protocol.RPCError {
	return &protocol.RPCError{Code: protocol.ErrInvalidParams, Message: fmt.Sprintf(format, a...)}
}

// DecodeParams unmarshals params (empty params are allowed) into v.
func DecodeParams(params json.RawMessage, v any) error {
	if len(params) == 0 || string(params) == "null" {
		return nil
	}
	if err := json.Unmarshal(params, v); err != nil {
		return InvalidParams("invalid params: %v", err)
	}
	return nil
}

// ---------------------------------------------------------------------------

// Dialer opens a connection to the server.
type Dialer func(ctx context.Context) (net.Conn, error)

// Client is a simple request/response JSON-RPC client. It dials per call,
// which keeps it robust across service restarts (calls are infrequent).
type Client struct {
	dial    Dialer
	nextID  atomic.Int64
	Timeout time.Duration
}

func NewClientWithDialer(d Dialer) *Client {
	return &Client{dial: d, Timeout: 15 * time.Second}
}

// Call invokes method with params and decodes the result into out (may be nil).
func (c *Client) Call(ctx context.Context, method string, params, out any) error {
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return fmt.Errorf("ipc dial: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	req := protocol.RPCRequest{JSONRPC: protocol.JSONRPCVersion, ID: c.nextID.Add(1), Method: method}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		req.Params = b
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("ipc write: %w", err)
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), MaxMessageBytes)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return fmt.Errorf("ipc read: %w", err)
		}
		return fmt.Errorf("ipc read: connection closed")
	}
	var resp protocol.RPCResponse
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		return fmt.Errorf("ipc decode: %w", err)
	}
	if resp.Error != nil {
		return resp.Error
	}
	if out != nil && len(resp.Result) > 0 {
		return json.Unmarshal(resp.Result, out)
	}
	return nil
}
