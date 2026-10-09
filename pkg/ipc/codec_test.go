package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

func pipeClient(t *testing.T, m *Mux, caller Caller) *Client {
	t.Helper()
	return NewClientWithDialer(func(ctx context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go m.ServeConn(context.Background(), b, caller)
		return a, nil
	})
}

func TestMuxRoundTrip(t *testing.T) {
	m := NewMux(nil)
	m.Handle("echo", func(ctx context.Context, p json.RawMessage) (any, error) {
		var v map[string]string
		if err := DecodeParams(p, &v); err != nil {
			return nil, err
		}
		v["caller"] = CallerFrom(ctx).User
		return v, nil
	})
	m.HandleAdmin("danger", func(ctx context.Context, p json.RawMessage) (any, error) { return "ok", nil })
	m.Handle("boom", func(ctx context.Context, p json.RawMessage) (any, error) { panic("x") })

	c := pipeClient(t, m, Caller{User: `IMAKER\ali`})
	var out map[string]string
	if err := c.Call(context.Background(), "echo", map[string]string{"a": "b"}, &out); err != nil {
		t.Fatal(err)
	}
	if out["a"] != "b" || out["caller"] != `IMAKER\ali` {
		t.Fatalf("got %v", out)
	}

	var rpcErr *protocol.RPCError
	err := c.Call(context.Background(), "danger", nil, nil)
	if !errors.As(err, &rpcErr) || rpcErr.Code != protocol.ErrUnauthorized {
		t.Fatalf("want unauthorized, got %v", err)
	}
	if err := pipeClient(t, m, Caller{IsAdmin: true}).Call(context.Background(), "danger", nil, nil); err != nil {
		t.Fatalf("admin should pass: %v", err)
	}
	err = c.Call(context.Background(), "nope", nil, nil)
	if !errors.As(err, &rpcErr) || rpcErr.Code != protocol.ErrMethodNotFound {
		t.Fatalf("want method not found, got %v", err)
	}
	err = c.Call(context.Background(), "boom", nil, nil)
	if !errors.As(err, &rpcErr) || rpcErr.Code != protocol.ErrInternal {
		t.Fatalf("panic should become internal error, got %v", err)
	}
}

type fakeSessions struct{ valid string }

func (f fakeSessions) Validate(token string) (string, bool) {
	if token != "" && token == f.valid {
		return "IMAKER\\it", true
	}
	return "", false
}

func TestPrivilegedRequiresSession(t *testing.T) {
	m := NewMux(nil)
	m.SetSessions(fakeSessions{valid: "good-token"})
	m.HandlePrivileged("wipe", func(ctx context.Context, p json.RawMessage) (any, error) {
		return map[string]string{"authed_as": AuthUserFrom(ctx)}, nil
	})

	admin := Caller{User: `IMAKER\it`, IsAdmin: true}

	// Admin but no session token -> rejected.
	c := pipeClient(t, m, admin)
	var rpcErr *protocol.RPCError
	if err := c.Call(context.Background(), "wipe", nil, nil); !errors.As(err, &rpcErr) || rpcErr.Code != protocol.ErrUnauthorized {
		t.Fatalf("privileged call without session must be unauthorized, got %v", err)
	}

	// Admin with a valid token -> allowed, and the authed user is on ctx.
	c2 := pipeClient(t, m, admin)
	c2.Token = "good-token"
	var out map[string]string
	if err := c2.Call(context.Background(), "wipe", nil, &out); err != nil {
		t.Fatalf("valid session should pass: %v", err)
	}
	if out["authed_as"] != `IMAKER\it` {
		t.Fatalf("authed user not propagated: %+v", out)
	}

	// Non-admin with a valid token -> still rejected (admin check comes first).
	c3 := pipeClient(t, m, Caller{User: `IMAKER\ali`})
	c3.Token = "good-token"
	if err := c3.Call(context.Background(), "wipe", nil, nil); !errors.As(err, &rpcErr) || rpcErr.Code != protocol.ErrUnauthorized {
		t.Fatalf("non-admin must be rejected even with a token, got %v", err)
	}
}
