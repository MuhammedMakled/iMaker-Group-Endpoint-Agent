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
