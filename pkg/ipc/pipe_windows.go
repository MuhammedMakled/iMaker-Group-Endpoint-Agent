//go:build windows

package ipc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// PipeSDDL grants full control to SYSTEM and Administrators and read/write to
// authenticated interactive users (so the tray app can connect). Admin-only
// RPC methods are enforced per call from the caller's process token.
const PipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"

// Server listens on a named pipe and serves a Mux.
type Server struct {
	PipeName string
	Mux      *Mux
	Logger   *slog.Logger

	ln net.Listener
	wg sync.WaitGroup
}

// Serve blocks until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	ln, err := winio.ListenPipe(s.PipeName, &winio.PipeConfig{
		SecurityDescriptor: PipeSDDL,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	})
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.PipeName, err)
	}
	s.ln = ln
	s.Logger.Info("ipc listening", "pipe", s.PipeName)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, winio.ErrPipeListenerClosed) {
				s.wg.Wait()
				return nil
			}
			s.Logger.Warn("ipc accept failed", "err", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		caller := identifyCaller(conn)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.Mux.ServeConn(ctx, conn, caller)
		}()
	}
}

// NewClient returns a client for the named pipe.
func NewClient(pipeName string) *Client {
	return NewClientWithDialer(func(ctx context.Context) (net.Conn, error) {
		return winio.DialPipeContext(ctx, pipeName)
	})
}

// identifyCaller resolves the client process's user and admin status from its
// token. Best-effort: on failure the caller is anonymous and non-admin.
func identifyCaller(conn net.Conn) Caller {
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return Caller{}
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(fd.Fd()), &pid); err != nil {
		return Caller{}
	}
	c := Caller{PID: pid}
	ph, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return c
	}
	defer windows.CloseHandle(ph)
	var tok windows.Token
	if err := windows.OpenProcessToken(ph, windows.TOKEN_QUERY, &tok); err != nil {
		return c
	}
	defer tok.Close()

	if tu, err := tok.GetTokenUser(); err == nil {
		c.SID = tu.User.Sid.String()
		if acct, dom, _, err := tu.User.Sid.LookupAccount(""); err == nil {
			c.User = dom + `\` + acct
		}
		if tu.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
			c.IsAdmin = true
			return c
		}
	}
	c.IsAdmin = tokenHasEnabledAdminGroup(tok)
	return c
}

// tokenHasEnabledAdminGroup is true only for an *elevated* admin: under UAC
// the filtered token carries BUILTIN\Administrators as deny-only.
func tokenHasEnabledAdminGroup(tok windows.Token) bool {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	groups, err := tok.GetTokenGroups()
	if err != nil {
		return false
	}
	for _, g := range groups.AllGroups() {
		if g.Sid.Equals(admins) && g.Attributes&windows.SE_GROUP_ENABLED != 0 &&
			g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return true
		}
	}
	return false
}
