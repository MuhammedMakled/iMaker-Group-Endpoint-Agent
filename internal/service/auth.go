package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/auth"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// setupAuth initialises the global-admin credential store + session manager.
func (c *Core) setupAuth(dir string) error {
	cs, err := auth.NewCredentialStore(dir)
	if err != nil {
		return err
	}
	c.cred = cs
	c.authMgr = auth.NewManager(cs, auth.ManagerConfig{IdleTimeout: c.cfg.AdminIdleTimeout.D()})
	return nil
}

func (c *Core) registerAuth(m *ipc.Mux) {
	if c.authMgr == nil {
		return
	}
	m.SetSessions(c.authMgr)
	m.HandleAdmin(protocol.MethodAuthStatus, c.handleAuthStatus)
	m.HandleAdmin(protocol.MethodAuthSetPassword, c.handleAuthSetPassword)
	m.HandleAdmin(protocol.MethodAuthLogin, c.handleAuthLogin)
	m.HandleAdmin(protocol.MethodAuthLogout, c.handleAuthLogout)
}

func (c *Core) handleAuthStatus(ctx context.Context, _ json.RawMessage) (any, error) {
	res := protocol.AuthStatusResult{
		PasswordSet:        c.cred.IsSet(),
		IdleTimeoutSeconds: int(c.authMgr.IdleTimeout().Seconds()),
	}
	if lu := c.authMgr.LockedUntil(); !lu.IsZero() {
		res.LockedUntil = lu.Format(time.RFC3339)
	}
	return res, nil
}

func (c *Core) handleAuthSetPassword(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.AuthSetPasswordParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	caller := ipc.CallerFrom(ctx)
	wasSet := c.cred.IsSet()

	// Once a password exists, the current one must be supplied correctly.
	// The first set (bootstrap) is allowed to any elevated admin.
	if wasSet && !c.cred.Verify(p.CurrentPassword) {
		err := errors.New("the current global admin password is incorrect")
		c.audit(caller, "auth_set_password", "", "REFUSED: wrong current password", err)
		return nil, ipc.InvalidParams("%v", err)
	}
	if err := c.cred.Set(p.NewPassword); err != nil {
		c.audit(caller, "auth_set_password", "", "REFUSED: "+err.Error(), err)
		return nil, ipc.InvalidParams("%v", err)
	}
	word := "set (first time)"
	if wasSet {
		word = "changed"
	}
	c.audit(caller, "auth_set_password", "", "global admin password "+word, nil)
	return map[string]string{"status": "ok", "action": word}, nil
}

func (c *Core) handleAuthLogin(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.AuthLoginParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	caller := ipc.CallerFrom(ctx)
	tok, exp, err := c.authMgr.Login(caller.User, p.Password)
	if err != nil {
		c.audit(caller, "auth_login", "", "FAILED: "+err.Error(), err)
		return nil, &protocol.RPCError{Code: protocol.ErrUnauthorized, Message: err.Error()}
	}
	c.audit(caller, "auth_login", "", "logged in", nil)
	return protocol.AuthLoginResult{Token: tok, ExpiresAt: exp}, nil
}

func (c *Core) handleAuthLogout(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.AuthLogoutParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	if p.Token != "" {
		c.authMgr.Logout(p.Token)
	}
	return map[string]string{"status": "ok"}, nil
}
