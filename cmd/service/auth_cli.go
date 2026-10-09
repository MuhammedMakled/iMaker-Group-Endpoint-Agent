//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// storedSession is the operator's cached login token (per Windows user).
type storedSession struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func sessionPath() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base, _ = os.UserHomeDir()
	}
	return filepath.Join(base, "Imaker", "session.json")
}

func loadToken() string {
	b, err := os.ReadFile(sessionPath())
	if err != nil {
		return ""
	}
	var s storedSession
	if json.Unmarshal(b, &s) != nil {
		return ""
	}
	// The service is the real authority on expiry (sliding idle window); this
	// local check only avoids obviously-dead tokens.
	if !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt.Add(24*time.Hour)) {
		return ""
	}
	return s.Token
}

func saveToken(token string, expires time.Time) error {
	p := sessionPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(storedSession{Token: token, ExpiresAt: expires})
	return os.WriteFile(p, b, 0o600)
}

func clearToken() { _ = os.Remove(sessionPath()) }

// authedClient returns an IPC client carrying the stored session token.
func authedClient(cfg *config.Config) *ipc.Client {
	cl := ipc.NewClient(pipeName(cfg))
	cl.Token = loadToken()
	return cl
}

// loginFlow prompts for the global admin password and caches the token.
func loginFlow(cfg *config.Config) error {
	pw, err := readHiddenPassword("Global admin password: ")
	if err != nil {
		return err
	}
	var res protocol.AuthLoginResult
	if err := ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodAuthLogin,
		protocol.AuthLoginParams{Password: pw}, &res); err != nil {
		return err
	}
	if err := saveToken(res.Token, res.ExpiresAt); err != nil {
		return err
	}
	fmt.Printf("Logged in. Session valid until you're idle for the configured timeout.\n")
	return nil
}

// ensurePrivileged runs fn (a privileged RPC call) and, if it fails because no
// valid session exists, prompts for login once and retries.
func ensurePrivileged(cfg *config.Config, fn func(cl *ipc.Client) error) error {
	cl := authedClient(cfg)
	err := fn(cl)
	if err == nil {
		return nil
	}
	var rpcErr *protocol.RPCError
	if errors.As(err, &rpcErr) && rpcErr.Code == protocol.ErrUnauthorized {
		fmt.Println("Global admin login required.")
		if lerr := loginFlow(cfg); lerr != nil {
			return lerr
		}
		cl = authedClient(cfg)
		return fn(cl)
	}
	return err
}

// setAdminPasswordFlow prompts for (current and) new password and sets it.
func setAdminPasswordFlow(cfg *config.Config) error {
	var st protocol.AuthStatusResult
	_ = ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodAuthStatus, nil, &st)

	var cur string
	var err error
	if st.PasswordSet {
		if cur, err = readHiddenPassword("Current global admin password: "); err != nil {
			return err
		}
	} else {
		fmt.Println("No global admin password is set yet — setting it for the first time.")
	}
	newPw, err := readHiddenPassword("New global admin password (min 10 chars, 3 character types): ")
	if err != nil {
		return err
	}
	confirm, err := readHiddenPassword("Confirm new password: ")
	if err != nil {
		return err
	}
	if newPw != confirm {
		return errors.New("passwords do not match")
	}
	var res map[string]string
	if err := ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodAuthSetPassword,
		protocol.AuthSetPasswordParams{NewPassword: newPw, CurrentPassword: cur}, &res); err != nil {
		return err
	}
	fmt.Println("Global admin password", res["action"]+".")
	clearToken() // force re-login with the new password
	return nil
}

// requireAdminForUninstall enforces that, once a global admin password is set,
// the agent can only be uninstalled by someone who knows it. This is the
// tamper-protection gate on removal. If the service isn't running (so we can't
// verify), we fall back to requiring the service be stopped intentionally and
// warn — a determined local admin can still remove it via the SCM, which the
// agent reports as a tamper alert on the next check-in.
func requireAdminForUninstall(cfg *config.Config) error {
	var st protocol.AuthStatusResult
	err := ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodAuthStatus, nil, &st)
	if err != nil {
		// Service not reachable — can't verify. Allow, but make it deliberate.
		fmt.Println("Warning: the agent service isn't reachable to verify the global admin password.")
		ok, _ := confirmYesNo("Continue uninstalling anyway?")
		if !ok {
			return errors.New("uninstall cancelled")
		}
		return nil
	}
	if !st.PasswordSet {
		return nil // no password configured yet
	}
	pw, err := readHiddenPassword("Global admin password (required to uninstall): ")
	if err != nil {
		return err
	}
	var res protocol.AuthLoginResult
	if err := ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodAuthLogin,
		protocol.AuthLoginParams{Password: pw}, &res); err != nil {
		return errors.New("incorrect global admin password; uninstall refused")
	}
	return nil
}

func confirmYesNo(prompt string) (bool, error) {
	fmt.Print(prompt + " [y/N]: ")
	line := readLine()
	l := strings.ToLower(strings.TrimSpace(line))
	return l == "y" || l == "yes", nil
}
