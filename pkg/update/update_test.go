package update

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodURL = "https://updates.imaker-group.co/agent/imaker-agent-1.5.0.zip"

func policy() Policy {
	return Policy{AllowedHosts: []string{"updates.imaker-group.co"}, Current: "1.4.0"}
}

func goodReq() Request {
	return Request{DownloadURL: goodURL, TargetVersion: "1.5.0", SHA256: strings.Repeat("ab", 32)}
}

func TestValidateRequest(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Request)
		pol    func(*Policy)
		ok     bool
	}{
		{name: "valid", ok: true},
		{name: "http refused", mutate: func(r *Request) { r.DownloadURL = "http://updates.imaker-group.co/a.zip" }},
		{name: "wrong host", mutate: func(r *Request) { r.DownloadURL = "https://evil.example.com/a.zip" }},
		{name: "suffix host refused", mutate: func(r *Request) { r.DownloadURL = "https://updates.imaker-group.co.evil.com/a.zip" }},
		{name: "credentials refused", mutate: func(r *Request) { r.DownloadURL = "https://u:p@updates.imaker-group.co/a.zip" }},
		{name: "non-443 port refused", mutate: func(r *Request) { r.DownloadURL = "https://updates.imaker-group.co:8443/a.zip" }},
		{name: "not a zip", mutate: func(r *Request) { r.DownloadURL = "https://updates.imaker-group.co/a.exe" }},
		{name: "short hash", mutate: func(r *Request) { r.SHA256 = "abc" }},
		{name: "non-hex hash", mutate: func(r *Request) { r.SHA256 = strings.Repeat("zz", 32) }},
		{name: "same version refused", mutate: func(r *Request) { r.TargetVersion = "1.4.0" }},
		{name: "downgrade refused", mutate: func(r *Request) { r.TargetVersion = "1.3.9" }},
		{name: "bad version", mutate: func(r *Request) { r.TargetVersion = "latest" }},
		{name: "no allowed hosts fails closed", pol: func(p *Policy) { p.AllowedHosts = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, p := goodReq(), policy()
			if tc.mutate != nil {
				tc.mutate(&r)
			}
			if tc.pol != nil {
				tc.pol(&p)
			}
			err := r.Validate(p)
			if tc.ok && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestVersionOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.5.0", "1.4.0", 1},
		{"1.4.0", "1.5.0", -1},
		{"1.10.0", "1.9.9", 1}, // numeric, not lexical
		{"1.5.0-abc1234", "1.5.0", 0},
		{"1.5", "1.5.0", 0},
	}
	for _, c := range cases {
		got, err := CompareVersions(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("CompareVersions(%s,%s)=%d,%v want %d", c.a, c.b, got, err, c.want)
		}
	}
}

func TestVerifySHA256(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f.bin")
	data := []byte("imaker bundle")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	good := hex.EncodeToString(sum[:])
	if err := VerifySHA256(p, good); err != nil {
		t.Fatalf("good hash rejected: %v", err)
	}
	if err := VerifySHA256(p, strings.ToUpper(good)); err != nil {
		t.Fatalf("uppercase hash should be accepted: %v", err)
	}
	if err := VerifySHA256(p, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong hash accepted")
	}
}

func makeZip(t *testing.T, entries map[string][]byte, order ...string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range order {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entries[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "bundle.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExtractBundle(t *testing.T) {
	good := map[string][]byte{ServiceExe: []byte("svc"), TrayExe: []byte("tray")}

	t.Run("exactly the two binaries", func(t *testing.T) {
		z := makeZip(t, good, ServiceExe, TrayExe)
		out, err := ExtractBundle(z, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 2 {
			t.Fatalf("extracted %d files", len(out))
		}
	})

	bad := map[string]struct {
		entries map[string][]byte
		order   []string
	}{
		"extra file":     {map[string][]byte{ServiceExe: []byte("a"), TrayExe: []byte("b"), "evil.dll": []byte("x")}, []string{ServiceExe, TrayExe, "evil.dll"}},
		"missing tray":   {map[string][]byte{ServiceExe: []byte("a")}, []string{ServiceExe}},
		"path traversal": {map[string][]byte{"../ImakerAgentService.exe": []byte("a"), TrayExe: []byte("b")}, []string{"../ImakerAgentService.exe", TrayExe}},
		"subdirectory":   {map[string][]byte{"x/ImakerAgentService.exe": []byte("a"), TrayExe: []byte("b")}, []string{"x/ImakerAgentService.exe", TrayExe}},
		"duplicate":      {map[string][]byte{ServiceExe: []byte("a"), TrayExe: []byte("b")}, []string{ServiceExe, ServiceExe}},
	}
	for name, tc := range bad {
		t.Run(name, func(t *testing.T) {
			z := makeZip(t, tc.entries, tc.order...)
			if _, err := ExtractBundle(z, t.TempDir()); err == nil {
				t.Fatal("unsafe bundle accepted")
			}
		})
	}
}

func TestDownloadLimitsAndRedirects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok.zip":
			_, _ = w.Write([]byte("0123456789"))
		case "/big.zip":
			_, _ = w.Write(bytes.Repeat([]byte("x"), 100))
		case "/redir-bad.zip":
			http.Redirect(w, r, "https://evil.example.com/x.zip", http.StatusFound)
		case "/missing.zip":
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := srv.Client()
	allowed := []string{"127.0.0.1"}
	ctx := context.Background()

	dst := filepath.Join(t.TempDir(), "ok.zip")
	if err := Download(ctx, client, srv.URL+"/ok.zip", dst, 1024, allowed); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if _, err := os.Stat(dst + ".part"); !os.IsNotExist(err) {
		t.Fatal("partial file left behind")
	}
	if err := Download(ctx, client, srv.URL+"/big.zip", filepath.Join(t.TempDir(), "b"), 10, allowed); err == nil {
		t.Fatal("oversize body accepted")
	}
	if err := Download(ctx, client, srv.URL+"/missing.zip", filepath.Join(t.TempDir(), "m"), 1024, allowed); err == nil {
		t.Fatal("404 accepted")
	}
	if err := Download(ctx, client, srv.URL+"/redir-bad.zip", filepath.Join(t.TempDir(), "r"), 1024, allowed); err == nil {
		t.Fatal("redirect to a non-allowed host followed")
	}
}

// fakeOps records calls and can fail specific steps.
type fakeOps struct {
	calls       []string
	failCopy    string // dst base name whose copy should fail
	healthy     bool   // StartService writes a healthy record for the target
	d           Dirs
	target      string
	copiedFiles map[string]string
}

func (f *fakeOps) StopTray() error { f.calls = append(f.calls, "stopTray"); return nil }
func (f *fakeOps) StopService(time.Duration) error {
	f.calls = append(f.calls, "stopService")
	return nil
}
func (f *fakeOps) StartService() error {
	f.calls = append(f.calls, "startService")
	if f.healthy {
		return WriteHealth(f.d, f.target, time.Now())
	}
	return nil
}
func (f *fakeOps) CopyFile(src, dst string) error {
	f.calls = append(f.calls, "copy:"+filepath.Base(dst)+"<-"+filepath.Base(filepath.Dir(src)))
	if filepath.Base(dst) == f.failCopy && strings.Contains(src, "staged") {
		return errors.New("disk full")
	}
	return nil
}

func setupApply(t *testing.T) (Dirs, string) {
	t.Helper()
	root := t.TempDir()
	d := Dirs{Root: root}
	install := filepath.Join(t.TempDir(), "Imaker")
	if err := os.MkdirAll(install, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteState(d, State{Phase: PhaseApplying, FromVersion: "1.4.0", TargetVersion: "1.5.0", InstallDir: install, RequestedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return d, install
}

func TestRunUpdaterSuccess(t *testing.T) {
	d, _ := setupApply(t)
	ops := &fakeOps{d: d, target: "1.5.0", healthy: true}
	st, err := RunUpdater(d, ops, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if st.Phase != PhaseSuccess || st.Status != StatusSuccess {
		t.Fatalf("want success, got %+v", st)
	}
	if read, _ := ReadState(d); read.Status != StatusSuccess {
		t.Fatal("success not persisted")
	}
}

func TestRunUpdaterRollsBackWhenNewVersionDoesNotStart(t *testing.T) {
	d, _ := setupApply(t)
	ops := &fakeOps{d: d, target: "1.5.0", healthy: false}
	st, err := RunUpdater(d, ops, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if st.Phase != PhaseFailed || st.Status != StatusFailed {
		t.Fatalf("want failed, got %+v", st)
	}
	if !strings.Contains(st.Error, "did not report healthy") {
		t.Fatalf("unexpected error: %q", st.Error)
	}
	// Backups must be restored after the failed attempt.
	assertContains(t, ops.calls, "copy:ImakerAgentService.exe<-backup")
	assertContains(t, ops.calls, "copy:ImakerTrayApp.exe<-backup")
}

func TestRunUpdaterRollsBackOnCopyFailure(t *testing.T) {
	d, _ := setupApply(t)
	ops := &fakeOps{d: d, target: "1.5.0", failCopy: ServiceExe}
	st, err := RunUpdater(d, ops, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != StatusFailed || !strings.Contains(st.Error, "disk full") {
		t.Fatalf("want failed with copy error, got %+v", st)
	}
	assertContains(t, ops.calls, "copy:ImakerAgentService.exe<-backup")
}

func TestRunUpdaterRefusesWhenNothingPending(t *testing.T) {
	d := Dirs{Root: t.TempDir()}
	if err := WriteState(d, State{Phase: PhaseSuccess}); err != nil {
		t.Fatal(err)
	}
	if _, err := RunUpdater(d, &fakeOps{d: d}, time.Second); err == nil {
		t.Fatal("ran with no pending update")
	}
}

func assertContains(t *testing.T, calls []string, want string) {
	t.Helper()
	for _, c := range calls {
		if c == want {
			return
		}
	}
	t.Fatalf("missing call %q in %v", want, calls)
}
