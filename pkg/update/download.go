package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Download fetches rawURL into dst. The transfer is refused if the redirect
// chain leaves https or the allowed hosts, if it exceeds maxBytes, or if the
// server returns a non-200 status. The file is written to dst+".part" and
// renamed only after the size check passes.
//
// client may be nil, in which case a client with a 10-minute timeout is used.
// The caller passes a client in tests to trust a test server.
func Download(ctx context.Context, client *http.Client, rawURL, dst string, maxBytes int64, allowedHosts []string) error {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	// Copy the client so redirect policy can be set without touching the caller's.
	c := *client
	c.CheckRedirect = redirectPolicy(allowedHosts)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return fmt.Errorf("bundle is %d bytes, above the %d byte limit", resp.ContentLength, maxBytes)
	}

	part := dst + ".part"
	f, err := os.Create(part)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(f, io.LimitReader(resp.Body, maxBytes+1))
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(part)
		return fmt.Errorf("download interrupted: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(part)
		return closeErr
	}
	if n > maxBytes {
		_ = os.Remove(part)
		return fmt.Errorf("bundle exceeded the %d byte limit", maxBytes)
	}
	return os.Rename(part, dst)
}

func redirectPolicy(allowedHosts []string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= MaxRedirects {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("redirect to non-https URL refused")
		}
		if !HostAllowed(req.URL.Hostname(), allowedHosts) {
			return fmt.Errorf("redirect to %q refused: host not in update_allowed_hosts", req.URL.Hostname())
		}
		return nil
	}
}

// Report is the body posted to the IT Command Center after an upgrade ends.
type Report struct {
	Status        string    `json:"status"`
	FromVersion   string    `json:"from_version"`
	TargetVersion string    `json:"target_version"`
	Error         string    `json:"error,omitempty"`
	FinishedAt    time.Time `json:"finished_at"`
	Hostname      string    `json:"hostname"`
}

// ValidateReportURL requires an https endpoint with a host.
func ValidateReportURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return errors.New("update_report_url must be an https URL")
	}
	return nil
}
