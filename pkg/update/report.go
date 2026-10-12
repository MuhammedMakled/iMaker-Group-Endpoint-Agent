package update

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PostReport sends an upgrade outcome to the IT Command Center.
//
// It returns an error for any non-2xx response or transport failure, in which
// case the caller leaves the state unreported so the next attempt retries.
//
// Authentication of this request is not defined yet. It depends on the
// gateway contract (per-device signing key, Phase 1 of the plan), so the URL
// must be configured deliberately before reports are sent.
func PostReport(ctx context.Context, client *http.Client, endpoint string, r Report) error {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if err := ValidateReportURL(endpoint); err != nil {
		return err
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("report failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("report rejected: HTTP %d", resp.StatusCode)
	}
	return nil
}
