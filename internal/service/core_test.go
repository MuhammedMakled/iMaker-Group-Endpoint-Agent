package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

type fakeSource struct{ n int }

func (f *fakeSource) Collect(context.Context) protocol.TelemetrySnapshot {
	f.n++
	return protocol.TelemetrySnapshot{CollectedAt: time.Now(), CPU: []protocol.CPUInfo{{Name: "Ryzen"}}}
}
func (f *fakeSource) Software(context.Context) protocol.SoftwareInventory {
	return protocol.SoftwareInventory{Items: []protocol.SoftwareItem{{Name: "Revit"}, {Name: "Dropbox"}}, Count: 2}
}

func newCore(t *testing.T) (*Core, *fakeSource) {
	cfg := config.Default()
	_ = cfg.Validate()
	src := &fakeSource{}
	c, err := NewCore(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return c, src
}

func call(t *testing.T, h ipc.HandlerFunc, caller ipc.Caller, params any) (any, error) {
	b, _ := json.Marshal(params)
	return h(ipc.WithCaller(context.Background(), caller), b)
}

func TestSubmitOverridesIdentityAndDedupes(t *testing.T) {
	c, _ := newCore(t)
	now := time.Now()
	s := protocol.WorkSession{ID: "abc", User: `EVIL\spoof`, App: protocol.AppRevit, Category: protocol.CategoryDesign,
		ProjectCode: "P-1", Start: now.Add(-40 * time.Minute), End: now.Add(-10 * time.Minute)}
	bad := protocol.WorkSession{ID: "bad", Start: now, End: now.Add(-time.Minute)}
	ali := ipc.Caller{User: `IMAKER\ali`, SID: "S-1-5-21-1"}

	for i := 0; i < 2; i++ { // second submit simulates a lost ack
		res, err := call(t, c.handleActivitySubmit, ali, protocol.ActivitySubmitParams{Sessions: []protocol.WorkSession{s, bad}})
		if err != nil {
			t.Fatal(err)
		}
		if r := res.(protocol.ActivitySubmitResult); r.AcceptedSessions != 1 {
			t.Fatalf("accepted %d", r.AcceptedSessions)
		}
	}
	res, err := call(t, c.handleActivityQuery, ali, protocol.ActivityQueryParams{From: now.Add(-time.Hour), To: now})
	if err != nil {
		t.Fatal(err)
	}
	q := res.(protocol.ActivityQueryResult)
	if len(q.Sessions) != 1 || q.Sessions[0].User != `IMAKER\ali` {
		t.Fatalf("identity must come from the pipe token, not payload: %+v", q.Sessions)
	}

	// Another user can't read Ali's activity…
	_, err = call(t, c.handleActivityQuery, ipc.Caller{User: `IMAKER\sara`}, protocol.ActivityQueryParams{User: `IMAKER\ali`})
	var rpcErr *protocol.RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != protocol.ErrUnauthorized {
		t.Fatalf("want unauthorized, got %v", err)
	}
	// …but an admin can.
	res, _ = call(t, c.handleActivitySummary, ipc.Caller{IsAdmin: true}, protocol.ActivitySummaryParams{User: `IMAKER\ali`})
	sum := res.(protocol.ActivitySummaryResult)
	if len(sum.Suggestions) != 1 || sum.Suggestions[0].RoundedHours != 0.5 {
		t.Fatalf("summary: %+v", sum)
	}
}

func TestTelemetryRateLimit(t *testing.T) {
	c, src := newCore(t)
	user := ipc.Caller{User: `IMAKER\ali`}
	call(t, c.handleTelemetryGet, user, protocol.TelemetryGetParams{})              // first: collects
	call(t, c.handleTelemetryGet, user, protocol.TelemetryGetParams{Refresh: true}) // rate-limited
	if src.n != 1 {
		t.Fatalf("non-admin refresh should be rate limited, collections=%d", src.n)
	}
	call(t, c.handleTelemetryGet, ipc.Caller{IsAdmin: true}, protocol.TelemetryGetParams{Refresh: true})
	if src.n != 2 {
		t.Fatalf("admin refresh should bypass the limit, collections=%d", src.n)
	}
	res, _ := call(t, c.handleSoftwareList, user, protocol.SoftwareListParams{Filter: "rev"})
	if inv := res.(protocol.SoftwareInventory); inv.Count != 1 {
		t.Fatalf("filter: %+v", inv)
	}
}

func (f *fakeSource) Identity(context.Context) protocol.AssetIdentity {
	return protocol.AssetIdentity{SerialNumber: "MB123456", SerialSource: "baseboard", IsCustomBuild: true}
}
