package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type rec struct {
	N int       `json:"n"`
	T time.Time `json:"t"`
}

func TestDailyLogAppendRead(t *testing.T) {
	l, err := NewDailyLog(t.TempDir(), "sessions")
	if err != nil {
		t.Fatal(err)
	}
	d1 := time.Date(2026, 10, 8, 10, 0, 0, 0, time.Local)
	d2 := d1.AddDate(0, 0, 1)
	if err := l.Append(d1, rec{1, d1}, rec{2, d1}); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(d2, rec{3, d2}); err != nil {
		t.Fatal(err)
	}
	raw, err := l.ReadRange(d1, d2)
	if err != nil {
		t.Fatal(err)
	}
	got := DecodeAll[rec](raw)
	if len(got) != 3 || got[2].N != 3 {
		t.Fatalf("unexpected records: %+v", got)
	}
	only2, _ := l.ReadRange(d2, d2)
	if len(only2) != 1 {
		t.Fatalf("want 1 record for d2, got %d", len(only2))
	}
}

func TestDailyLogTornLineAndPrune(t *testing.T) {
	dir := t.TempDir()
	l, _ := NewDailyLog(dir, "x")
	now := time.Now()
	_ = l.Append(now, rec{N: 1})
	// Simulate a crash mid-write.
	f, _ := os.OpenFile(l.fileFor(now), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"n":2,"t":"20`)
	f.Close()
	raw, _ := l.ReadRange(now, now)
	if len(raw) != 1 {
		t.Fatalf("torn line should be skipped, got %d", len(raw))
	}
	old := now.AddDate(0, 0, -200)
	_ = l.Append(old, rec{N: 9})
	n, err := l.Prune(90)
	if err != nil || n != 1 {
		t.Fatalf("prune removed %d (err %v), want 1", n, err)
	}
}

func TestOutbox(t *testing.T) {
	o, _ := NewOutbox(filepath.Join(t.TempDir(), "outbox.jsonl"), 3)
	for i := 1; i <= 5; i++ {
		if err := o.Push(rec{N: i}); err != nil {
			t.Fatal(err)
		}
	}
	if o.Len() != 3 {
		t.Fatalf("cap not applied: %d", o.Len())
	}
	raw, _ := o.Peek(2)
	got := DecodeAll[rec](raw)
	if len(got) != 2 || got[0].N != 3 {
		t.Fatalf("oldest should be dropped first: %+v", got)
	}
	if err := o.Ack(2); err != nil {
		t.Fatal(err)
	}
	rest := DecodeAll[rec](mustPeek(t, o))
	if len(rest) != 1 || rest[0].N != 5 {
		t.Fatalf("after ack: %+v", rest)
	}
	_ = o.Ack(10)
	if o.Len() != 0 {
		t.Fatal("outbox should be empty")
	}
}

func mustPeek(t *testing.T, o *Outbox) []json.RawMessage {
	t.Helper()
	r, err := o.Peek(0)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
