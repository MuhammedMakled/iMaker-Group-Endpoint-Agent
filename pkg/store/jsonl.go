// Package store provides an offline-first, dependency-free persistence layer:
//
//   - DailyLog: append-only JSON Lines files partitioned by day
//     (e.g. sessions-2026-10-09.jsonl) with retention pruning. Easy to ship,
//     grep, and later bulk-upload to the Command Center.
//   - Outbox: a durable FIFO queue used by the tray app to hold records until
//     the service (or, later, the backend API) acknowledges them.
//
// JSONL was chosen over SQLite to keep the binaries CGO-free and tiny; the
// interface is narrow enough to swap in modernc.org/sqlite later if needed.
package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const dateLayout = "2006-01-02"

// maxLine bounds a single record so a corrupt file can't exhaust memory.
const maxLine = 4 << 20

// DailyLog is a set of day-partitioned JSONL files sharing a prefix.
type DailyLog struct {
	mu     sync.Mutex
	dir    string
	prefix string
	loc    *time.Location
}

// NewDailyLog creates (if needed) dir and returns a log for prefix.
func NewDailyLog(dir, prefix string) (*DailyLog, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &DailyLog{dir: dir, prefix: prefix, loc: time.Local}, nil
}

func (l *DailyLog) fileFor(day time.Time) string {
	return filepath.Join(l.dir, fmt.Sprintf("%s-%s.jsonl", l.prefix, day.In(l.loc).Format(dateLayout)))
}

// Append writes records into the file for the given timestamp's day.
func (l *DailyLog) Append(at time.Time, records ...any) error {
	if len(records) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, r := range records {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.fileFor(at), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ReadRange returns raw records from every day file between from and to
// (inclusive, by calendar day). Malformed lines are skipped.
func (l *DailyLog) ReadRange(from, to time.Time) ([]json.RawMessage, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []json.RawMessage
	start := truncDay(from.In(l.loc))
	end := truncDay(to.In(l.loc))
	for d := start; !d.After(end); d = d.AddDate(0, 0, 1) {
		recs, err := readLines(l.fileFor(d))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return out, err
		}
		out = append(out, recs...)
	}
	return out, nil
}

// Prune deletes day files older than retentionDays.
func (l *DailyLog) Prune(retentionDays int) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := truncDay(time.Now().In(l.loc)).AddDate(0, 0, -retentionDays)
	matches, err := filepath.Glob(filepath.Join(l.dir, l.prefix+"-*.jsonl"))
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, m := range matches {
		base := strings.TrimSuffix(filepath.Base(m), ".jsonl")
		ds := strings.TrimPrefix(base, l.prefix+"-")
		d, err := time.ParseInLocation(dateLayout, ds, l.loc)
		if err != nil {
			continue
		}
		if d.Before(cutoff) {
			if os.Remove(m) == nil {
				removed++
			}
		}
	}
	return removed, nil
}

func truncDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

func readLines(path string) ([]json.RawMessage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return scanJSONL(f)
}

func scanJSONL(r io.Reader) ([]json.RawMessage, error) {
	var out []json.RawMessage
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || !json.Valid(line) {
			continue // tolerate a torn final line after a crash
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		out = append(out, cp)
	}
	return out, sc.Err()
}

// DecodeAll unmarshals raw records into a typed slice.
func DecodeAll[T any](raw []json.RawMessage) []T {
	out := make([]T, 0, len(raw))
	for _, r := range raw {
		var v T
		if json.Unmarshal(r, &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

// ---------------------------------------------------------------------------

// Outbox is a durable FIFO of JSON records stored in a single file.
type Outbox struct {
	mu   sync.Mutex
	path string
	max  int
}

// NewOutbox opens (creating if needed) an outbox file. maxItems caps growth
// when the consumer is unreachable for a long time (oldest records are
// dropped first); 0 means unlimited.
func NewOutbox(path string, maxItems int) (*Outbox, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return &Outbox{path: path, max: maxItems}, nil
}

// Push appends records to the queue.
func (o *Outbox) Push(records ...any) error {
	if len(records) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, r := range records {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	f, err := os.OpenFile(o.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.Write(buf.Bytes())
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	if o.max > 0 {
		return o.trimLocked()
	}
	return nil
}

func (o *Outbox) trimLocked() error {
	recs, err := readLines(o.path)
	if err != nil || len(recs) <= o.max {
		return err
	}
	return o.rewriteLocked(recs[len(recs)-o.max:])
}

// Peek returns up to n queued records (n <= 0 means all) without removing them.
func (o *Outbox) Peek(n int) ([]json.RawMessage, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	recs, err := readLines(o.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if n > 0 && len(recs) > n {
		recs = recs[:n]
	}
	return recs, err
}

// Ack removes the first n records (call after a successful Peek+send).
func (o *Outbox) Ack(n int) error {
	if n <= 0 {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	recs, err := readLines(o.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if n >= len(recs) {
		return os.Remove(o.path)
	}
	return o.rewriteLocked(recs[n:])
}

// Len returns the number of queued records.
func (o *Outbox) Len() int {
	recs, _ := o.Peek(0)
	return len(recs)
}

func (o *Outbox) rewriteLocked(recs []json.RawMessage) error {
	tmp := o.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, r := range recs {
		w.Write(r)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, o.path) // atomic replace on NTFS
}

// SortByTime is a helper for callers that merged several day files.
func SortByTime[T any](items []T, ts func(T) time.Time) {
	sort.SliceStable(items, func(i, j int) bool { return ts(items[i]).Before(ts(items[j])) })
}
