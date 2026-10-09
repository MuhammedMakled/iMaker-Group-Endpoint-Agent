// Package logging provides a structured slog logger backed by a small
// size-rotating file writer (no external dependencies).
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	defaultMaxBytes = 10 << 20 // 10 MB
	defaultBackups  = 3
)

// RotatingFile is an io.Writer that rotates file.log -> file.log.1 ... .N.
type RotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	backups  int
	f        *os.File
	size     int64
}

func NewRotatingFile(path string, maxBytes int64, backups int) (*RotatingFile, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	if backups <= 0 {
		backups = defaultBackups
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	r := &RotatingFile{path: path, maxBytes: maxBytes, backups: backups}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *RotatingFile) rotate() error {
	if r.f != nil {
		r.f.Close()
	}
	for i := r.backups - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	_ = os.Rename(r.path, r.path+".1")
	return r.open()
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	return r.f.Close()
}

// ParseLevel maps "debug|info|warn|error" to a slog.Level.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// New creates a JSON logger writing to path (and optionally also stderr).
func New(path, level string, alsoStderr bool) (*slog.Logger, io.Closer, error) {
	rf, err := NewRotatingFile(path, defaultMaxBytes, defaultBackups)
	if err != nil {
		return nil, nil, err
	}
	var w io.Writer = rf
	if alsoStderr {
		w = io.MultiWriter(rf, os.Stderr)
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: ParseLevel(level)})
	return slog.New(h), rf, nil
}
