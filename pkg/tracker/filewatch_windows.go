//go:build windows

package tracker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

const (
	watchBufSize = 64 * 1024 // max for network shares; DWORD-aligned below
	watchMask    = windows.FILE_NOTIFY_CHANGE_FILE_NAME |
		windows.FILE_NOTIFY_CHANGE_LAST_WRITE |
		windows.FILE_NOTIFY_CHANGE_SIZE
)

// FileWatcher watches one or more directory trees with ReadDirectoryChangesW
// (overlapped I/O) and emits debounced FileEvents for tracked design files.
type FileWatcher struct {
	Roots       []string
	Filter      *FileFilter
	Debounce    *Debouncer
	ProjectCode func(string) string
	OnEvent     func(protocol.FileEvent)
	Logger      *slog.Logger
	// SettleDelay lets the CAD app finish writing before we stat the file.
	SettleDelay time.Duration
}

// Run blocks until ctx is cancelled. Each root runs in its own goroutine and
// is restarted with back-off if the directory disappears (e.g. Dropbox
// unmounted) and comes back.
func (w *FileWatcher) Run(ctx context.Context) {
	if w.Logger == nil {
		w.Logger = slog.Default()
	}
	if w.SettleDelay == 0 {
		w.SettleDelay = 1500 * time.Millisecond
	}
	var wg sync.WaitGroup
	for _, r := range w.Roots {
		root := filepath.Clean(r)
		wg.Add(1)
		go func() {
			defer wg.Done()
			backoff := 5 * time.Second
			for ctx.Err() == nil {
				err := w.watchRoot(ctx, root)
				if ctx.Err() != nil {
					return
				}
				w.Logger.Warn("file watcher stopped; retrying", "root", root, "err", err, "in", backoff)
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < 5*time.Minute {
					backoff *= 2
				}
			}
		}()
	}
	wg.Wait()
}

func (w *FileWatcher) watchRoot(ctx context.Context, root string) error {
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return fmt.Errorf("root not available: %v", err)
	}
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return fmt.Errorf("CreateFile: %w", err)
	}
	defer windows.CloseHandle(h)

	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("CreateEvent: %w", err)
	}
	defer windows.CloseHandle(ev)

	// []uint32 guarantees the DWORD alignment ReadDirectoryChangesW requires.
	backing := make([]uint32, watchBufSize/4)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&backing[0])), watchBufSize)

	w.Logger.Info("watching folder", "root", root)
	for {
		var ov windows.Overlapped
		ov.HEvent = ev
		_ = windows.ResetEvent(ev)
		err := windows.ReadDirectoryChanges(h, &buf[0], uint32(len(buf)), true, watchMask, nil, &ov, 0)
		if err != nil {
			return fmt.Errorf("ReadDirectoryChanges: %w", err)
		}

		// Wait in short slices so cancellation is responsive.
		for {
			r, werr := windows.WaitForSingleObject(ev, 500)
			if werr != nil {
				return werr
			}
			if r == windows.WAIT_OBJECT_0 {
				break
			}
			if ctx.Err() != nil {
				_ = windows.CancelIoEx(h, &ov)
				var n uint32
				_ = windows.GetOverlappedResult(h, &ov, &n, true) // wait so buf isn't freed under the kernel
				return ctx.Err()
			}
		}

		var n uint32
		if err := windows.GetOverlappedResult(h, &ov, &n, false); err != nil {
			if errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
				return ctx.Err()
			}
			return fmt.Errorf("GetOverlappedResult: %w", err)
		}
		if n == 0 {
			// Buffer overflow: changes were lost. Not fatal for heartbeat purposes.
			w.Logger.Debug("change buffer overflow", "root", root)
			continue
		}
		w.dispatch(root, buf[:n])
	}
}

func (w *FileWatcher) dispatch(root string, data []byte) {
	off := 0
	for off < len(data) {
		info := (*windows.FileNotifyInformation)(unsafe.Pointer(&data[off]))
		nameLen := int(info.FileNameLength / 2)
		name := windows.UTF16ToString(unsafe.Slice(&info.FileName, nameLen))
		full := filepath.Join(root, name)

		action := ""
		switch info.Action {
		case windows.FILE_ACTION_MODIFIED:
			action = "modified"
		case windows.FILE_ACTION_ADDED:
			action = "added"
		case windows.FILE_ACTION_RENAMED_NEW_NAME:
			action = "renamed" // AutoCAD/SketchUp save via temp file + rename
		}
		if action != "" && w.Filter.Accept(full) && w.Debounce.Allow(full, time.Now()) {
			go w.emitAfterSettle(full, action)
		}

		if info.NextEntryOffset == 0 {
			break
		}
		off += int(info.NextEntryOffset)
	}
}

func (w *FileWatcher) emitAfterSettle(path, action string) {
	time.Sleep(w.SettleDelay)
	ev, ok := BuildFileEvent(path, action, time.Now(), w.ProjectCode)
	if ok && w.OnEvent != nil {
		w.OnEvent(ev)
	}
}
