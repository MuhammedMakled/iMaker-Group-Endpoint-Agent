package update

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
)

// ExtractBundle opens the zip at zipPath and extracts the binaries into
// destDir. The bundle must contain exactly BundleFiles, each once, at the top
// level with no directories, no path separators and no duplicates. Anything
// else is refused before any file is written. It returns name -> extracted path.
func ExtractBundle(zipPath, destDir string) (map[string]string, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("bundle is not a valid zip: %w", err)
	}
	defer zr.Close()

	if len(zr.File) != len(BundleFiles) {
		return nil, fmt.Errorf("bundle must contain exactly %d files, found %d", len(BundleFiles), len(zr.File))
	}
	seen := map[string]bool{}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			return nil, fmt.Errorf("bundle entry %q is a directory", f.Name)
		}
		if !slices.Contains(BundleFiles, f.Name) {
			return nil, fmt.Errorf("bundle entry %q is not an allowed file", f.Name)
		}
		if seen[f.Name] {
			return nil, fmt.Errorf("bundle entry %q appears twice", f.Name)
		}
		seen[f.Name] = true
		if f.UncompressedSize64 > MaxBundleBytes {
			return nil, fmt.Errorf("bundle entry %q is larger than the %d byte limit", f.Name, MaxBundleBytes)
		}
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(BundleFiles))
	for _, f := range zr.File {
		dst := filepath.Join(destDir, f.Name)
		if err := extractOne(f, dst); err != nil {
			return nil, err
		}
		out[f.Name] = dst
	}
	return out, nil
}

func extractOne(f *zip.File, dst string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	w, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(w, io.LimitReader(rc, MaxBundleBytes+1))
	closeErr := w.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n > MaxBundleBytes {
		return fmt.Errorf("bundle entry %q exceeded the size limit while extracting", f.Name)
	}
	return nil
}
