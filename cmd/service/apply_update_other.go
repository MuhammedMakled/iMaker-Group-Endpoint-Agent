//go:build !windows

package main

// runApplyUpdate is Windows-only; other platforms have nothing to update.
func runApplyUpdate() int { return 2 }
