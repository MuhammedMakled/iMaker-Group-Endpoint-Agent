//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// readHiddenPassword reads a line from the console with echo disabled, so the
// password is not shown or left in the shell history.
func readHiddenPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		// Not a console (piped): fall back to a normal read.
		return readLine(), nil
	}
	_ = windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT)
	defer windows.SetConsoleMode(h, mode)
	pw := readLine()
	fmt.Println()
	return pw, nil
}

func readLine() string {
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		return strings.TrimRight(sc.Text(), "\r\n")
	}
	return ""
}

// confirmInteractive requires the operator to retype the computer name before
// a real wipe proceeds — a last guard against the wrong machine.
func confirmInteractive(host string) bool {
	fmt.Printf("Type the computer name (%s) to confirm the wipe: ", host)
	got := readLine()
	return strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(host))
}
