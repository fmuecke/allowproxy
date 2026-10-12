// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later
// https://github.com/fmuecke/egress-gate

package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// TestLogRotationFailure makes the log file impossible to rename, because
// another program holds it open, and to reopen, because it is read-only. The
// lines written meanwhile are lost, but the log reports the gap once it works
// again.
func TestLogRotationFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.log")
	log, err := openRotatingFile(path, 200, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	line := func(name string) string { return name + strings.Repeat(".", 150) + "\n" }
	write := func(name string) {
		t.Helper()
		if n, err := log.Write([]byte(line(name))); n != len(line(name)) || err != nil {
			t.Fatalf("write %s: %d, %v; want no error, so that other log writers still get the line", name, n, err)
		}
	}

	write("first")
	holder, err := syscall.CreateFile(syscall.StringToUTF16Ptr(path), syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0) // no FILE_SHARE_DELETE
	if err != nil {
		t.Fatal(err)
	}
	release := sync.OnceFunc(func() {
		syscall.CloseHandle(holder)
		os.Chmod(path, 0o600)
	})
	defer release()
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	write("lost-1") // rotates, but can neither rename nor reopen
	write("lost-2") // still can't reopen
	release()
	write("after")

	if data, _ := os.ReadFile(path + ".1"); string(data) != line("first") {
		t.Errorf("backup = %q, want the first line", data)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 3 ||
		!strings.Contains(lines[0], `level=WARN msg="log rotation failed"`) ||
		!strings.Contains(lines[1], `level=WARN msg="log lines lost" lines=2 error=`) ||
		lines[2]+"\n" != line("after") {
		t.Errorf("log after the lock:\n%s\nwant a rotation warning, a warning about 2 lost lines, then the line", data)
	}
}
