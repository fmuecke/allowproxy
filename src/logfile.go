// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later
// https://github.com/fmuecke/allowproxy

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync"
)

// Every request is logged, also denied ones, so without a bound a client
// could fill the disk. The log takes at most (logBackups+1) * maxLogSize.
const (
	maxLogSize = 10 << 20
	logBackups = 3
)

// rotatingFile is an append-only log file. When a write would grow it beyond
// maxSize, the file becomes <name>.1, older files move up to <name>.<backups>,
// and the oldest is deleted.
//
// Logging must not stop the proxy, so a line that can't be written is only
// counted. Once the file works again, it first gets a warning about the lost
// lines and the problems of the last rotation.
type rotatingFile struct {
	path    string
	maxSize int64
	backups int

	mu        sync.Mutex
	file      *os.File // nil while it can't be reopened
	size      int64
	lost      int   // lines not written since the last warning
	lostErr   error // why the last of them wasn't written
	rotateErr error // problems of rotations since the last warning
}

func openRotatingFile(path string, maxSize int64, backups int) (*rotatingFile, error) {
	r := &rotatingFile{path: path, maxSize: maxSize, backups: backups}
	if err := r.open(os.O_APPEND); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open(mode int) error {
	f, err := os.OpenFile(r.path, mode|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.file, r.size = f, info.Size()
	return nil
}

func (r *rotatingFile) Name() string { return r.path }

// Write never fails, so that other writers of a MultiWriter still get the
// line, and slog discards the error anyway.
func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.write(p); err != nil {
		r.lost++
		r.lostErr = err
	}
	return len(p), nil
}

func (r *rotatingFile) write(p []byte) error {
	if r.file == nil {
		if err := r.open(os.O_APPEND); err != nil {
			return err
		}
	}
	if r.size > 0 && r.size+int64(len(p)) > r.maxSize {
		if err := r.rotate(); err != nil {
			return err
		}
	}
	if warning := r.warning(); len(warning) > 0 {
		if err := r.writeFile(warning); err != nil {
			return err
		}
		r.lost, r.lostErr, r.rotateErr = 0, nil, nil
	}
	return r.writeFile(p)
}

func (r *rotatingFile) writeFile(p []byte) error {
	n, err := r.file.Write(p)
	r.size += int64(n)
	return err
}

// warning returns log lines about lost lines and rotation problems, if any.
func (r *rotatingFile) warning() []byte {
	var b bytes.Buffer
	log := slog.New(slog.NewTextHandler(&b, nil))
	if r.rotateErr != nil {
		log.Warn("log rotation failed", "error", r.rotateErr)
	}
	if r.lost > 0 {
		log.Warn("log lines lost", "lines", r.lost, "error", r.lostErr)
	}
	return b.Bytes()
}

func (r *rotatingFile) rotate() error {
	errs := []error{r.rotateErr, r.file.Close()}
	r.file = nil
	for i := r.backups; i > 1; i-- {
		// fails while there are fewer backups
		if err := os.Rename(r.backup(i-1), r.backup(i)); !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	mode := os.O_APPEND
	if err := os.Rename(r.path, r.backup(1)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("truncating the log instead: %w", err))
		mode = os.O_TRUNC // keep the size bound rather than the old lines
	}
	r.rotateErr = errors.Join(errs...)
	return r.open(mode)
}

func (r *rotatingFile) backup(i int) string {
	return fmt.Sprintf("%s.%d", r.path, i)
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	return r.file.Close()
}
