package store

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

/*
	Safety of the plain-file store.

	The three colon-delimited files are rewritten whole on every change, and
	users span all three. What keeps them consistent:

	- lockPlain: the in-process lock plus, where the OS has one, a file lock
	  next to the data, so two minioth processes on the same directory
	  serialize too (the mutex alone only covered one process).
	- rewriteFile writes a temporary file, syncs it and renames it over the
	  original: readers see the old or the new file, never a truncated or
	  half-written one (it used to truncate in place with os.Create).
	- Useradd writes mpasswd, the file that makes a user exist, last, and
	  checks every write; appends first finish a line a crash left
	  unterminated, so the next entry can't be glued onto it.
	- Values with ":" or line breaks are refused: they would split or add
	  records.
*/

var errPlainValue = errors.New("value contains ':' or a line break, which the plain store can't hold")

// checkPlainValues refuses values that would break the file format.
func checkPlainValues(values ...string) error {
	for _, v := range values {
		if strings.ContainsAny(v, DEL+"\n\r") {
			return fmt.Errorf("%w: %q", errPlainValue, v)
		}
	}

	return nil
}

// checkPlainFields checks the string values of a patch, except the keys in
// skip (e.g. a password, which is stored hashed).
func checkPlainFields(fields map[string]interface{}, skip ...string) error {
	for k, v := range fields {
		s, ok := v.(string)
		if !ok || contains(skip, k) {
			continue
		}
		if err := checkPlainValues(s); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}

	return nil
}

func contains(list []string, s string) bool {
	for _, l := range list {
		if l == s {
			return true
		}
	}

	return false
}

// lockPlain takes the store's lock (exclusive for writers, shared for
// readers) and returns the function that releases it.
func lockPlain(write bool) func() {
	if write {
		plainWriteMu.Lock()
	} else {
		plainWriteMu.RLock()
	}
	release := osLock(filepath.Join(filepath.Dir(MINIOTH_PASSWD), ".lock"), write)

	return func() {
		release()
		if write {
			plainWriteMu.Unlock()
		} else {
			plainWriteMu.RUnlock()
		}
	}
}

// rewriteFile replaces path with lines, atomically.
func rewriteFile(path string, lines []string) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	if _, err = tmp.WriteString(b.String()); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("failed to write to file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()

		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), path)
}

// terminateLastLine appends a newline if f (opened for appending) ends in
// the middle of a line, e.g. after a crash during a write.
func terminateLastLine(f *os.File) error {
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return err
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, st.Size()-1); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if last[0] != '\n' {
		log.Printf("plain store: %s ended mid-line (an interrupted write); terminating it", f.Name())
		_, err = f.WriteString("\n")
	}

	return err
}
