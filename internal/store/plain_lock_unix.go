//go:build unix

package store

import (
	"log"
	"os"
	"syscall"
)

// osLock takes an flock on path (exclusive or shared) and returns its
// release; if the lock can't be taken it logs and relies on the in-process
// lock alone.
func osLock(path string, exclusive bool) func() {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		log.Printf("plain store: no file lock (%v); in-process lock only", err)

		return func() {}
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		log.Printf("plain store: no file lock (%v); in-process lock only", err)
		_ = f.Close()

		return func() {}
	}

	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
}
