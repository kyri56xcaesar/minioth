//go:build !unix

package store

// osLock: no file locks here (e.g. Windows builds); the in-process lock is
// all there is, so run one minioth per plain data directory.
func osLock(string, bool) func() { return func() {} }
