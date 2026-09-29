package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReady(t *testing.T) {
	t.Run("db", func(t *testing.T) {
		withTempWD(t)
		h := &DBHandler{DBpath: filepath.Join(t.TempDir(), "minioth.db")}
		h.Init(testRoot())
		if err := h.Ready(); err != nil {
			t.Fatalf("fresh database: %v", err)
		}
		h.Close()
		if err := h.Ready(); err == nil {
			t.Error("a closed database reported ready")
		}
	})
	t.Run("plain", func(t *testing.T) {
		withTempWD(t)
		h := &PlainHandler{}
		h.Init(testRoot())
		if err := h.Ready(); err != nil {
			t.Fatalf("fresh files: %v", err)
		}
		if err := os.Remove(MINIOTH_SHADOW); err != nil {
			t.Fatal(err)
		}
		if err := h.Ready(); err == nil {
			t.Error("a missing mshadow reported ready")
		}
		leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(MINIOTH_PASSWD), ".ready-*"))
		if len(leftovers) != 0 {
			t.Errorf("the writability probe left %v", leftovers)
		}
	})
}
