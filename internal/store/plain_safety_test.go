package store

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kyri56xcaesar/minioth/internal/domain"
)

func TestPlainRefusesValuesThatBreakTheFormat(t *testing.T) {
	withTempWD(t)
	h := &PlainHandler{}
	h.Init(testRoot())
	before, _ := os.ReadFile(MINIOTH_PASSWD)

	for _, u := range []domain.User{
		{Name: "eve:0:0", Password: domain.Password{Hashpass: "hunter22"}},
		{Name: "mallory", Info: "line\nroot::0:0", Password: domain.Password{Hashpass: "hunter22"}},
		{Name: "trent", Home: "/home/a:b", Password: domain.Password{Hashpass: "hunter22"}},
	} {
		if _, _, err := h.Useradd(u); !errors.Is(err, errPlainValue) {
			t.Errorf("useradd %q: %v, want errPlainValue", u.Name, err)
		}
	}
	if after, _ := os.ReadFile(MINIOTH_PASSWD); string(after) != string(before) {
		t.Error("a refused user changed the passwd file")
	}
	uid, _, err := h.Useradd(domain.User{Name: "alice", Password: domain.Password{Hashpass: "hunter22"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Userpatch(strconv.Itoa(uid), map[string]interface{}{"info": "a\nb"}); !errors.Is(err, errPlainValue) {
		t.Errorf("userpatch with a newline: %v", err)
	}
	if err := h.Userpatch(strconv.Itoa(uid), map[string]interface{}{"password": "with:colon-ok"}); err != nil {
		t.Errorf("passwords are hashed, so ':' is fine there: %v", err)
	}
	if _, err := h.Groupadd(domain.Group{Name: "a:b"}); !errors.Is(err, errPlainValue) {
		t.Errorf("groupadd: %v", err)
	}
}

// Rewrites go through a temporary file and a rename: nothing is left
// behind and the result is complete.
func TestPlainRewritesAreAtomic(t *testing.T) {
	withTempWD(t)
	h := &PlainHandler{}
	h.Init(testRoot())
	uid, _, err := h.Useradd(domain.User{Name: "bob", Password: domain.Password{Hashpass: "hunter22"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Userdel(strconv.Itoa(uid)); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(MINIOTH_PASSWD))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
	for _, line := range readFileLines(t, MINIOTH_PASSWD) {
		if strings.HasPrefix(line, "bob:") {
			t.Error("deleted user still in passwd")
		}
	}
	if st, _ := os.Stat(MINIOTH_PASSWD); st.Mode().Perm() != 0o600 {
		t.Errorf("rewritten file mode %v, want 0600", st.Mode().Perm())
	}
}

// A crash in the middle of a write leaves a line without its newline; the
// next entry must not be glued onto it.
func TestPlainRecoversFromAnInterruptedWrite(t *testing.T) {
	withTempWD(t)
	h := &PlainHandler{}
	h.Init(testRoot())
	f, err := os.OpenFile(MINIOTH_PASSWD, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("halfwritten:3ncr") // no newline: the crash
	_ = f.Close()

	if _, _, err := h.Useradd(domain.User{Name: "carol", Password: domain.Password{Hashpass: "hunter22"}}); err != nil {
		t.Fatal(err)
	}
	if u, err := h.Authenticate("carol", "hunter22"); err != nil || u == nil || u.Name != "carol" {
		t.Errorf("user added after an interrupted write: %+v, %v", u, err)
	}
}

// The file lock serializes separate lock holders (another minioth process
// holds its own file description, like a second osLock here).
func TestPlainFileLockExcludes(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lock")
	release := osLock(path, true)
	got := make(chan struct{})
	go func() {
		r := osLock(path, true)
		close(got)
		r()
	}()
	select {
	case <-got:
		t.Fatal("a second exclusive lock was granted while the first was held")
	case <-time.After(150 * time.Millisecond):
	}
	release()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("the lock was not handed over after release")
	}
}
