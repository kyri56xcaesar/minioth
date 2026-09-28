package store

import (
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/kyri56xcaesar/minioth/internal/domain"
)

func bothBackends() []struct {
	name string
	h    domain.MiniothHandler
} {
	return []struct {
		name string
		h    domain.MiniothHandler
	}{
		{"plain", &PlainHandler{}},
		{"db", &DBHandler{DBpath: "test.db"}},
	}
}

// TestConcurrentWrites hammers each backend with concurrent writers and
// readers — Useradd (the id-allocation race dbWriteMu/plainWriteMu exist
// to close), Userpatch, RevokeTokens, Authenticate and Select all at
// once — then checks nothing was lost, duplicated or corrupted. Run it
// with -race to also catch unsynchronized memory access.
func TestConcurrentWrites(t *testing.T) {
	const (
		writers        = 40
		revokesPerUser = 3
	)

	for _, b := range bothBackends() {
		t.Run(b.name, func(t *testing.T) {
			withTempWD(t)
			b.h.Init(testRoot())
			defer b.h.Close()

			var (
				wg   sync.WaitGroup
				mu   sync.Mutex
				uids = map[int]string{}
				errs []error
			)
			fail := func(err error) {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}

			for i := 0; i < writers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					name := fmt.Sprintf("load%d", i)
					uid, _, err := b.h.Useradd(domain.User{
						Name:     name,
						Password: domain.Password{Hashpass: "loadpass" + strconv.Itoa(i)},
					})
					if err != nil {
						fail(fmt.Errorf("useradd %s: %w", name, err))
						return
					}
					mu.Lock()
					if other, dup := uids[uid]; dup {
						errs = append(errs, fmt.Errorf("uid %d handed to both %s and %s", uid, other, name))
					}
					uids[uid] = name
					mu.Unlock()

					uidStr := strconv.Itoa(uid)
					if err := b.h.Userpatch(uidStr, map[string]interface{}{"info": "info-" + name}); err != nil {
						fail(fmt.Errorf("userpatch %s: %w", name, err))
					}
					for r := 0; r < revokesPerUser; r++ {
						if err := b.h.RevokeTokens(uidStr); err != nil {
							fail(fmt.Errorf("revoke %s: %w", name, err))
						}
					}
				}(i)

				// A reader per writer, racing the writes above.
				wg.Add(1)
				go func() {
					defer wg.Done()
					b.h.Select("users")
					b.h.Select("groups")
					if _, err := b.h.Authenticate("root", "root"); err != nil {
						fail(fmt.Errorf("root authenticate during load: %w", err))
					}
				}()
			}
			wg.Wait()

			for _, err := range errs {
				t.Error(err)
			}
			if t.Failed() {
				return
			}

			users := b.h.Select("users")
			if len(users) != writers+1 { // + root
				t.Fatalf("expected %d users after load, got %d", writers+1, len(users))
			}
			for _, u := range users {
				user := u.(domain.User)
				if user.Name == "root" {
					continue
				}
				if want := "info-" + user.Name; user.Info != want {
					t.Errorf("%s: info = %q, want %q (lost update?)", user.Name, user.Info, want)
				}
				i := user.Name[len("load"):]
				if _, err := b.h.Authenticate(user.Name, "loadpass"+i); err != nil {
					t.Errorf("%s can't authenticate after load: %v", user.Name, err)
				}
				v, err := b.h.TokenVersion(strconv.Itoa(user.Uid))
				if err != nil || v != revokesPerUser {
					t.Errorf("%s: token version = %d (err %v), want %d", user.Name, v, err, revokesPerUser)
				}
			}
		})
	}
}

// TestTokenVersions covers revocation's storage side on both backends:
// versions start at 0, each RevokeTokens bumps by one, users are
// independent, and Userdel bumps too so a reused uid doesn't inherit the
// deleted user's still-unexpired tokens.
func TestTokenVersions(t *testing.T) {
	for _, b := range bothBackends() {
		t.Run(b.name, func(t *testing.T) {
			withTempWD(t)
			b.h.Init(testRoot())
			defer b.h.Close()

			uid, _, err := b.h.Useradd(domain.User{Name: "erin", Password: domain.Password{Hashpass: "hunter22"}})
			if err != nil {
				t.Fatalf("useradd failed: %v", err)
			}
			uidStr := strconv.Itoa(uid)

			version := func(uid string) int {
				t.Helper()
				v, err := b.h.TokenVersion(uid)
				if err != nil {
					t.Fatalf("tokenversion(%s) failed: %v", uid, err)
				}
				return v
			}

			if v := version(uidStr); v != 0 {
				t.Fatalf("expected initial version 0, got %d", v)
			}
			if err := b.h.RevokeTokens(uidStr); err != nil {
				t.Fatalf("revoke failed: %v", err)
			}
			if err := b.h.RevokeTokens(uidStr); err != nil {
				t.Fatalf("revoke failed: %v", err)
			}
			if v := version(uidStr); v != 2 {
				t.Errorf("expected version 2 after two revokes, got %d", v)
			}
			if v := version("0"); v != 0 {
				t.Errorf("revoking erin changed root's version to %d", v)
			}

			if err := b.h.Userdel(uidStr); err != nil {
				t.Fatalf("userdel failed: %v", err)
			}
			if v := version(uidStr); v != 3 {
				t.Errorf("expected Userdel to bump the version to 3, got %d", v)
			}
		})
	}
}

// TestDBHandlerUserpatchHashesPasswordAndIgnoresUnknownColumns: Userpatch
// used to store a patched password unhashed (so the user could no longer
// log in) and interpolated any JSON key into the UPDATE as a column name.
func TestDBHandlerUserpatchHashesPasswordAndIgnoresUnknownColumns(t *testing.T) {
	withTempWD(t)
	h := &DBHandler{DBpath: "test.db"}
	h.Init(testRoot())
	defer h.Close()

	uid, pgroup, err := h.Useradd(domain.User{Name: "frank", Password: domain.Password{Hashpass: "hunter22"}})
	if err != nil {
		t.Fatalf("useradd failed: %v", err)
	}
	uidStr := strconv.Itoa(uid)

	if err := h.Userpatch(uidStr, map[string]interface{}{"password": "newpass123"}); err != nil {
		t.Fatalf("userpatch password failed: %v", err)
	}
	user, err := h.Authenticate("frank", "newpass123")
	if err != nil {
		t.Fatalf("expected login with the patched password to work: %v", err)
	}
	if user.Password.Hashpass == "newpass123" {
		t.Error("patched password was stored in plaintext")
	}

	err = h.Userpatch(uidStr, map[string]interface{}{
		"info":                     "legit",
		"username = 'pwned', info": "x",
		"pgroup":                   0,
		"info = (SELECT hashpass FROM passwords WHERE uid = 0), shell": "y",
	})
	if err != nil {
		t.Fatalf("userpatch failed: %v", err)
	}
	got := h.Select("users?uid=" + uidStr)[0].(domain.User)
	// the "pgroup": 0 key must not reach SQL: the primary group stays the
	// user's own group (its gid, which need not equal the uid)
	if got.Name != "frank" || got.Info != "legit" || got.Pgroup != pgroup {
		t.Errorf("unknown columns reached SQL: %+v", got)
	}
}
