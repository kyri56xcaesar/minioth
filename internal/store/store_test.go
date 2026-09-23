package store

import (
	"os"
	"strconv"
	"testing"

	"github.com/kyri56xcaesar/minioth/internal/domain"
)

// testRoot is the root user Init() seeds with in these tests — the
// interface now takes a caller-supplied root (see the configurable root
// credential feature), so every Init() call needs one.
func testRoot() domain.User {
	return domain.User{Name: "root", Password: domain.Password{Hashpass: "root"}}
}

func TestPlainHandlerUseraddAndAuthenticate(t *testing.T) {
	withTempWD(t)

	h := &PlainHandler{}
	h.Init(testRoot())

	uid, pgroup, err := h.Useradd(domain.User{
		Name:     "alice",
		Password: domain.Password{Hashpass: "hunter22"},
		Info:     "test user",
		Home:     "/home/alice",
		Shell:    "/bin/bash",
	})
	if err != nil {
		t.Fatalf("useradd failed: %v", err)
	}
	if uid != pgroup {
		t.Fatalf("expected primary group to equal uid, got uid=%d pgroup=%d", uid, pgroup)
	}

	// PlainHandler.Authenticate used to return (nil, nil) on success, which
	// would nil-pointer panic any caller that dereferenced the user.
	user, err := h.Authenticate("alice", "hunter22")
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}
	if user == nil {
		t.Fatal("expected a non-nil user on successful authentication")
	}
	if user.Name != "alice" || user.Uid != uid {
		t.Errorf("unexpected user: %+v", user)
	}

	if _, err := h.Authenticate("alice", "wrong-password"); err == nil {
		t.Error("expected authentication to fail with the wrong password")
	}
}

func TestPlainHandlerUserdelByUID(t *testing.T) {
	withTempWD(t)

	h := &PlainHandler{}
	h.Init(testRoot())

	uid, _, err := h.Useradd(domain.User{
		Name:     "bob",
		Password: domain.Password{Hashpass: "hunter22"},
	})
	if err != nil {
		t.Fatalf("useradd failed: %v", err)
	}

	// Userdel takes a uid (per the MiniothHandler interface and every
	// caller), not a username — this used to compare the uid string
	// against the passwd file's username field and never match.
	if err := h.Userdel(strconv.Itoa(uid)); err != nil {
		t.Fatalf("userdel failed: %v", err)
	}

	if _, err := h.Authenticate("bob", "hunter22"); err == nil {
		t.Error("expected deleted user to no longer authenticate")
	}
}

func TestDBHandlerUserpatchWithoutGroupsField(t *testing.T) {
	withTempWD(t)
	// DBHandler.Init() only handles a DBpath relative to the working
	// directory (it joins cwd with everything but the last path segment),
	// same as the one real caller (cmd/minioth: "minioth.db").
	h := &DBHandler{DBpath: "test.db"}
	h.Init(testRoot())
	defer h.Close()

	uid, _, err := h.Useradd(domain.User{
		Name:     "carol",
		Password: domain.Password{Hashpass: "hunter22"},
	})
	if err != nil {
		t.Fatalf("useradd failed: %v", err)
	}

	// A patch payload with no "groups" key used to panic on an unguarded
	// `groups.(string)` type assertion against a nil interface{}.
	if err := h.Userpatch(strconv.Itoa(uid), map[string]interface{}{"info": "updated"}); err != nil {
		t.Fatalf("userpatch failed: %v", err)
	}
}

// TestEmailAndGroupAssignment covers the two additions shared by both
// backends: Email/EmailVerified round-tripping through Useradd/Select/
// VerifyEmail, and AssignGroup adding a user to a group (gid 0, "admin")
// without touching their existing memberships — the mechanism
// /admin/promote uses. Table-driven across both handlers since both
// independently reimplement the same field, in DB columns vs. flat-file
// format positions respectively — exactly the kind of change where the
// two backends drift apart if only one gets tested.
func TestEmailAndGroupAssignment(t *testing.T) {
	backends := []struct {
		name string
		h    domain.MiniothHandler
	}{
		{"plain", &PlainHandler{}},
		{"db", &DBHandler{DBpath: "test.db"}},
	}

	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			withTempWD(t)
			b.h.Init(testRoot())
			defer b.h.Close()

			uid, _, err := b.h.Useradd(domain.User{
				Name:     "dave",
				Password: domain.Password{Hashpass: "hunter22"},
				Email:    "dave@example.com",
			})
			if err != nil {
				t.Fatalf("useradd failed: %v", err)
			}
			uidStr := strconv.Itoa(uid)

			results := b.h.Select("users?uid=" + uidStr)
			if len(results) != 1 {
				t.Fatalf("expected 1 user, got %d", len(results))
			}
			user, ok := results[0].(domain.User)
			if !ok {
				t.Fatalf("unexpected result type: %T", results[0])
			}
			if user.Email != "dave@example.com" {
				t.Errorf("expected email to round-trip, got %q", user.Email)
			}
			if user.EmailVerified {
				t.Error("expected email_verified to start false")
			}

			if err := b.h.VerifyEmail(uidStr); err != nil {
				t.Fatalf("verifyemail failed: %v", err)
			}
			results = b.h.Select("users?uid=" + uidStr)
			user = results[0].(domain.User)
			if !user.EmailVerified {
				t.Error("expected email_verified to be true after VerifyEmail")
			}

			if err := b.h.AssignGroup(uidStr, 0); err != nil {
				t.Fatalf("assigngroup failed: %v", err)
			}
			foundInAdminGroup := false
			for _, g := range b.h.Select("groups") {
				group, ok := g.(domain.Group)
				if !ok || group.Gid != 0 {
					continue
				}
				for _, u := range group.Users {
					if u.Name == "dave" {
						foundInAdminGroup = true
					}
				}
			}
			if !foundInAdminGroup {
				t.Error("expected dave to be a member of gid 0 after AssignGroup")
			}
		})
	}
}

// withTempWD chdirs into a fresh temp directory for the duration of the
// test, restoring the original working directory on cleanup. The handlers
// under test all use relative "data/..." paths.
func withTempWD(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Chdir(orig)
	})
}
