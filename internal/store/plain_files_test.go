package store

/* Tests in this file check the actual bytes PlainHandler writes to disk —
* not just that the Go API round-trips correctly (store_test.go already
* covers that), but that the colon-delimited file format itself is
* correct: right delimiter, right field count and order, right values.
* This is exactly the class of bug a field-count change (like adding
* email/email_verified) risks introducing silently if only the Go-API
* round-trip is tested, since a wrong field OFFSET can still happen to
* read back a value that merely looks plausible. */

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/kyri56xcaesar/minioth/internal/domain"
)

// readFileLines reads a file directly (bypassing every PlainHandler
// method) and returns its non-empty lines, so assertions are against what
// actually landed on disk.
func readFileLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// findLineByField scans lines for the one whose colon-delimited field at
// index equals want, failing the test if there isn't exactly one match —
// mirrors what a correct parser should find, without using any of
// PlainHandler's own parsing helpers.
func findLineByField(t *testing.T, lines []string, index int, want string) []string {
	t.Helper()
	var matches [][]string
	for _, l := range lines {
		parts := strings.Split(l, DEL)
		if index < len(parts) && parts[index] == want {
			matches = append(matches, parts)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 line with field[%d]=%q, got %d (lines: %v)", index, want, len(matches), lines)
	}
	return matches[0]
}

func TestPlainUseraddFileFormat(t *testing.T) {
	withTempWD(t)

	h := &PlainHandler{}
	h.Init(testRoot())

	uid, _, err := h.Useradd(domain.User{
		Name:     "hank",
		Password: domain.Password{Hashpass: "hankpass1"},
		Info:     "hank the user",
		Home:     "/home/hank",
		Shell:    "/bin/zsh",
		Email:    "hank@example.com",
	})
	if err != nil {
		t.Fatalf("useradd failed: %v", err)
	}
	uidStr := strconv.Itoa(uid)

	// --- mpasswd: username:password_ref:uid:pgroup:info:home:shell:email:email_verified
	passwdLines := readFileLines(t, MINIOTH_PASSWD)
	fields := findLineByField(t, passwdLines, 0, "hank")
	if len(fields) != MPASSWD_FIELDS {
		t.Fatalf("expected %d colon-delimited fields in mpasswd line, got %d: %q", MPASSWD_FIELDS, len(fields), fields)
	}
	if fields[1] != PLACEHOLDER_PASS {
		t.Errorf("field[1] (password ref) = %q, want placeholder %q", fields[1], PLACEHOLDER_PASS)
	}
	if fields[2] != uidStr {
		t.Errorf("field[2] (uid) = %q, want %q", fields[2], uidStr)
	}
	if fields[3] != uidStr {
		t.Errorf("field[3] (pgroup) = %q, want %q (own primary group)", fields[3], uidStr)
	}
	if fields[4] != "hank the user" {
		t.Errorf("field[4] (info) = %q", fields[4])
	}
	if fields[5] != "/home/hank" {
		t.Errorf("field[5] (home) = %q", fields[5])
	}
	if fields[6] != "/bin/zsh" {
		t.Errorf("field[6] (shell) = %q", fields[6])
	}
	if fields[7] != "hank@example.com" {
		t.Errorf("field[7] (email) = %q", fields[7])
	}
	if fields[8] != "false" {
		t.Errorf("field[8] (email_verified) = %q, want \"false\" — must never start true regardless of caller input", fields[8])
	}

	// --- mshadow: username:hashpass:lastPasswordChange:minAge:maxAge:warningPeriod:inactivityPeriod:expirationDate:len(hashpass)
	shadowLines := readFileLines(t, MINIOTH_SHADOW)
	sfields := findLineByField(t, shadowLines, 0, "hank")
	if len(sfields) != 9 {
		t.Fatalf("expected 9 colon-delimited fields in mshadow line, got %d: %q", len(sfields), sfields)
	}
	if sfields[1] == "hankpass1" {
		t.Error("shadow entry stores the plaintext password instead of a bcrypt hash")
	}
	if !strings.HasPrefix(sfields[1], "$2a$") {
		t.Errorf("field[1] (hashpass) doesn't look like a bcrypt hash: %q", sfields[1])
	}

	// --- mgroup: hank's own primary group, groupname:password_ref:gid:members
	groupLines := readFileLines(t, MINIOTH_GROUP)
	gfields := findLineByField(t, groupLines, 0, "hank")
	if len(gfields) != 4 {
		t.Fatalf("expected 4 colon-delimited fields in mgroup line, got %d: %q", len(gfields), gfields)
	}
	if gfields[2] != uidStr {
		t.Errorf("field[2] (gid) = %q, want %q (own primary group gid == uid)", gfields[2], uidStr)
	}
	if gfields[3] != "hank" {
		t.Errorf("field[3] (members) = %q, want just %q", gfields[3], "hank")
	}
}

func TestPlainUserdelRemovesFileLines(t *testing.T) {
	withTempWD(t)

	h := &PlainHandler{}
	h.Init(testRoot())

	uid, _, err := h.Useradd(domain.User{Name: "ivan", Password: domain.Password{Hashpass: "ivanpass1"}})
	if err != nil {
		t.Fatalf("useradd failed: %v", err)
	}

	if err := h.Userdel(strconv.Itoa(uid)); err != nil {
		t.Fatalf("userdel failed: %v", err)
	}

	for _, path := range []string{MINIOTH_PASSWD, MINIOTH_SHADOW} {
		for _, l := range readFileLines(t, path) {
			if strings.HasPrefix(l, "ivan"+DEL) {
				t.Errorf("expected no line for ivan in %s after Userdel, found: %q", path, l)
			}
		}
	}
	// Userdel also drops ivan's own primary group from mgroup entirely.
	for _, l := range readFileLines(t, MINIOTH_GROUP) {
		if strings.HasPrefix(l, "ivan"+DEL) {
			t.Errorf("expected ivan's primary group gone from mgroup, found: %q", l)
		}
	}
}

func TestPlainUsermodPreservesEmailFields(t *testing.T) {
	withTempWD(t)

	h := &PlainHandler{}
	h.Init(testRoot())

	uid, _, err := h.Useradd(domain.User{
		Name: "jill", Password: domain.Password{Hashpass: "jillpass1"},
		Info: "old info", Email: "jill@example.com",
	})
	if err != nil {
		t.Fatalf("useradd failed: %v", err)
	}
	if err := h.VerifyEmail(strconv.Itoa(uid)); err != nil {
		t.Fatalf("verifyemail failed: %v", err)
	}

	if err := h.Usermod(domain.User{Name: "jill", Info: "new info", Home: "/home/jill", Shell: "/bin/sh"}); err != nil {
		t.Fatalf("usermod failed: %v", err)
	}

	fields := findLineByField(t, readFileLines(t, MINIOTH_PASSWD), 0, "jill")
	if fields[4] != "new info" {
		t.Errorf("expected info updated to %q, got %q", "new info", fields[4])
	}
	// Usermod never touches email/email_verified — they must survive
	// untouched, not get zeroed out by the rewrite.
	if fields[7] != "jill@example.com" {
		t.Errorf("expected email preserved across Usermod, got %q", fields[7])
	}
	if fields[8] != "true" {
		t.Errorf("expected email_verified preserved as true across Usermod, got %q", fields[8])
	}
}

func TestPlainUserpatchEmailFields(t *testing.T) {
	withTempWD(t)

	h := &PlainHandler{}
	h.Init(testRoot())

	uid, _, err := h.Useradd(domain.User{Name: "kate", Password: domain.Password{Hashpass: "katepass1"}})
	if err != nil {
		t.Fatalf("useradd failed: %v", err)
	}

	if err := h.Userpatch(strconv.Itoa(uid), map[string]interface{}{"email": "kate@example.com"}); err != nil {
		t.Fatalf("userpatch failed: %v", err)
	}
	fields := findLineByField(t, readFileLines(t, MINIOTH_PASSWD), 0, "kate")
	if fields[7] != "kate@example.com" {
		t.Errorf("expected email patched to %q, got %q", "kate@example.com", fields[7])
	}
	if fields[8] != "false" {
		t.Errorf("expected email_verified still false after only patching email, got %q", fields[8])
	}
}

func TestPlainGroupaddAndAssignGroupFileFormat(t *testing.T) {
	withTempWD(t)

	h := &PlainHandler{}
	h.Init(testRoot())

	uid, _, err := h.Useradd(domain.User{Name: "leo", Password: domain.Password{Hashpass: "leopass1"}})
	if err != nil {
		t.Fatalf("useradd failed: %v", err)
	}

	gid, err := h.Groupadd(domain.Group{Name: "engineering"})
	if err != nil {
		t.Fatalf("groupadd failed: %v", err)
	}
	gidStr := strconv.Itoa(gid)

	fields := findLineByField(t, readFileLines(t, MINIOTH_GROUP), 0, "engineering")
	if len(fields) != 4 {
		t.Fatalf("expected 4 fields in mgroup line, got %d: %q", len(fields), fields)
	}
	if fields[2] != gidStr {
		t.Errorf("field[2] (gid) = %q, want %q", fields[2], gidStr)
	}
	if fields[3] != "" {
		t.Errorf("expected a freshly added group to start with no members, got %q", fields[3])
	}

	// AssignGroup must append, not replace, and must not duplicate a
	// member already present.
	if err := h.AssignGroup(strconv.Itoa(uid), gid); err != nil {
		t.Fatalf("assigngroup failed: %v", err)
	}
	if err := h.AssignGroup(strconv.Itoa(uid), gid); err != nil {
		t.Fatalf("assigngroup (repeat) failed: %v", err)
	}
	fields = findLineByField(t, readFileLines(t, MINIOTH_GROUP), 0, "engineering")
	members := strings.Split(fields[3], ",")
	count := 0
	for _, m := range members {
		if m == "leo" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected leo to appear exactly once in members after two AssignGroup calls, got %d (members: %q)", count, fields[3])
	}
}

func TestPlainGrouppatchAndGroupdelFileFormat(t *testing.T) {
	withTempWD(t)

	h := &PlainHandler{}
	h.Init(testRoot())

	gid, err := h.Groupadd(domain.Group{Name: "sales"})
	if err != nil {
		t.Fatalf("groupadd failed: %v", err)
	}
	gidStr := strconv.Itoa(gid)

	if err := h.Grouppatch(gidStr, map[string]interface{}{"groupname": "sales-and-marketing"}); err != nil {
		t.Fatalf("grouppatch failed: %v", err)
	}
	lines := readFileLines(t, MINIOTH_GROUP)
	for _, l := range lines {
		if strings.HasPrefix(l, "sales"+DEL) {
			t.Errorf("expected old groupname gone after rename, found: %q", l)
		}
	}
	findLineByField(t, lines, 0, "sales-and-marketing")

	if err := h.Groupdel(gidStr); err != nil {
		t.Fatalf("groupdel failed: %v", err)
	}
	for _, l := range readFileLines(t, MINIOTH_GROUP) {
		parts := strings.Split(l, DEL)
		if len(parts) >= 3 && parts[2] == gidStr {
			t.Errorf("expected gid %s gone from mgroup after Groupdel, found: %q", gidStr, l)
		}
	}
}

func TestSeedStandardGroupsFileFormat(t *testing.T) {
	withTempWD(t)

	h := &PlainHandler{}
	h.Init(testRoot()) // Init calls seedStandardGroups internally

	lines := readFileLines(t, MINIOTH_GROUP)
	for _, want := range []struct {
		name string
		gid  string
	}{
		{"admin", "0"},
		{"mod", "100"},
		{"user", "1000"},
	} {
		fields := findLineByField(t, lines, 0, want.name)
		if fields[2] != want.gid {
			t.Errorf("expected %q at gid %s, got gid %s", want.name, want.gid, fields[2])
		}
	}

	// Re-running Init (e.g. a process restart against existing files)
	// must not duplicate the seeded groups.
	h2 := &PlainHandler{}
	h2.Init(testRoot())
	lines = readFileLines(t, MINIOTH_GROUP)
	adminCount := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "admin"+DEL) {
			adminCount++
		}
	}
	if adminCount != 1 {
		t.Errorf("expected exactly 1 \"admin\" line after re-running Init, got %d", adminCount)
	}
}

func TestSetPlainDataDirRelocatesFiles(t *testing.T) {
	withTempWD(t)
	// Restore the package-level paths afterward — they're process-global
	// (see SetPlainDataDir's doc comment), so leaking a custom dir out of
	// this test would break every test that runs after it.
	origPasswd, origGroup, origShadow := MINIOTH_PASSWD, MINIOTH_GROUP, MINIOTH_SHADOW
	t.Cleanup(func() {
		MINIOTH_PASSWD, MINIOTH_GROUP, MINIOTH_SHADOW = origPasswd, origGroup, origShadow
	})

	SetPlainDataDir("custom/nested/plaindir")

	h := &PlainHandler{}
	h.Init(testRoot())

	for _, path := range []string{MINIOTH_PASSWD, MINIOTH_GROUP, MINIOTH_SHADOW} {
		if !strings.HasPrefix(path, "custom/nested/plaindir"+string(os.PathSeparator)) && !strings.HasPrefix(path, "custom/nested/plaindir/") {
			t.Errorf("expected path under the custom data dir, got %q", path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected %s to exist under the custom data dir: %v", path, err)
		}
	}
	if _, err := os.Stat("data/plain/mpasswd"); err == nil {
		t.Error("expected nothing written to the old default data/plain location once SetPlainDataDir was called")
	}
}
