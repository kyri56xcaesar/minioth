package store

/*
* PlainHandler stores users, passwords and groups in colon-delimited flat
* files (data/plain/{mpasswd,mshadow,mgroup}), mirroring /etc/passwd +
* /etc/shadow + /etc/group. It's a fully functional alternative to
* DBHandler for small/embedded deployments that don't want a SQLite
* dependency at all.
*
* Caveats, so a future caller knows what they're picking: plainWriteMu (see
* below) only guards against concurrent access from goroutines within this
* one process — concurrent writers across separate processes can still
* interleave and corrupt a file — and every write rewrites the whole file
* it touches, which is fine for tens or hundreds of users, not for scale.
* Neither of those apply to DBHandler.
* */

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/kyri56xcaesar/minioth/internal/domain"
	"github.com/kyri56xcaesar/minioth/internal/util"
)

const (
	PLACEHOLDER_PASS string = "3ncrypr3d"
	DEL              string = ":"
	// username:password ref:uuid:guid:info:home:shell:email:email_verified
	ENTRY_MPASSWD_FORMAT string = "%s" + DEL + "%s" + DEL + "%v" + DEL + "%v" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%v\n"
	MPASSWD_FIELDS       int    = 9
	ENTRY_MSHADOW_FORMAT string = "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%v\n"
	// groupname:password ref:gid:comma-separated member usernames
	ENTRY_MGROUP_FORMAT string = "%s" + DEL + "%s" + DEL + "%v" + DEL + "%s\n"
)

// MINIOTH_PASSWD/GROUP/SHADOW are package-level `var`, not `const` — the
// same "mutable config, set once at boot" pattern domain.HASH_COST and
// friends already use — so cmd/minioth's -data-dir flag can relocate them
// before any PlainHandler.Init() runs. Left as relative paths by default
// (matching every existing test's withTempWD-based isolation, which
// relies on relative paths re-resolving against whatever the process's
// current directory is), overridable via SetPlainDataDir.
var (
	MINIOTH_PASSWD = filepath.Join("data", "plain", "mpasswd")
	MINIOTH_GROUP  = filepath.Join("data", "plain", "mgroup")
	MINIOTH_SHADOW = filepath.Join("data", "plain", "mshadow")
	// uid:version lines, one per user whose tokens were ever revoked —
	// see TokenVersion/RevokeTokens. Created lazily on first revocation.
	MINIOTH_TOKENS = filepath.Join("data", "plain", "mtokens")
)

// SetPlainDataDir relocates where PlainHandler reads and writes its three
// flat files, all directly under dir (no further "plain" subdirectory —
// the caller's dir already is the plain-backend-specific location, e.g.
// "$DATA_DIR/plain"). Call once, before constructing/Init-ing any
// PlainHandler.
func SetPlainDataDir(dir string) {
	MINIOTH_PASSWD = filepath.Join(dir, "mpasswd")
	MINIOTH_GROUP = filepath.Join(dir, "mgroup")
	MINIOTH_SHADOW = filepath.Join(dir, "mshadow")
	MINIOTH_TOKENS = filepath.Join(dir, "mtokens")
}

type PlainHandler struct{}

// plainWriteMu guards every read-modify-write against the three flat files.
// It needs to be stricter than DBHandler's dbWriteMu (see db.go): that one
// only wraps the two id-allocation races (Useradd/Groupadd) because
// SQLite's UNIQUE/PRIMARY KEY constraints are a second line of defense for every
// other mutation. A colon-delimited text file enforces nothing — two
// concurrent Useradd calls can both compute the same uid via nextUid() and
// silently write two rows with it, and rewriteFile (used by every
// delete/patch/mod path) truncates the file with os.Create before writing
// it back, so a concurrent reader (Select, Authenticate, nextUid, ...) can
// observe a half-written or momentarily empty file. Every write method
// below takes the write lock; the read-only ones (Select, Authenticate)
// take the read lock so concurrent reads still don't serialize against each
// other, only against a write.
var plainWriteMu sync.RWMutex

/*  */
/* Pretty important!*/
/* initialization routines. check if data directory is there, check if root user exists...*/
func (m *PlainHandler) Init(root domain.User) {
	log.Print("Initializing minioth Plain")

	// All three files live in the same directory (see SetPlainDataDir), so
	// MkdirAll against any one of them creates it — including any missing
	// parents, unlike the old hardcoded two-step "data" then "data/plain"
	// os.Mkdir calls this replaced, which broke if -data-dir pointed
	// somewhere whose parent didn't exist yet.
	dir := filepath.Dir(MINIOTH_PASSWD)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		panic(fmt.Sprintf("failed to create plain data directory %q: %v", dir, err))
	}

	// Seed the same admin/mod/user groups DBHandler.Init creates
	// automatically. Without these, AuthMiddleware("admin", ...) (which
	// matches by group *name*) can never succeed for anyone on this
	// backend — Useradd only ever creates a user's own per-username
	// primary group, never adds them to a shared, named group.
	if err := seedStandardGroups(); err != nil {
		log.Printf("failed to seed standard groups: %v", err)
	}

	log.Print("Checking if plain dir exists...")
	// Should check if root exists...
	if err := verifyFilePrefix(MINIOTH_PASSWD, root.Name); err != nil {
		// Add root user
		if _, _, err := m.Useradd(domain.User{
			Name: root.Name,
			Password: domain.Password{
				Hashpass: root.Password.Hashpass,
			},
			Uid:    0,
			Pgroup: 0,
			Info:   "HEADMASTER",
			Home:   "/",
			Shell:  "/bin/gshell",
		}); err != nil {
			log.Printf("failed to seed root user: %v", err)
		} else if err := m.AssignGroup("0", 0); err != nil {
			// Useradd only joins uid 0 to its own "root" primary group —
			// without this, root itself couldn't pass AuthMiddleware("admin").
			log.Printf("failed to add root to the admin group: %v", err)
		}
	}
}

func (m *PlainHandler) Useradd(user domain.User) (int, int, error) {
	defer lockPlain(true)()

	log.Printf("Adding user %q ...", user.Name)
	if err := checkPlainValues(user.Name, user.Info, user.Home, user.Shell, user.Email); err != nil {
		return -1, -1, err
	}

	// Open/Create files first to handle all file errors at once.
	file, err := os.OpenFile(MINIOTH_PASSWD, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("error opening file: %v", err)
		return -1, -1, err
	}
	defer file.Close()

	pfile, err := os.OpenFile(MINIOTH_SHADOW, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("error opening file: %v", err)
		return -1, -1, err
	}
	defer pfile.Close()

	gfile, err := os.OpenFile(MINIOTH_GROUP, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("error opening file: %v", err)
		return -1, -1, err
	}
	defer gfile.Close()

	// Check if exists
	err = exists(&user)
	if err != nil {
		log.Printf("error: user already exists: %v", err)
		return -1, -1, err
	}

	// Generate password early, return early if failed...
	hashPass, err := domain.Hash([]byte(user.Password.Hashpass))
	if err != nil {
		log.Printf("Failed to hash the pass... :%v", err)
		return -1, -1, err
	}

	uuid := nextUid()
	for _, f := range []*os.File{pfile, gfile, file} {
		if err := terminateLastLine(f); err != nil {
			return -1, -1, err
		}
	}
	// shadow and group first, passwd (which makes the user exist) last: a
	// failure in between leaves unused lines, never a user without a password
	if _, err := fmt.Fprintf(pfile, ENTRY_MSHADOW_FORMAT, user.Name, hashPass, user.Password.LastPasswordChange, user.Password.MinPasswordAge, user.Password.MaxPasswordAge, user.Password.WarningPeriod, user.Password.InactivityPeriod, user.Password.ExpirationDate, len(user.Password.Hashpass)); err != nil {
		return -1, -1, fmt.Errorf("write shadow: %w", err)
	}
	// every user gets their own primary group (gid == uid in this store)
	if _, err := fmt.Fprintf(gfile, ENTRY_MGROUP_FORMAT, user.Name, PLACEHOLDER_PASS, uuid, user.Name); err != nil {
		return -1, -1, fmt.Errorf("write group: %w", err)
	}
	// email_verified always starts false here, regardless of anything the
	// caller set on user.EmailVerified — same reasoning as DBHandler.Useradd.
	if _, err := fmt.Fprintf(file, ENTRY_MPASSWD_FORMAT, user.Name, PLACEHOLDER_PASS, uuid, uuid, user.Info, user.Home, user.Shell, user.Email, false); err != nil {
		return -1, -1, fmt.Errorf("write passwd: %w", err)
	}
	for _, f := range []*os.File{pfile, gfile, file} {
		if err := f.Sync(); err != nil {
			return -1, -1, err
		}
	}

	iuud, err := strconv.Atoi(uuid)
	if err != nil {
		log.Printf("failed to atoi uid: %v", err)
		return -1, -1, err
	}
	log.Print("Useradd successful.")
	return iuud, iuud, nil
}

/* delete a user: their passwd/shadow entries, their own primary group, and
* their membership in every other group. */
func (m *PlainHandler) Userdel(uid string) error {
	defer lockPlain(true)()

	log.Printf("Deleting user with uid %q ...", uid)
	if uid == "" {
		return fmt.Errorf("must provide a uid")
	}
	if uid == "0" {
		return fmt.Errorf("deleting the root?")
	}

	username, err := usernameForUID(uid)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	if err := removeLineByKey(MINIOTH_PASSWD, username); err != nil {
		return fmt.Errorf("failed to remove passwd entry: %w", err)
	}
	if err := removeLineByKey(MINIOTH_SHADOW, username); err != nil {
		return fmt.Errorf("failed to remove shadow entry: %w", err)
	}
	if err := removeUserFromGroups(username); err != nil {
		return fmt.Errorf("failed to update group memberships: %w", err)
	}
	// Same reason as DBHandler.Userdel: nextUid can hand this uid out again.
	if err := bumpTokenVersion(uid); err != nil {
		return fmt.Errorf("failed to revoke deleted user's tokens: %w", err)
	}

	log.Print("Deletion successful.")

	return nil
}

/* replace an existing user's info/home/shell. Identity (name, uid) doesn't
* change through Usermod — that's what Userdel+Useradd is for. */
func (m *PlainHandler) Usermod(user domain.User) error {
	defer lockPlain(true)()
	if err := checkPlainValues(user.Info, user.Home, user.Shell); err != nil {
		return err
	}

	f, err := os.Open(MINIOTH_PASSWD)
	if err != nil {
		return err
	}

	var kept []string
	found := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, DEL, MPASSWD_FIELDS)
		if len(parts) == MPASSWD_FIELDS && parts[0] == user.Name {
			found = true
			// email/email_verified (parts[7], parts[8]) are preserved as-is
			// — Usermod only ever touches info/home/shell.
			kept = append(kept, strings.Join([]string{parts[0], parts[1], parts[2], parts[3], user.Info, user.Home, user.Shell, parts[7], parts[8]}, DEL))
			continue
		}
		kept = append(kept, line)
	}
	f.Close()

	if !found {
		return fmt.Errorf("user not found")
	}
	return rewriteFile(MINIOTH_PASSWD, kept)
}

/* partially patch a user identified by uid: info/home/shell (passwd file)
* and/or password (shadow file). */
func (m *PlainHandler) Userpatch(uid string, fields map[string]interface{}) error {
	defer lockPlain(true)()

	if len(fields) == 0 {
		return fmt.Errorf("no inputs")
	}
	if err := checkPlainFields(fields, "password"); err != nil {
		return err
	}

	username, err := usernameForUID(uid)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	if err := patchPasswdFields(username, fields); err != nil {
		return err
	}

	if v, ok := fields["password"]; ok {
		if pw, ok := v.(string); ok && pw != "" {
			hashPass, err := domain.Hash([]byte(pw))
			if err != nil {
				return fmt.Errorf("failed to hash password: %w", err)
			}
			if err := patchShadowPassword(username, string(hashPass)); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *PlainHandler) Groupadd(group domain.Group) (int, error) {
	defer lockPlain(true)()

	log.Printf("Adding group %q...", group.Name)
	if err := checkPlainValues(group.Name); err != nil {
		return -1, err
	}
	for _, u := range group.Users {
		if err := checkPlainValues(u.Name); err != nil {
			return -1, err
		}
	}

	if groupExists(group.Name) {
		return -1, fmt.Errorf("group already exists")
	}

	gfile, err := os.OpenFile(MINIOTH_GROUP, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return -1, err
	}
	defer gfile.Close()

	gid := nextGid()
	members := make([]string, 0, len(group.Users))
	for _, u := range group.Users {
		members = append(members, u.Name)
	}

	if err := terminateLastLine(gfile); err != nil {
		return -1, err
	}
	if _, err := fmt.Fprintf(gfile, ENTRY_MGROUP_FORMAT, group.Name, PLACEHOLDER_PASS, gid, strings.Join(members, ",")); err != nil {
		return -1, fmt.Errorf("write group: %w", err)
	}

	return gid, gfile.Sync()
}

func (m *PlainHandler) Groupdel(gid string) error {
	defer lockPlain(true)()

	f, err := os.Open(MINIOTH_GROUP)
	if err != nil {
		return err
	}

	var kept []string
	found := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, DEL, 4)
		if len(parts) >= 3 && parts[2] == gid {
			found = true
			continue
		}
		kept = append(kept, line)
	}
	f.Close()

	if !found {
		return fmt.Errorf("group not found")
	}
	return rewriteFile(MINIOTH_GROUP, kept)
}

func (m *PlainHandler) Grouppatch(gid string, fields map[string]interface{}) error {
	defer lockPlain(true)()
	if err := checkPlainFields(fields); err != nil {
		return err
	}

	f, err := os.Open(MINIOTH_GROUP)
	if err != nil {
		return err
	}

	var kept []string
	found := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, DEL, 4)
		if len(parts) >= 3 && parts[2] == gid {
			found = true
			name := parts[0]
			members := ""
			if len(parts) == 4 {
				members = parts[3]
			}
			if v, ok := fields["groupname"]; ok {
				if s, ok := v.(string); ok && s != "" {
					name = s
				}
			}
			if v, ok := fields["users"]; ok {
				if s, ok := v.(string); ok {
					members = s
				}
			}
			kept = append(kept, strings.Join([]string{name, PLACEHOLDER_PASS, gid, members}, DEL))
			continue
		}
		kept = append(kept, line)
	}
	f.Close()

	if !found {
		return fmt.Errorf("group not found")
	}
	return rewriteFile(MINIOTH_GROUP, kept)
}

func (m *PlainHandler) Groupmod(group domain.Group) error {
	defer lockPlain(true)()
	if err := checkPlainValues(group.Name); err != nil {
		return err
	}

	f, err := os.Open(MINIOTH_GROUP)
	if err != nil {
		return err
	}

	gidStr := strconv.Itoa(group.Gid)
	members := make([]string, 0, len(group.Users))
	for _, u := range group.Users {
		members = append(members, u.Name)
	}

	var kept []string
	found := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, DEL, 4)
		if len(parts) >= 3 && parts[2] == gidStr {
			found = true
			kept = append(kept, strings.Join([]string{group.Name, PLACEHOLDER_PASS, gidStr, strings.Join(members, ",")}, DEL))
			continue
		}
		kept = append(kept, line)
	}
	f.Close()

	if !found {
		return fmt.Errorf("group not found")
	}
	return rewriteFile(MINIOTH_GROUP, kept)
}

func (m *PlainHandler) Passwd(username, password string) error {
	defer lockPlain(true)()

	hashPass, err := domain.Hash([]byte(password))
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	return patchShadowPassword(username, string(hashPass))
}

// VerifyEmail marks uid's email as verified. Reached only via a signed
// email-verification token (internal/auth), not gated behind admin auth.
func (m *PlainHandler) VerifyEmail(uid string) error {
	defer lockPlain(true)()

	username, err := usernameForUID(uid)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	return patchPasswdFields(username, map[string]interface{}{"email_verified": true})
}

// AssignGroup adds uid to gid's membership — Grouppatch's "users" field
// replaces a group's whole member list wholesale, it has no notion of
// adding a single member, so promoting a user (e.g. to the admin group,
// gid 0) needs its own operation, same as DBHandler.AssignGroup.
func (m *PlainHandler) AssignGroup(uid string, gid int) error {
	defer lockPlain(true)()

	username, err := usernameForUID(uid)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	gidStr := strconv.Itoa(gid)

	f, err := os.Open(MINIOTH_GROUP)
	if err != nil {
		return err
	}

	var kept []string
	found := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, DEL, 4)
		if len(parts) >= 3 && parts[2] == gidStr {
			found = true
			members := []string{}
			if len(parts) == 4 && parts[3] != "" {
				members = strings.Split(parts[3], ",")
			}
			alreadyMember := false
			for _, existing := range members {
				if existing == username {
					alreadyMember = true
					break
				}
			}
			if !alreadyMember {
				members = append(members, username)
			}
			kept = append(kept, strings.Join([]string{parts[0], PLACEHOLDER_PASS, gidStr, strings.Join(members, ",")}, DEL))
			continue
		}
		kept = append(kept, line)
	}
	f.Close()

	if !found {
		return fmt.Errorf("group not found")
	}
	return rewriteFile(MINIOTH_GROUP, kept)
}

/* this method is supposed to return eveyrhing from the given file */
func (m *PlainHandler) TokenVersion(uid string) (int, error) {
	defer lockPlain(false)()

	versions, err := readTokenVersions()
	if err != nil {
		return 0, err
	}
	return versions[uid], nil
}

func (m *PlainHandler) RevokeTokens(uid string) error {
	defer lockPlain(true)()

	return bumpTokenVersion(uid)
}

func (m *PlainHandler) Select(id string) []interface{} {
	defer lockPlain(false)()

	base, param, value := util.SplitSelectID(id)

	switch base {
	case "users":
		return m.selectUsers(param, value)
	case "groups":
		return m.selectGroups(param, value)
	default:
		log.Print("Invalid id: " + id)
		return nil
	}
}

func (m *PlainHandler) selectUsers(param, value string) []interface{} {
	pf, err := os.Open(MINIOTH_PASSWD)
	if err != nil {
		log.Printf("error reading file: %v", err)
		return nil
	}
	defer pf.Close()

	shadow, err := readShadowByUsername()
	if err != nil {
		log.Printf("error reading shadow file: %v", err)
	}
	groupsByUser, err := readGroupMembership()
	if err != nil {
		log.Printf("error reading group file: %v", err)
	}

	var result []interface{}
	scanner := bufio.NewScanner(pf)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), DEL, MPASSWD_FIELDS)
		if len(parts) != MPASSWD_FIELDS {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		pgroup, _ := strconv.Atoi(parts[3])
		user := domain.User{
			Name: parts[0], Uid: uid, Pgroup: pgroup,
			Info: parts[4], Home: parts[5], Shell: parts[6],
			Email: parts[7], EmailVerified: parts[8] == "true",
		}
		if pw, ok := shadow[user.Name]; ok {
			user.Password = pw
		}
		user.Groups = groupsByUser[user.Name]

		switch param {
		case "uid":
			if strconv.Itoa(user.Uid) != value {
				continue
			}
		case "username":
			if user.Name != value {
				continue
			}
		}
		result = append(result, user)
	}
	return result
}

func (m *PlainHandler) selectGroups(param, value string) []interface{} {
	f, err := os.Open(MINIOTH_GROUP)
	if err != nil {
		log.Printf("error reading file: %v", err)
		return nil
	}
	defer f.Close()

	var result []interface{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), DEL, 4)
		if len(parts) < 3 {
			continue
		}
		gid, _ := strconv.Atoi(parts[2])
		group := domain.Group{Name: parts[0], Gid: gid}
		if len(parts) == 4 && parts[3] != "" {
			for _, name := range strings.Split(parts[3], ",") {
				group.Users = append(group.Users, domain.User{Name: name})
			}
		}

		switch param {
		case "gid":
			if strconv.Itoa(group.Gid) != value {
				continue
			}
		case "groupname":
			if group.Name != value {
				continue
			}
		}
		result = append(result, group)
	}
	return result
}

/* approval of minioth means, user exists and password is valid */
func (m *PlainHandler) Authenticate(username, password string) (*domain.User, error) {
	defer lockPlain(false)()

	log.Printf("authenticating user... %q", username)

	file, err := os.Open(MINIOTH_PASSWD)
	if err != nil {
		log.Printf("failed to open file: %v", err)
		return nil, err
	}
	defer file.Close()

	pfile, err := os.Open(MINIOTH_SHADOW)
	if err != nil {
		log.Printf("failed to open file: %v", err)
		return nil, err
	}
	defer pfile.Close()

	log.Print("searching for user entry...")
	userline, _, err := search(username, file)
	if err != nil {
		log.Printf("failed to search for user: %v", err)
		return nil, fmt.Errorf("user not found")
	}

	log.Print("searching for password entry...")
	passline, _, err := search(username, pfile)
	if err != nil {
		log.Printf("failed to search for pass: %v", err)
		return nil, fmt.Errorf("user not found")
	}

	hashpass := strings.SplitN(passline, DEL, 3)[1]
	if !domain.VerifyPass([]byte(hashpass), []byte(password)) {
		return nil, fmt.Errorf("failed to authenticate, bad creds")
	}

	parts := strings.SplitN(userline, DEL, MPASSWD_FIELDS)
	if len(parts) != MPASSWD_FIELDS {
		return nil, fmt.Errorf("corrupt passwd entry for %q", username)
	}
	uid, _ := strconv.Atoi(parts[2])
	pgroup, _ := strconv.Atoi(parts[3])
	user := &domain.User{
		Name: parts[0], Uid: uid, Pgroup: pgroup,
		Info: parts[4], Home: parts[5], Shell: parts[6],
		Email: parts[7], EmailVerified: parts[8] == "true",
	}

	if groupsByUser, err := readGroupMembership(); err == nil {
		user.Groups = groupsByUser[username]
	}

	return user, nil
}

// Ready checks that the three files can be read and that their directory
// takes new files (every write is a temp file renamed over the original).
func (p *PlainHandler) Ready() error {
	for _, f := range []string{MINIOTH_PASSWD, MINIOTH_SHADOW, MINIOTH_GROUP} {
		fh, err := os.Open(f)
		if err != nil {
			return fmt.Errorf("plain store: %w", err)
		}
		_ = fh.Close()
	}
	tmp, err := os.CreateTemp(filepath.Dir(MINIOTH_PASSWD), ".ready-*")
	if err != nil {
		return fmt.Errorf("plain store: directory not writable: %w", err)
	}
	_ = tmp.Close()

	return os.Remove(tmp.Name())
}

func (p *PlainHandler) Close() {
}

/* just read the first 4 bytes from a file...
* Used to check if root is entried.*/
func verifyFilePrefix(filePath, prefix string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	buffer := make([]byte, 4)

	n, err := file.Read(buffer)
	if err != nil {
		return fmt.Errorf("failed to read from file: %w", err)
	}

	if n < 4 {
		return fmt.Errorf("file is too short, only read %d bytes", n)
	}

	if string(buffer) == prefix {
		return nil
	}

	return fmt.Errorf("prefix doesn't match %s", prefix)
}

/* check if a user is already here. Error nil if not*/
func exists(user *domain.User) error {
	log.Printf("checking if %q exists...", user.Name)
	file, err := os.Open(MINIOTH_PASSWD)
	if err != nil {
		log.Printf("error opening file: %v", err)
		return err
	}
	defer file.Close()
	res, line, err := search(user.Name, file)
	if err == nil && line != -1 {
		log.Printf("user: %q exists at line: %v", strings.SplitN(res, ":", 2)[0], line)
		return fmt.Errorf("user already exists")
	}

	return nil
}

// seedStandardGroups ensures the admin (gid 0) / mod (gid 100) / user (gid
// 1000) groups exist, matching DBHandler.Init's seeding — idempotent,
// skips whichever already exist so re-running Init on an existing mgroup
// file is a no-op.
func seedStandardGroups() error {
	gfile, err := os.OpenFile(MINIOTH_GROUP, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer gfile.Close()

	standard := []struct {
		name string
		gid  int
	}{
		{"admin", 0},
		{"mod", 100},
		{"user", 1000},
	}
	if err := terminateLastLine(gfile); err != nil {
		return err
	}
	for _, g := range standard {
		if groupExists(g.name) {
			continue
		}
		if _, err := fmt.Fprintf(gfile, ENTRY_MGROUP_FORMAT, g.name, PLACEHOLDER_PASS, g.gid, ""); err != nil {
			return err
		}
	}
	return gfile.Sync()
}

func groupExists(name string) bool {
	f, err := os.Open(MINIOTH_GROUP)
	if err != nil {
		return false
	}
	defer f.Close()
	_, line, err := search(name, f)
	return err == nil && line != -1
}

// must have
// function to check for existance of a user
func search(username string, file *os.File) (string, int, error) {
	if username == "" || file == nil {
		return "", -1, fmt.Errorf("must provide parameter")
	}
	scanner := bufio.NewScanner(file)

	lineIndex := 0
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, DEL, 2)
		if len(parts) != 2 {
			return "", -1, fmt.Errorf("no content found")
		}
		if username == parts[0] {
			return line, lineIndex, nil
		}

		lineIndex++

	}

	return "", -1, fmt.Errorf("user not found")
}

// usernameForUID looks up a username by uid in the passwd file — the
// public handler methods are keyed by uid (matching DBHandler and the
// MiniothHandler interface), while the flat file itself is keyed by
// username, so every uid-keyed operation routes through this first.
func usernameForUID(uid string) (string, error) {
	f, err := os.Open(MINIOTH_PASSWD)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), DEL, MPASSWD_FIELDS)
		if len(parts) != MPASSWD_FIELDS {
			continue
		}
		if parts[2] == uid {
			return parts[0], nil
		}
	}
	return "", fmt.Errorf("user not found")
}

// removeLineByKey rewrites path, dropping every line whose first
// colon-delimited field equals key.
func removeLineByKey(path, key string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}

	var kept []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, DEL, 2)
		if len(parts) != 2 || parts[0] != key {
			kept = append(kept, line)
		}
	}
	f.Close()

	return rewriteFile(path, kept)
}

// removeUserFromGroups drops username's own primary group (groupname ==
// username, by the Useradd convention above) and scrubs it out of every
// other group's member list.
func removeUserFromGroups(username string) error {
	f, err := os.Open(MINIOTH_GROUP)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	var kept []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, DEL, 4)
		if len(parts) != 4 {
			kept = append(kept, line)
			continue
		}
		groupname, passRef, gidStr, membersField := parts[0], parts[1], parts[2], parts[3]
		if groupname == username {
			continue
		}

		var members []string
		if membersField != "" {
			members = strings.Split(membersField, ",")
		}
		filtered := members[:0]
		for _, member := range members {
			if member != username {
				filtered = append(filtered, member)
			}
		}
		kept = append(kept, strings.Join([]string{groupname, passRef, gidStr, strings.Join(filtered, ",")}, DEL))
	}
	f.Close()

	return rewriteFile(MINIOTH_GROUP, kept)
}

// patchPasswdFields updates only the info/home/shell/email/email_verified
// columns present in fields — username and uid never change via a patch.
// email_verified is only ever driven by VerifyEmail in practice (this
// whitelist just keeps it symmetric with DBHandler.Userpatch, whose
// generic default-case column update already accepts any field name).
func patchPasswdFields(username string, fields map[string]interface{}) error {
	f, err := os.Open(MINIOTH_PASSWD)
	if err != nil {
		return err
	}

	var kept []string
	found := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, DEL, MPASSWD_FIELDS)
		if len(parts) == MPASSWD_FIELDS && parts[0] == username {
			found = true
			info, home, shell, email, emailVerified := parts[4], parts[5], parts[6], parts[7], parts[8]
			if v, ok := fields["info"].(string); ok {
				info = v
			}
			if v, ok := fields["home"].(string); ok {
				home = v
			}
			if v, ok := fields["shell"].(string); ok {
				shell = v
			}
			if v, ok := fields["email"].(string); ok {
				email = v
			}
			if v, ok := fields["email_verified"].(bool); ok {
				emailVerified = strconv.FormatBool(v)
			}
			kept = append(kept, strings.Join([]string{parts[0], parts[1], parts[2], parts[3], info, home, shell, email, emailVerified}, DEL))
			continue
		}
		kept = append(kept, line)
	}
	f.Close()

	if !found {
		return fmt.Errorf("user not found")
	}
	return rewriteFile(MINIOTH_PASSWD, kept)
}

func readTokenVersions() (map[string]int, error) {
	f, err := os.Open(MINIOTH_TOKENS)
	if os.IsNotExist(err) {
		return map[string]int{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]int{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), DEL, 2)
		if len(parts) != 2 {
			continue
		}
		v, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		out[parts[0]] = v
	}
	return out, scanner.Err()
}

// bumpTokenVersion increments uid's token generation. Callers must hold
// plainWriteMu's write lock.
func bumpTokenVersion(uid string) error {
	versions, err := readTokenVersions()
	if err != nil {
		return err
	}
	versions[uid]++

	uids := make([]string, 0, len(versions))
	for u := range versions {
		uids = append(uids, u)
	}
	sort.Strings(uids)

	lines := make([]string, 0, len(uids))
	for _, u := range uids {
		lines = append(lines, u+DEL+strconv.Itoa(versions[u]))
	}
	return rewriteFile(MINIOTH_TOKENS, lines)
}

func patchShadowPassword(username, hashPass string) error {
	f, err := os.Open(MINIOTH_SHADOW)
	if err != nil {
		return err
	}

	var kept []string
	found := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, DEL, 9)
		if len(parts) == 9 && parts[0] == username {
			found = true
			parts[1] = hashPass
			kept = append(kept, strings.Join(parts, DEL))
			continue
		}
		kept = append(kept, line)
	}
	f.Close()

	if !found {
		return fmt.Errorf("user not found")
	}
	return rewriteFile(MINIOTH_SHADOW, kept)
}

func readShadowByUsername() (map[string]domain.Password, error) {
	f, err := os.Open(MINIOTH_SHADOW)
	if os.IsNotExist(err) {
		return map[string]domain.Password{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]domain.Password{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), DEL, 9)
		if len(parts) != 9 {
			continue
		}
		out[parts[0]] = domain.Password{
			Hashpass:           parts[1],
			LastPasswordChange: parts[2],
			MinPasswordAge:     parts[3],
			MaxPasswordAge:     parts[4],
			WarningPeriod:      parts[5],
			InactivityPeriod:   parts[6],
			ExpirationDate:     parts[7],
		}
	}
	return out, nil
}

func readGroupMembership() (map[string][]domain.Group, error) {
	f, err := os.Open(MINIOTH_GROUP)
	if os.IsNotExist(err) {
		return map[string][]domain.Group{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string][]domain.Group{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), DEL, 4)
		if len(parts) < 3 {
			continue
		}
		gid, _ := strconv.Atoi(parts[2])
		group := domain.Group{Name: parts[0], Gid: gid}
		if len(parts) == 4 && parts[3] != "" {
			for _, member := range strings.Split(parts[3], ",") {
				out[member] = append(out[member], group)
			}
		}
	}
	return out, nil
}

/* Look for all the existing uids and give the succeeding one in order.
 * It verifies uniqueness*/
func nextUid() string {
	f, err := os.Open(MINIOTH_PASSWD)
	if err != nil {
		panic("couldn't retrieve uuid")
	}
	defer f.Close()

	currentUids := []string{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != MPASSWD_FIELDS {
			continue
		}
		id := parts[2]
		currentUids = append(currentUids, id)
	}

	var iuuid int
	// check for next available
	intExists := func(id int) bool {
		for _, i := range currentUids {
			if strconv.Itoa(id) == i {
				return true
			}
		}
		return false
	}
	if len(currentUids) == 0 {
		iuuid = 0
	} else {
		iuuid = 1000
		for intExists(iuuid) {
			iuuid++
		}
	}

	return strconv.Itoa(iuuid)
}

/* same idea as nextUid, for the group file. */
func nextGid() int {
	f, err := os.Open(MINIOTH_GROUP)
	if err != nil {
		return 1000
	}
	defer f.Close()

	existing := map[int]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), DEL, 4)
		if len(parts) < 3 {
			continue
		}
		if gid, err := strconv.Atoi(parts[2]); err == nil {
			existing[gid] = true
		}
	}

	gid := 1000
	for existing[gid] {
		gid++
	}
	return gid
}
