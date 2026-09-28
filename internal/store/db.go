package store

/*
* A minioth handler, encircling a SQLite database.
*
* */

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/kyri56xcaesar/minioth/internal/domain"
	"github.com/kyri56xcaesar/minioth/internal/util"
)

/* utility constants and globals */
const (
	initSql string = `
  CREATE TABLE IF NOT EXISTS users (
		uid INTEGER PRIMARY KEY,
		username TEXT UNIQUE,
		info TEXT,
		home TEXT,
		shell TEXT,
		pgroup INTEGER,
		email TEXT DEFAULT '',
		email_verified BOOLEAN DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS passwords (
		uid INTEGER,
		hashpass TEXT,
		lastPasswordChange TEXT,
		minimumPasswordAge TEXT,
		maximumPasswordAge TEXT,
		warningPeriod TEXT,
		inactivityPeriod TEXT,
		expirationDate TEXT
	);
	CREATE TABLE IF NOT EXISTS groups (
		gid INTEGER PRIMARY KEY,
		groupname TEXT UNIQUE
	);
  CREATE TABLE IF NOT EXISTS user_groups (
    uid INTEGER NOT NULL,
    gid INTEGER NOT NULL
  );
  -- Its own table rather than a users column: CREATE TABLE IF NOT EXISTS
  -- retrofits it onto an existing minioth.db, where a new users column
  -- would need an ALTER TABLE. Rows deliberately outlive their user (see
  -- Userdel).
  CREATE TABLE IF NOT EXISTS token_versions (
    uid INTEGER PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 0
  );
  `
)

/* central object */
type DBHandler struct {
	db     *sql.DB
	DBpath string
}

// dbWriteMu serializes every user/group-creating write. SQLite locks at the
// database-file level, not per-row, so it doesn't give this package real
// row-level locking, and computing the next id (SELECT MAX(id)+1) is never atomic with the
// INSERT that consumes it on its own — two concurrent Useradd calls could
// compute the same uid. Serializing writes closes that race outright; the
// UNIQUE/PRIMARY KEY constraints on users.username, users.uid, groups.gid
// and groups.groupname (see initSql) are the second line of defense if a
// future caller ever bypasses this handler and writes concurrently anyway.
var dbWriteMu sync.Mutex

// sqliteDSNParams apply to every pooled connection (database/sql opens
// several, so a one-off PRAGMA after Open wouldn't stick). Without them,
// concurrent writes failed outright with SQLITE_BUSY ("database is
// locked") instead of waiting their turn — found by TestConcurrentWrites:
//   - busy_timeout: wait up to 5s for a competing writer's lock.
//   - _txlock=immediate: take the write lock at BEGIN. A deferred
//     transaction that reads first and then writes can't be rescued by
//     busy_timeout — SQLite fails the upgrade immediately to avoid a
//     deadlock.
//   - WAL: readers (Select, Authenticate) don't block on, or block,
//     writers. Adds minioth.db-wal / minioth.db-shm beside the db file.
const sqliteDSNParams = "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate"

/* "singleton" like db connection reference */
func (m *DBHandler) getConn() (*sql.DB, error) {
	db := m.db
	var err error

	if db == nil {
		db, err = sql.Open("sqlite", m.DBpath+sqliteDSNParams)
		m.db = db
		if err != nil {
			log.Printf("Failed to connect to SQLite: %v", err)
			return nil, err
		}
	}
	return db, err
}

/* initialization method for root user, could be reconfigured*/
func (m *DBHandler) insertRootUser(user domain.User, db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	userQuery := `
    INSERT INTO
        users (uid, username, info, home, shell, pgroup)
    VALUES
        (?, ?, ?, ?, ?, ?)`
	_, err = tx.Exec(userQuery, user.Uid, user.Name, user.Info, user.Home, user.Shell, user.Pgroup)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to insert root user: %w", err)
	}

	hashPass, err := domain.Hash([]byte(user.Password.Hashpass))
	if err != nil {
		log.Printf("failed to hash the pass: %v", err)
		tx.Rollback()
		return err
	}

	passwordQuery := `
    INSERT INTO
        passwords (uid, hashpass, lastPasswordChange, minimumPasswordAge, maximumPasswordAge, warningPeriod, inactivityPeriod, expirationDate)
    VALUES
        (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = tx.Exec(passwordQuery, user.Uid, hashPass, user.Password.LastPasswordChange, user.Password.MinPasswordAge,
		user.Password.MaxPasswordAge, user.Password.WarningPeriod, user.Password.InactivityPeriod, user.Password.ExpirationDate)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to insert root password: %w", err)
	}

	usergroupQuery := `
    INSERT INTO
      user_groups (uid, gid)
    VALUES
      (?, ?)`
	_, err = tx.Exec(usergroupQuery, user.Uid, 0)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to group root user: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

/* INTERFACE agent methods */
func (m *DBHandler) Init(root domain.User) {
	log.Print("Initializing... Minioth DB")

	if strings.HasSuffix(m.DBpath, string(filepath.Separator)) {
		panic(fmt.Sprintf("invalid db path value %q: must be a file path, not a directory", m.DBpath))
	}
	// filepath.Dir handles both relative (e.g. "data/minioth.db" -> "data")
	// and absolute (e.g. "/data/minioth.db" -> "/data") paths correctly —
	// the manual string-splitting this replaced always prepended the
	// current working directory, which broke MkdirAll for any absolute
	// -db-path (silently building a path like "$cwd/data/minioth.db"
	// instead of "/data/minioth.db"). "." (a bare filename, no directory
	// component) needs no MkdirAll at all.
	if dir := filepath.Dir(m.DBpath); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			panic(fmt.Sprintf("failed to create db directory %q: %v", dir, err))
		}
	}

	db, err := m.getConn()
	if err != nil {
		panic("destructive")
	}

	// set ref to db
	m.db = db

	_, err = db.Exec(initSql)
	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	// users created before the fix above have pgroup = uid while their own
	// group has another gid; point them at their group
	if res, err := db.Exec(`
		UPDATE users SET pgroup = (
			SELECT g.gid FROM groups g JOIN user_groups ug ON ug.gid = g.gid
			WHERE g.groupname = users.username AND ug.uid = users.uid)
		WHERE uid != 0 AND EXISTS (
			SELECT 1 FROM groups g JOIN user_groups ug ON ug.gid = g.gid
			WHERE g.groupname = users.username AND ug.uid = users.uid AND g.gid != users.pgroup)`); err != nil {
		log.Printf("failed to repair primary groups: %v", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("repaired the primary group of %d user(s)", n)
	}

	// Check for main group existence
	log.Print("Checking for main groups...")
	var mainGroupsExist bool
	err = db.QueryRow("SELECT EXISTS(SELECT 2 FROM groups WHERE gid = 0 OR gid = 1000)").Scan(&mainGroupsExist)
	if err != nil {
		log.Fatalf("Failed to query groups")
	}

	if !mainGroupsExist {
		log.Print("Inserting main groups: admin/user -> gid: 0/1000")

		query := `
      INSERT INTO
        groups (gid, groupname)
      VALUES
        (0, 'admin'),
        (100, 'mod'),
        (1000, 'user');`

		_, err = db.Exec(query, nil)
		if err != nil {
			log.Fatalf("failed to insert groups: %v", err)
		}
	} else {
		log.Print("groups already exist!")
	}

	log.Print("Checking for root user...")
	// Check if the root user already exists
	var rootExists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", root.Name).Scan(&rootExists)
	if err != nil {
		log.Fatalf("Failed to check for root user: %v", err)
	}

	if !rootExists {
		log.Print("Inserting root user...")
		// Directly insert the root user with UID 0
		user := domain.User{
			Name: root.Name,
			Password: domain.Password{
				Hashpass: root.Password.Hashpass, // Ensure proper hashing is applied later
			},
			Uid:    0,
			Pgroup: 0,
			Info:   "HEADMASTER",
			Home:   "/",
			Shell:  "/bin/gshell",
		}
		err = m.insertRootUser(user, db)
		if err != nil {
			log.Fatalf("Failed to insert root user: %v", err)
		}
	} else {
		log.Print("Root user already exists")
	}
}

/* Useradd method
* will insert a given user in the relational db
*
* relations:
* passwords, user_groups, groups
*
* Each user should be associated with his own group. The existence check,
* id allocation, user/password/group rows and user_groups links all happen
* inside one transaction (see groupAddTx) — previously the primary-group
* insert went through a *separate* db.Exec outside this transaction, so a
* rollback here could leave an orphaned group row behind.
* */
func (m *DBHandler) Useradd(user domain.User) (int, int, error) {
	dbWriteMu.Lock()
	defer dbWriteMu.Unlock()

	log.Printf("Inserting user %q", user.Name)
	db, err := m.getConn()
	if err != nil {
		return -1, -1, err
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("failed to begin transaction: %v", err)
		return -1, -1, err
	}

	// check if user exists...
	var exists int
	err = tx.QueryRow("SELECT 1 FROM users WHERE username = ?", user.Name).Scan(&exists)
	if err == sql.ErrNoRows {
		log.Printf("User with name %q does not exist.", user.Name)
	} else if err != nil {
		log.Printf("Error checking for user existence: %v", err)
		tx.Rollback()
		return -1, -1, fmt.Errorf("error checking for user existence: %w", err)
	} else {
		log.Printf("User with name %q already exists.", user.Name)
		tx.Rollback()
		return -1, -1, fmt.Errorf("user already exists")
	}

	user.Uid, err = m.nextIdTx(tx, "users")
	if err != nil {
		log.Printf("failed to retrieve the next avaible uid: %v", err)
		tx.Rollback()
		return -1, -1, err
	}
	user.Pgroup = user.Uid

	log.Printf("uid fetched: %v", user.Uid)

	userQuery := `
  INSERT INTO
    users (uid, username, info, home, shell, pgroup, email, email_verified)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?)
  `
	// email_verified always starts false here, regardless of anything the
	// caller set on user.EmailVerified — that field only ever becomes true
	// via VerifyEmail, reached through a signed verification token, never
	// by a client just asserting it at registration time.
	if _, err = tx.Exec(userQuery, user.Uid, user.Name, user.Info, user.Home, user.Shell, user.Pgroup, user.Email, false); err != nil {
		log.Printf("failed to execute query: %v", err)
		tx.Rollback()
		return -1, -1, err
	}

	/* add the user unique/primary group, in the same transaction */
	gid, err := m.groupAddTx(tx, domain.Group{Name: user.Name, Users: nil, Gid: user.Uid})
	if err != nil {
		log.Printf("failed to insert user unique/primary group: %v", err)
		tx.Rollback()
		return -1, -1, err
	}
	// the group gets its own gid (it differs from the uid once a gid is
	// taken); record that as the primary group, not the uid guessed above
	if _, err = tx.Exec(`UPDATE users SET pgroup = ? WHERE uid = ?`, gid, user.Uid); err != nil {
		tx.Rollback()
		return -1, -1, fmt.Errorf("record primary group: %w", err)
	}

	usergroupQuery := `
    INSERT INTO
      user_groups (uid, gid)
    VALUES
      (?, ?),
      (?, ?)`
	if _, err = tx.Exec(usergroupQuery, user.Uid, 1000, user.Uid, gid); err != nil {
		tx.Rollback()
		log.Printf("failed to group user: %v", err)
		return -1, -1, err
	}

	hashPass, err := domain.Hash([]byte(user.Password.Hashpass))
	if err != nil {
		log.Printf("failed to hash the pass: %v", err)
		tx.Rollback()
		return -1, -1, err
	}

	passwordQuery := `
  INSERT INTO
    passwords (uid, hashpass, lastpasswordchange, minimumpasswordage, maximumpasswordage, warningperiod, inactivityperiod, expirationdate)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `
	if _, err = tx.Exec(passwordQuery, user.Uid, hashPass, user.Password.LastPasswordChange, user.Password.MinPasswordAge,
		user.Password.MaxPasswordAge, user.Password.WarningPeriod, user.Password.InactivityPeriod, user.Password.ExpirationDate); err != nil {
		tx.Rollback()
		log.Printf("failed to execute query: %v", err)
		return -1, -1, err
	}

	if err := tx.Commit(); err != nil {
		log.Printf("failed to commit transaction: %v", err)
		return -1, -1, err
	}

	return user.Uid, gid, nil
}

func (m *DBHandler) Userdel(uid string) error {
	log.Printf("Deleting user with id: %s", uid)
	if err := checkIfRoot(uid); err != nil {
		log.Print("can't delete the root...")
		return fmt.Errorf("deleting the root?%v", nil)
	}

	db, err := m.getConn()
	if err != nil {
		log.Printf("failed to get db conn: %v", err)
		return err
	}

	deleteUserQuery := `DELETE FROM users WHERE uid = ?`
	deletePasswordQuery := `DELETE FROM passwords WHERE uid = ?`
	deleteUserGroupQuery := `DELETE FROM user_groups WHERE uid = ?`

	var (
		gid            int
		pgroup_deleted bool
	)
	err = db.QueryRow(`
    SELECT
      gid
    FROM
      groups
    WHERE groupname = (
      SELECT
        username
      FROM
        users
      WHERE
        uid = ?
    )`, uid).Scan(&gid)
	if err != nil {
		log.Printf("failed to retrieve primary group gid of the user")
		pgroup_deleted = true
	}

	if !pgroup_deleted {
		deletePrimaryGroupQuery := `
      DELETE FROM
        groups
      WHERE
        gid = ?
      `
		cleanRemenantsQuery := `
      DELETE FROM
        user_groups
      WHERE
        gid = ?
    `
		_, err = db.Exec(deletePrimaryGroupQuery, gid)
		if err != nil {
			log.Printf("error, failed to delete user primary group: %v", err)
			return err
		}

		_, err = db.Exec(cleanRemenantsQuery, gid)
		if err != nil {
			log.Printf("error, failed to clean the user_group to the deleted group relation: %v", err)
			return err
		}
	}

	_, err = db.Exec(deleteUserGroupQuery, uid)
	if err != nil {
		log.Printf("error, failed to delete usergroups: %v", err)
		return err
	}

	_, err = db.Exec(deletePasswordQuery, uid)
	if err != nil {
		log.Printf("error, failed to delete password: %v", err)
		return err
	}

	res, err := db.Exec(deleteUserQuery, uid)
	if err != nil {
		log.Printf("error, failed to delete user: %v", err)
		return err
	}

	rAffected, err := res.RowsAffected()
	if err != nil {
		log.Printf("failed to get the rows affected")
		return err
	}

	if rAffected == 0 {
		log.Print("no users were deleted")
		return fmt.Errorf("user not found")
	}

	// uids get reused (nextIdTx is MAX+1), so without this the next user
	// assigned this uid would accept the deleted user's unexpired tokens.
	if err := m.RevokeTokens(uid); err != nil {
		log.Printf("error, failed to revoke deleted user's tokens: %v", err)
		return err
	}

	return nil
}

func (m *DBHandler) Usermod(user domain.User) error {
	log.Printf("Updating user with uid: %v", user.Uid)
	db, err := m.getConn()
	if err != nil {
		log.Printf("Failed to get DB connection: %v", err)
		return err
	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Failed to begin transaction: %v", err)
		return err
	}

	// Rollback in case of any error
	defer func() {
		if err != nil {
			log.Printf("Rolling back transaction due to error: %v", err)
			tx.Rollback()
		}
	}()

	// Step 1: Delete dependent records
	deleteUserGroupsQuery := `DELETE FROM user_groups WHERE uid = ?`
	_, err = tx.Exec(deleteUserGroupsQuery, user.Uid)
	if err != nil {
		log.Printf("Failed to delete user-group associations: %v", err)
		return fmt.Errorf("failed to delete user-group associations: %w", err)
	}

	deletePasswordQuery := `DELETE FROM passwords WHERE uid = ?`
	_, err = tx.Exec(deletePasswordQuery, user.Uid)
	if err != nil {
		log.Printf("Failed to delete password: %v", err)
		return fmt.Errorf("failed to delete password: %w", err)
	}

	// Step 2: Update the `users` table
	updateUserQuery := `
    UPDATE
      users
    SET
      username = ?, info = ?, home = ?, shell = ?
    WHERE
      uid = ?;
  `
	_, err = tx.Exec(updateUserQuery, user.Name, user.Info, user.Home, user.Shell, user.Uid)
	if err != nil {
		log.Printf("Failed to update user: %v", err)
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Step 3: Reinsert into `passwords`
	insertPasswordQuery := `
    INSERT INTO
      passwords (uid, hashpass, lastpasswordchange, minimumpasswordage, maximumpasswordage, warningperiod, inactivityperiod, expirationdate)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
  `
	_, err = tx.Exec(insertPasswordQuery, user.Uid, user.Password.Hashpass, user.Password.LastPasswordChange,
		user.Password.MinPasswordAge, user.Password.MaxPasswordAge, user.Password.WarningPeriod,
		user.Password.InactivityPeriod, user.Password.ExpirationDate)
	if err != nil {
		log.Printf("Failed to insert password: %v", err)
		return fmt.Errorf("failed to insert password: %w", err)
	}

	// Step 4: Reinsert into `user_groups`
	if len(user.Groups) > 0 {
		insertUserGroupsQuery := `
      INSERT INTO
        user_groups (uid, gid)
      VALUES
    `
		var params []interface{}
		for i, group := range user.Groups {
			insertUserGroupsQuery += "(?, ?)"
			if i < len(user.Groups)-1 {
				insertUserGroupsQuery += ", "
			}
			params = append(params, user.Uid, group.Gid)
		}

		_, err = tx.Exec(insertUserGroupsQuery, params...)
		if err != nil {
			log.Printf("Failed to insert user-group associations: %v", err)
			return fmt.Errorf("failed to insert user-group associations: %w", err)
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		log.Printf("Failed to commit transaction: %v", err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// userPatchColumns are the only users columns Userpatch will write — the
// same set PlainHandler's patchPasswdFields accepts. Keys are interpolated
// into the UPDATE as column names, so anything else in fields (a typo, or
// a crafted key like "info = (SELECT ...)") is skipped, never reaches SQL.
var userPatchColumns = map[string]bool{
	"info":           true,
	"home":           true,
	"shell":          true,
	"email":          true,
	"email_verified": true,
}

func (m *DBHandler) Userpatch(uid string, fields map[string]interface{}) error {
	query := "UPDATE users SET "
	args := []interface{}{}

	var groupsField string
	var password string
	for key, value := range fields {
		switch key {
		case "uid":
			continue

		case "groups":
			// Guard the type assertion: a patch payload that omits "groups"
			// (the common case — patching just one field) previously left
			// this as a nil interface{}, and `groups.(string)` without the
			// ", ok" form panicked on every such request.
			if s, ok := value.(string); ok {
				groupsField = s
			}
			continue
		case "password":
			if s, ok := value.(string); ok {
				password = s
			}
		default:
			if !userPatchColumns[key] {
				log.Printf("userpatch: ignoring unknown field %q", key)
				continue
			}
			if value == "" {
				continue
			}
			query += fmt.Sprintf("%s = ?, ", key)
			args = append(args, value)
		}
	}

	if len(args) == 0 && groupsField == "" && password == "" {
		return fmt.Errorf("no inputs")
	}

	// Hash before storing, like Passwd and PlainHandler.Userpatch do —
	// this used to write the plaintext straight into passwords.hashpass,
	// which also left the user unable to log in (VerifyPass expects a
	// bcrypt hash).
	var hashPass []byte
	if password != "" {
		var err error
		hashPass, err = domain.Hash([]byte(password))
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
	}

	db, err := m.getConn()
	if err != nil {
		return fmt.Errorf("failed to connect to db: %w", err)
	}
	tx, err := db.Begin()
	if err != nil {
		log.Printf("failed to begin transaction: %v", err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	if len(args) != 0 {
		// Key patches
		query = strings.TrimSuffix(query, ", ") + " WHERE uid = ?"
		args = append(args, uid)

		log.Printf("patching user with uid: %q", uid)
		log.Printf("patching fields: %+v", args)

		_, err = tx.Exec(query, args...)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to execute update query: %w", err)
		}
	}

	// group patch
	// if groups arg is here, we need to update the relation
	if len(groupsField) > 0 {
		log.Print("deleting old group relations...")
		_, err := tx.Exec("DELETE FROM user_groups WHERE uid = ?", uid)
		if err != nil {
			log.Printf("failed to delete old relations..:%v", err)
			tx.Rollback()
			return fmt.Errorf("failed to delete old relations: %w", err)
		}

		groups := strings.Split(groupsField, ",")           // Assuming `groups` is a string of comma-separated group names
		placeholders := strings.Repeat(",?", len(groups)-1) // Create placeholders for additional groups

		insQuery := `
      INSERT INTO
          user_groups (uid, gid)
      SELECT
          ?, gid
      FROM
          groups
      WHERE
          groupname IN (?` + placeholders + `)
    `
		insArgs := []interface{}{uid}
		for _, group := range groups {
			insArgs = append(insArgs, strings.TrimSpace(group))
		}

		log.Print("inserting user group relation...")
		res, err := tx.Exec(insQuery, insArgs...)
		if err != nil {
			log.Printf("failed to insert user groups: %v", err)
			tx.Rollback()
			return fmt.Errorf("failed to insert user groups: %w", err)
		}

		rowsAffected, _ := res.RowsAffected()
		log.Printf("Rows affected: %d", rowsAffected)

	}

	// password patch
	if password != "" {
		log.Print("updating password relation...")
		pquery := `
      UPDATE
        passwords
      SET
        hashpass = ?, lastpasswordchange = ?
      WHERE
        uid = ?`

		_, err = tx.Exec(pquery, hashPass, time.Now().String(), uid)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to update password: %w", err)
		}
	}

	err = tx.Commit()
	if err != nil {
		log.Printf("failed to commit transaction: %v", err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

/* Groupadd inserts a standalone group in its own transaction. Useradd needs
* the same insert logic but as part of *its* transaction (so a rollback
* doesn't orphan the group row) — see groupAddTx, which both routes
* through. */
func (m *DBHandler) Groupadd(group domain.Group) (int, error) {
	dbWriteMu.Lock()
	defer dbWriteMu.Unlock()

	log.Printf("Adding new group: %v", group)

	db, err := m.getConn()
	if err != nil {
		log.Printf("failed to get the db conn: %v", err)
		return -1, err
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("failed to begin transaction: %v", err)
		return -1, err
	}

	gid, err := m.groupAddTx(tx, group)
	if err != nil {
		tx.Rollback()
		return -1, err
	}

	if err := tx.Commit(); err != nil {
		log.Printf("failed to commit transaction: %v", err)
		return -1, err
	}

	return gid, nil
}

func (m *DBHandler) groupAddTx(tx *sql.Tx, group domain.Group) (int, error) {
	// check if group exists...
	var exists int
	err := tx.QueryRow("SELECT 1 FROM groups WHERE groupname = ?", group.Name).Scan(&exists)
	if err == sql.ErrNoRows {
		log.Printf("group with name %q does not exist.", group.Name)
	} else if err != nil {
		log.Printf("errror checking for group existence: %v", err)
		return -1, fmt.Errorf("error checking for group existence: %w", err)
	} else {
		log.Printf("group with name %q already exists.", group.Name)
		return -1, fmt.Errorf("group already exists")
	}

	gid, err := m.nextIdTx(tx, "groups")
	if err != nil {
		log.Printf("failed to retrieve the nextid")
		return -1, err
	}

	groupAddQuery := `
    INSERT INTO
      groups (gid, groupname)
    VALUES
      (?, ?);

  `
	if _, err = tx.Exec(groupAddQuery, gid, group.Name); err != nil {
		log.Printf("error executing groupAddQuery: %v", err)
		return -1, err
	}

	// "update" or insert group user relation
	if len(group.Users) > 0 {
		placeholders := strings.Repeat("(?, ?),", len(group.Users))
		placeholders = strings.TrimSuffix(placeholders, ",") // Remove trailing comma
		userGroupQuery := fmt.Sprintf("INSERT INTO user_groups (uid, gid) VALUES %s", placeholders)

		args := []interface{}{}
		for _, user := range group.Users {
			args = append(args, user.Uid, gid)
		}

		if _, err = tx.Exec(userGroupQuery, args...); err != nil {
			log.Printf("Error executing userGroupQuery: %v", err)
			return -1, err
		}
	}

	return gid, nil
}

func (m *DBHandler) Groupdel(gid string) error {
	log.Printf("Deleting group with id: %s", gid)
	db, err := m.getConn()
	if err != nil {
		log.Printf("failed to get db conn: %v", err)
		return err
	}
	groupDelQuery := `DELETE FROM groups WHERE gid = ?`
	userGroupDel := `DELETE FROM user_groups WHERE gid = ?`

	res, err := db.Exec(groupDelQuery, gid)
	if err != nil {
		log.Printf("error, failed to delete group: %v", err)
		return err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		log.Printf("error getting rows affected num: %v", err)
		return err
	}

	if rowsAffected == 0 {
		log.Printf("group: %q doesn't exist", gid)
		return fmt.Errorf("group doens't exist")
	}

	_, err = db.Exec(userGroupDel, gid)
	if err != nil {
		log.Printf("error, failed to delete usergroups: %v", err)
		return err
	}

	return nil
}

func (m *DBHandler) Groupmod(group domain.Group) error {
	log.Printf("Modifying group: %v", group)
	db, err := m.getConn()
	if err != nil {
		log.Printf("Failed to get DB connection: %v", err)
		return err
	}

	// Update group information
	updateGroupQuery := `
    UPDATE groups
    SET groupname = ?
    WHERE gid = ?;
  `
	_, err = db.Exec(updateGroupQuery, group.Name, group.Gid)
	if err != nil {
		log.Printf("Failed to update group: %v", err)
		return err
	}

	// Update user-group relations
	deleteUserGroupsQuery := `DELETE FROM user_groups WHERE gid = ?`
	_, err = db.Exec(deleteUserGroupsQuery, group.Gid)
	if err != nil {
		log.Printf("Failed to delete user-group associations: %v", err)
		return err
	}

	if len(group.Users) > 0 {
		placeholders := strings.Repeat("(?, ?),", len(group.Users))
		placeholders = strings.TrimSuffix(placeholders, ",")
		insertUserGroupsQuery := fmt.Sprintf("INSERT INTO user_groups (uid, gid) VALUES %s", placeholders)

		args := []interface{}{}
		for _, user := range group.Users {
			args = append(args, user.Uid, group.Gid)
		}

		_, err = db.Exec(insertUserGroupsQuery, args...)
		if err != nil {
			log.Printf("Failed to insert user-group associations: %v", err)
			return err
		}
	}

	log.Printf("Successfully modified group %v", group)
	return nil
}

func (m *DBHandler) Grouppatch(gid string, fields map[string]interface{}) error {
	log.Printf("Patching group %s with fields: %v", gid, fields)
	db, err := m.getConn()
	if err != nil {
		log.Printf("Failed to get DB connection: %v", err)
		return err
	}

	// Build the dynamic update query
	query := "UPDATE groups SET "
	args := []interface{}{}
	for field, value := range fields {
		query += fmt.Sprintf("%s = ?, ", field)
		args = append(args, value)
	}
	query = strings.TrimSuffix(query, ", ") // Remove the trailing comma
	query += " WHERE gid = ?"
	args = append(args, gid)

	_, err = db.Exec(query, args...)
	if err != nil {
		log.Printf("Failed to patch group: %v", err)
		return err
	}

	log.Printf("Successfully patched group %s", gid)
	return nil
}

func (m *DBHandler) Passwd(username, password string) error {
	log.Printf("Changing password for %q", username)
	db, err := m.getConn()
	if err != nil {
		log.Printf("failed to connect to database: %v", err)
		return err
	}

	hashPass, err := domain.Hash([]byte(password))
	if err != nil {
		log.Printf("failed to hash the pass: %v", err)
		return err
	}

	now := time.Now().String()

	updateQuery := `
    UPDATE
      passwords
    SET
      hashpass = ?,
      lastPasswordChange = ?
    WHERE
      uid = (
        SELECT
          uid
        FROM
          users
        WHERE
          username = ?
      );
  `
	res, err := db.Exec(updateQuery, hashPass, now, username)
	if err != nil {
		log.Printf("failed to exec update query: %v", err)
		return err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		log.Printf("failed to retrieve rows affected: %v", err)
		return err
	}

	log.Printf("rows affected: %v", rowsAffected)

	return nil
}

// VerifyEmail marks uid's email as verified. Reached only via a signed
// email-verification token (internal/auth), not gated behind admin auth.
func (m *DBHandler) VerifyEmail(uid string) error {
	db, err := m.getConn()
	if err != nil {
		return err
	}

	res, err := db.Exec("UPDATE users SET email_verified = true WHERE uid = ?", uid)
	if err != nil {
		return err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// AssignGroup adds uid to gid's membership — Grouppatch only ever updates
// a group's own columns, never user_groups, so there's no existing way to
// add someone to a group (e.g. promoting a user to the admin group, gid
// 0) without this.
func (m *DBHandler) AssignGroup(uid string, gid int) error {
	db, err := m.getConn()
	if err != nil {
		return err
	}

	var exists int
	err = db.QueryRow("SELECT 1 FROM user_groups WHERE uid = ? AND gid = ?", uid, gid).Scan(&exists)
	if err == nil {
		return nil // already a member
	}
	if err != sql.ErrNoRows {
		return err
	}

	if _, err := db.Exec("INSERT INTO user_groups (uid, gid) VALUES (?, ?)", uid, gid); err != nil {
		return err
	}

	return nil
}

func (m *DBHandler) TokenVersion(uid string) (int, error) {
	db, err := m.getConn()
	if err != nil {
		return 0, err
	}

	var version int
	err = db.QueryRow("SELECT version FROM token_versions WHERE uid = ?", uid).Scan(&version)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return version, err
}

func (m *DBHandler) RevokeTokens(uid string) error {
	db, err := m.getConn()
	if err != nil {
		return err
	}

	_, err = db.Exec(`
    INSERT INTO
      token_versions (uid, version)
    VALUES
      (?, 1)
    ON CONFLICT(uid) DO UPDATE SET version = version + 1`, uid)
	return err
}

func (m *DBHandler) Select(id string) []interface{} {
	base, param, value := util.SplitSelectID(id)

	db, err := m.getConn()
	if err != nil {
		log.Printf("failed to connect to database: %v", err)
		return nil
	}

	switch base {
	case "users":
		var (
			result    []interface{}
			userQuery string
			rows      *sql.Rows
			err       error
		)

		if param != "" && value != "" {
			userQuery = fmt.Sprintf(`
			SELECT
			  u.uid, u.username, p.hashpass, p.lastPasswordChange, p.minimumPasswordAge,
			  p.maximumPasswordAge, p.warningPeriod, p.inactivityPeriod, p.expirationDate,
			  u.info, u.home, u.shell, u.pgroup, u.email, u.email_verified, GROUP_CONCAT(g.groupname), GROUP_CONCAT(g.gid) as groups
			FROM
			  users u
			LEFT JOIN passwords p ON p.uid = u.uid
			LEFT JOIN user_groups ug ON ug.uid = u.uid
			LEFT JOIN groups g ON g.gid = ug.gid
			WHERE
			  u.%s = ?
			GROUP BY
			  u.uid, u.username, u.info, u.home, u.shell, u.pgroup, u.email, u.email_verified, p.hashpass, p.lastPasswordChange, p.minimumPasswordAge, p.maximumPasswordAge, p.warningPeriod, p.inactivityPeriod, p.expirationDate;
	  		`, param)

			rows, err = db.Query(userQuery, value)

		} else {
			userQuery = `
			SELECT
			  u.uid, u.username, p.hashpass, p.lastPasswordChange, p.minimumPasswordAge,
			  p.maximumPasswordAge, p.warningPeriod, p.inactivityPeriod, p.expirationDate,
			  u.info, u.home, u.shell, u.pgroup, u.email, u.email_verified, GROUP_CONCAT(g.groupname), GROUP_CONCAT(g.gid) as groups
			FROM
			  users u
			LEFT JOIN passwords p ON p.uid = u.uid
			LEFT JOIN user_groups ug ON ug.uid = u.uid
			LEFT JOIN groups g ON g.gid = ug.gid
			GROUP BY
			  u.uid, u.username, u.info, u.home, u.shell, u.pgroup, u.email, u.email_verified, p.hashpass, p.lastPasswordChange, p.minimumPasswordAge, p.maximumPasswordAge, p.warningPeriod, p.inactivityPeriod, p.expirationDate;
	  		`
			rows, err = db.Query(userQuery)

		}

		if err != nil {
			log.Printf("failed to query users: %v", err)
			return nil
		}
		defer rows.Close()

		for rows.Next() {
			var user domain.User
			var groupNames sql.NullString // Use sql.NullString to handle NULL values
			var groupIds sql.NullString
			err := rows.Scan(&user.Uid, &user.Name, &user.Password.Hashpass, &user.Password.LastPasswordChange, &user.Password.MinPasswordAge, &user.Password.MaxPasswordAge, &user.Password.WarningPeriod, &user.Password.InactivityPeriod, &user.Password.ExpirationDate, &user.Info, &user.Home, &user.Shell, &user.Pgroup, &user.Email, &user.EmailVerified, &groupNames, &groupIds)
			if err != nil {
				log.Printf("failed to scan user: %v", err)
				return nil
			}

			groups := []domain.Group{}
			if groupNames.Valid && groupNames.String != "" && groupIds.Valid && groupIds.String != "" { // Check if groupNames is valid and not empty
				groupNameList := strings.Split(groupNames.String, ",")
				groupIdsList := strings.Split(groupIds.String, ",")
				for i, groupName := range groupNameList {
					gid, err := strconv.Atoi(groupIdsList[i])
					if err != nil {
						log.Printf("failed to atoi gid from: %v", groupIdsList[i])
					}
					groups = append(groups, domain.Group{
						Name: groupName,
						Gid:  gid,
					})
				}
			}
			user.Groups = groups

			result = append(result, user)
		}

		return result

	case "groups":
		var result []interface{}

		groupQuery := `
      SELECT
        g.gid, g.groupname, GROUP_CONCAT(u.username), GROUP_CONCAT(u.uid) as users
      FROM
        groups g
      LEFT JOIN user_groups ug ON g.gid = ug.gid
      LEFT JOIN users u ON u.uid = ug.uid
      GROUP BY
        g.gid, g.groupname;
    `
		rows, err := db.Query(groupQuery)
		if err != nil {
			log.Printf("failed to query groups: %v", err)
			return nil
		}
		defer rows.Close()

		for rows.Next() {
			var group domain.Group
			var userNames sql.NullString
			var userIds sql.NullString
			err := rows.Scan(&group.Gid, &group.Name, &userNames, &userIds)
			if err != nil {
				log.Printf("failed to scan group: %v", err)
				return nil
			}

			// Parse user names into dummy domain.User structs

			users := []domain.User{}
			if userNames.Valid && userNames.String != "" {
				userNameList := strings.Split(userNames.String, ",")
				userIdsList := strings.Split(userIds.String, ",")
				for i, userName := range userNameList {
					uid, err := strconv.Atoi(userIdsList[i])
					if err != nil {
						log.Printf("failed to atoi a uid: %v", userIdsList[i])
						return nil
					}
					users = append(users, domain.User{
						Name: userName,
						Uid:  uid,
					})
				}
			}
			group.Users = users

			// Append group as an interface{}
			result = append(result, group)
		}

		return result

	default:
		log.Printf("Invalid id: %s", id)
		return nil
	}
}

func (m *DBHandler) Authenticate(username, password string) (*domain.User, error) {
	log.Printf("authenticating user... %q", username)

	db, err := m.getConn()
	if err != nil {
		return nil, err
	}
	user := getUser(username, db)
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	if domain.VerifyPass([]byte(user.Password.Hashpass), []byte(password)) {
		return user, nil
	} else {
		return nil, fmt.Errorf("failed to authenticate bad credentials: %v", nil)
	}
}

/* close the prev "singleton" db connection */
func (m *DBHandler) Close() {
	if m.db != nil {
		m.db.Close()
	}
}

/* somewhat UTILITY functions and methods */
/* select all user information given a username */
func getUser(username string, db *sql.DB) *domain.User {
	// lets check if the user exists before joining the big guns
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		log.Printf("failed to check if user exists: %v", err)
	}

	if !exists {
		return nil
	}

	userQuery := `
    SELECT
      u.username, u.info, u.home, u.shell, u.uid, u.pgroup, u.email, u.email_verified,
      g.gid, g.groupname
    FROM
      users u
    LEFT JOIN
      user_groups ug ON u.uid = ug.uid
    LEFT JOIN
      groups g ON ug.gid = g.gid
    WHERE
      username = ?
    `

	log.Printf("looking for user with name: %q...", username)

	rows, err := db.Query(userQuery, username)
	if err != nil {
		log.Printf("error on query: %v", err)
		return nil
	}
	defer rows.Close()

	user := domain.User{}
	groups := make([]domain.Group, 0)

	var (
		gid   sql.NullInt64
		gname sql.NullString
	)

	for rows.Next() {
		if err := rows.Scan(&user.Name, &user.Info, &user.Home, &user.Shell, &user.Uid, &user.Pgroup, &user.Email, &user.EmailVerified, &gid, &gname); err != nil {
			log.Printf("failed to ugr scan row: %v", err)
			return nil
		}

		if gid.Valid && gname.Valid {
			groups = append(groups, domain.Group{
				Gid:  int(gid.Int64),
				Name: gname.String,
			})
		}
	}

	user.Groups = groups

	passwordQuery := `
    SELECT
      hashpass, lastPasswordChange, minimumPasswordAge, maximumPasswordAge,
      warningPeriod, inactivityPeriod, expirationDate
    FROM
      passwords
    WHERE
      uid = ?`
	password := domain.Password{}
	row := db.QueryRow(passwordQuery, user.Uid)
	if row == nil {
		return nil
	}

	err = row.Scan(&password.Hashpass, &password.LastPasswordChange, &password.MinPasswordAge,
		&password.MaxPasswordAge, &password.WarningPeriod, &password.InactivityPeriod, &password.ExpirationDate)
	if err != nil {
		log.Printf("failed to scan password: %v", err)
		return nil
	}

	user.Password = password
	log.Printf("User found: %+v", user)
	return &user
}

// nextIdTx computes the next id for "users"/"groups" as part of an
// existing transaction, so the read and the INSERT that consumes it are
// atomic with respect to each other. See dbWriteMu for the rest of the
// concurrency story.
func (m *DBHandler) nextIdTx(tx *sql.Tx, table string) (int, error) {
	var id string
	switch table {
	case "users":
		id = "uid"
	case "groups":
		id = "gid"
	default:
		return 0, fmt.Errorf("unsupported table: %s", table)
	}

	query := "SELECT COALESCE(MAX(" + id + "), 999) + 1 FROM " + table + " WHERE " + id + " >= 1000"

	var nextID int
	if err := tx.QueryRow(query).Scan(&nextID); err != nil {
		return 0, fmt.Errorf("failed to retrieve next id: %w", err)
	}

	return nextID, nil
}

func checkIfRoot(uid string) error {
	iuid, err := strconv.Atoi(uid)
	if err != nil {
		log.Printf("failed to atoi: %v", err)
		return err
	}

	if iuid == 0 {
		return fmt.Errorf("indeed root: %v", nil)
	}
	return nil
}
