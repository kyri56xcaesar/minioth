package minioth

/*
* A minioth handler, encircling a DuckDB.
*
* */

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

/* utility constants and globals */
const (
	MINIOTH_DB string = "data/db/minioth.db"

	initSql string = `
  CREATE TABLE IF NOT EXISTS users (
		uid INTEGER,
		username TEXT,
		info TEXT,
		home TEXT,
		shell TEXT,
		pgroup INTEGER
	);
	CREATE TABLE IF NOT EXISTS passwords (
		uid INTEGER,
		hashpass TEXT,
		lastPasswordChange TEXT,
		minimumPasswordAge TEXT,
		maximumPasswordAge TEXT,
		warningPeriod TEXT,
		inactivityPeriod TEXT,
		expirationDate TEXT,
	);
	CREATE TABLE IF NOT EXISTS groups (
		gid INTEGER,
		groupname TEXT 
	);
  CREATE TABLE IF NOT EXISTS user_groups (
    uid INTEGER NOT NULL,
    gid INTEGER NOT NULL
  );
  `
)

/* central object */
type DBHandler struct {
	db     *sql.DB
	DBName string
}

/* "singleton" like db connection reference */
func (m *DBHandler) getConn() (*sql.DB, error) {
	db := m.db
	var err error

	if db == nil {
		db, err = sql.Open("duckdb", "data/db/"+m.DBName)
		m.db = db
		if err != nil {
			log.Printf("Failed to connect to DuckDB: %v", err)
			return nil, err
		}
	}
	return db, err
}

/* initialization method for root user, could be reconfigured*/
func (m *DBHandler) insertRootUser(user User, db *sql.DB) error {
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

	hashPass, err := hash([]byte(user.Password.Hashpass))
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
func (m *DBHandler) Init() {
	log.Print("Initializing... Minioth DB")
	_, err := os.Stat("data")
	if err != nil {
		err = os.Mkdir("data", 0o700)
		if err != nil {
			panic("failed to make new directory.")
		}
	}

	_, err = os.Stat("data/db")
	if err != nil {
		err = os.Mkdir("data/db", 0o700)
		if err != nil {
			panic("failed to make new directory.")
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
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = 'root')").Scan(&rootExists)
	if err != nil {
		log.Fatalf("Failed to check for root user: %v", err)
	}

	if !rootExists {
		log.Print("Inserting root user...")
		// Directly insert the root user with UID 0
		user := User{
			Name: "root",
			Password: Password{
				Hashpass: "root", // Ensure proper hashing is applied later
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
* Each user should be associated with his own group
* */
func (m *DBHandler) Useradd(user User) (int, error) {
	log.Printf("Inserting user %q", user.Name)
	db, err := m.getConn()
	if err != nil {
		return -1, err
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("failed to begin transaction: %v", err)
		return -1, err
	}

	// check if user exists...
	var exists int
	err = db.QueryRow("SELECT 1 FROM users WHERE username = ?", user.Name).Scan(&exists)
	if err == sql.ErrNoRows {
		log.Printf("User with name %q does not exist.", user.Name)
	} else if err != nil {
		log.Printf("Error checking for user existence: %v", err)
		return -1, fmt.Errorf("error checking for user existence: %w", err)
	} else {
		log.Printf("User with name %q already exists.", user.Name)
		return -1, fmt.Errorf("user already exists")
	}

	userQuery := `
  INSERT INTO 
    users (uid, username, info, home, shell, pgroup) 
  VALUES 
    (?, ?, ?, ?, ?, ?)
  `

	user.Uid, err = m.nextId("users")
	if err != nil {
		log.Printf("failed to retrieve the next avaible uid: %v", err)
		return -1, err
	}
	user.Pgroup = user.Uid

	log.Printf("uid fetched: %v", user.Uid)

	_, err = tx.Exec(userQuery, user.Uid, user.Name, user.Info, user.Home, user.Shell, user.Pgroup)
	if err != nil {
		log.Printf("failed to execute query: %v", err)
		tx.Rollback()
		return -1, err
	}

	passwordQuery := `
  INSERT INTO
    passwords (uid, hashpass, lastpasswordchange, minimumpasswordage, maximumpasswordage, warningperiod, inactivityperiod, expirationdate)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `
	/* add the user inique group */
	gid, err := m.Groupadd(Group{user.Name, nil, user.Uid})
	if err != nil {
		log.Printf("failed to insert user unique/primary group: %v", err)
		return -1, err
	}

	usergroupQuery := `
    INSERT INTO
      user_groups (uid, gid)
    VALUES
      (?, ?),
      (?, ?)`
	_, err = tx.Exec(usergroupQuery, user.Uid, 1000, user.Uid, gid)
	if err != nil {
		tx.Rollback()
		log.Printf("failed to group user: %v", err)
		return -1, err
	}

	hashPass, err := hash([]byte(user.Password.Hashpass))
	if err != nil {
		log.Printf("failed to hash the pass: %v", err)
		tx.Rollback()
		return -1, err
	}

	_, err = tx.Exec(passwordQuery, user.Uid, hashPass, user.Password.LastPasswordChange, user.Password.MinPasswordAge,
		user.Password.MaxPasswordAge, user.Password.WarningPeriod, user.Password.InactivityPeriod, user.Password.ExpirationDate)
	if err != nil {
		tx.Rollback()
		log.Printf("failed to execute query: %v", err)
		return -1, err
	}

	if err := tx.Commit(); err != nil {
		log.Printf("failed to commit transaction: %v", err)
		return -1, err
	}

	return user.Uid, nil
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

	return nil
}

func (m *DBHandler) Usermod(user User) error {
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

func (m *DBHandler) Userpatch(uid string, fields map[string]interface{}) error {
	query := "UPDATE users SET "
	args := []interface{}{}

	var groups interface{}
	var password string
	for key, value := range fields {
		switch key {
		case "uid":
			continue

		case "groups":
			groups = fields[key]
			continue
		case "password":
			password = fields[key].(string)
		default:
			if fields[key] == "" {
				continue
			}
			query += fmt.Sprintf("%s = ?, ", key)
			args = append(args, value)
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
			return fmt.Errorf("failed to execute update query: %w", err)
		}
	}

	// group patch
	// if groups arg is here, we need to update the relation
	if len(groups.(string)) > 0 {
		log.Print("deleting old group relations...")
		_, err := tx.Exec("DELETE FROM user_groups WHERE uid = ?", uid)
		if err != nil {
			log.Printf("failed to delete old relations..:%v", err)
			return fmt.Errorf("failed to delete old relations: %w", err)
		}

		groups := strings.Split(groups.(string), ",")       // Assuming `groups` is a string of comma-separated group names
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
		args := []interface{}{uid}
		for _, group := range groups {
			args = append(args, strings.TrimSpace(group))
		}

		log.Print("inserting user group relation...")
		res, err := tx.Exec(insQuery, args...)
		if err != nil {
			log.Printf("failed to insert user groups: %v", err)
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

		_, err = tx.Exec(pquery, password, time.Now(), uid)
		if err != nil {
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

func (m *DBHandler) Groupadd(group Group) (int, error) {
	log.Printf("Adding new group: %v", group)

	db, err := m.getConn()
	if err != nil {
		log.Printf("failed to get the db conn: %v", err)
		return -1, err
	}

	// check if group exists...
	var exists int
	err = db.QueryRow("SELECT 1 FROM groups WHERE groupname = ?", group.Name).Scan(&exists)
	if err == sql.ErrNoRows {
		log.Printf("group with name %q does not exist.", group.Name)
	} else if err != nil {
		log.Printf("errror checking for group existence: %v", err)
		return -1, fmt.Errorf("error checking for group existence: %w", err)
	} else {
		log.Printf("group with name %q already exists.", group.Name)
		return -1, fmt.Errorf("group already exists")
	}

	groupAddQuery := `
    INSERT INTO
      groups (gid, groupname)
    VALUES
      (?, ?);
    
  `

	// insert group
	gid, err := m.nextId("groups")
	if err != nil {
		log.Printf("failed to retrieve the nextid")
		return -1, err
	}

	_, err = db.Exec(groupAddQuery, gid, group.Name)
	if err != nil {
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

		_, err = db.Exec(userGroupQuery, args...)
		if err != nil {
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

func (m *DBHandler) Groupmod(group Group) error {
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

	hashPass, err := hash([]byte(password))
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

func (m *DBHandler) Select(id string) []interface{} {
	log.Printf("Selecting all %q", id)
	db, err := m.getConn()
	if err != nil {
		log.Printf("failed to connect to database: %v", err)
		return nil
	}

	switch id {
	case "users":
		var result []interface{}

		userQuery := `
      SELECT  
        u.uid, u.username, p.hashpass, p.lastPasswordChange, p.minimumPasswordAge,
        p.maximumPasswordAge, p.warningPeriod, p.inactivityPeriod, p.expirationDate,
        u.info, u.home, u.shell, u.pgroup, GROUP_CONCAT(g.groupname) as groups
      FROM 
        users u
      LEFT JOIN passwords p ON p.uid = u.uid
      LEFT JOIN user_groups ug ON ug.uid = u.uid
      LEFT JOIN groups g ON g.gid = ug.gid
      GROUP BY 
        u.uid, u.username, u.info, u.home, u.shell, u.pgroup, p.hashpass, p.lastPasswordChange, p.minimumPasswordAge, p.maximumPasswordAge, p.warningPeriod, p.inactivityPeriod, p.expirationDate;
    `
		rows, err := db.Query(userQuery)
		if err != nil {
			log.Printf("failed to query users: %v", err)
			return nil
		}
		defer rows.Close()

		for rows.Next() {
			var user User
			var groupNames sql.NullString // Use sql.NullString to handle NULL values
			err := rows.Scan(&user.Uid, &user.Name, &user.Password.Hashpass, &user.Password.LastPasswordChange, &user.Password.MinPasswordAge, &user.Password.MaxPasswordAge, &user.Password.WarningPeriod, &user.Password.InactivityPeriod, &user.Password.ExpirationDate, &user.Info, &user.Home, &user.Shell, &user.Pgroup, &groupNames)
			if err != nil {
				log.Printf("failed to scan user: %v", err)
				return nil
			}

			groups := []Group{}
			if groupNames.Valid && groupNames.String != "" { // Check if groupNames is valid and not empty
				groupNameList := strings.Split(groupNames.String, ",")
				for _, groupName := range groupNameList {
					groups = append(groups, Group{
						Name: groupName,
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
        g.gid, g.groupname, GROUP_CONCAT(u.username) as users
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
			var group Group
			var userNames sql.NullString
			err := rows.Scan(&group.Gid, &group.Name, &userNames)
			if err != nil {
				log.Printf("failed to scan group: %v", err)
				return nil
			}

			// Parse user names into dummy User structs

			users := []User{}
			if userNames.Valid && userNames.String != "" {
				userNameList := strings.Split(userNames.String, ",")
				for _, userName := range userNameList {
					users = append(users, User{
						Name: userName,
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

func (m *DBHandler) Authenticate(username, password string) (*User, error) {
	log.Printf("authenticating user... %q:%q", username, password)

	db, err := m.getConn()
	if err != nil {
		return nil, err
	}
	user := getUser(username, db)
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	if verifyPass([]byte(user.Password.Hashpass), []byte(password)) {
		return user, nil
	} else {
		return nil, fmt.Errorf("failed to authenticate, bad credentials.")
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
func getUser(username string, db *sql.DB) *User {
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
      u.username, u.info, u.home, u.shell, u.uid, u.pgroup,
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

	user := User{}
	groups := make([]Group, 0)

	var (
		gid   sql.NullInt64
		gname sql.NullString
	)

	for rows.Next() {
		if err := rows.Scan(&user.Name, &user.Info, &user.Home, &user.Shell, &user.Uid, &user.Pgroup, &gid, &gname); err != nil {
			log.Printf("failed to ugr scan row: %v", err)
			return nil
		}

		if gid.Valid && gname.Valid {
			groups = append(groups, Group{
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
	password := Password{}
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

func (m *DBHandler) nextId(table string) (int, error) {
	db, err := m.getConn()
	if err != nil {
		return 0, fmt.Errorf("failed to connect to database: %w", err)
	}

	var id, query string
	switch table {
	case "users":
		id = "uid"
		query = "SELECT COALESCE(MAX(uid), 999) + 1 FROM " + table + " WHERE " + id + " >= 1000"
	case "groups":
		id = "gid"
		query = "SELECT COALESCE(MAX(gid), 999) + 1 FROM " + table + " WHERE " + id + " >= 1000"
	}

	var nextUid int
	err = db.QueryRow(query).Scan(&nextUid)
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve next UID: %w", err)
	}

	return nextUid, nil
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
