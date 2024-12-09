package minioth

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/marcboeker/go-duckdb"
)

const (
	initSql string = `
  CREATE TABLE IF NOT EXISTS users (
		uid INTEGER PRIMARY KEY,
		username TEXT UNIQUE,
		info TEXT,
		home TEXT,
		shell TEXT,
		pgroup INTEGER
	);
	CREATE TABLE IF NOT EXISTS passwords (
		uid INTEGER PRIMARY KEY,
		hashpass TEXT,
		lastPasswordChange TEXT,
		minimumPasswordAge TEXT,
		maximumPasswordAge TEXT,
		warningPeriod TEXT,
		inactivityPeriod TEXT,
		expirationDate TEXT,
		passwordLength INTEGER,
		FOREIGN KEY(uid) REFERENCES users(uid)
	);
	CREATE TABLE IF NOT EXISTS groups (
		gid INTEGER PRIMARY KEY,
		groupname TEXT UNIQUE
	);
  `
)

type DBHandler struct {
	DBName string
}

func (m *DBHandler) getConn() (*sql.DB, error) {
	db, err := sql.Open("duckdb", "data/db/"+m.DBName)
	if err != nil {
		log.Printf("Failed to connect to DuckDB: %v", err)
		return nil, err
	}
	return db, err
}

func (m *DBHandler) Init() {
	log.Print("Initializing minioth DB")
	_, err := os.Stat("data")
	if err != nil {
		log.Print("doesn't exist...")
		err = os.Mkdir("data", 0o700)
		if err != nil {
			panic("failed to make new directory.")
		}
	}

	log.Print("Checking if data dir exists...")

	_, err = os.Stat("data/db")
	if err != nil {
		log.Print("doesn't exist...")
		err = os.Mkdir("data/db", 0o700)
		if err != nil {
			panic("failed to make new directory.")
		}
	}

	log.Print("Checking if plain dir exists...")

	db, err := m.getConn()
	if err != nil {
		panic("destructive")
	}
	defer db.Close()

	_, err = db.Exec(initSql)
	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	log.Print("Inserting root user...")
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
        passwords (uid, hashpass, lastPasswordChange, minimumPasswordAge, maximumPasswordAge, warningPeriod, inactivityPeriod, expirationDate, passwordLength) 
    VALUES 
        (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = tx.Exec(passwordQuery, user.Uid, hashPass, user.Password.LastPasswordChange, user.Password.MinPasswordAge,
		user.Password.MaxPasswordAge, user.Password.WarningPeriod, user.Password.InactivityPeriod, user.Password.ExpirationDate, user.Password.Length)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to insert root password: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (m *DBHandler) Useradd(user User) error {
	log.Printf("Inserting user %+v", user)
	db, err := m.getConn()
	if err != nil {
		return err
	}
	defer db.Close()

	log.Print("beginning transaction...")
	tx, err := db.Begin()
	if err != nil {
		log.Printf("failed to begin transaction: %v", err)
		return err
	}

	userQuery := `
  INSERT INTO 
    users (uid, username, info, home, shell, pgroup) 
  VALUES 
    (?, ?, ?, ?, ?, ?)
  `

	log.Print("fetching next uid...")
	user.Uid, err = m.NextUid()
	if err != nil {
		log.Printf("failed to retrieve the next avaible uid: %v", err)
		return err
	}
	user.Pgroup = user.Uid

	log.Printf("uid fetched: %v", user.Uid)

	log.Print("executing query...")
	_, err = tx.Exec(userQuery, user.Uid, user.Name, user.Info, user.Home, user.Shell, user.Pgroup)
	if err != nil {
		log.Printf("failed to execute query: %v", err)
		tx.Rollback()
		return err
	}

	log.Print("inserting password!")
	passwordQuery := `
  INSERT INTO
    passwords (uid, hashpass, lastpasswordchange, minimumpasswordage, maximumpasswordage, warningperiod, inactivityperiod, expirationdate, passwordlength)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `

	hashPass, err := hash([]byte(user.Password.Hashpass))
	if err != nil {
		log.Printf("failed to hash the pass: %v", err)
		tx.Rollback()
		return err
	}

	log.Print("executing password query...")
	_, err = tx.Exec(passwordQuery, user.Uid, hashPass, user.Password.LastPasswordChange, user.Password.MinPasswordAge,
		user.Password.MaxPasswordAge, user.Password.WarningPeriod, user.Password.InactivityPeriod, user.Password.ExpirationDate, user.Password.Length)
	if err != nil {
		tx.Rollback()
		log.Printf("failed to execute query: %v", err)
		return err
	}

	log.Print("committing transaction...")
	if err := tx.Commit(); err != nil {
		log.Printf("failed to commit transaction: %v", err)
		return err
	}

	return nil
}

func (m *DBHandler) Userdel(username string) error {
	db, err := m.getConn()
	if err != nil {
		return err
	}
	defer db.Close()

	deleteUserQuery := `DELETE FROM users WHERE username = ?`
	deletePasswordQuery := `DELETE FROM passwords WHERE uid = ?`

	res, err := db.Exec(deleteUserQuery, username)
	if err != nil {
		log.Printf("error, failed to delete user: %v", err)
		return err
	}
	uid, err := res.LastInsertId()
	if err != nil {
		log.Printf("error, failed to retrieve last inserted id: %v", err)
		return err
	}

	_, err = db.Exec(deletePasswordQuery, int(uid))
	if err != nil {
		log.Printf("error, failed to delete password: %v", err)
		return err
	}

	return nil
}

func (m *DBHandler) Usermod(user User) error {
	return nil
}

func (m *DBHandler) Groupadd(group Group) error {
	return nil
}

func (m *DBHandler) Groupdel(groupname string) error {
	return nil
}

func (m *DBHandler) Groupmod(group Group) error {
	return nil
}

func (m *DBHandler) Passwd(username, password string) error {
	return nil
}

func (m *DBHandler) Select(id string) []string {
	log.Printf("Selecting all %q", id)
	db, err := m.getConn()
	if err != nil {
		return nil
	}
	defer db.Close()

	switch id {
	case "users":
		var users []string

		userQuery := `SELECT * FROM users`
		rows, err := db.Query(userQuery, nil)
		if err != nil {
			log.Printf("failed to query users...:%v", err)
			return nil
		}
		defer rows.Close()

		for rows.Next() {
			var user User
			err := rows.Scan(&user.Uid, &user.Name, &user.Info, &user.Home, &user.Shell, &user.Pgroup)
			if err != nil {
				log.Printf("failed to scan user...: %v", err)
				return nil
			}
			users = append(users, user.toString())
		}

		return users
	case "groups":
		var groups []string

		return groups
	default:
		log.Print("Invalid id: " + id)
		return nil
	}
}

func (m *DBHandler) Authenticate(username, password string) (bool, error) {
	log.Printf("authenticating user... %q:%q", username, password)

	db, err := m.getConn()
	if err != nil {
		return false, err
	}
	defer db.Close()

	user := getUser(username, db)
	if user == nil {
		log.Print("user not found")
		return false, fmt.Errorf("user not existent")
	}

	return verifyPass([]byte(user.Password.Hashpass), []byte(password)), nil
}

func getUser(username string, db *sql.DB) *User {
	userQuery := `SELECT username, info, home, shell, uid, pgroup FROM users WHERE username = ?`
	passwordQuery := `SELECT hashpass, lastPasswordChange, minimumPasswordAge, maximumPasswordAge, warningPeriod, inactivityPeriod, expirationDate, passwordLength FROM passwords WHERE uid = ?`

	log.Printf("looking for user with name: %q...", username)

	user := User{}
	err := db.QueryRow(userQuery, username).Scan(&user.Name, &user.Info, &user.Home, &user.Shell, &user.Uid, &user.Pgroup)
	if err != nil {
		log.Printf("user not found: %v", err)
		return nil
	}

	password := Password{}
	err = db.QueryRow(passwordQuery, user.Uid).Scan(&password.Hashpass, &password.LastPasswordChange, &password.MinPasswordAge,
		&password.MaxPasswordAge, &password.WarningPeriod, &password.InactivityPeriod, &password.ExpirationDate, &password.Length)
	if err != nil {
		log.Printf("password not found: %v", err)
		return nil
	}

	user.Password = password
	log.Printf("User found: %+v", user)
	return &user
}

func (m *DBHandler) NextUid() (int, error) {
	// Connect to the database
	db, err := m.getConn()
	if err != nil {
		return 0, fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	// Query to get the maximum UID
	query := "SELECT COALESCE(MAX(uid), 999) + 1 FROM users WHERE uid >= 1000"
	var nextUid int
	err = db.QueryRow(query).Scan(&nextUid)
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve next UID: %w", err)
	}

	return nextUid, nil
}
