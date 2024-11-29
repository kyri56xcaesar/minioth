package minioth

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/glebarez/go-sqlite"
)

const (
	initSql string = `CREATE TABLE IF NOT EXISTS users
    (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      uid LONG INTEGER,
      pid INTEGER,
      groups TEXT,
      FOREIGN KEY (pid) REFERENCES passwords (id)
    );
    CREATE TABLE IF NOT EXISTS passwords 
    (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hashpass TEXT,
      expirationDate TEXT,
      length INTEGER
    );
    CREATE TABLE IF NOT EXISTS groups
    (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      users TEXT,
      gid LONG INT
    );

  `
)

func (m *Minioth) Init() error {
	if !m.useDB || m.dbPath == "" {
		log.Print("Properties not set")
		return fmt.Errorf("Cannot init if properties are not set: %v, %v", m.useDB, m.dbPath)
	}

	db, err := sql.Open("sqlite", m.dbPath)
	if err != nil {
		log.Printf("error opening db at %s: %v", m.dbPath, err)
		return fmt.Errorf("error opening db at %s: %v", m.dbPath, err)
	}
	defer db.Close()

	res, err := db.Exec(initSql, nil)
	if err != nil {
		log.Printf("error executing initsql script: %v", err)
		return fmt.Errorf("error executing initsql script: %v", err)
	}

	raffected, err := res.RowsAffected()
	if err == nil {
		log.Printf("Rows affected: %v", raffected)
	}

	return nil
}
