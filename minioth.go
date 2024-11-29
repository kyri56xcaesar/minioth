package minioth

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// I want to implement a simplistic but handy user/group state system.
// Let's copy the UNIX model
//
// /etc/passwd, /etc/shadow, /etc/group

const (
	MINIOTH_PASSWD string = "data/mpasswd"
	MINIOTH_GROUP  string = "data/mgroup"
	MINIOTH_SHADOW string = "data/mshadow"

	HASH_COST  int    = 16
	MINIOTH_DB string = "data/minioth.db"
)

type userspace interface {
	useradd() error
	userdel() error
	usermod() error

	groupadd() error
	groupdel() error
	groupmod() error

	passwd() error
}

type User struct {
	Name     string
	Info     string
	Home     string
	Shell    string
	Password Password
	Uid      int
	Pgroup   int
}
type Password struct {
	Hashpass           string
	LastPasswordChange string
	MinPasswordAge     string
	MaxPasswordAge     string
	WarningPeriod      string
	InactivityPeriod   string
	ExpirationDate     string
	Length             int
}
type Group struct {
	Name     string
	Password Password
	Users    []User
	Gid      int64
}

func Hash(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, HASH_COST)
}

func verifyPass(hashedPass, password []byte) bool {
	if err := bcrypt.CompareHashAndPassword(hashedPass, password); err == nil {
		return true
	}
	return false
}

type Minioth struct {
	dbPath string

	root       User
	usercount  int
	groupcount int

	useDB bool
}

func NewMinioth(rootname string, useDb bool, dbPath string) Minioth {
	log.Print("Creating new minioth")
	newM := Minioth{
		dbPath: dbPath,
		root: User{
			Name: rootname,
			Password: Password{
				Hashpass:       "",
				ExpirationDate: "",
				Length:         0,
			},
			Pgroup: 0,
			Uid:    0,
		},
		usercount:  0,
		groupcount: 0,
		useDB:      useDb,
	}
	newM.init()

	return newM
}

func (m *Minioth) init() {
	log.Print("Initializing minioth")
	// Reset file
	err := os.Remove(MINIOTH_PASSWD)
	if err != nil {
		log.Print(err)
	}

	// Add root user
	m.Useradd("root", "root", "Root of the system", "/", "/bin/gshell")
}

func (m *Minioth) sync() error {
	return nil
}

func (m *Minioth) Select(id string) []string {
	log.Printf("Selecting all %q", id)
	switch id {
	case "users":
		var users []string

		res, err := os.ReadFile(MINIOTH_PASSWD)
		if err != nil {
			log.Printf("error reading file: %v", err)
			return nil
		}
		users = strings.Split(string(res), "\n")

		return users
	case "groups":
		var groups []string

		res, err := os.ReadFile(MINIOTH_GROUP)
		if err != nil {
			log.Printf("error reading file: %v", err)
			return nil
		}
		groups = strings.Split(string(res), "\n")
		return groups
	default:
		log.Print("Invalid id: " + id)
		return nil
	}
}

func (m *Minioth) Useraddu(user User) error {
	log.Printf("Adding user %q ...", user.Name)
	file, err := os.OpenFile(MINIOTH_PASSWD, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("error opening file: %v", err)
		return err
	}
	defer file.Close()

	if exists(user.Name, file) {
		// TODO: handle error cases
		return err
	}

	// get uuid
	uuid := nextUid()

	file.WriteString(strings.Join([]string{user.Name, "3ncrypr3d", uuid, uuid, user.Info, user.Home, user.Shell}, ":") + "\n")

	log.Print("Useradd successful.")
	return nil
}

func (m *Minioth) Useradd(username, password, info, home, shell string) error {
	log.Printf("Adding user %q ...", username)
	file, err := os.OpenFile(MINIOTH_PASSWD, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("error opening file: %v", err)
		return err
	}
	defer file.Close()

	if exists(username, file) {
		// TODO: handle error cases
		return err
	}

	// get uuid
	uuid := nextUid()

	file.WriteString(strings.Join([]string{username, "3ncrypr3d", uuid, uuid, info, home, shell}, ":") + "\n")

	log.Print("Useradd successful.")
	return nil
}

func exists(username string, file *os.File) bool {
	if res, line, err := search(username, file); err == nil {
		log.Printf("user: %q exists at line: %v", strings.SplitN(res, ":", 2)[0], line)
		return true
	}
	return false
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
		parts := strings.SplitN(line, ":", 2)
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
		if len(parts) != 7 {
			continue
		}
		id := parts[2]
		currentUids = append(currentUids, id)
	}
	// log.Print(currentUids)

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

func (m *Minioth) Userdel(username string) error {
	log.Printf("Deleting user %q ...", username)
	if username == "" {
		log.Print("must provide a username")
		return fmt.Errorf("must provide a username")
	}

	f, err := os.OpenFile(MINIOTH_PASSWD, os.O_RDWR, 0o600)
	if err != nil {
		fmt.Printf("error opening file: %v", err)
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	var updated []string

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] != username {
			updated = append(updated, line)
		}
	}

	f, err = os.Create(MINIOTH_PASSWD)
	if err != nil {
		log.Print("failed to create the file")
		return err
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, line := range updated {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	log.Print("Deletion successful.")

	return nil
}

func (m *Minioth) usermod(username, password string, groupnames []string) error {
	return nil
}

func (m *Minioth) groupadd(groupname, password string, usernames []string) error {
	return nil
}

func (m *Minioth) groupdel(groupname string) error {
	return nil
}

func (m *Minioth) groupmod(groupname, password string, usernames []string) error {
	return nil
}

func (m *Minioth) passwd(username, password string) error {
	return nil
}
