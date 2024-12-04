package minioth

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

/* I want to implement a simplistic but handy user/group state system.
* Let's copy the UNIX model
*
* /etc/passwd, /etc/shadow, /etc/group
*
* TODO: This program should provide atomicity perhaps
*
* WARNING: not currently threadsafe...
 */

const (
	MINIOTH_PASSWD string = "data/mpasswd"
	MINIOTH_GROUP  string = "data/mgroup"
	MINIOTH_SHADOW string = "data/mshadow"

	HASH_COST  int    = 16
	MINIOTH_DB string = "data/minioth.db"

	PLACEHOLDER_PASS string = "3ncrypr3d"
	DEL              string = ":"
	// username:password ref:uuid:guid:info:home:shell
	ENTRY_MPASSWD_FORMAT string = "%s" + DEL + "%s" + DEL + "%v" + DEL + "%v" + DEL + "%s" + DEL + "%s" + DEL + "%s\n"
	ENTRY_MSHADOW_FORMAT string = "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%v\n"
	ENTRY_MGROUP_FORMAT  string = "%s" + DEL + "%s" + DEL + "%v\n"
)

/* idk if this is useful yet.. */
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
	Name     string   `json:"username" form:"username"`
	Info     string   `json:"info" form:"info"`
	Home     string   `json:"home" form:"home"`
	Shell    string   `json:"shell" form:"shell"`
	Password Password `json:"password"`
	Uid      int      `json:"uid"`
	Pgroup   int      `json:"pgroup"`
}
type Password struct {
	Hashpass           string `json:"hashpass"`
	LastPasswordChange string `json:"lastPasswordChange"`
	MinPasswordAge     string `json:"minimumPasswordAge"`
	MaxPasswordAge     string `json:"maximumPasswordAge"`
	WarningPeriod      string `json:"warningPeriod"`
	InactivityPeriod   string `json:"inactivityPeriod"`
	ExpirationDate     string `json:"expirationDate"`
	Length             int    `json:"passwordLength"`
}
type Group struct {
	Name  string `json:"groupname" form:"groupname"`
	Users []User
	Gid   int64 `json:"gid" form:"gid"`
}

func (m *Minioth) sync() error {
	return nil
}

/* use bcrypt blowfish algo (and std lib) to hash a byte array */
func hash(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, HASH_COST)
}

/* check if a passowrd is correct */
func verifyPass(hashedPass, password []byte) bool {
	if err := bcrypt.CompareHashAndPassword(hashedPass, password); err == nil {
		return true
	}
	return false
}

type Minioth struct {
	dbPath string

	root       User /* perhaps we dont need to hold a ref to this, but each Minioth should have a root user. Its handled on init*/
	usercount  int  /* just stats.. */
	groupcount int  /* just stats.. */

	useDB bool /* for intrgrating with a db. NOTE:sqlite (for now)*/
}

/* Use this function to create an instance of minioth. */
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

/* delete the 3 state files */
func (m *Minioth) purge() {
	log.Print("Purging everything...")

	_, err := os.Stat("data")
	if err != nil {
		log.Printf("error stating data dir: %v", err)
		err = os.Mkdir("data", 0o700)
		if err != nil {
			panic("failed to make new directory.")
		}
	}

	err = os.Remove(MINIOTH_PASSWD)
	if err != nil {
		log.Print(err)
	}
	err = os.Remove(MINIOTH_GROUP)
	if err != nil {
		log.Print(err)
	}
	err = os.Remove(MINIOTH_SHADOW)
	if err != nil {
		log.Print(err)
	}
	err = os.Remove(MINIOTH_DB)
	if err != nil {
		log.Print(err)
	}

	// TODO: delete more stuff.>!!!!
}

/*  */
/* Pretty important!*/
/* initialization routines. check if data directory is there, check if root user exists...*/
func (m *Minioth) init() {
	log.Print("Initializing minioth")

	_, err := os.Stat("data")
	if err != nil {
		log.Printf("error stating data dir: %v", err)
		err = os.Mkdir("data", 0o700)
		if err != nil {
			panic("failed to make new directory.")
		}
	}

	// TODO: should check for existing files integrity...
	log.Print("Checking if data file exists...")

	// Should check if root exists...
	if err := verifyFilePrefix(MINIOTH_PASSWD, "root"); err != nil {
		// Add root user
		m.Useradd(User{
			Name: "root",
			Password: Password{
				Hashpass: "root",
			},
			Uid:    0,
			Pgroup: 0,
			Info:   "HEADMASTER",
			Home:   "/",
			Shell:  "/bin/gshell",
		})
	}
}

/* this method is supposed to return eveyrhing from the given file */
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

/* This function doesn't check if user already exists. */
func (m *Minioth) Useradd(user User) error {
	log.Printf("Adding user %q ...", user.Name)

	// Generate password early, return early if failed...
	hashPass, err := hash([]byte(user.Password.Hashpass))
	if err != nil {
		log.Printf("Failed to hash the pass... :%v", err)
		return err
	}

	// Open/Create files first to handle all file errors at once.
	file, err := os.OpenFile(MINIOTH_PASSWD, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("error opening file: %v", err)
		return err
	}
	defer file.Close()

	pfile, err := os.OpenFile(MINIOTH_SHADOW, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("error opening file: %v", err)
		return err
	}
	defer pfile.Close()

	gfile, err := os.OpenFile(MINIOTH_GROUP, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("error opening file: %v", err)
		return err
	}
	defer gfile.Close()

	// passwd file
	// get uuid
	uuid := nextUid()
	fmt.Fprintf(file, ENTRY_MPASSWD_FORMAT, user.Name, PLACEHOLDER_PASS, uuid, uuid, user.Info, user.Home, user.Shell)

	// file.WriteString(strings.Join([]string{user.Name, "3ncrypr3d", uuid, uuid, user.Info, user.Home, user.Shell}, DEL) + "\n")

	// shadow file
	fmt.Fprintf(pfile, ENTRY_MSHADOW_FORMAT, user.Name, hashPass, user.Password.LastPasswordChange, user.Password.MinPasswordAge, user.Password.MaxPasswordAge, user.Password.WarningPeriod, user.Password.InactivityPeriod, user.Password.ExpirationDate, user.Password.Length)

	log.Print("Useradd successful.")
	m.usercount++
	return nil
}

/* approval of minioth means, user exists and password is valid */
func (m *Minioth) approveUser(username, password string) bool {
	log.Printf("approving user... %q:%q", username, password)

	file, err := os.Open(MINIOTH_PASSWD)
	if err != nil {
		log.Printf("failed to open file: %v", err)
		return false
	}
	defer file.Close()

	pfile, err := os.Open(MINIOTH_SHADOW)
	if err != nil {
		log.Printf("failed to open file: %v", err)
		return false
	}
	defer pfile.Close()

	log.Print("searching for user entry...")
	userline, line, err := search(username, file)
	if err != nil || line == -1 {
		log.Printf("failed to search for user: %v", err)
		return false
	}
	log.Print(userline)

	log.Print("searching for password entry...")
	passline, pline, err := search(username, pfile)
	if err != nil || pline == -1 {
		log.Printf("failed to search for pass: %v", err)
		return false
	}

	// log.Printf("userentry: %s, passwordentry: %s", userline, passline)

	hashpass := strings.SplitN(passline, DEL, 3)[1]

	return verifyPass([]byte(hashpass), []byte(password))
}

/* check if a user is already here. Error nil if not*/
func exists(user *User) error {
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
		return errors.New("user already exists")
	}

	return nil
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

/* simply delete a user.. */
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

/* check password fields for allowed values...*/
func (p *Password) validatePassword() error {
	// Validate Password Length
	if p.Length < 8 {
		return fmt.Errorf("password length '%d' is too short: minimum required length is 8 characters", p.Length)
	}

	// Validate Hashpass
	if p.Hashpass == "" {
		return errors.New("hashpass cannot be empty")
	}

	// Validate Last Password Change
	if p.LastPasswordChange == "" {
		return errors.New("last password change date cannot be empty")
	}

	// Validate Min Password Age
	if p.MinPasswordAge == "" {
		return errors.New("minimum password age cannot be empty")
	}

	// Validate Max Password Age
	if p.MaxPasswordAge == "" {
		return errors.New("maximum password age cannot be empty")
	}

	// Validate Warning Period
	if p.WarningPeriod == "" {
		return errors.New("warning period cannot be empty")
	}

	// Validate Inactivity Period
	if p.InactivityPeriod == "" {
		return errors.New("inactivity period cannot be empty")
	}

	// Validate Expiration Date
	if p.ExpirationDate == "" {
		return errors.New("expiration date cannot be empty")
	}

	return nil
}

// Unused
func checkIfUserExists(u User) error {
	log.Printf("Checking if name:%s, already exists...", u.Name)
	var users []string

	data, err := os.ReadFile(MINIOTH_PASSWD)
	if err != nil {
		log.Printf("error opening file: %v", err)
		return err
	}
	users = strings.Split(string(data), "\n")

	for _, line := range users {
		parts := strings.SplitN(line, ":", 4)
		if len(parts) != 4 {
			break
		}
		username := parts[0]
		// compare username
		if u.Name == username {
			log.Printf("user %s already exists.", username)
			return errors.New("user already exists.")
		}
	}

	return nil
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
