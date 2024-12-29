package minioth

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

const (
	MINIOTH_PASSWD   string = "data/plain/mpasswd"
	MINIOTH_GROUP    string = "data/plain/mgroup"
	MINIOTH_SHADOW   string = "data/plain/mshadow"
	PLACEHOLDER_PASS string = "3ncrypr3d"
	DEL              string = ":"
	// username:password ref:uuid:guid:info:home:shell
	ENTRY_MPASSWD_FORMAT string = "%s" + DEL + "%s" + DEL + "%v" + DEL + "%v" + DEL + "%s" + DEL + "%s" + DEL + "%s\n"
	ENTRY_MSHADOW_FORMAT string = "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%s" + DEL + "%v\n"
	ENTRY_MGROUP_FORMAT  string = "%s" + DEL + "%s" + DEL + "%v\n"
)

type PlainHandler struct{}

/*  */
/* Pretty important!*/
/* initialization routines. check if data directory is there, check if root user exists...*/
func (m *PlainHandler) Init() {
	log.Print("Initializing minioth Plain")

	_, err := os.Stat("data")
	if err != nil {
		log.Printf("error stating data dir: %v", err)
		err = os.Mkdir("data", 0o700)
		if err != nil {
			panic("failed to make new directory.")
		}
	}

	log.Print("Checking if data dir exists...")

	_, err = os.Stat("data/plain")
	if err != nil {
		log.Printf("error stating plain dir: %v", err)
		err = os.Mkdir("data/plain", 0o700)
		if err != nil {
			panic("failed to make new directory.")
		}
	}

	log.Print("Checking if plain dir exists...")
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

func (m *PlainHandler) Useradd(user User) error {
	log.Printf("Adding user %q ...", user.Name)

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

	// Check if exists
	err = exists(&user)
	if err != nil {
		log.Printf("error: user already exists: %v", err)
		return err
	}

	// Generate password early, return early if failed...
	hashPass, err := hash([]byte(user.Password.Hashpass))
	if err != nil {
		log.Printf("Failed to hash the pass... :%v", err)
		return err
	}

	// passwd file
	// get uuid
	uuid := nextUid()
	fmt.Fprintf(file, ENTRY_MPASSWD_FORMAT, user.Name, PLACEHOLDER_PASS, uuid, uuid, user.Info, user.Home, user.Shell)

	// file.WriteString(strings.Join([]string{user.Name, "3ncrypr3d", uuid, uuid, user.Info, user.Home, user.Shell}, DEL) + "\n")

	// shadow file
	fmt.Fprintf(pfile, ENTRY_MSHADOW_FORMAT, user.Name, hashPass, user.Password.LastPasswordChange, user.Password.MinPasswordAge, user.Password.MaxPasswordAge, user.Password.WarningPeriod, user.Password.InactivityPeriod, user.Password.ExpirationDate, len(user.Password.Hashpass))

	log.Print("Useradd successful.")
	return nil
}

/* simply delete a user.. */
func (m *PlainHandler) Userdel(username string) error {
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

func (m *PlainHandler) Usermod(user User) error {
	return nil
}

func (m *PlainHandler) Userpatch(uid string, fields map[string]interface{}) error {
	return nil
}

func (m *PlainHandler) Groupadd(group Group) error {
	return nil
}

func (m *PlainHandler) Groupdel(groupname string) error {
	return nil
}

func (m *PlainHandler) Grouppatch(gid string, fields map[string]interface{}) error {
	return nil
}

func (m *PlainHandler) Groupmod(group Group) error {
	return nil
}

func (m *PlainHandler) Passwd(username, password string) error {
	return nil
}

/* this method is supposed to return eveyrhing from the given file */
func (m *PlainHandler) Select(id string) []interface{} {
	log.Printf("Selecting all %q", id)
	switch id {
	case "users":
		// var users []User

		//res, err := os.ReadFile(MINIOTH_PASSWD)
		//if err != nil {
		//	log.Printf("error reading file: %v", err)
		//	return nil
		//}
		//users = strings.Split(string(res), "\n")

		// return users
		return nil
	case "groups":
		/*var groups []string

		res, err := os.ReadFile(MINIOTH_GROUP)
		if err != nil {
			log.Printf("error reading file: %v", err)
			return nil
		}
		groups = strings.Split(string(res), "\n")*/
		return nil
	default:
		log.Print("Invalid id: " + id)
		return nil
	}
}

/* approval of minioth means, user exists and password is valid */
func (m *PlainHandler) Authenticate(username, password string) (*User, error) {
	log.Printf("authenticating user... %q:%q", username, password)

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

	gfile, err := os.Open(MINIOTH_GROUP)
	if err != nil {
		log.Printf("failed to open file: %v", err)
		return nil, err
	}
	defer gfile.Close()

	log.Print("searching for user entry...")
	userline, line, err := search(username, file)
	if err != nil || line == -1 {
		log.Printf("failed to search for user: %v", err)
		return nil, err
	}
	log.Print(userline)

	log.Print("searching for password entry...")
	passline, pline, err := search(username, pfile)
	if err != nil || pline == -1 {
		log.Printf("failed to search for pass: %v", err)
		return nil, err
	}

	// log.Printf("userentry: %s, passwordentry: %s", userline, passline)

	hashpass := strings.SplitN(passline, DEL, 3)[1]

	if verifyPass([]byte(hashpass), []byte(password)) {
		return nil, nil
	} else {
		return nil, fmt.Errorf("failed to authenticate, bad creds")
	}
}

func (p *PlainHandler) Close() {
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
			return fmt.Errorf("user already exists.")
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
		return fmt.Errorf("user already exists")
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

func getGroups(username string, file *os.File) ([]Group, error) {
	if username == "" || file == nil {
		return nil, fmt.Errorf("must provide valid parms")
	}
	scanner := bufio.NewScanner(file)

	var groups []Group
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, DEL, 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("no content found")
		}
		if strings.Contains(parts[1], username) {
			group := Group{
				Name: parts[0],
			}
			groups = append(groups, group)
		}

	}
	return groups, nil
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
