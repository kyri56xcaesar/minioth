package minioth

import (
	"errors"
	"fmt"
	"log"
	"os"
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
 */

const (
	HASH_COST int = 16
)

type MiniothHandler interface {
	Init()
	Useradd(user User) error
	Userdel(username string) error
	Usermod(user User) error

	Groupadd(group Group) error
	Groupdel(groupname string) error
	Groupmod(group Group) error

	Passwd(username, password string) error

	Select(id string) []string

	Authenticate(username, password string) ([]Group, error)
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
	handler MiniothHandler
	root    User /* perhaps we dont need to hold a ref to this, but each Minioth should have a root user. Its handled on init*/
}

/* Use this function to create an instance of minioth. */
func NewMinioth(rootname string, useDb bool, dbPath string) Minioth {
	log.Print("Creating new minioth...")

	var handler MiniothHandler

	if useDb {
		handler = &DBHandler{DBName: dbPath}
	} else {
		handler = &PlainHandler{}
	}

	newM := Minioth{
		root: User{
			Name: rootname,
			Password: Password{
				Hashpass:       rootname,
				ExpirationDate: "",
				Length:         0,
			},
			Pgroup: 0,
			Uid:    0,
		},
		handler: handler,
	}

	newM.handler.Init()

	return newM
}

func (m *Minioth) Useradd(user User) error {
	return m.handler.Useradd(user)
}

func (m *Minioth) Userdel(username string) error {
	return m.handler.Userdel(username)
}

func (m *Minioth) Usermod(user User) error {
	return m.handler.Usermod(user)
}

func (m *Minioth) Groupadd(group Group) error {
	return m.handler.Groupadd(group)
}

func (m *Minioth) Groupdel(groupname string) error {
	return m.handler.Groupdel(groupname)
}

func (m *Minioth) Groupmod(group Group) error {
	return m.handler.Groupmod(group)
}

func (m *Minioth) Passwd(username, password string) error {
	return m.handler.Passwd(username, password)
}

func (m *Minioth) Select(id string) []string {
	return m.handler.Select(id)
}

func (m *Minioth) Authenticate(username, password string) ([]Group, error) {
	return m.handler.Authenticate(username, password)
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

	return nil
}

/* delete the 3 state files */
func (m *Minioth) purge() {
	log.Print("Purging everything...")

	_, err := os.Stat("data/plain")
	if err == nil {
		log.Print("data/plain dir exist")

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

		err = os.Remove("data/plain")
		if err != nil {
			log.Print(err)
		}
	}

	_, err = os.Stat("data/db")
	if err == nil {
		log.Print("data/db dir exists")
		err = os.Remove("data/*.db")
		if err != nil {
			log.Print(err)
		}

		err = os.Remove("data/db")
		if err != nil {
			log.Print(err)
		}
	}
}

/* This function should sync the DB state and the Plain state. TODO:*/
func (m *Minioth) sync() error {
	return nil
}

func (u *User) toString() string {
	return fmt.Sprintf("{%v, %v, %v, %v, %v, %v}", u.Name, u.Info, u.Home, u.Shell, u.Uid, u.Pgroup)
}

func (g *Group) toString() string {
	return fmt.Sprintf("%v", g.Name)
}

func groupsToString(groups []Group) string {
	var res []string

	for _, group := range groups {
		res = append(res, group.toString())
	}

	return strings.Join(res, ",")
}
