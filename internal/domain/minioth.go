package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

/*
* WARNING: don't use the plain handler.
 */

/* hash cost for bcrypt hash function, reconfigurable from config*/
var HASH_COST int = 16

/* password policy, reconfigurable from config (see EnvConfig / NewMService) */
var (
	PasswordMinLength      = 8
	PasswordMaxLength      = 72 // bcrypt silently ignores input past 72 bytes
	PasswordRequireUpper   = false
	PasswordRequireLower   = false
	PasswordRequireDigit   = false
	PasswordRequireSpecial = false
)

var (
	upperRe   = regexp.MustCompile(`[A-Z]`)
	lowerRe   = regexp.MustCompile(`[a-z]`)
	digitRe   = regexp.MustCompile(`[0-9]`)
	specialRe = regexp.MustCompile(`[^a-zA-Z0-9]`)
)

/*
*
* */
type Minioth struct {
	handler MiniothHandler
	root    User /* perhaps we dont need to hold a ref to this, but each Minioth should have a root user. Its handled on init*/
}

/* each minioth instance consists of a handler which
*  implements this interface.
* */
type MiniothHandler interface {
	Init(root User)
	Useradd(user User) (uid, pgroup int, err error) /* should return the uid as well*/
	Userdel(uid string) error
	Usermod(user User) error
	Userpatch(uid string, fields map[string]interface{}) error

	Groupadd(group Group) (gid int, err error) /* should return the gid inserted as well*/
	Groupdel(gid string) error
	Groupmod(group Group) error
	Grouppatch(gid string, fields map[string]interface{}) error

	Passwd(username, password string) error

	// VerifyEmail marks uid's email as verified. Reached only via a signed,
	// purpose-scoped token (see internal/auth's email verification token
	// functions) — not gated behind admin auth like Userpatch, since the
	// token itself is the credential.
	VerifyEmail(uid string) error

	// AssignGroup adds uid to gid's membership, without touching any other
	// group field — Grouppatch only ever updates a group's own columns
	// (name), it has no notion of membership, so promoting a user (e.g. to
	// the admin group, gid 0) needs its own operation.
	AssignGroup(uid string, gid int) error

	// TokenVersion returns uid's current token generation (0 if tokens
	// were never revoked). Every token minioth issues carries the
	// generation current at issue time, and is only accepted while that
	// still matches — see internal/auth's SetTokenVersionSource.
	TokenVersion(uid string) (int, error)
	// RevokeTokens bumps uid's token generation, invalidating every
	// access, refresh and password-reset token issued to them so far.
	// Backends also call it from Userdel, so a later user who happens to
	// be assigned the same uid can't inherit the deleted user's tokens.
	RevokeTokens(uid string) error

	Select(id string) []interface{}

	Authenticate(username, password string) (*User, error)

	Close()
}

/* "constructor"
* Use this function to create an instance of minioth. The caller picks and
* constructs the backend (DBHandler, PlainHandler, ...) and injects it here,
* since domain can't import store without creating an import cycle (store
* needs domain's User/Group/Password types). The caller also builds the
* root user (name + plaintext password, to be hashed by the handler on
* insert) so root's credentials are configurable rather than hardcoded. */
func NewMinioth(root User, handler MiniothHandler) Minioth {
	log.Print("Creating new minioth...")

	newM := Minioth{
		root:    root,
		handler: handler,
	}

	newM.handler.Init(root)

	return newM
}

/* attach handler methods to minioth.
*  just to avoid redundant dot calls
* */
func (m *Minioth) Useradd(user User) (int, int, error) {
	return m.handler.Useradd(user)
}

func (m *Minioth) Userdel(username string) error {
	return m.handler.Userdel(username)
}

func (m *Minioth) Usermod(user User) error {
	return m.handler.Usermod(user)
}

func (m *Minioth) Userpatch(uid string, fields map[string]interface{}) error {
	return m.handler.Userpatch(uid, fields)
}

func (m *Minioth) Groupadd(group Group) (int, error) {
	return m.handler.Groupadd(group)
}

func (m *Minioth) Groupdel(groupname string) error {
	return m.handler.Groupdel(groupname)
}

func (m *Minioth) Groupmod(group Group) error {
	return m.handler.Groupmod(group)
}

func (m *Minioth) Grouppatch(gid string, fields map[string]interface{}) error {
	return m.handler.Grouppatch(gid, fields)
}

func (m *Minioth) Passwd(username, password string) error {
	return m.handler.Passwd(username, password)
}

func (m *Minioth) VerifyEmail(uid string) error {
	return m.handler.VerifyEmail(uid)
}

func (m *Minioth) AssignGroup(uid string, gid int) error {
	return m.handler.AssignGroup(uid, gid)
}

func (m *Minioth) TokenVersion(uid string) (int, error) {
	return m.handler.TokenVersion(uid)
}

func (m *Minioth) RevokeTokens(uid string) error {
	return m.handler.RevokeTokens(uid)
}

func (m *Minioth) Select(id string) []interface{} {
	return m.handler.Select(id)
}

func (m *Minioth) Authenticate(username, password string) (*User, error) {
	return m.handler.Authenticate(username, password)
}

func (m *Minioth) Close() {
	m.handler.Close()
}

/* NOTE: irrelevant atm
* delete the 3 state files */
func (m *Minioth) Purge() {
	log.Print("Purging everything...")

	if _, err := os.Stat("data/plain"); err == nil {
		log.Print("data/plain dir exist")

		// Literal plain-backend paths (not store.MINIOTH_PASSWD etc.) — domain
		// can't import store without creating an import cycle.
		for _, f := range []string{"data/plain/mpasswd", "data/plain/mgroup", "data/plain/mshadow"} {
			if err := os.Remove(f); err != nil {
				log.Print(err)
			}
		}
		if err := os.Remove("data/plain"); err != nil {
			log.Print(err)
		}
	}

	if _, err := os.Stat("data/db"); err == nil {
		log.Print("data/db dir exists")

		// os.Remove doesn't glob ("data/*.db" was always a literal,
		// nonexistent filename) — this is what actually deletes the *.db
		// files it names.
		matches, err := filepath.Glob("data/*.db")
		if err != nil {
			log.Print(err)
		}
		for _, f := range matches {
			if err := os.Remove(f); err != nil {
				log.Print(err)
			}
		}

		if err := os.Remove("data/db"); err != nil {
			log.Print(err)
		}
	}
}

/* NOTE: irrelevant atm
* This function should sync the DB state and the Plain state. TODO:*/
func (m *Minioth) Sync() error {
	return nil
}

/* main user struct */
type User struct {
	Name          string   `json:"username" form:"username"`
	Info          string   `json:"info" form:"info"`
	Home          string   `json:"home" form:"home"`
	Shell         string   `json:"shell" form:"shell"`
	Email         string   `json:"email" form:"email"`
	EmailVerified bool     `json:"email_verified" form:"email_verified"`
	Password      Password `json:"password"`
	Groups        []Group  `json:"groups"`
	Uid           int      `json:"uid"`
	Pgroup        int      `json:"pgroup"`
}

func (u *User) PtrFields() []any {
	return []any{&u.Name, &u.Info, &u.Home, &u.Shell, &u.Uid, &u.Pgroup}
}

func (u *User) ToString() string {
	return fmt.Sprintf("%v, %v, %v, %v, %v, %v", u.Name, u.Info, u.Home, u.Shell, u.Uid, u.Pgroup)
}

/* main password struct */
type Password struct {
	Hashpass           string `json:"hashpass"`
	LastPasswordChange string `json:"lastPasswordChange"`
	MinPasswordAge     string `json:"minimumPasswordAge"`
	MaxPasswordAge     string `json:"maximumPasswordAge"`
	WarningPeriod      string `json:"warningPeriod"`
	InactivityPeriod   string `json:"inactivityPeriod"`
	ExpirationDate     string `json:"expirationDate"`
}

// MarshalJSON leaves Hashpass out of every JSON response. Password is
// embedded in User, which handlers return as-is (/v1/user/me,
// /v1/admin/users, ...), so without this the bcrypt hash went out in the
// response body. Unmarshaling is untouched: register/useradd still read
// the plaintext password from "hashpass" on the way in.
func (p Password) MarshalJSON() ([]byte, error) {
	type public struct {
		LastPasswordChange string `json:"lastPasswordChange"`
		MinPasswordAge     string `json:"minimumPasswordAge"`
		MaxPasswordAge     string `json:"maximumPasswordAge"`
		WarningPeriod      string `json:"warningPeriod"`
		InactivityPeriod   string `json:"inactivityPeriod"`
		ExpirationDate     string `json:"expirationDate"`
	}
	return json.Marshal(public{
		LastPasswordChange: p.LastPasswordChange,
		MinPasswordAge:     p.MinPasswordAge,
		MaxPasswordAge:     p.MaxPasswordAge,
		WarningPeriod:      p.WarningPeriod,
		InactivityPeriod:   p.InactivityPeriod,
		ExpirationDate:     p.ExpirationDate,
	})
}

func (p *Password) PtrFields() []any {
	return []any{&p.Hashpass, &p.LastPasswordChange, &p.MinPasswordAge, &p.MaxPasswordAge, &p.WarningPeriod, &p.InactivityPeriod, &p.ExpirationDate}
}

/* check password fields for allowed values, per the configurable password policy */
func (p *Password) ValidatePassword() error {
	n := len(p.Hashpass)

	if n == 0 {
		return errors.New("hashpass cannot be empty")
	}

	if n < PasswordMinLength {
		return fmt.Errorf("password length '%d' is too short: minimum required length is %d characters", n, PasswordMinLength)
	}

	if n > PasswordMaxLength {
		return fmt.Errorf("password length '%d' is too long: maximum allowed length is %d characters", n, PasswordMaxLength)
	}

	if PasswordRequireUpper && !upperRe.MatchString(p.Hashpass) {
		return errors.New("password must contain at least one uppercase letter")
	}

	if PasswordRequireLower && !lowerRe.MatchString(p.Hashpass) {
		return errors.New("password must contain at least one lowercase letter")
	}

	if PasswordRequireDigit && !digitRe.MatchString(p.Hashpass) {
		return errors.New("password must contain at least one digit")
	}

	if PasswordRequireSpecial && !specialRe.MatchString(p.Hashpass) {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

/* main group struct */
type Group struct {
	Name  string `json:"groupname" form:"groupname"`
	Users []User `json:"users" form:"users"`
	Gid   int    `json:"gid" form:"gid"`
}

func (g *Group) PtrFields() []any {
	return []any{&g.Name, &g.Gid}
}

func (g *Group) toString() string {
	return fmt.Sprintf("%v", g.Name)
}

func GroupsToString(groups []Group) string {
	var res []string

	for _, group := range groups {
		res = append(res, group.toString())
	}

	return strings.Join(res, ",")
}

func GidsToString(groups []Group) string {
	var res []string
	for _, group := range groups {
		res = append(res, strconv.Itoa(group.Gid))
	}
	return strings.Join(res, ",")
}

/* UTIL functions */
/* use bcrypt blowfish algo (and std lib) to hash a byte array */
func Hash(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, HASH_COST)
}

func HashWithCost(password []byte, cost int) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, cost)
}

/* check if a passowrd is correct */
func VerifyPass(hashedPass, password []byte) bool {
	if err := bcrypt.CompareHashAndPassword(hashedPass, password); err == nil {
		return true
	}
	return false
}
