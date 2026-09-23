package server

/* Handler methods for the admin-only user/group CRUD plus a couple of
* operational utilities (password verification, raw hasher).
* registerAdminRoutes (routes_admin.go) only wires paths to these methods —
* the actual request handling lives here. Everything under here sits
* behind AuthMiddleware("admin", ...) — see internal/auth/middleware.go. */

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kyri56xcaesar/minioth/internal/domain"
)

// AdminHandler holds the admin routes' dependencies.
type AdminHandler struct {
	Minioth *domain.Minioth
}

// just a login with no token issueing
func (h *AdminHandler) VerifyPassword(c *gin.Context) {
	var lclaim LoginClaim
	err := c.BindJSON(&lclaim)
	if err != nil {
		log.Printf("error binding request body to struct: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "binding error"})
		return
	}

	// Verify user credentials
	err = lclaim.validateClaim()
	if err != nil {
		log.Printf("failed to validate: %v", err)
		c.JSON(400, gin.H{
			"error": err.Error(),
		})
		return
	}

	_, err = h.Minioth.Authenticate(lclaim.Username, lclaim.Password)
	if err != nil {
		log.Printf("error: %v", err)
		audit(c, "verify-password", lclaim.Username, "failure: "+err.Error())
		if strings.Contains(err.Error(), "not found") {
			c.JSON(404, gin.H{"error": "user not found"})
		} else {
			c.JSON(400, gin.H{
				"error": "invalid",
			})
		}
		return
	}
	audit(c, "verify-password", lclaim.Username, "success")
	c.JSON(http.StatusOK, gin.H{"status": "valid"})
}

func (h *AdminHandler) Hasher(c *gin.Context) {
	var b struct {
		HashAlg  string `json:"hashalg"`
		HashText string `json:"hash"`
		Text     string `json:"text"`
		HashCost int    `json:"hashcost"`
	}
	err := c.BindJSON(&b)
	if err != nil {
		log.Printf("error binding request body to struct: %v", err)
		c.JSON(400, gin.H{"error": "binding"})
		return
	}

	hashed, err := domain.HashWithCost([]byte(b.Text), b.HashCost)
	if err != nil {
		log.Printf("error hasing the text: %v", err)
		c.JSON(500, gin.H{"error": "hashing"})
		return
	}

	if b.HashText == "" {
		c.JSON(200, gin.H{"result": string(hashed)})
	} else {
		c.JSON(200, gin.H{"result": strconv.FormatBool(domain.VerifyPass([]byte(b.HashText), []byte(b.Text)))})
	}
}

// AuditLogs: every privileged admin action is logged as a structured
// "[AUDIT] actor=... action=... target=... result=..." line (see
// audit.go) — grep the server's stdout for "[AUDIT]". There's no
// queryable store behind this route yet (see Known weaknesses for why:
// the PlainHandler backend has no query surface, so persisting audit
// events only for -backend=db would make the two backends behave
// asymmetrically), so it stays informational rather than returning 200
// with an empty body.
func (h *AdminHandler) AuditLogs(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not queryable via the API yet — audit events are logged to stdout, grep for \"[AUDIT]\""})
}

func (h *AdminHandler) ListUsers(c *gin.Context) {
	users := h.Minioth.Select("users?uid=" + c.Request.URL.Query().Get("uid"))

	c.JSON(http.StatusOK, gin.H{
		"content": users,
	})
}

func (h *AdminHandler) ListGroups(c *gin.Context) {
	groups := h.Minioth.Select("groups")

	c.JSON(http.StatusOK, gin.H{
		"content": groups,
	})
}

/* same as register but dont verify content */
func (h *AdminHandler) UserAdd(c *gin.Context) {
	var uclaim RegisterClaim
	err := c.BindJSON(&uclaim)
	if err != nil {
		log.Printf("error binding request body to struct: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	uid, pgroup, err := h.Minioth.Useradd(uclaim.User)
	if err != nil {
		log.Print("failed to add user")
		audit(c, "useradd", uclaim.User.Name, "failure: "+err.Error())
		if strings.Contains(strings.ToLower(err.Error()), "alr") {
			c.JSON(403, gin.H{"error": "already exists!"})
		} else {
			c.JSON(400, gin.H{
				"error": "failed to insert the user",
			})
		}
		return
	}

	audit(c, "useradd", uclaim.User.Name, fmt.Sprintf("success: uid=%d", uid))
	c.JSON(200, gin.H{
		"message":   fmt.Sprintf("User %v added.", uid),
		"uid":       uid,
		"pgroup":    pgroup,
		"login_url": "sure",
	})
}

func (h *AdminHandler) UserDel(c *gin.Context) {
	uid := c.Query("uid")
	if uid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "uid is required"})
		return
	}

	err := h.Minioth.Userdel(uid)
	if err != nil {
		audit(c, "userdel", uid, "failure: "+err.Error())
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		} else if strings.Contains(err.Error(), "root") {
			c.JSON(400, gin.H{"error": "really bro?"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user"})
		}

		return
	}

	audit(c, "userdel", uid, "success")
	c.JSON(http.StatusOK, gin.H{"message": "user deleted successfully"})
}

func (h *AdminHandler) UserPatch(c *gin.Context) {
	var updateFields map[string]interface{}
	if err := c.ShouldBindJSON(&updateFields); err != nil {
		log.Printf("failed to bind req body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	uidValue, ok := updateFields["uid"]
	if !ok {
		log.Printf("uid is not ok: %v", uidValue)
		c.JSON(http.StatusBadRequest, gin.H{"error": "uid is required"})
		return
	}
	var uid string
	switch v := uidValue.(type) {
	case string:
		uid = v
	case float64:
		uid = fmt.Sprintf("%.0f", v)
	case int:
		uid = strconv.Itoa(v)
	default:
		log.Printf("uid type not supported: %T", v)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid uid format"})
		return
	}

	switch uid {
	case "":
		log.Print("empty uid")

	case "0":
		log.Print("sm1 is trying to change the root..")
		c.JSON(400, gin.H{"error": "not allowed"})
		return
	}

	err := h.Minioth.Userpatch(uid, updateFields)
	if err != nil {
		log.Printf("failed to patch user: %v", err)
		audit(c, "userpatch", uid, "failure: "+err.Error())
		if err.Error() == "no inputs" {
			c.JSON(404, gin.H{"error": "bad request"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}

	audit(c, "userpatch", uid, "success")
	c.JSON(http.StatusOK, gin.H{"message": "user patched successfully"})
}

func (h *AdminHandler) UserMod(c *gin.Context) {
	var ruser RegisterClaim
	if err := c.ShouldBindJSON(&ruser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	log.Printf("user %+v", ruser)

	err := ruser.validateUser()
	if err != nil {
		log.Printf("invalid user, cannot update: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad input format"})
		return
	}

	err = h.Minioth.Usermod(ruser.User)
	if err != nil {
		audit(c, "usermod", ruser.User.Name, "failure: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}

	audit(c, "usermod", ruser.User.Name, "success")
	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

func (h *AdminHandler) GroupAdd(c *gin.Context) {
	var group domain.Group
	if err := c.ShouldBindJSON(&group); err != nil {
		log.Printf("Invalid group data: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group data"})
		return
	}

	if _, err := h.Minioth.Groupadd(group); err != nil {
		log.Printf("Failed to add group: %v", err)
		audit(c, "groupadd", group.Name, "failure: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add group"})
		return
	}

	audit(c, "groupadd", group.Name, "success")
	c.JSON(http.StatusCreated, gin.H{"message": "Group added successfully"})
}

func (h *AdminHandler) GroupPatch(c *gin.Context) {
	var payload struct {
		Fields map[string]interface{} `json:"fields" binding:"required"`
		Gid    string                 `json:"gid" binding:"required"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		log.Printf("Invalid patch payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid patch payload"})
		return
	}

	if err := h.Minioth.Grouppatch(payload.Gid, payload.Fields); err != nil {
		log.Printf("Failed to patch group: %v", err)
		audit(c, "grouppatch", payload.Gid, "failure: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to patch group"})
		return
	}

	audit(c, "grouppatch", payload.Gid, "success")
	c.JSON(http.StatusOK, gin.H{"message": "Group patched successfully"})
}

func (h *AdminHandler) GroupMod(c *gin.Context) {
	var group domain.Group
	if err := c.ShouldBindJSON(&group); err != nil {
		log.Printf("Invalid group data: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group data"})
		return
	}

	if err := h.Minioth.Groupmod(group); err != nil {
		log.Printf("Failed to modify group: %v", err)
		audit(c, "groupmod", group.Name, "failure: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to modify group"})
		return
	}

	audit(c, "groupmod", group.Name, "success")
	c.JSON(http.StatusOK, gin.H{"message": "Group modified successfully"})
}

func (h *AdminHandler) GroupDel(c *gin.Context) {
	gid := c.Query("gid")
	if gid == "" {
		log.Print("gid is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "gid is required"})
		return
	}

	if err := h.Minioth.Groupdel(gid); err != nil {
		log.Printf("Failed to delete group: %v", err)
		audit(c, "groupdel", gid, "failure: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete group"})
		return
	}

	audit(c, "groupdel", gid, "success")
	c.JSON(http.StatusOK, gin.H{"message": "Group deleted successfully"})
}

// Promote adds a user to a group — gid defaults to 0 (the "admin" group)
// when omitted, so an admin can grant another user admin privileges: "an
// admin should be able to create admins" without the create-then-mutate
// two-step /admin/useradd would need if group membership were only
// settable at creation time. Any gid works, not just 0 — this is the
// general-purpose "add uid to gid" operation Grouppatch doesn't provide
// (see AssignGroup in internal/domain).
func (h *AdminHandler) Promote(c *gin.Context) {
	var body struct {
		Uid string `json:"uid" binding:"required"`
		Gid int    `json:"gid"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "uid is required"})
		return
	}

	if err := h.Minioth.AssignGroup(body.Uid, body.Gid); err != nil {
		log.Printf("failed to assign group: %v", err)
		audit(c, "promote", body.Uid, fmt.Sprintf("failure: gid=%d err=%v", body.Gid, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assign group"})
		return
	}

	audit(c, "promote", body.Uid, fmt.Sprintf("success: gid=%d", body.Gid))
	c.JSON(http.StatusOK, gin.H{"message": "user promoted successfully"})
}
