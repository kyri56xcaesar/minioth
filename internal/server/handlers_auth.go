package server

/* Handler methods for the end-user facing auth flow: register, login, token
* refresh/introspection, and password change. registerAuthRoutes
* (routes_auth.go) only wires paths to these methods — the actual request
* handling lives here. */

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kyri56xcaesar/minioth/internal/auth"
	"github.com/kyri56xcaesar/minioth/internal/domain"
)

// AuthHandler holds the end-user auth routes' dependencies.
type AuthHandler struct {
	Minioth *domain.Minioth
}

func (h *AuthHandler) Register(c *gin.Context) {
	var uclaim RegisterClaim
	err := c.BindJSON(&uclaim)
	if err != nil {
		log.Printf("error binding request body to struct: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Verify user credentials
	err = uclaim.validateUser()
	if err != nil {
		log.Printf("failed to validate: %v", err)
		c.JSON(400, gin.H{
			"error": err.Error(),
		})
		return
	}
	// Check for uniquness [ NOTE: Now its done internally ]
	// Proceed with Registration
	uid, pgroup, err := h.Minioth.Useradd(uclaim.User)
	if err != nil {
		log.Print("failed to add user")
		if strings.Contains(strings.ToLower(err.Error()), "alr") {
			c.JSON(403, gin.H{"error": "already exists!"})
		} else {
			c.JSON(400, gin.H{
				"error": "failed to insert the user",
			})
		}
		return
	}
	// TODO: should insta "pseudo" login issue a token for registration.
	// can I redirect to login?
	c.JSON(200, gin.H{
		"message":   fmt.Sprintf("User %v PGroup %v Registration successful!. Log in.", uid, pgroup),
		"uid":       uid,
		"pgroup":    pgroup,
		"login_url": "/v1/login",
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
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

	user, err := h.Minioth.Authenticate(lclaim.Username, lclaim.Password)
	if err != nil {
		log.Printf("error: %v", err)
		if strings.Contains(err.Error(), "not found") {
			c.JSON(404, gin.H{"error": "user not found"})
		} else {
			c.JSON(400, gin.H{
				"error": "failed to authenticate",
			})
		}
		return
	}

	strGroups := domain.GroupsToString(user.Groups)
	strGids := domain.GidsToString(user.Groups)

	var pgroup int
	for _, group := range user.Groups {
		if group.Name == user.Name {
			pgroup = group.Gid
		}
	}
	token, err := auth.GenerateAccessJWT(strconv.Itoa(user.Uid), lclaim.Username, strGroups, strGids)
	if err != nil {
		// A signing failure is this request's problem, not the whole
		// process's — it must not take the server down.
		log.Printf("failed generating jwt token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
		return
	}

	refreshToken, err := auth.GenerateRefreshJWT(lclaim.Username)
	if err != nil {
		log.Printf("failed to generate refresh token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
		return
	}

	// for now return detailed information so that frontend is accomodated
	// and followup authorization is provided (ids needed)
	// NOTE: use Authorization header for now.
	c.JSON(200, gin.H{
		"username":      lclaim.Username,
		"user_id":       user.Uid,
		"groups":        strGroups,
		"group_ids":     strGids,
		"pgroup":        pgroup,
		"access_token":  token,
		"refresh_token": refreshToken,
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var requestBody struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.BindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "refresh_token required",
		})
		return
	}

	claims, err := auth.ParseRefreshToken(requestBody.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid refresh token",
		})
		return
	}

	newAccessToken, err := auth.GenerateAccessJWT(claims.UserID, claims.Username, claims.Groups, claims.GroupIDS)
	if err != nil {
		log.Printf("error generating new access token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "error generating access_token",
		})
		return
	}

	newRefreshToken, err := auth.GenerateRefreshJWT(claims.UserID)
	if err != nil {
		log.Printf("error generating new refresh token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "error generating refresh_token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
}

func (h *AuthHandler) TokenInfo(c *gin.Context) {
	tokenString, ok := auth.ExtractBearerToken(c)
	if !ok {
		return
	}

	// Access tokens only: a refresh token must not work here, it is only
	// valid at /token/refresh.
	claims, err := auth.ParseAccessToken(tokenString)
	if err != nil {
		log.Printf("invalid access token: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "bad token",
		})
		c.Abort()
		return
	}

	response := make(map[string]string)
	response["valid"] = "true"
	response["user_id"] = claims.UserID
	response["username"] = claims.Username
	response["groups"] = claims.Groups
	response["group_ids"] = claims.GroupIDS
	response["issued_at"] = claims.IssuedAt.String()
	response["expires_at"] = claims.ExpiresAt.String()

	c.JSON(http.StatusOK, gin.H{
		"info": response,
	})
}

func (h *AuthHandler) Me(c *gin.Context) {
	tokenString, ok := auth.ExtractBearerToken(c)
	if !ok {
		return
	}

	// Access tokens only: a refresh token must not work here, it is only
	// valid at /token/refresh.
	claims, err := auth.ParseAccessToken(tokenString)
	if err != nil {
		log.Printf("invalid access token: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "bad token",
		})
		c.Abort()
		return
	}

	user := h.Minioth.Select("users?uid=" + claims.UserID)

	if len(user) != 1 {
		c.JSON(http.StatusNotFound, gin.H{"status": "not found"})
		return
	} else {
		c.JSON(http.StatusOK, user[0])
	}
}

/* This endpoint should change a user password. It must "authenticate" the user. User can only change his password. */
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var lclaim LoginClaim
	err := c.BindJSON(&lclaim)
	if err != nil {
		log.Printf("error binding request body to struct: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "binding error"})
		return
	}

	pass := domain.Password{
		Hashpass: lclaim.Password,
	}
	// Verify user credentials
	if lclaim.Password == "" {
		c.JSON(400, gin.H{
			"error": "no password provided",
		})
		return
	} else if err := pass.ValidatePassword(); err != nil {
		c.JSON(400, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = h.Minioth.Passwd(lclaim.Username, lclaim.Password)
	if err != nil {
		log.Printf("failed to change password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to change password"})
		return
	}

	c.JSON(200, gin.H{"status": "password changed successfully"})
}

// selectOneUser runs a Select("users?...") query expected to match
// exactly one user, and reports whether it did — every handler below
// needs to go from "uid" or "username" to a full domain.User (for their
// current email, or to recover a username Passwd needs from a uid-only
// token claim).
func selectOneUser(minioth *domain.Minioth, query string) (domain.User, bool) {
	results := minioth.Select(query)
	if len(results) != 1 {
		return domain.User{}, false
	}
	user, ok := results[0].(domain.User)
	return user, ok
}

// RequestEmailVerification issues a signed, 24h verification token for
// the caller's own on-file email address. Simulated delivery: the token
// is logged and returned directly in the response instead of being
// emailed — see the README for why (this is a lightweight identity
// simulation tool, not a mail-sending service).
func (h *AuthHandler) RequestEmailVerification(c *gin.Context) {
	tokenString, ok := auth.ExtractBearerToken(c)
	if !ok {
		return
	}

	claims, err := auth.ParseAccessToken(tokenString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad token"})
		return
	}

	user, ok := selectOneUser(h.Minioth, "users?uid="+claims.UserID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if user.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no email on file"})
		return
	}

	verifyToken, err := auth.GenerateEmailVerificationToken(claims.UserID, user.Email)
	if err != nil {
		log.Printf("failed to generate email verification token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue verification token"})
		return
	}

	log.Printf("[EMAIL] verification requested for %s <%s>: token=%s", user.Name, user.Email, verifyToken)

	c.JSON(http.StatusOK, gin.H{
		"message":            "verification token issued (simulated email — see server log)",
		"verification_token": verifyToken,
	})
}

// VerifyEmail confirms an email-verification token issued by
// RequestEmailVerification, marking the user's email verified. Reached by
// the token itself, not admin auth — anyone holding a valid token proved
// they received it via the (simulated) email.
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	tokenString := c.Query("token")
	if tokenString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	claims, err := auth.ParseEmailVerificationToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired verification token"})
		return
	}

	// Confirm the token's embedded email still matches what's on file —
	// closes the (unlikely but cheap-to-close) gap where a user's email
	// changed after the token was issued but before it was used.
	user, ok := selectOneUser(h.Minioth, "users?uid="+claims.UserID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if user.Email != claims.Extra {
		c.JSON(http.StatusConflict, gin.H{"error": "email on file has changed since this token was issued"})
		return
	}

	if err := h.Minioth.VerifyEmail(claims.UserID); err != nil {
		log.Printf("failed to mark email verified: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "email verified"})
}

// RequestPasswordReset issues a signed, 1h reset token for the named
// user. No auth required — that's the point of password reset. Simulated
// delivery, same as email verification: logged and returned directly
// rather than emailed.
func (h *AuthHandler) RequestPasswordReset(c *gin.Context) {
	var body struct {
		Username string `json:"username" binding:"required"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username required"})
		return
	}

	user, ok := selectOneUser(h.Minioth, "users?username="+body.Username)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	resetToken, err := auth.GeneratePasswordResetToken(strconv.Itoa(user.Uid))
	if err != nil {
		log.Printf("failed to generate password reset token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue reset token"})
		return
	}

	log.Printf("[EMAIL] password reset requested for %s: token=%s", user.Name, resetToken)

	c.JSON(http.StatusOK, gin.H{
		"message":     "reset token issued (simulated email — see server log)",
		"reset_token": resetToken,
	})
}

// ResetPassword consumes a password-reset token to set a new password,
// without needing the old one — the token itself, proven only by
// RequestPasswordReset's (simulated) delivery, is the credential.
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var body struct {
		ResetToken  string `json:"reset_token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reset_token and new_password are required"})
		return
	}

	claims, err := auth.ParsePasswordResetToken(body.ResetToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired reset token"})
		return
	}

	if err := (&domain.Password{Hashpass: body.NewPassword}).ValidatePassword(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, ok := selectOneUser(h.Minioth, "users?uid="+claims.UserID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	if err := h.Minioth.Passwd(user.Name, body.NewPassword); err != nil {
		log.Printf("failed to reset password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reset password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "password reset successfully"})
}
