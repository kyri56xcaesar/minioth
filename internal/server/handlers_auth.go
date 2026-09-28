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

	version, err := h.Minioth.TokenVersion(strconv.Itoa(user.Uid))
	if err != nil {
		log.Printf("failed to look up token version: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
		return
	}

	token, strGroups, strGids, pgroup, err := issueAccessToken(*user, version)
	if err != nil {
		// A signing failure is this request's problem, not the whole
		// process's — it must not take the server down.
		log.Printf("failed generating jwt token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
		return
	}

	refreshToken, err := auth.GenerateRefreshJWT(strconv.Itoa(user.Uid), version)
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

	// Re-read the user: a refresh token only carries the uid, and the new
	// access token must reflect the user's current groups.
	found := h.Minioth.Select("users?uid=" + claims.UserID)
	if len(found) != 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}
	user, ok := found[0].(domain.User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error generating access_token"})
		return
	}
	// ParseRefreshToken already confirmed claims.Ver is still the user's
	// current token generation.
	newAccessToken, _, _, _, err := issueAccessToken(user, claims.Ver)
	if err != nil {
		log.Printf("error generating new access token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "error generating access_token",
		})
		return
	}

	newRefreshToken, err := auth.GenerateRefreshJWT(claims.UserID, claims.Ver)
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
	response["pgroup"] = claims.PGroup
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

// ChangePassword changes the caller's own password. Two credentials are
// required: a bearer access token (which user) and current_password
// (proof it's really them, so a leaked access token alone can't take over
// the account). This endpoint used to accept a bare {username, password}
// with no authentication at all — anyone could set anyone's password.
// Success revokes every token the user holds, the caller's included.
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	claims, ok := h.accessClaims(c)
	if !ok {
		return
	}

	var body struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "current_password and new_password are required"})
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

	if _, err := h.Minioth.Authenticate(user.Name, body.CurrentPassword); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		return
	}

	if err := h.Minioth.Passwd(user.Name, body.NewPassword); err != nil {
		log.Printf("failed to change password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to change password"})
		return
	}

	if err := h.Minioth.RevokeTokens(claims.UserID); err != nil {
		log.Printf("password changed but failed to revoke tokens for uid %s: %v", claims.UserID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password changed, but failed to revoke existing tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "password changed successfully; all existing tokens revoked, log in again"})
}

// Logout revokes every token the caller holds (access, refresh, pending
// password reset) — on every device, since revocation is per user, not
// per token. See auth.SetTokenVersionSource.
func (h *AuthHandler) Logout(c *gin.Context) {
	claims, ok := h.accessClaims(c)
	if !ok {
		return
	}

	if err := h.Minioth.RevokeTokens(claims.UserID); err != nil {
		log.Printf("failed to revoke tokens for uid %s: %v", claims.UserID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to log out"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "logged out; all tokens revoked"})
}

// UpdateMe lets a user edit their own profile — email, info and shell.
// Home, groups, uid etc. stay admin-only (PATCH /admin/userpatch).
// Omitted or empty fields are left unchanged. Changing the email resets
// email_verified, since the new address hasn't been proven yet.
func (h *AuthHandler) UpdateMe(c *gin.Context) {
	claims, ok := h.accessClaims(c)
	if !ok {
		return
	}

	var body struct {
		Email *string `json:"email"`
		Info  *string `json:"info"`
		Shell *string `json:"shell"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	user, ok := selectOneUser(h.Minioth, "users?uid="+claims.UserID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	fields := map[string]interface{}{}
	for name, v := range map[string]*string{"email": body.Email, "info": body.Info, "shell": body.Shell} {
		if v == nil || *v == "" {
			continue
		}
		// ':' and newlines would corrupt the plain backend's
		// colon-delimited, one-entry-per-line files.
		if strings.ContainsAny(*v, ":\r\n") {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("%s must not contain ':' or newlines", name)})
			return
		}
		fields[name] = *v
	}
	if body.Info != nil && len(*body.Info) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "info field is too long: maximum allowed length is 100 characters"})
		return
	}
	if body.Email != nil && *body.Email != "" && !strings.Contains(*body.Email, "@") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email address"})
		return
	}
	if len(fields) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nothing to update: provide email, info and/or shell"})
		return
	}
	if email, ok := fields["email"]; ok && email != user.Email {
		fields["email_verified"] = false
	}

	if err := h.Minioth.Userpatch(claims.UserID, fields); err != nil {
		log.Printf("failed to update profile for uid %s: %v", claims.UserID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update profile"})
		return
	}

	updated, ok := selectOneUser(h.Minioth, "users?uid="+claims.UserID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read back updated profile"})
		return
	}
	c.JSON(http.StatusOK, updated)
}

// accessClaims extracts and verifies the caller's bearer access token,
// writing the error response itself and returning ok=false on failure.
func (h *AuthHandler) accessClaims(c *gin.Context) (*auth.CustomClaims, bool) {
	tokenString, ok := auth.ExtractBearerToken(c)
	if !ok {
		return nil, false
	}
	claims, err := auth.ParseAccessToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "bad token"})
		c.Abort()
		return nil, false
	}
	return claims, true
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

	version, err := h.Minioth.TokenVersion(strconv.Itoa(user.Uid))
	if err != nil {
		log.Printf("failed to look up token version: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue reset token"})
		return
	}

	resetToken, err := auth.GeneratePasswordResetToken(strconv.Itoa(user.Uid), version)
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

	// Also what makes the reset token single-use: it carries the old
	// generation, so it's rejected from here on.
	if err := h.Minioth.RevokeTokens(claims.UserID); err != nil {
		log.Printf("password reset but failed to revoke tokens for uid %s: %v", claims.UserID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password reset, but failed to revoke existing tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "password reset successfully; all existing tokens revoked"})
}

// issueAccessToken signs an access token for user, returning it with the
// groups, group ids and primary group it encodes. version is the user's
// current token generation (see auth.SetTokenVersionSource). The primary group is the
// group named after the user (falling back to the stored pgroup).
func issueAccessToken(user domain.User, version int) (string, string, string, int, error) {
	strGroups := domain.GroupsToString(user.Groups)
	strGids := domain.GidsToString(user.Groups)
	pgroup := user.Pgroup
	for _, group := range user.Groups {
		if group.Name == user.Name {
			pgroup = group.Gid
		}
	}
	token, err := auth.GenerateAccessJWT(strconv.Itoa(user.Uid), user.Name, strGroups, strGids, strconv.Itoa(pgroup), version)

	return token, strGroups, strGids, pgroup, err
}
