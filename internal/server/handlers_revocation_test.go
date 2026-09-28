package server

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// loginTokens logs in and returns both tokens.
func (h *testHarness) loginTokens(t *testing.T, username, password string) (access, refresh string) {
	t.Helper()
	rec := h.do(t, http.MethodPost, "/v1/login", gin.H{"username": username, "password": password}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login(%q) = %d, body %s", username, rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	decode(t, rec, &resp)
	return resp.AccessToken, resp.RefreshToken
}

func (h *testHarness) refresh(t *testing.T, refreshToken string) int {
	t.Helper()
	return h.do(t, http.MethodPost, "/v1/token/refresh", gin.H{"refresh_token": refreshToken}, nil).Code
}

func TestLogoutRevokesAllTokens(t *testing.T) {
	h := newTestHarness(t)
	h.registerUser(t, "liam", "liampass123", "")
	access1, refresh1 := h.loginTokens(t, "liam", "liampass123")
	access2, _ := h.loginTokens(t, "liam", "liampass123") // a second "device"

	if code := h.refresh(t, refresh1); code != http.StatusOK {
		t.Fatalf("expected refresh to work before logout, got %d", code)
	}

	if rec := h.do(t, http.MethodPost, "/v1/logout", nil, bearer(access1)); rec.Code != http.StatusOK {
		t.Fatalf("logout = %d, body %s", rec.Code, rec.Body.String())
	}

	for name, tok := range map[string]string{"access1": access1, "access2": access2} {
		if rec := h.do(t, http.MethodGet, "/v1/user/me", nil, bearer(tok)); rec.Code == http.StatusOK {
			t.Errorf("%s still accepted by /user/me after logout", name)
		}
		if rec := h.do(t, http.MethodGet, "/v1/user/token", nil, bearer(tok)); rec.Code == http.StatusOK {
			t.Errorf("%s still accepted by /user/token after logout", name)
		}
	}
	if code := h.refresh(t, refresh1); code != http.StatusUnauthorized {
		t.Errorf("expected refresh token revoked by logout (401), got %d", code)
	}

	// Logging back in issues working tokens again — no same-second
	// cutoff edge case, since revocation is a generation counter.
	access3, refresh3 := h.loginTokens(t, "liam", "liampass123")
	if rec := h.do(t, http.MethodGet, "/v1/user/me", nil, bearer(access3)); rec.Code != http.StatusOK {
		t.Errorf("expected a fresh login to work after logout, got %d", rec.Code)
	}
	if code := h.refresh(t, refresh3); code != http.StatusOK {
		t.Errorf("expected a fresh refresh token to work after logout, got %d", code)
	}
}

func TestRevokedAdminTokenLosesAdminAccess(t *testing.T) {
	h := newTestHarness(t)
	root := h.rootToken(t)

	if rec := h.do(t, http.MethodPost, "/v1/logout", nil, bearer(root)); rec.Code != http.StatusOK {
		t.Fatalf("logout = %d", rec.Code)
	}
	if rec := h.do(t, http.MethodGet, "/v1/admin/users", nil, bearer(root)); rec.Code != http.StatusUnauthorized {
		t.Errorf("expected a revoked admin token to be rejected by AuthMiddleware, got %d", rec.Code)
	}
}

func TestAdminRevoke(t *testing.T) {
	h := newTestHarness(t)
	root := bearer(h.rootToken(t))
	uid := h.registerUser(t, "mia", "miapass1234", "")
	access, refresh := h.loginTokens(t, "mia", "miapass1234")

	// Non-admins can't revoke.
	if rec := h.do(t, http.MethodPost, "/v1/admin/revoke", gin.H{"uid": "0"}, bearer(access)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected non-admin revoke to be rejected, got %d", rec.Code)
	}

	if rec := h.do(t, http.MethodPost, "/v1/admin/revoke", gin.H{"uid": strconv.Itoa(uid)}, root); rec.Code != http.StatusOK {
		t.Fatalf("admin revoke = %d, body %s", rec.Code, rec.Body.String())
	}
	if rec := h.do(t, http.MethodGet, "/v1/user/me", nil, bearer(access)); rec.Code == http.StatusOK {
		t.Error("expected mia's access token to be revoked")
	}
	if code := h.refresh(t, refresh); code != http.StatusUnauthorized {
		t.Errorf("expected mia's refresh token to be revoked, got %d", code)
	}
	// Root's own token is unaffected.
	if rec := h.do(t, http.MethodGet, "/v1/admin/users", nil, root); rec.Code != http.StatusOK {
		t.Errorf("revoking mia affected root's token: %d", rec.Code)
	}

	if rec := h.do(t, http.MethodPost, "/v1/admin/revoke", gin.H{"uid": "999999"}, root); rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 revoking an unknown uid, got %d", rec.Code)
	}
}

func TestPasswordResetTokenIsSingleUse(t *testing.T) {
	h := newTestHarness(t)
	h.registerUser(t, "nina", "ninapass1234", "")
	access, _ := h.loginTokens(t, "nina", "ninapass1234")

	rec := h.do(t, http.MethodPost, "/v1/passwd/reset-request", gin.H{"username": "nina"}, nil)
	var resp struct {
		ResetToken string `json:"reset_token"`
	}
	decode(t, rec, &resp)

	reset := func(pw string) int {
		return h.do(t, http.MethodPost, "/v1/passwd/reset", gin.H{"reset_token": resp.ResetToken, "new_password": pw}, nil).Code
	}
	if code := reset("ninanewpass1"); code != http.StatusOK {
		t.Fatalf("first reset = %d", code)
	}
	if code := reset("ninanewpass2"); code != http.StatusUnauthorized {
		t.Errorf("expected a used reset token to be rejected, got %d", code)
	}
	if rec := h.do(t, http.MethodGet, "/v1/user/me", nil, bearer(access)); rec.Code == http.StatusOK {
		t.Error("expected the reset to revoke pre-existing access tokens")
	}
}

func TestDeletedUsersTokenDoesNotCarryOverToReusedUID(t *testing.T) {
	h := newTestHarness(t)
	root := bearer(h.rootToken(t))
	uid := h.registerUser(t, "olga", "olgapass1234", "")
	stale := h.loginUser(t, "olga", "olgapass1234")

	if rec := h.do(t, http.MethodDelete, "/v1/admin/userdel?uid="+strconv.Itoa(uid), nil, root); rec.Code != http.StatusOK {
		t.Fatalf("userdel = %d", rec.Code)
	}
	if newUID := h.registerUser(t, "pavel", "pavelpass123", ""); newUID != uid {
		t.Skipf("uid not reused (got %d, deleted %d) — nothing to check", newUID, uid)
	}

	if rec := h.do(t, http.MethodGet, "/v1/user/me", nil, bearer(stale)); rec.Code == http.StatusOK {
		t.Errorf("deleted user's token resolved to the new user holding the same uid: %s", rec.Body.String())
	}
}

func TestUpdateMe(t *testing.T) {
	h := newTestHarness(t)
	h.registerUser(t, "quinn", "quinnpass123", "quinn@example.com")
	token := h.loginUser(t, "quinn", "quinnpass123")

	// Verify the original email first, so we can see a change reset it.
	rec := h.do(t, http.MethodPost, "/v1/verify-email/request", nil, bearer(token))
	var vr struct {
		VerificationToken string `json:"verification_token"`
	}
	decode(t, rec, &vr)
	if rec := h.do(t, http.MethodGet, "/v1/verify-email?token="+vr.VerificationToken, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("verify-email = %d", rec.Code)
	}

	type profile struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Info          string `json:"info"`
		Shell         string `json:"shell"`
		Home          string `json:"home"`
	}

	// Info-only change leaves the verified email alone.
	rec = h.do(t, http.MethodPatch, "/v1/user/me", gin.H{"info": "hello", "shell": "/bin/zsh"}, bearer(token))
	if rec.Code != http.StatusOK {
		t.Fatalf("update me = %d, body %s", rec.Code, rec.Body.String())
	}
	var p profile
	decode(t, rec, &p)
	if p.Info != "hello" || p.Shell != "/bin/zsh" || !p.EmailVerified {
		t.Errorf("unexpected profile after info/shell update: %+v", p)
	}

	// Email change resets verification.
	rec = h.do(t, http.MethodPatch, "/v1/user/me", gin.H{"email": "quinn@new.example.com"}, bearer(token))
	if rec.Code != http.StatusOK {
		t.Fatalf("update email = %d, body %s", rec.Code, rec.Body.String())
	}
	p = profile{}
	decode(t, rec, &p)
	if p.Email != "quinn@new.example.com" || p.EmailVerified {
		t.Errorf("expected new unverified email, got %+v", p)
	}

	// home isn't self-service; it's silently not a field here.
	h.do(t, http.MethodPatch, "/v1/user/me", gin.H{"home": "/root", "info": "x"}, bearer(token))
	rec = h.do(t, http.MethodGet, "/v1/user/me", nil, bearer(token))
	p = profile{}
	decode(t, rec, &p)
	if p.Home == "/root" {
		t.Error("home should not be self-service editable")
	}

	for name, body := range map[string]gin.H{
		"colon":     {"info": "a:b"},
		"newline":   {"shell": "/bin/sh\nroot"},
		"bad email": {"email": "not-an-email"},
		"too long":  {"info": strings.Repeat("x", 101)},
		"empty":     {},
	} {
		if rec := h.do(t, http.MethodPatch, "/v1/user/me", body, bearer(token)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}

	if rec := h.do(t, http.MethodPatch, "/v1/user/me", gin.H{"info": "x"}, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without a token, got %d", rec.Code)
	}
}

func TestPasswordHashNotInResponses(t *testing.T) {
	h := newTestHarness(t)
	root := bearer(h.rootToken(t))
	uid := h.registerUser(t, "rita", "ritapass1234", "")
	token := h.loginUser(t, "rita", "ritapass1234")

	bodies := map[string]string{
		"/user/me":         h.do(t, http.MethodGet, "/v1/user/me", nil, bearer(token)).Body.String(),
		"PATCH /user/me":   h.do(t, http.MethodPatch, "/v1/user/me", gin.H{"info": "x"}, bearer(token)).Body.String(),
		"/admin/users":     h.do(t, http.MethodGet, "/v1/admin/users", nil, root).Body.String(),
		"/admin/users?uid": h.do(t, http.MethodGet, "/v1/admin/users?uid="+strconv.Itoa(uid), nil, root).Body.String(),
		"/admin/groups":    h.do(t, http.MethodGet, "/v1/admin/groups", nil, root).Body.String(),
	}
	for name, body := range bodies {
		if strings.Contains(body, "hashpass") || strings.Contains(body, "$2a$") {
			t.Errorf("%s leaks the password hash: %s", name, body)
		}
	}
}
