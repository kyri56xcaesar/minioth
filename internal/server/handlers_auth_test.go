package server

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRegisterAndLogin(t *testing.T) {
	h := newTestHarness(t)

	rec := h.do(t, http.MethodPost, "/v1/register", gin.H{
		"user": gin.H{"username": "alice", "password": gin.H{"hashpass": "alicepass1"}},
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("register = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = h.do(t, http.MethodPost, "/v1/login", gin.H{"username": "alice", "password": "alicepass1"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Username     string `json:"username"`
	}
	decode(t, rec, &resp)
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Errorf("expected both tokens issued, got access=%q refresh=%q", resp.AccessToken, resp.RefreshToken)
	}
	if resp.Username != "alice" {
		t.Errorf("expected username echoed back, got %q", resp.Username)
	}
}

func TestRegisterDuplicateUsername(t *testing.T) {
	h := newTestHarness(t)
	h.registerUser(t, "bob", "bobpass123", "")

	rec := h.do(t, http.MethodPost, "/v1/register", gin.H{
		"user": gin.H{"username": "bob", "password": gin.H{"hashpass": "different1"}},
	}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on duplicate registration, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRegisterOffLimitsUsername(t *testing.T) {
	h := newTestHarness(t)

	rec := h.do(t, http.MethodPost, "/v1/register", gin.H{
		"user": gin.H{"username": "root", "password": gin.H{"hashpass": "whatever12"}},
	}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 registering an off-limits username, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRegisterWeakPasswordRejected(t *testing.T) {
	h := newTestHarness(t)

	rec := h.do(t, http.MethodPost, "/v1/register", gin.H{
		"user": gin.H{"username": "carol", "password": gin.H{"hashpass": "short"}},
	}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a too-short password, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoginWrongPassword(t *testing.T) {
	h := newTestHarness(t)
	h.registerUser(t, "dave", "davepass123", "")

	rec := h.do(t, http.MethodPost, "/v1/login", gin.H{"username": "dave", "password": "wrong-password"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong password, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoginUnknownUser(t *testing.T) {
	h := newTestHarness(t)

	rec := h.do(t, http.MethodPost, "/v1/login", gin.H{"username": "ghost", "password": "whatever12"}, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown user, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenRefresh(t *testing.T) {
	h := newTestHarness(t)
	h.registerUser(t, "erin", "erinpass123", "")

	rec := h.do(t, http.MethodPost, "/v1/login", gin.H{"username": "erin", "password": "erinpass123"}, nil)
	var login struct {
		RefreshToken string `json:"refresh_token"`
	}
	decode(t, rec, &login)

	rec = h.do(t, http.MethodPost, "/v1/token/refresh", gin.H{"refresh_token": login.RefreshToken}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh = %d, body %s", rec.Code, rec.Body.String())
	}
	var refreshed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	decode(t, rec, &refreshed)
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Errorf("expected a new access/refresh pair, got access=%q refresh=%q", refreshed.AccessToken, refreshed.RefreshToken)
	}

	// A refresh token must not authenticate its own endpoint — only the
	// dedicated /token/refresh path.
	rec = h.do(t, http.MethodPost, "/v1/token/refresh", gin.H{"refresh_token": "not-a-real-token"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for a bogus refresh token, got %d", rec.Code)
	}
}

func TestUserTokenIntrospection(t *testing.T) {
	h := newTestHarness(t)
	h.registerUser(t, "frank", "frankpass123", "")
	token := h.loginUser(t, "frank", "frankpass123")

	rec := h.do(t, http.MethodGet, "/v1/user/token", nil, bearer(token))
	if rec.Code != http.StatusOK {
		t.Fatalf("token introspection = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = h.do(t, http.MethodGet, "/v1/user/token", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with no Authorization header, got %d", rec.Code)
	}
}

func TestUserMe(t *testing.T) {
	h := newTestHarness(t)
	h.registerUser(t, "grace", "gracepass123", "grace@example.com")
	token := h.loginUser(t, "grace", "gracepass123")

	rec := h.do(t, http.MethodGet, "/v1/user/me", nil, bearer(token))
	if rec.Code != http.StatusOK {
		t.Fatalf("/user/me = %d, body %s", rec.Code, rec.Body.String())
	}
	var user struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	decode(t, rec, &user)
	if user.Username != "grace" || user.Email != "grace@example.com" {
		t.Errorf("unexpected /user/me body: %+v", user)
	}
}

func TestChangePassword(t *testing.T) {
	h := newTestHarness(t)
	h.registerUser(t, "hank", "hankpass123", "")

	rec := h.do(t, http.MethodPost, "/v1/passwd", gin.H{"username": "hank", "password": "hanknewpass456"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("passwd change = %d, body %s", rec.Code, rec.Body.String())
	}

	// New password works, old one no longer does.
	if rec := h.do(t, http.MethodPost, "/v1/login", gin.H{"username": "hank", "password": "hanknewpass456"}, nil); rec.Code != http.StatusOK {
		t.Errorf("expected login with the new password to succeed, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := h.do(t, http.MethodPost, "/v1/login", gin.H{"username": "hank", "password": "hankpass123"}, nil); rec.Code == http.StatusOK {
		t.Error("expected login with the old password to fail")
	}
}

func TestEmailVerificationFlow(t *testing.T) {
	h := newTestHarness(t)
	h.registerUser(t, "ivy", "ivypass123", "ivy@example.com")
	token := h.loginUser(t, "ivy", "ivypass123")

	rec := h.do(t, http.MethodPost, "/v1/verify-email/request", nil, bearer(token))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-email/request = %d, body %s", rec.Code, rec.Body.String())
	}
	var reqResp struct {
		VerificationToken string `json:"verification_token"`
	}
	decode(t, rec, &reqResp)
	if reqResp.VerificationToken == "" {
		t.Fatal("expected a non-empty verification_token")
	}

	rec = h.do(t, http.MethodGet, "/v1/verify-email?token="+reqResp.VerificationToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-email confirm = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = h.do(t, http.MethodGet, "/v1/user/me", nil, bearer(token))
	var user struct {
		EmailVerified bool `json:"email_verified"`
	}
	decode(t, rec, &user)
	if !user.EmailVerified {
		t.Error("expected email_verified to be true after confirming")
	}

	// Reusing an unrelated token type (an access token) as a verification
	// token must not work — purpose-scoping check.
	rec = h.do(t, http.MethodGet, "/v1/verify-email?token="+token, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 using an access token as a verification token, got %d", rec.Code)
	}
}

func TestEmailVerificationRequestWithNoEmailOnFile(t *testing.T) {
	h := newTestHarness(t)
	h.registerUser(t, "jack", "jackpass123", "") // no email
	token := h.loginUser(t, "jack", "jackpass123")

	rec := h.do(t, http.MethodPost, "/v1/verify-email/request", nil, bearer(token))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 requesting verification with no email on file, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPasswordResetFlow(t *testing.T) {
	h := newTestHarness(t)
	h.registerUser(t, "kate", "kateoldpass1", "")

	rec := h.do(t, http.MethodPost, "/v1/passwd/reset-request", gin.H{"username": "kate"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset-request = %d, body %s", rec.Code, rec.Body.String())
	}
	var reqResp struct {
		ResetToken string `json:"reset_token"`
	}
	decode(t, rec, &reqResp)
	if reqResp.ResetToken == "" {
		t.Fatal("expected a non-empty reset_token")
	}

	rec = h.do(t, http.MethodPost, "/v1/passwd/reset", gin.H{
		"reset_token": reqResp.ResetToken, "new_password": "katebrandnewpass1",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset = %d, body %s", rec.Code, rec.Body.String())
	}

	if rec := h.do(t, http.MethodPost, "/v1/login", gin.H{"username": "kate", "password": "katebrandnewpass1"}, nil); rec.Code != http.StatusOK {
		t.Errorf("expected login with the reset password to succeed, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := h.do(t, http.MethodPost, "/v1/login", gin.H{"username": "kate", "password": "kateoldpass1"}, nil); rec.Code == http.StatusOK {
		t.Error("expected login with the pre-reset password to fail")
	}

	// The reset token should not be reusable for anything requiring a
	// different purpose (defense covered structurally by ParsePurposeToken
	// — spot check via the verify-email endpoint).
	rec = h.do(t, http.MethodGet, "/v1/verify-email?token="+reqResp.ResetToken, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 using a password-reset token as an email-verification token, got %d", rec.Code)
	}
}

func TestPasswordResetUnknownUser(t *testing.T) {
	h := newTestHarness(t)

	rec := h.do(t, http.MethodPost, "/v1/passwd/reset-request", gin.H{"username": "nobody"}, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 requesting a reset for an unknown user, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPasswordResetInvalidToken(t *testing.T) {
	h := newTestHarness(t)

	rec := h.do(t, http.MethodPost, "/v1/passwd/reset", gin.H{
		"reset_token": "not-a-real-token", "new_password": "whatever12",
	}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a bogus reset token, got %d: %s", rec.Code, rec.Body.String())
	}
}
