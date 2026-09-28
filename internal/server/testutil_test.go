package server

/* Shared harness for HTTP-layer tests: a real gin.Engine wired up exactly
* the way ServeHTTP wires one (same route registration, same middleware),
* dispatched via httptest instead of a real listening socket — so these
* tests exercise actual routing + CORS/auth middleware + JSON binding +
* handler + store code, not a mocked slice of it. Backed by PlainHandler
* (fastest to set up, no DB file) in a fresh temp directory per test. */

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kyri56xcaesar/minioth/internal/auth"
	"github.com/kyri56xcaesar/minioth/internal/config"
	"github.com/kyri56xcaesar/minioth/internal/domain"
	"github.com/kyri56xcaesar/minioth/internal/store"
)

// testRootUsername/testRootPassword are fixed (rather than left to the
// random-generation default) so admin-flow tests can log in as root
// without scraping it out of a log line.
const (
	testRootUsername = "root"
	testRootPassword = "root-test-password-123"
)

type testHarness struct {
	engine  *gin.Engine
	minioth *domain.Minioth
	cfg     *config.EnvConfig
}

// newTestHarness chdirs into a fresh temp dir (PlainHandler's paths are
// relative — see internal/store/plain.go), sets the env vars LoadConfig
// requires, and builds a full engine via the same registerXRoutes calls
// ServeHTTP uses. envOverrides (optional, at most one map) lets a test
// override specific vars — e.g. the rate-limit tests need a low
// RATE_LIMIT_RPS/BURST instead of the generous default below.
func newTestHarness(t *testing.T, envOverrides ...map[string]string) *testHarness {
	t.Helper()

	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) })

	// LoadConfig's required fields, plus a fast HashCost and a generous
	// rate limit so these tests aren't slow or flaky by default — tests
	// that specifically want to exercise the rate limiter override it.
	t.Setenv("JWT_SECRET_KEY", "test-jwt-secret-key")
	t.Setenv("JWT_REFRESH_KEY", "test-jwt-refresh-key")
	t.Setenv("SERVICE_SECRETS", "testsvc:testsvcsecret")
	t.Setenv("HASH_COST", "4")
	t.Setenv("GIN_MODE", "test")
	t.Setenv("ROOT_USERNAME", testRootUsername)
	t.Setenv("ROOT_PASSWORD", testRootPassword)
	t.Setenv("RATE_LIMIT_RPS", "1000")
	t.Setenv("RATE_LIMIT_BURST", "1000")
	for _, overrides := range envOverrides {
		for k, v := range overrides {
			t.Setenv(k, v)
		}
	}

	// The path doesn't need to exist — LoadConfig logs and falls back to
	// the env vars just set (see config.go: godotenv.Load's failure is
	// non-fatal), which is what actually drives this.
	cfg := Bootstrap("nonexistent-test.env")

	root := domain.User{Name: cfg.RootUsername, Password: domain.Password{Hashpass: cfg.RootPassword}}
	m := domain.NewMinioth(root, &store.PlainHandler{})
	auth.SetTokenVersionSource(m.TokenVersion)
	t.Cleanup(func() { auth.SetTokenVersionSource(nil) })

	gin.SetMode(cfg.GinMode) // matches NewMService — silences gin's debug route/warning dump
	engine := gin.New()
	engine.Use(auth.CORSMiddleware(cfg))

	apiV1 := engine.Group("/v1")
	registerAuthRoutes(apiV1, &m, cfg)

	admin := apiV1.Group("/admin")
	admin.Use(auth.AuthMiddleware("admin", cfg))
	registerAdminRoutes(admin, &m)

	srv := &MService{Minioth: &m, Engine: engine, Config: cfg}
	wellknown := apiV1.Group("/.well-known")
	registerWellKnownRoutes(wellknown, srv)

	return &testHarness{engine: engine, minioth: &m, cfg: cfg}
}

// do dispatches a request through the real engine (real routing, real
// middleware) and returns the recorded response. body, if non-nil, is
// JSON-marshaled; headers may be nil.
func (h *testHarness) do(t *testing.T, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
		reader = bytes.NewReader(b)
	}

	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	h.engine.ServeHTTP(rec, req)
	return rec
}

// decode unmarshals a recorded response body into v, failing the test on
// invalid JSON — every handler in this codebase responds with JSON, so a
// decode failure itself usually indicates a real bug worth surfacing
// loudly rather than a silently-empty result.
func decode(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("failed to decode response body %q: %v", rec.Body.String(), err)
	}
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// registerUser registers username/password (both required) plus an
// optional email, failing the test on anything but success, and returns
// the assigned uid.
func (h *testHarness) registerUser(t *testing.T, username, password, email string) int {
	t.Helper()
	rec := h.do(t, http.MethodPost, "/v1/register", gin.H{
		"user": gin.H{
			"username": username,
			"password": gin.H{"hashpass": password},
			"email":    email,
		},
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("register(%q) = %d, body %s", username, rec.Code, rec.Body.String())
	}
	var resp struct {
		Uid int `json:"uid"`
	}
	decode(t, rec, &resp)
	return resp.Uid
}

// loginUser logs in and returns the access token, failing the test on
// anything but success.
func (h *testHarness) loginUser(t *testing.T, username, password string) string {
	t.Helper()
	rec := h.do(t, http.MethodPost, "/v1/login", gin.H{
		"username": username,
		"password": password,
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login(%q) = %d, body %s", username, rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	decode(t, rec, &resp)
	if resp.AccessToken == "" {
		t.Fatalf("login(%q) returned no access_token: %s", username, rec.Body.String())
	}
	return resp.AccessToken
}

// rootToken logs in as the harness's seeded root user (admin group
// membership included — see internal/store's seedStandardGroups) and
// returns its access token, for tests exercising admin-gated routes.
func (h *testHarness) rootToken(t *testing.T) string {
	t.Helper()
	return h.loginUser(t, testRootUsername, testRootPassword)
}
