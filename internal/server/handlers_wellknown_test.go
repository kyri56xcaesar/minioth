package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiveness(t *testing.T) {
	h := newTestHarness(t)

	rec := h.do(t, http.MethodGet, "/v1/.well-known/minioth", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("liveness = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Status string `json:"status"`
	}
	decode(t, rec, &resp)
	if resp.Status != "alive" {
		t.Errorf("expected status=alive, got %q", resp.Status)
	}
}

func TestOpenIDConfiguration(t *testing.T) {
	h := newTestHarness(t)

	rec := h.do(t, http.MethodGet, "/v1/.well-known/openid-configuration", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("openid-configuration = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Issuer                           string   `json:"issuer"`
		JWKSURI                          string   `json:"jwks_uri"`
		TokenEndpoint                    string   `json:"token_endpoint"`
		UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
		IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	}
	decode(t, rec, &resp)
	if resp.Issuer == "" || resp.JWKSURI == "" || resp.TokenEndpoint == "" || resp.UserinfoEndpoint == "" {
		t.Errorf("expected every discovery field populated, got %+v", resp)
	}
	if len(resp.IDTokenSigningAlgValuesSupported) != 1 || resp.IDTokenSigningAlgValuesSupported[0] != "HS256" {
		t.Errorf("expected [\"HS256\"] (the harness's default alg), got %v", resp.IDTokenSigningAlgValuesSupported)
	}
}

func TestJWKSEmptyForHS256(t *testing.T) {
	h := newTestHarness(t)

	rec := h.do(t, http.MethodGet, "/v1/.well-known/jwks.json", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("jwks.json = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Keys []any `json:"keys"`
	}
	decode(t, rec, &resp)
	// HS256 is symmetric — the secret must never be published, so the
	// live JWKS must advertise an empty key set for it (see internal/auth).
	if len(resp.Keys) != 0 {
		t.Errorf("expected an empty key set for HS256, got %d keys", len(resp.Keys))
	}
}

// Readiness reflects the store; liveness stays up regardless.
func TestReadiness(t *testing.T) {
	h := newTestHarness(t)
	if rec := h.do(t, http.MethodGet, "/v1/.well-known/ready", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("ready = %d, body %s", rec.Code, rec.Body.String())
	}

	// the harness runs the plain store in a temp working directory
	if err := os.Remove(filepath.Join("data", "plain", "mpasswd")); err != nil {
		t.Fatal(err)
	}
	rec := h.do(t, http.MethodGet, "/v1/.well-known/ready", nil, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("ready without mpasswd = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "mpasswd") {
		t.Errorf("the reason (with its path) leaked: %s", rec.Body.String())
	}
	if rec := h.do(t, http.MethodGet, "/v1/.well-known/minioth", nil, nil); rec.Code != http.StatusOK {
		t.Errorf("liveness = %d, want 200 while not ready", rec.Code)
	}
}
