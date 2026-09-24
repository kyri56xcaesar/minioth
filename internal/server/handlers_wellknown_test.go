package server

import (
	"net/http"
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
