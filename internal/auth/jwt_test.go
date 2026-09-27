package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/kyri56xcaesar/minioth/internal/config"
)

func TestJWTRoundTripHS256(t *testing.T) {
	defer setJWTState(t, "HS256", []byte("test-secret"), []byte("test-refresh"))()

	token, err := GenerateAccessJWT("1000", "alice", "user", "1000", "1000")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	claims, err := ParseAccessToken(token)
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if claims.Username != "alice" || claims.UserID != "1000" {
		t.Errorf("unexpected claims: %+v", claims)
	}

	// HS256 is symmetric — the secret must never be published, so the JWKS
	// endpoint must advertise an empty key set for it.
	keySet := JWKS()
	keys, ok := keySet["keys"].([]any)
	if !ok || len(keys) != 0 {
		t.Errorf("expected an empty JWKS key set for HS256, got %v", keySet)
	}
}

func TestJWTRoundTripRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	defer saveJWTState(t)()

	InitJWTSigning(&config.EnvConfig{
		JWTSecretKey:         []byte("unused"),
		JWTRefreshKey:        []byte("unused-refresh"),
		JWTSigningAlg:        "RS256",
		JWTRSAPrivateKeyPath: keyPath,
	})

	token, err := GenerateAccessJWT("1000", "alice", "user", "1000", "1000")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	claims, err := ParseAccessToken(token)
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if claims.Username != "alice" {
		t.Errorf("unexpected claims: %+v", claims)
	}

	keySet := JWKS()
	keys, ok := keySet["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("expected exactly one published key for RS256, got %v", keySet)
	}
	jwk, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected jwk shape: %v", keys[0])
	}
	if jwk["kty"] != "RSA" || jwk["alg"] != "RS256" || jwk["n"] == "" || jwk["kid"] == "" {
		t.Errorf("unexpected jwk contents: %+v", jwk)
	}
}

// A token signed for one algorithm must not verify once the server is
// reconfigured for another — the alg-confusion guard in parseAccessToken
// (token.Method.Alg() != jwtSigningAlg).
func TestJWTRejectsAlgMismatch(t *testing.T) {
	restore := setJWTState(t, "HS256", []byte("test-secret"), []byte("test-refresh"))
	token, err := GenerateAccessJWT("1000", "alice", "user", "1000", "1000")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	restore()

	defer setJWTState(t, "RS256", nil, nil)()
	if _, err := ParseAccessToken(token); err == nil {
		t.Error("expected an HS256 token to be rejected once the server is configured for RS256")
	}
}

func saveJWTState(t *testing.T) func() {
	t.Helper()
	sk, rk, alg, priv, pub, kid := jwtSecretKey, jwtRefreshKey, jwtSigningAlg, rsaPrivateKey, rsaPublicKey, jwtKeyID
	return func() {
		jwtSecretKey, jwtRefreshKey, jwtSigningAlg, rsaPrivateKey, rsaPublicKey, jwtKeyID = sk, rk, alg, priv, pub, kid
	}
}

// setJWTState overrides the package-level signing state for the duration of
// a test and returns a restore func. A nil secret/refresh leaves that
// particular key untouched (used when the test only cares about alg).
func setJWTState(t *testing.T, alg string, secret, refresh []byte) func() {
	t.Helper()
	restore := saveJWTState(t)
	jwtSigningAlg = alg
	if secret != nil {
		jwtSecretKey = secret
	}
	if refresh != nil {
		jwtRefreshKey = refresh
	}
	rsaPrivateKey = nil
	rsaPublicKey = nil
	jwtKeyID = ""
	return restore
}
