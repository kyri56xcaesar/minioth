package auth

/* Everything JWT: claims, signing, parsing, and JWKS publication. Pulled out
* of minioth_server.go so the signing/verification logic lives in exactly
* one place instead of being re-derived at every call site.
*
* Access tokens are signed with whichever algorithm the admin configures
* (JWT_SIGNING_ALG=HS256 or RS256). Refresh tokens are always HS256 signed
* with jwtRefreshKey: they're opaque, internal-only tokens that are never
* handed to a third party or checked against the published JWKS, so there's
* no reason to involve RSA key management for them.
* */

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kyri56xcaesar/minioth/internal/config"
)

// JWT_VALIDITY_HOURS moved here from minioth_server.go — the only consumer
// is GenerateAccessJWT below.
const JWT_VALIDITY_HOURS = 1

var (
	jwtSecretKey  = []byte("default_placeholder_key")
	jwtRefreshKey = []byte("default_refresh_placeholder_key")
	jwtSigningAlg = "HS256"

	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
	jwtKeyID      string
)

/* JWT token signed claims.
* what information the jwt will contain.
* */
type CustomClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Groups   string `json:"groups"`
	GroupIDS string `json:"group_ids"`
	jwt.RegisteredClaims
}

// initJWTSigning wires up the module-level signing state from config. For
// RS256 it loads the RSA private key up front and fails fast (log.Fatalf)
// if that's missing or invalid — same fail-fast contract as a missing JWT
// secret, since a server that silently can't sign tokens is worse than one
// that refuses to start.
func InitJWTSigning(cfg *config.EnvConfig) {
	jwtSecretKey = cfg.JWTSecretKey
	jwtRefreshKey = cfg.JWTRefreshKey
	jwtSigningAlg = cfg.JWTSigningAlg

	if jwtSigningAlg != "RS256" {
		return
	}

	key, err := loadRSAPrivateKey(cfg.JWTRSAPrivateKeyPath)
	if err != nil {
		log.Fatalf("JWT_SIGNING_ALG=RS256 requires a valid JWT_RSA_PRIVATE_KEY_PATH: %v", err)
	}
	rsaPrivateKey = key
	rsaPublicKey = &key.PublicKey
	jwtKeyID = rsaKeyID(rsaPublicKey)
	log.Printf("loaded RSA signing key from %s, kid=%s", cfg.JWTRSAPrivateKeyPath, jwtKeyID)
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("no key path configured")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unsupported private key format: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}

// rsaKeyID derives a stable, non-secret key identifier from the public
// modulus, so JWKS consumers can tell rotated keys apart by "kid".
func rsaKeyID(pub *rsa.PublicKey) string {
	sum := sha256.Sum256(pub.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// jwks returns the current signing key(s) in JWK Set format (RFC 7517),
// derived live from whatever key is actually loaded. HS256 is symmetric —
// the secret must never be published — so an HS256-configured server
// advertises an empty key set; a JWKS is only ever meaningful for the
// asymmetric case.
func JWKS() map[string]any {
	if jwtSigningAlg != "RS256" || rsaPublicKey == nil {
		return map[string]any{"keys": []any{}}
	}
	return map[string]any{
		"keys": []any{
			map[string]any{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": jwtKeyID,
				"n":   base64.RawURLEncoding.EncodeToString(rsaPublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPublicKey.E)).Bytes()),
			},
		},
	}
}

// SigningAlg reports the currently configured access-token signing
// algorithm, for callers (e.g. the OIDC discovery document) that need to
// advertise it without reaching into auth's unexported signing state.
func SigningAlg() string {
	return jwtSigningAlg
}

func signingKeyFor(alg string) (interface{}, error) {
	switch alg {
	case "RS256":
		if rsaPrivateKey == nil {
			return nil, fmt.Errorf("RS256 configured but no private key loaded")
		}
		return rsaPrivateKey, nil
	case "HS256":
		return jwtSecretKey, nil
	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", alg)
	}
}

func GenerateAccessJWT(userID, username, groups, gids string) (string, error) {
	claims := CustomClaims{
		UserID:   userID,
		Username: username,
		Groups:   groups,
		GroupIDS: gids,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "minioth",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * time.Duration(JWT_VALIDITY_HOURS))),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(jwtSigningAlg), claims)
	if jwtSigningAlg == "RS256" {
		token.Header["kid"] = jwtKeyID
	}

	key, err := signingKeyFor(jwtSigningAlg)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func GenerateRefreshJWT(userID string) (string, error) {
	claims := CustomClaims{
		UserID: userID,
		Groups: "not-needed",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)), // Token expiration time (72 hours)
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtRefreshKey)
}

// parseAccessToken parses and validates a bearer token as an ACCESS token,
// signed with whichever algorithm the server is currently configured for
// (jwtSigningAlg). It rejects any token whose header claims a different
// algorithm than the one configured — including a refresh token, which
// must only ever work at /token/refresh (see parseRefreshToken).
func ParseAccessToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwtSigningAlg {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		if jwtSigningAlg == "RS256" {
			return rsaPublicKey, nil
		}
		return jwtSecretKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	return claims, nil
}

// parseRefreshToken parses and validates a bearer token as a REFRESH token:
// always HS256, always jwtRefreshKey, independent of the access-token
// signing algorithm.
func ParseRefreshToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtRefreshKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	return claims, nil
}

/* Purpose-scoped tokens: short-lived, single-use-by-convention JWTs for
* email verification and password reset. Like refresh tokens, these are
* internal-only (always HS256, signed with jwtRefreshKey, never checked
* against the published JWKS) — the difference is the Purpose claim, which
* ParsePurposeToken checks against the caller's expectation so a
* verification token can't be replayed as a reset token or vice versa.
* There's no persistent token storage: the JWT's own signature and
* expiry *are* the validity check, same tradeoff refresh tokens already
* make (see the README's refresh-token/revocation caveat — the same one
* applies here). */

const (
	PurposeVerifyEmail   = "verify_email"
	PurposePasswordReset = "password_reset"
)

type PurposeClaims struct {
	UserID  string `json:"user_id"`
	Purpose string `json:"purpose"`
	// Extra carries purpose-specific data — currently just the email being
	// verified, so ParsePurposeToken's caller can confirm it still matches
	// the user's current on-file address before marking it verified.
	Extra string `json:"extra,omitempty"`
	jwt.RegisteredClaims
}

func generatePurposeJWT(userID, purpose, extra string, validity time.Duration) (string, error) {
	claims := PurposeClaims{
		UserID:  userID,
		Purpose: purpose,
		Extra:   extra,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "minioth",
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(validity)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtRefreshKey)
}

func parsePurposeJWT(tokenString, expectedPurpose string) (*PurposeClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &PurposeClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtRefreshKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*PurposeClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}
	if claims.Purpose != expectedPurpose {
		return nil, fmt.Errorf("token purpose %q does not match expected %q", claims.Purpose, expectedPurpose)
	}

	return claims, nil
}

// GenerateEmailVerificationToken builds a 24-hour token for confirming
// userID's ownership of email — email is embedded so verification can
// double-check it against whatever's on file at confirm time.
func GenerateEmailVerificationToken(userID, email string) (string, error) {
	return generatePurposeJWT(userID, PurposeVerifyEmail, email, 24*time.Hour)
}

func ParseEmailVerificationToken(tokenString string) (*PurposeClaims, error) {
	return parsePurposeJWT(tokenString, PurposeVerifyEmail)
}

// GeneratePasswordResetToken builds a 1-hour token — shorter-lived than
// email verification, since a leaked reset token is directly usable to
// take over the account, not just confirm an email address.
func GeneratePasswordResetToken(userID string) (string, error) {
	return generatePurposeJWT(userID, PurposePasswordReset, "", time.Hour)
}

func ParsePasswordResetToken(tokenString string) (*PurposeClaims, error) {
	return parsePurposeJWT(tokenString, PurposePasswordReset)
}
