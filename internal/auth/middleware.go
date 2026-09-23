package auth

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/kyri56xcaesar/minioth/internal/config"
)

/* Applies the configured CORS policy (ALLOWED_ORIGINS / ALLOWED_HEADERS /
* ALLOWED_METHODS). With no origins configured, cross-origin requests are
* simply not granted access (browsers enforce same-origin by default; this
* middleware only ever widens that, never narrows it). */
func CORSMiddleware(cfg *config.EnvConfig) gin.HandlerFunc {
	allowedHeaders := strings.Join(cfg.AllowedHeaders, ", ")
	allowedMethods := strings.Join(cfg.AllowedMethods, ", ")

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && originAllowed(origin, cfg.AllowedOrigins) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			if allowedHeaders != "" {
				c.Header("Access-Control-Allow-Headers", allowedHeaders)
			}
			if allowedMethods != "" {
				c.Header("Access-Control-Allow-Methods", allowedMethods)
			}
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == "*" || a == origin {
			return true
		}
	}
	return false
}

// extractBearerToken pulls the bearer token out of the Authorization header,
// writing the appropriate 401 response and returning ok=false on any
// failure. Every route that needs a bearer token shares this one code path
// instead of re-deriving the same three checks.
func ExtractBearerToken(c *gin.Context) (string, bool) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
		c.Abort()
		return "", false
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "must contain Bearer token"})
		c.Abort()
		return "", false
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token is required"})
		c.Abort()
		return "", false
	}

	return tokenString, true
}

/* For this service, authorization is required only for admin role.
*
* Two ways in:
*  1. a Bearer access token whose `groups` claim contains `role` exactly.
*  2. an X-Service-Secret header naming a configured service identity (see
*     matchServiceSecret) — for trusted inter-service calls that have no
*     end-user token to present. A wrong or unknown secret is rejected with
*     401 rather than silently falling through, and never falls back to
*     also trying the Bearer path.
 */
func AuthMiddleware(role string, cfg *config.EnvConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if secretHeader := c.GetHeader("X-Service-Secret"); secretHeader != "" {
			svc, ok := matchServiceSecret(cfg.ServiceSecrets, secretHeader)
			if !ok {
				log.Print("service secret invalid. access not granted")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid service secret"})
				c.Abort()
				return
			}
			log.Printf("service %q authenticated via X-Service-Secret. access granted.", svc)
			c.Set("service", svc)
			c.Next()
			return
		}

		tokenString, ok := ExtractBearerToken(c)
		if !ok {
			return
		}

		// Access tokens only: a refresh token must not grant admin access.
		claims, err := ParseAccessToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if !hasGroup(claims.Groups, role) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid user",
			})
			c.Abort()
			return
		}
		c.Set("username", claims.UserID)
		c.Set("groups", claims.Groups)

		c.Next()
	}
}

// matchServiceSecret checks a presented secret against every configured
// service identity in constant time and reports which service, if any, it
// belongs to.
//
// This replaces a single shared static secret compared with `==`: that
// design had two problems beyond the non-constant-time comparison — every
// caller shared one value (leaking or rotating it affects every service at
// once, and a request can't be attributed to whoever sent it), and it
// bypassed role checks entirely regardless of which service used it. Named
// per-service credentials fix attribution and independent revocation
// without changing the trust model (still a shared-secret bypass of
// AuthMiddleware, just a scoped and accountable one).
//
// For a stronger guarantee than a shared secret can ever give — proof of
// the calling service's identity, not just knowledge of a value that could
// have leaked — the next step up is mutual TLS (each service authenticates
// with its own client certificate) or short-lived service JWTs that minioth
// itself issues per-service (audience "internal", narrow scope, minutes not
// forever), so a compromised credential expires fast instead of working
// until someone notices and rotates it.
func matchServiceSecret(secrets map[string][]byte, presented string) (string, bool) {
	presentedBytes := []byte(presented)
	matched := ""
	found := false
	// Deliberately don't return on the first match: walking every entry
	// keeps the check's timing independent of which (or whether any)
	// service matched, and of map iteration order.
	for svc, secret := range secrets {
		if subtle.ConstantTimeCompare(secret, presentedBytes) == 1 {
			matched = svc
			found = true
		}
	}
	return matched, found
}

/* checks for an exact group name match within a comma-separated groups claim.
* deliberately not a substring check: "admin" must not match "administrator" or "notadmin". */
func hasGroup(groupsClaim, group string) bool {
	for _, g := range strings.Split(groupsClaim, ",") {
		if strings.TrimSpace(g) == group {
			return true
		}
	}
	return false
}
