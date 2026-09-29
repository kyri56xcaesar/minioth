package server

/* Handler methods for service discovery: liveness, an OIDC-flavored
* configuration document, and the JWKS endpoint. registerWellKnownRoutes
* (routes_wellknown.go) only wires paths to these methods. auth.JWKS() (see
* internal/auth/jwt.go) derives its response live from whatever signing key
* is actually loaded, so this can never drift out of sync with the real
* signing algorithm the way a hand-maintained jwks.json file could. */

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kyri56xcaesar/minioth/internal/auth"
	"github.com/kyri56xcaesar/minioth/internal/config"
	"github.com/kyri56xcaesar/minioth/internal/domain"
)

// WellKnownHandler holds the service-discovery routes' dependencies.
type WellKnownHandler struct {
	Config *config.EnvConfig
	Store  *domain.Minioth
}

func (h *WellKnownHandler) Liveness(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"version": "0.0.1",
		"status":  "alive",
	})
}

// Readiness answers 200 only while the store can serve requests (Liveness
// only shows the process is up). The reason is logged, not returned: it can
// hold file paths.
func (h *WellKnownHandler) Readiness(c *gin.Context) {
	if err := h.Store.Ready(); err != nil {
		log.Printf("[ready] not ready: %v", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})

		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

func (h *WellKnownHandler) OpenIDConfiguration(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                h.Config.ISSUER,
		"jwks_uri":                              fmt.Sprintf("%s/.well-known/jwks.json", h.Config.ISSUER),
		"token_endpoint":                        fmt.Sprintf("%s/%s/login", h.Config.ISSUER, VERSION),
		"userinfo_endpoint":                     fmt.Sprintf("%s/%s/user/me", h.Config.ISSUER, VERSION),
		"id_token_signing_alg_values_supported": []string{auth.SigningAlg()},
	})
}

func (h *WellKnownHandler) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, auth.JWKS())
}
