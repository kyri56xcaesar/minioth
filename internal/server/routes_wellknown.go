package server

/* Service discovery routes: liveness, readiness, OIDC discovery document, JWKS. Route
* wiring only — the handler methods live in handlers_wellknown.go
* (WellKnownHandler). */

import "github.com/gin-gonic/gin"

func registerWellKnownRoutes(rg *gin.RouterGroup, srv *MService) {
	h := &WellKnownHandler{Config: srv.Config, Store: srv.Minioth}

	rg.GET("/minioth", h.Liveness)
	rg.GET("/ready", h.Readiness)
	rg.GET("/openid-configuration", h.OpenIDConfiguration)
	rg.GET("/jwks.json", h.JWKS)
}
