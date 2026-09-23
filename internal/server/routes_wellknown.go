package server

/* Service discovery routes: liveness, OIDC discovery document, JWKS. Route
* wiring only — the handler methods live in handlers_wellknown.go
* (WellKnownHandler). */

import "github.com/gin-gonic/gin"

func registerWellKnownRoutes(rg *gin.RouterGroup, srv *MService) {
	h := &WellKnownHandler{Config: srv.Config}

	rg.GET("/minioth", h.Liveness)
	rg.GET("/openid-configuration", h.OpenIDConfiguration)
	rg.GET("/jwks.json", h.JWKS)
}
