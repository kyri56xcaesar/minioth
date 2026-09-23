package server

/* End-user facing auth flow: register, login, token refresh/introspection,
* and password change. Route wiring only — the handler methods live in
* handlers_auth.go (AuthHandler). Request models (RegisterClaim/LoginClaim)
* are still defined in server.go since they're shared by more than one
* route group. */

import (
	"github.com/gin-gonic/gin"

	"github.com/kyri56xcaesar/minioth/internal/domain"
)

func registerAuthRoutes(rg *gin.RouterGroup, minioth *domain.Minioth) {
	h := &AuthHandler{Minioth: minioth}

	rg.POST("/register", h.Register)
	rg.POST("/login", h.Login)
	rg.POST("/token/refresh", h.RefreshToken)
	rg.GET("/user/token", h.TokenInfo)
	rg.GET("/user/me", h.Me)
	rg.POST("/passwd", h.ChangePassword)

	rg.POST("/verify-email/request", h.RequestEmailVerification)
	rg.GET("/verify-email", h.VerifyEmail)

	rg.POST("/passwd/reset-request", h.RequestPasswordReset)
	rg.POST("/passwd/reset", h.ResetPassword)
}
