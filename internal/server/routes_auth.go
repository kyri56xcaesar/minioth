package server

/* End-user facing auth flow: register, login, token refresh/introspection,
* and password change. Route wiring only — the handler methods live in
* handlers_auth.go (AuthHandler). Request models (RegisterClaim/LoginClaim)
* are still defined in server.go since they're shared by more than one
* route group. */

import (
	"github.com/gin-gonic/gin"

	"github.com/kyri56xcaesar/minioth/internal/auth"
	"github.com/kyri56xcaesar/minioth/internal/config"
	"github.com/kyri56xcaesar/minioth/internal/domain"
)

func registerAuthRoutes(rg *gin.RouterGroup, minioth *domain.Minioth, cfg *config.EnvConfig) {
	h := &AuthHandler{Minioth: minioth}

	// One shared limiter instance (one shared per-IP budget) across every
	// credential-sensitive route it's attached to below — see
	// RateLimitMiddleware's doc comment for why constructing it once
	// matters.
	limited := auth.RateLimitMiddleware(cfg)

	rg.POST("/register", limited, h.Register)
	rg.POST("/login", limited, h.Login)
	rg.POST("/token/refresh", h.RefreshToken)
	rg.GET("/user/token", h.TokenInfo)
	rg.GET("/user/me", h.Me)
	rg.POST("/passwd", limited, h.ChangePassword)

	rg.POST("/verify-email/request", h.RequestEmailVerification)
	rg.GET("/verify-email", h.VerifyEmail)

	rg.POST("/passwd/reset-request", limited, h.RequestPasswordReset)
	rg.POST("/passwd/reset", limited, h.ResetPassword)
}
