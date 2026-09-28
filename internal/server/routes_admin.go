package server

/* Admin-only endpoints: user/group CRUD plus a couple of operational
* utilities (password verification, raw hasher). Route wiring only — the
* handler methods live in handlers_admin.go (AdminHandler). Everything
* under here sits behind AuthMiddleware("admin", ...) — see
* internal/auth/middleware.go. */

import (
	"github.com/gin-gonic/gin"

	"github.com/kyri56xcaesar/minioth/internal/domain"
)

func registerAdminRoutes(rg *gin.RouterGroup, minioth *domain.Minioth) {
	h := &AdminHandler{Minioth: minioth}

	rg.POST("/verify-password", h.VerifyPassword)
	rg.POST("/hasher", h.Hasher)
	rg.GET("/audit/logs", h.AuditLogs)
	rg.GET("/users", h.ListUsers)
	rg.GET("/groups", h.ListGroups)
	rg.POST("/useradd", h.UserAdd)
	rg.DELETE("/userdel", h.UserDel)
	rg.PATCH("/userpatch", h.UserPatch)
	rg.PUT("/usermod", h.UserMod)
	rg.POST("/groupadd", h.GroupAdd)
	rg.PATCH("/grouppatch", h.GroupPatch)
	rg.PUT("/groupmod", h.GroupMod)
	rg.DELETE("/groupdel", h.GroupDel)
	rg.POST("/promote", h.Promote)
	rg.POST("/revoke", h.Revoke)
}
