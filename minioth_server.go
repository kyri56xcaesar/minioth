package minioth

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"kyri56xcaesar/discord_bots_app/internal/serverconfig"
)

type MService struct {
	Engine  *gin.Engine
	Config  *serverconfig.EnvConfig
	Minioth *Minioth
}

const (
	DEFAULT_conf_name      string = "minioth.env"
	DEFAULT_conf_path      string = "configs/"
	DEFAULT_audit_log_path string = "data/minioth.log"
)

func NewMSerivce(m *Minioth, conf string) MService {
	cfg := serverconfig.LoadConfig(conf)

	srv := MService{
		Minioth: m,
		Engine:  gin.Default(),
		Config:  cfg,
	}

	return srv
}

func (srv *MService) ServeHTTP() {
	minioth := srv.Minioth

	apiV1 := srv.Engine.Group("/v1")
	{
		// Should implement the following endpoints:
		// /login, /logout, /register, /user/me, /token/refresh,
		// /groups, /groups/{groupID}/assign/{userID}
		// /token/refresh
		// /health, /audit/logs, /admin/users, /admin/users

		apiV1.POST("/login", func(c *gin.Context) {
		})

		apiV1.POST("/register", func(c *gin.Context) {
		})

		apiV1.POST("/logout", func(c *gin.Context) {
		})

		apiV1.POST("/token/refresh", func(c *gin.Context) {
		})

		apiV1.POST("/user/me", func(c *gin.Context) {
		})
	}
	admin := srv.Engine.Group("/admin")
	{
		admin.GET("/health", func(c *gin.Context) {
		})

		admin.GET("/audit/logs", func(c *gin.Context) {
		})

		admin.GET("/admin/users", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"content": minioth.Select("users"),
			})
		})

		admin.GET("/admin/groups", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"content": minioth.Select("groups"),
			})
		})
	}

	server := &http.Server{
		Addr:              srv.Config.Addr(),
		Handler:           srv.Engine,
		ReadHeaderTimeout: time.Second * 5,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()
	<-ctx.Done()

	stop()
	log.Println("shutting down gracefully, press Ctrl+C again to force")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown: ", err)
	}

	log.Println("Server exiting")
}
