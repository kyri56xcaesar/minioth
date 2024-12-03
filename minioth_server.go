package minioth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

type MService struct {
	Engine  *gin.Engine
	Config  *EnvConfig
	Minioth *Minioth
}

const (
	DEFAULT_conf_name      string = "minioth.env"
	DEFAULT_conf_path      string = "configs/"
	DEFAULT_audit_log_path string = "data/minioth.log"
)

type UserClaim struct {
	User User `json:"user"`
}

func offLimits(str string) bool {
	if str == "root" || str == "kubernetes" {
		return true
	}
	return false
}

func (u *UserClaim) validateUser() error {
	if u.User.Name == "" {
		return errors.New("username cannot be empty")
	}

	if offLimits(u.User.Name) {
		return errors.New("username off limits")
	}

	if !IsAlphanumericPlus(u.User.Name) {
		return fmt.Errorf("username %q is invalid: only alphanumeric characters[@+] are allowed", u.User.Name)
	}

	if len(u.User.Info) > 100 {
		return fmt.Errorf("info field is too long: maximum allowed length is 100 characters")
	}

	// Validate UID
	if u.User.Uid < 0 {
		return fmt.Errorf("uid '%d' is invalid: must be a non-negative integer", u.User.Uid)
	}

	// Validate Primary Group
	if u.User.Pgroup < 0 {
		return fmt.Errorf("primary group '%d' is invalid: must be a non-negative integer", u.User.Pgroup)
	}

	if err := u.User.Password.validatePassword(); err != nil {
		return fmt.Errorf("password validation error: %w", err)
	}

	return nil
}

func NewMSerivce(m *Minioth, conf string) MService {
	cfg := LoadConfig(conf)

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
			var uclaim UserClaim
			err := c.Bind(&uclaim)
			if err != nil {
				log.Printf("error binding request body to struct: %v", err)
				c.Error(err)
				return
			}
			// Verify user credentials
			err = uclaim.validateUser()
			if err != nil {
				log.Printf("failed to validate: %v", err)
				c.JSON(400, gin.H{
					"error": err.Error(),
				})
				return
			}
			// Check for uniquness
			err = checkIfUserExists(uclaim.User)
			if err != nil {
				log.Printf("failed checking for uniqueness...: %v", err)
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}
			// Proceed with Registration
			c.JSON(200, gin.H{
				"username": uclaim.User.Name,
				"password": uclaim.User.Password.Hashpass,
			})

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

		admin.GET("/users", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"content": minioth.Select("users"),
			})
		})

		admin.GET("/groups", func(c *gin.Context) {
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
