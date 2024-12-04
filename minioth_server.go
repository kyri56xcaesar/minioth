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
	"github.com/golang-jwt/jwt/v5"
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

type RegisterClaim struct {
	User User `json:"user"`
}

type LoginClaim struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func offLimits(str string) bool {
	if str == "root" || str == "kubernetes" {
		return true
	}
	return false
}

func (l *LoginClaim) validateClaim() error {
	if l.Username == "" {
		return errors.New("username cannot be empty")
	}

	if !IsAlphanumericPlus(l.Username) {
		return fmt.Errorf("username %q is invalid: only alphanumeric chararctes[@+] are allowed", l.Username)
	}

	if l.Password == "" {
		return errors.New("password cannot be empty")
	}

	return nil
}

func (u *RegisterClaim) validateUser() error {
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
	log.Print(cfg.ToString())

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

		apiV1.POST("/register", func(c *gin.Context) {
			var uclaim RegisterClaim
			err := c.BindJSON(&uclaim)
			if err != nil {
				log.Printf("error binding request body to struct: %v", err)
				c.Error(err)
				return
			}

			log.Printf("%+v", uclaim)
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
			err = exists(&uclaim.User)
			if err != nil {
				log.Printf("failed checking for uniqueness...: %v", err)
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}
			// Proceed with Registration
			srv.Minioth.Useradd(uclaim.User)

			c.JSON(200, gin.H{
				"username": uclaim.User.Name,
				"password": uclaim.User.Password.Hashpass,
			})
		})

		apiV1.POST("/login", func(c *gin.Context) {
			var lclaim LoginClaim
			err := c.BindJSON(&lclaim)
			if err != nil {
				log.Printf("error binding request body to struct: %v", err)
				c.Error(err)
				return
			}

			log.Printf("login claim: %+v", lclaim)
			// Verify user credentials
			err = lclaim.validateClaim()
			if err != nil {
				log.Printf("failed to validate: %v", err)
				c.JSON(400, gin.H{
					"error": err.Error(),
				})
				return
			}
			log.Print("claim validated")

			// TODO: approve user
			approved := srv.Minioth.approveUser(lclaim.Username, lclaim.Password)
			if !approved {
				log.Printf("invalid credentials. login failed")
				c.JSON(400, gin.H{
					"error": "invalid credentials",
				})
				return
			}
			log.Print("claim approved")

			// TODO: issue a token
			//
			// TODO: idk, propably a cookie... or sth(session)

			token := "t0k3n_1s_r4nd0m"
			c.JSON(200, gin.H{
				"username": lclaim.Username,
				"token":    token,
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

		admin.POST("/useradd", func(c *gin.Context) {
		})

		admin.DELETE("/userdel", func(c *gin.Context) {
		})

		admin.PUT("/usermod", func(c *gin.Context) {
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

var jwtSecretKey = []byte("your_secret_key")

// CustomClaims represents the claims for the JWT token
type CustomClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func GenerateJWT(userID, role string) (string, error) {
	// Set the claims for the token
	claims := CustomClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "minioth",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)), // Token expiration time (24 hours)
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}

	// Create the token using the HS256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token using the secret key
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func VerifyJWT(tokenString string) (*CustomClaims, error) {
	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Make sure the signing method is HMAC (HS256)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecretKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract claims if the token is valid
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
