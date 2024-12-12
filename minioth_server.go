package minioth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

/*
*
* Constants */
const (
	DEFAULT_conf_name      string = "minioth.env"
	DEFAULT_conf_path      string = "configs/"
	DEFAULT_audit_log_path string = "data/minioth.log"
)

/*
*
* Variables */
var (
	handler       MiniothHandler
	jwtSecretKey  = []byte("default_placeholder_key")
	jwtRefreshKey = []byte("default_refresh_placeholder_key")
)

/*
*
* Structs */
type MService struct {
	Engine  *gin.Engine
	Config  *EnvConfig
	Minioth *Minioth
}

type RegisterClaim struct {
	User User `json:"user"`
}

type LoginClaim struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type CustomClaims struct {
	UserID string `json:"user_id"`
	Groups string `json:"groups"`
	jwt.RegisteredClaims
}

/*
*
* Functions and methods */
func NewMSerivce(m *Minioth, conf string) MService {
	cfg := LoadConfig(conf)
	log.Print(cfg.ToString())

	srv := MService{
		Minioth: m,
		Engine:  gin.Default(),
		Config:  cfg,
	}
	jwtSecretKey = cfg.JWTSecretKey
	jwtRefreshKey = cfg.JWTRefreshKey
	HASH_COST = cfg.HashCost
	log.Printf("updating jwt key...: %s", jwtSecretKey)
	log.Printf("updating jwt refresh key...: %s", jwtRefreshKey)
	log.Printf("setting hashcost to : HASH_COST=%v", HASH_COST)
	handler = m.handler

	return srv
}

/* Should implement the following endpoints:
 * /login,  /register, /user/me, /token/refresh,
 * /groups, /groups/{groupID}/assign/{userID}
 * /token/refresh
 * /healthz, /audit/logs, /admin/users, /admin/users
 */
func (srv *MService) ServeHTTP() {
	minioth := srv.Minioth

	srv.Engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "alive.",
		})
	})
	apiV1 := srv.Engine.Group("/v1")
	{
		apiV1.POST("/register", func(c *gin.Context) {
			var uclaim RegisterClaim
			err := c.BindJSON(&uclaim)
			if err != nil {
				log.Printf("error binding request body to struct: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{
					"error": err.Error(),
				})
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
			// Check for uniquness [ NOTE: Now its done internally ]

			// Proceed with Registration
			err = srv.Minioth.Useradd(uclaim.User)
			if err != nil {
				log.Print("failed to add user")
				if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
					c.JSON(403, gin.H{"error": "already exists!"})
				} else {
					c.JSON(400, gin.H{
						"error": "failed to insert the user",
					})
				}
				return
			}

			// TODO: should insta "pseudo" login issue a token for registration.
			// can I redirect to login?
			c.JSON(200, gin.H{
				"message":   "Registration successful!. Log in.",
				"login_url": "/v1/login",
			})
		})

		apiV1.POST("/login", func(c *gin.Context) {
			var lclaim LoginClaim
			err := c.BindJSON(&lclaim)
			if err != nil {
				log.Printf("error binding request body to struct: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "binding error"})
				return
			}

			// Verify user credentials
			err = lclaim.validateClaim()
			if err != nil {
				log.Printf("failed to validate: %v", err)
				c.JSON(400, gin.H{
					"error": err.Error(),
				})
				return
			}

			groups, err := srv.Minioth.Authenticate(lclaim.Username, lclaim.Password)
			if err != nil {
				log.Printf("error: %v", err)
				if strings.Contains(err.Error(), "not found") {
					c.JSON(404, gin.H{"error": "user not found"})
				} else {
					c.JSON(400, gin.H{
						"error": "failed to authenticate",
					})
				}
				return
			}

			strGroups := groupsToString(groups)

			// TODO: should upgrde the way I create users.. need to be able to create admins as well...
			// or perhaps make the root admin be able to "promote" a user
			token, err := GenerateAccessJWT(lclaim.Username, strGroups)
			if err != nil {
				log.Fatalf("failed generating jwt token: %v", err)
			}

			refreshToken, err := GenerateRefreshJWT(lclaim.Username)
			if err != nil {
				log.Fatalf("failed to generate refresh token: %v", err)
			}

			// NOTE: use Authorization header for now.
			c.JSON(200, gin.H{
				"username":      lclaim.Username,
				"groups":        strGroups,
				"access_token":  token,
				"refresh_token": refreshToken,
			})
		})

		apiV1.POST("/token/refresh", func(c *gin.Context) {
			var requestBody struct {
				RefreshToken string `json:"refresh_token" binding:"required"`
			}

			if err := c.BindJSON(&requestBody); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "refresh_token required",
				})
				return
			}

			refreshToken := requestBody.RefreshToken
			token, err := jwt.ParseWithClaims(refreshToken, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return jwtRefreshKey, nil
			})

			if err != nil || !token.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "invalid refresh token",
				})
				return
			}

			claims, ok := token.Claims.(*CustomClaims)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "invalid claims",
				})
				return
			}

			newAccessToken, err := GenerateAccessJWT(claims.UserID, claims.Groups)
			if err != nil {
				log.Printf("error generating new access token: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "error generating access_token",
				})
				return
			}

			newRefreshToken, err := GenerateRefreshJWT(claims.UserID)
			if err != nil {
				log.Printf("error generating new refresh token: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "error generating refresh_token",
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"access_token":  newAccessToken,
				"refresh_token": newRefreshToken,
			})
		})

		apiV1.GET("/user/me", func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
				c.Abort()
				return
			}

			if !strings.Contains(authHeader, "Bearer ") {
				c.JSON(http.StatusBadRequest, gin.H{"error": "must contain Bearer token"})
				c.Abort()
				return
			}
			// Extract the token from the Authorization header
			tokenString := authHeader[len("Bearer "):]
			if tokenString == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token is required"})
				c.Abort()
				return
			}

			// Parse and validate the token
			token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return jwtSecretKey, nil
			})

			if err != nil || !token.Valid {
				token, err = jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return jwtRefreshKey, nil
				})
			}

			if err != nil {
				log.Printf("%v token, exiting", token)
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "bad token",
				})
				c.Abort()
				return
			}

			claims, ok := token.Claims.(*CustomClaims)
			if !ok {
				log.Printf("not okay when retrieving claims")
				return
			}

			response := make(map[string]string)
			response["valid"] = strconv.FormatBool(token.Valid)
			response["user"] = claims.UserID
			response["groups"] = claims.Groups
			response["issued_at"] = claims.IssuedAt.String()
			response["expires_at"] = claims.ExpiresAt.String()

			c.JSON(http.StatusOK, gin.H{
				"info": response,
			})
		})

		apiV1.POST("/user/me", func(c *gin.Context) {
			var reqBody struct {
				Token string `json:"token" binding:"required"`
			}

			err := c.BindJSON(&reqBody)
			if err != nil {
				log.Printf("provide a access_token to examine...")
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "provide an access_token...",
				})
				return
			}

			tokenString := reqBody.Token

			// Parse and validate the token
			token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return jwtSecretKey, nil
			})

			if err != nil || !token.Valid {
				token, err = jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return jwtRefreshKey, nil
				})
			}

			claims, ok := token.Claims.(*CustomClaims)
			if !ok {
				log.Printf("not okay when retrieving claims")
				return
			}

			response := make(map[string]string)
			response["valid"] = strconv.FormatBool(token.Valid)
			response["user"] = claims.UserID
			response["groups"] = claims.Groups
			response["issued_at"] = claims.IssuedAt.String()
			response["expires_at"] = claims.ExpiresAt.String()

			c.JSON(http.StatusOK, gin.H{
				"info": response,
			})
		})

		/* This endpoint should change a user password. It must "authenticate" the user. User can only change his password. */
		apiV1.POST("/passwd", func(c *gin.Context) {
		})

	}

	admin := srv.Engine.Group("/admin")
	admin.Use(AuthMiddleware("admin"))
	{

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

		/* same as register but dont verify content */
		admin.POST("/useradd", func(c *gin.Context) {
			var uclaim RegisterClaim
			err := c.BindJSON(&uclaim)
			if err != nil {
				log.Printf("error binding request body to struct: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{
					"error": err.Error(),
				})
				return
			}

			err = srv.Minioth.Useradd(uclaim.User)
			if err != nil {
				log.Print("failed to add user")
				if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
					c.JSON(403, gin.H{"error": "already exists!"})
				} else {
					c.JSON(400, gin.H{
						"error": "failed to insert the user",
					})
				}
				return
			}

			// TODO: should insta "pseudo" login issue a token for registration.
			// can I redirect to login?
			c.JSON(200, gin.H{
				"message":   "User added.",
				"login_url": "sure",
			})
		})

		admin.DELETE("/userdel", func(c *gin.Context) {
		})

		admin.PUT("/usermod", func(c *gin.Context) {
		})

		admin.POST("/groupadd", func(c *gin.Context) {
		})

		admin.PUT("/groupmod", func(c *gin.Context) {
		})

		admin.DELETE("/groupdel", func(c *gin.Context) {
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

/* For this service, authorization is required only for admin role. */
func AuthMiddleware(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// Extract the token from the Authorization header
		tokenString := authHeader[len("Bearer "):]
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token is required"})
			c.Abort()
			return
		}

		// Parse and validate the token
		token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecretKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Set claims in the context for further use
		if claims, ok := token.Claims.(*CustomClaims); ok {
			if !strings.Contains(claims.Groups, role) {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "invalid user",
				})
				c.Abort()
				return
			}
			c.Set("username", claims.UserID)
			c.Set("groups", claims.Groups)
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func GenerateJWT(userID, groups string) (string, error) {
	// Set the claims for the token
	claims := CustomClaims{
		UserID: userID,
		Groups: groups,
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

// jwt
func GenerateAccessJWT(userID, groups string) (string, error) {
	// Set the claims for the token
	claims := CustomClaims{
		UserID: userID,
		Groups: groups,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "minioth",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 2)), // Token expiration time (24 hours)
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

func GenerateRefreshJWT(userID string) (string, error) {
	claims := CustomClaims{
		UserID: userID,
		Groups: "not-needed",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)), // Token expiration time (24 hours)
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtRefreshKey)
}
