package minioth

/* Minioth server is responsible for listening */

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
	VERSION                       = ""
	JWT_VALIDITY_HOURS     int    = 1
)

/*
*
* Variables */
var (
	handler       MiniothHandler
	jwtSecretKey  = []byte("default_placeholder_key")
	jwtRefreshKey = []byte("default_refresh_placeholder_key")

	forbidden_names []string = []string{
		"root",
		"kubernetes",
		"k8s",
	}
)

/*
* Structs
*
* minioth server central object.
* -> reference to a server engine
* -> configuration
* -> reference to minioth
*
*
* the model structs used by the server are defined in minioth.go
* */
type MService struct {
	Engine  *gin.Engine
	Config  *EnvConfig
	Minioth *Minioth
}

/* Incoming Register and Login requests binding structs */
type RegisterClaim struct {
	User User `json:"user"`
}

type LoginClaim struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

/* JWT token signed claims.
* what information the jwt will contain.
* */
type CustomClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Groups   string `json:"groups"`
	GroupIDS string `json:"group_ids"`
	jwt.RegisteredClaims
}

/*
*
* "constructor of minioth server central object" */
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

	apiV1 := srv.Engine.Group(VERSION)
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
			uid, err := minioth.Useradd(uclaim.User)
			if err != nil {
				log.Print("failed to add user")
				if strings.Contains(strings.ToLower(err.Error()), "alr") {
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
				"message":   fmt.Sprintf("User %v Registration successful!. Log in.", uid),
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

			user, err := minioth.Authenticate(lclaim.Username, lclaim.Password)
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

			strGroups := groupsToString(user.Groups)
			strGids := gidsToString(user.Groups)

			// TODO: should upgrde the way I create users.. need to be able to create admins as well...
			// or perhaps make the root admin be able to "promote" a user
			token, err := GenerateAccessJWT(strconv.Itoa(user.Uid), lclaim.Username, strGroups, strGids)
			if err != nil {
				log.Fatalf("failed generating jwt token: %v", err)
			}

			refreshToken, err := GenerateRefreshJWT(lclaim.Username)
			if err != nil {
				log.Fatalf("failed to generate refresh token: %v", err)
			}

			// for now return detailed information so that frontend is accomodated
			// and followup authorization is provided (ids needed)
			// NOTE: use Authorization header for now.
			c.JSON(200, gin.H{
				"username":      lclaim.Username,
				"user_id":       user.Uid,
				"groups":        strGroups,
				"group_ids":     strGids,
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
			newAccessToken, err := GenerateAccessJWT(claims.UserID, claims.Username, claims.Groups, claims.GroupIDS)
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
			response["user_id"] = claims.UserID
			response["username"] = claims.Username
			response["groups"] = claims.Groups
			response["group_ids"] = claims.GroupIDS
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

			valid, claims, err := DecodeJWT(tokenString)

			response := make(map[string]string)
			response["valid"] = strconv.FormatBool(valid)
			response["user_id"] = claims.UserID
			response["username"] = claims.Username
			response["groups"] = claims.Groups
			response["group_ids"] = claims.GroupIDS
			response["issued_at"] = claims.IssuedAt.String()
			response["expires_at"] = claims.ExpiresAt.String()

			c.JSON(http.StatusOK, gin.H{
				"info": response,
			})
		})

		/* This endpoint should change a user password. It must "authenticate" the user. User can only change his password. */
		apiV1.POST("/passwd", func(c *gin.Context) {
			var lclaim LoginClaim
			err := c.BindJSON(&lclaim)
			if err != nil {
				log.Printf("error binding request body to struct: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "binding error"})
				return
			}

			pass := Password{
				Hashpass: lclaim.Password,
			}
			// Verify user credentials
			if lclaim.Password == "" {
				c.JSON(400, gin.H{
					"error": "no password provided",
				})
				return
			} else if err := pass.validatePassword(); err != nil {
				c.JSON(400, gin.H{
					"error": err.Error(),
				})
				return
			}

			err = minioth.Passwd(lclaim.Username, lclaim.Password)
			if err != nil {
				log.Printf("failed to change password: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to change password"})
				return
			}

			c.JSON(200, gin.H{"status": "password changed successfully"})
		})
	}

	/* admin endpoints */
	admin := srv.Engine.Group("/admin")
	admin.Use(AuthMiddleware("admin", srv))
	{
		admin.POST("/hasher", func(c *gin.Context) {
			var b struct {
				HashAlg  string `json:"hashalg"`
				HashText string `json:"hash"`
				Text     string `json:"text"`
				HashCost int    `json:"hashcost"`
			}
			err := c.BindJSON(&b)
			if err != nil {
				log.Printf("error binding request body to struct: %v", err)
				c.JSON(400, gin.H{"error": "binding"})
				return
			}

			hashed, err := hash_cost([]byte(b.Text), b.HashCost)
			if err != nil {
				log.Printf("error hasing the text: %v", err)
				c.JSON(500, gin.H{"error": "hashing"})
				return
			}

			if b.HashText == "" {
				c.JSON(200, gin.H{"result": string(hashed)})
			} else {
				c.JSON(200, gin.H{"result": strconv.FormatBool(verifyPass([]byte(b.HashText), []byte(b.Text)))})
			}
		})

		admin.GET("/audit/logs", func(c *gin.Context) {
		})

		admin.GET("/users", func(c *gin.Context) {
			users := minioth.Select("users")

			c.JSON(http.StatusOK, gin.H{
				"content": users,
			})
		})

		admin.GET("/groups", func(c *gin.Context) {
			groups := minioth.Select("groups")

			c.JSON(http.StatusOK, gin.H{
				"content": groups,
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

			uid, err := minioth.Useradd(uclaim.User)
			if err != nil {
				log.Print("failed to add user")
				if strings.Contains(strings.ToLower(err.Error()), "") {
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
				"message":   fmt.Sprintf("User %v added.", uid),
				"login_url": "sure",
			})
		})

		admin.DELETE("/userdel", func(c *gin.Context) {
			uid := c.Query("uid")
			if uid == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "uid is required"})
				return
			}

			err := minioth.Userdel(uid)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
				} else if strings.Contains(err.Error(), "root") {
					c.JSON(400, gin.H{"error": "really bro?"})
				} else {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user"})
				}

				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "user deleted successfully"})
		})

		admin.PATCH("/userpatch", func(c *gin.Context) {
			var updateFields map[string]interface{}
			if err := c.ShouldBindJSON(&updateFields); err != nil {
				log.Printf("failed to bind req body: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
				return
			}

			uidValue, ok := updateFields["uid"]
			if !ok {
				log.Printf("uid is not ok: %v", uidValue)
				c.JSON(http.StatusBadRequest, gin.H{"error": "uid is required"})
				return
			}
			var uid string
			switch v := uidValue.(type) {
			case string:
				uid = v
			case float64:
				uid = fmt.Sprintf("%.0f", v)
			case int:
				uid = strconv.Itoa(v)
			default:
				log.Printf("uid type not supported: %T", v)
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid uid format"})
				return
			}

			switch uid {
			case "":
				log.Print("empty uid")

			case "0":
				log.Print("sm1 is trying to change the root..")
				c.JSON(400, gin.H{"error": "not allowed"})
				return
			}

			err := minioth.Userpatch(uid, updateFields)
			if err != nil {
				log.Printf("failed to patch user: %v", err)
				if err.Error() == "no inputs" {
					c.JSON(404, gin.H{"error": "bad request"})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "user patched successfully"})
		})

		admin.PUT("/usermod", func(c *gin.Context) {
			var ruser RegisterClaim
			if err := c.ShouldBindJSON(&ruser); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
				return
			}

			err := minioth.Usermod(ruser.User)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
		})

		admin.POST("/groupadd", func(c *gin.Context) {
			var group Group
			if err := c.ShouldBindJSON(&group); err != nil {
				log.Printf("Invalid group data: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group data"})
				return
			}

			if _, err := minioth.Groupadd(group); err != nil {
				log.Printf("Failed to add group: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add group"})
				return
			}

			c.JSON(http.StatusCreated, gin.H{"message": "Group added successfully"})
		})

		admin.PATCH("/grouppatch", func(c *gin.Context) {
			var payload struct {
				Fields map[string]interface{} `json:"fields" binding:"required"`
				Gid    string                 `json:"gid" binding:"required"`
			}
			if err := c.ShouldBindJSON(&payload); err != nil {
				log.Printf("Invalid patch payload: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid patch payload"})
				return
			}

			if err := minioth.Grouppatch(payload.Gid, payload.Fields); err != nil {
				log.Printf("Failed to patch group: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to patch group"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Group patched successfully"})
		})

		admin.PUT("/groupmod", func(c *gin.Context) {
			var group Group
			if err := c.ShouldBindJSON(&group); err != nil {
				log.Printf("Invalid group data: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group data"})
				return
			}

			if err := minioth.Groupmod(group); err != nil {
				log.Printf("Failed to modify group: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to modify group"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Group modified successfully"})
		})

		admin.DELETE("/groupdel", func(c *gin.Context) {
			gid := c.Query("gid")
			if gid == "" {
				log.Print("gid is required")
				c.JSON(http.StatusBadRequest, gin.H{"error": "gid is required"})
				return
			}

			if err := minioth.Groupdel(gid); err != nil {
				log.Printf("Failed to delete group: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete group"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Group deleted successfully"})
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

	log.Print("closing db connection...")
	handler.Close()

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
func AuthMiddleware(role string, srv *MService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// if service secret exists and validated, grant access
		if s_secret_claim := c.GetHeader("X-Service-Secret"); s_secret_claim != "" {
			if s_secret_claim == string(srv.Config.ServiceSecret) {
				log.Printf("service secret accepted. access granted.")
				c.Next()
				return
			} else {
				log.Printf("service secret invalid. access not granted")
				c.Abort()
				return
			}
		}

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

/* Filter incoming login and register requests. Don't allow wierd chars...*/
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

/* functions */
/* just a function to see if a given name is in input */
func offLimits(str string) bool {
	for _, name := range forbidden_names {
		if str == name {
			return true
		}
	}
	return false
}

// jwt
func GenerateAccessJWT(userID, username, groups, gids string) (string, error) {
	// Set the claims for the token
	claims := CustomClaims{
		UserID:   userID,
		Username: username,
		Groups:   groups,
		GroupIDS: gids,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "minioth",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * time.Duration(JWT_VALIDITY_HOURS))),
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

func DecodeJWT(tokenString string) (bool, *CustomClaims, error) {
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
		return false, nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		log.Printf("not okay when retrieving claims")
		return false, nil, errors.New("invalid claims")
	}

	return true, claims, nil
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

func groupsToString(groups []Group) string {
	var res []string

	for _, group := range groups {
		res = append(res, group.toString())
	}

	return strings.Join(res, ",")
}

func gidsToString(groups []Group) string {
	var res []string
	for _, group := range groups {
		res = append(res, strconv.Itoa(group.Gid))
	}
	return strings.Join(res, ",")
}
