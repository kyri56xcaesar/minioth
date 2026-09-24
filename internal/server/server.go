package server

/* Minioth server is responsible for listening.
*
* This file is the composition root: it owns MService, boots config/JWT
* signing, registers the route groups (defined in routes_auth.go,
* routes_admin.go, routes_wellknown.go — see those for the actual
* handlers, and auth.AuthMiddleware / auth.GenerateAccessJWT etc. for auth
* and token logic), and handles graceful shutdown. Request-model validation
* (RegisterClaim / LoginClaim) lives here too since it's shared by more
* than one route group. */

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kyri56xcaesar/minioth/internal/auth"
	"github.com/kyri56xcaesar/minioth/internal/config"
	"github.com/kyri56xcaesar/minioth/internal/domain"
	"github.com/kyri56xcaesar/minioth/internal/util"
)

/*
*
* Constants */
const (
	DEFAULT_conf_name      = "minioth.env"
	DEFAULT_conf_path      = "configs/"
	DEFAULT_audit_log_path = "data/minioth.log"
	VERSION                = "v1"
)

/*
*
* Variables */
var forbidden_names []string = []string{
	"root",
	"kubernetes",
	"k8s",
}

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
	Config  *config.EnvConfig
	Minioth *domain.Minioth
}

/* Incoming Register and Login requests binding structs */
type RegisterClaim struct {
	User domain.User `json:"user"`
}

type LoginClaim struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Bootstrap loads the .env config and applies its process-wide side
// effects (JWT signing state, domain.HASH_COST, password policy). Callers
// must run this — and let it finish — before constructing anything that
// might use those values (domain.NewMinioth's root-user seeding hashes a
// password, for one), since NewMService used to do this itself but
// required an already-constructed *domain.Minioth as an argument, which
// meant the config couldn't be loaded until after the very thing that
// needed it had already run with un-configured defaults.
func Bootstrap(conf string) *config.EnvConfig {
	cfg := config.LoadConfig(conf)
	log.Print(cfg.ToString())

	auth.InitJWTSigning(cfg)
	domain.HASH_COST = cfg.HashCost
	domain.PasswordMinLength = cfg.PasswordMinLength
	domain.PasswordMaxLength = cfg.PasswordMaxLength
	domain.PasswordRequireUpper = cfg.PasswordRequireUpper
	domain.PasswordRequireLower = cfg.PasswordRequireLower
	domain.PasswordRequireDigit = cfg.PasswordRequireDigit
	domain.PasswordRequireSpecial = cfg.PasswordRequireSpecial
	log.Printf("jwt signing alg: %s", cfg.JWTSigningAlg)
	log.Printf("setting hashcost to : HASH_COST=%v", domain.HASH_COST)
	log.Printf("password policy: minLength=%d maxLength=%d requireUpper=%v requireLower=%v requireDigit=%v requireSpecial=%v",
		domain.PasswordMinLength, domain.PasswordMaxLength, domain.PasswordRequireUpper, domain.PasswordRequireLower, domain.PasswordRequireDigit, domain.PasswordRequireSpecial)

	// The configured root username is as off-limits for self-registration
	// as the hardcoded names below — a configurable root account only
	// stays privileged-and-singular if nobody else can register as it.
	forbidden_names = append(forbidden_names, strings.ToLower(cfg.RootUsername))

	return cfg
}

/*
*
* "constructor of minioth server central object" */
func NewMService(m *domain.Minioth, cfg *config.EnvConfig) MService {
	// Must happen before gin.Default() constructs the engine: it's what
	// suppresses gin's verbose debug route/stack logging outside of
	// GinMode == "debug".
	gin.SetMode(cfg.GinMode)

	return MService{
		Minioth: m,
		Engine:  gin.Default(),
		Config:  cfg,
	}
}

/* Should implement the following endpoints:
 * /login,  /register, /user/token, /token/refresh,
 * /groups, /groups/{groupID}/assign/{userID}
 * /token/refresh
 * /audit/logs, /admin/users, /admin/users
 */
func (srv *MService) ServeHTTP() {
	minioth := srv.Minioth

	srv.Engine.Use(auth.CORSMiddleware(srv.Config))

	apiV1 := srv.Engine.Group("/" + VERSION)
	registerAuthRoutes(apiV1, minioth, srv.Config)

	admin := apiV1.Group("/admin")
	admin.Use(auth.AuthMiddleware("admin", srv.Config))
	registerAdminRoutes(admin, minioth)

	wellknown := apiV1.Group("/.well-known")
	registerWellKnownRoutes(wellknown, srv)

	server := &http.Server{
		Addr:              srv.Config.Addr(),
		Handler:           srv.Engine,
		ReadHeaderTimeout: time.Second * 5,
	}

	// Both set: serve HTTPS directly, for deployments that won't sit
	// behind a TLS-terminating reverse proxy. Neither set: plain HTTP, as
	// before. One set without the other is a misconfiguration — fail fast
	// rather than let ListenAndServeTLS produce a more confusing error.
	useTLS := srv.Config.TLSCertFile != "" && srv.Config.TLSKeyFile != ""
	if (srv.Config.TLSCertFile != "") != (srv.Config.TLSKeyFile != "") {
		log.Fatalf("TLS_CERT_FILE and TLS_KEY_FILE must both be set, or both left empty")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		var err error
		if useTLS {
			log.Printf("serving TLS on %s", srv.Config.Addr())
			err = server.ListenAndServeTLS(srv.Config.TLSCertFile, srv.Config.TLSKeyFile)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()
	<-ctx.Done()

	log.Print("closing db connection...")
	minioth.Close()

	stop()
	log.Println("shutting down gracefully, press Ctrl+C again to force")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown: ", err)
	}

	log.Println("Server exiting")
}

/* Filter incoming login and register requests. Don't allow wierd chars...*/
func (l *LoginClaim) validateClaim() error {
	if l.Username == "" {
		return errors.New("username cannot be empty")
	}

	if !util.IsAlphanumericPlus(l.Username) {
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

	if !util.IsAlphanumericPlus(u.User.Name) {
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

	if err := u.User.Password.ValidatePassword(); err != nil {
		return fmt.Errorf("password validation error: %w", err)
	}

	return nil
}

/* functions */
/* checks a given name against the forbidden list, case-insensitively — a
* user shouldn't be able to grab "Root" or "ROOT" just because offLimits()
* only ever checked the exact lowercase spelling. */
func offLimits(str string) bool {
	lower := strings.ToLower(str)
	for _, name := range forbidden_names {
		if lower == name {
			return true
		}
	}
	return false
}
