package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type EnvConfig struct {
	ConfigPath string

	API_PORT string
	ISSUER   string
	IP       string

	// GinMode picks gin's run mode ("debug", "release", or "test"). Gin
	// itself reads GIN_MODE from the OS environment at package-init time,
	// before main() (and any .env file it loads) ever runs — too early to
	// pick up a value from ROOT_USERNAME's .env file, so this is applied
	// explicitly via gin.SetMode() once config is loaded (see server.go).
	GinMode string

	// TLSCertFile/TLSKeyFile: when both are set, ServeHTTP serves HTTPS
	// directly instead of plain HTTP — for deployments that won't sit
	// behind a TLS-terminating reverse proxy. Empty (default) keeps the
	// existing plain-HTTP behavior.
	TLSCertFile string
	TLSKeyFile  string

	// RootUsername/RootPassword seed the one privileged account every
	// backend creates on first boot. RootPassword is generated and logged
	// once if not configured (see getRootPassword) rather than defaulting
	// to a fixed, guessable value.
	RootUsername string
	RootPassword string

	// JWT signing. Access tokens are signed with whichever algorithm is
	// configured here (HS256, symmetric, or RS256, asymmetric); refresh
	// tokens are always HS256 (see jwt.go) since they're never handed to a
	// third party or checked against the published JWKS.
	JWTSecretKey         []byte
	JWTRefreshKey        []byte
	JWTSigningAlg        string
	JWTRSAPrivateKeyPath string

	// ServiceSecrets maps a service identity to its own bypass credential
	// (SERVICE_SECRETS="svcA:secretA,svcB:secretB"), so inter-service calls
	// via X-Service-Secret are attributable and revocable per-service
	// instead of sharing one static value across every caller.
	ServiceSecrets map[string][]byte

	AllowedOrigins []string
	AllowedHeaders []string
	AllowedMethods []string
	HashCost       int

	PasswordMinLength      int
	PasswordMaxLength      int
	PasswordRequireUpper   bool
	PasswordRequireLower   bool
	PasswordRequireDigit   bool
	PasswordRequireSpecial bool

	// RateLimitRPS/RateLimitBurst configure the per-client-IP token bucket
	// (internal/auth's RateLimitMiddleware) applied to credential-sensitive
	// routes (register, login, password change/reset — see
	// registerAuthRoutes). RateLimitRPS is the sustained rate; RateLimitBurst
	// is how many requests can arrive back-to-back before that sustained
	// rate kicks in.
	RateLimitRPS   float64
	RateLimitBurst int
}

func LoadConfig(path string) *EnvConfig {
	if err := godotenv.Load(path); err != nil {
		log.Printf("Could not load %s config file. Using default variables", path)
	}

	split := strings.Split(path, "/")

	hashcost, err := strconv.Atoi(getEnv("HASH_COST", "16"))
	if err != nil {
		log.Print("failed to atoi hascost, setting default...")
		hashcost = 16
	} else if hashcost < 0 || hashcost > 30 {
		log.Print("invalid hashcost value, setting default...")
		hashcost = 16
	}

	config := &EnvConfig{
		ConfigPath:     split[len(split)-1],
		API_PORT:       getEnv("API_PORT", "9090"),
		ISSUER:         getEnv("ISSUER", "http://localhost:9090"),
		IP:             getEnv("IP", "localhost"),
		AllowedOrigins: getEnvs("ALLOWED_ORIGINS", nil),
		AllowedHeaders: getEnvs("ALLOWED_HEADERS", nil),
		AllowedMethods: getEnvs("ALLOWED_METHODS", nil),

		GinMode: getGinMode("GIN_MODE"),

		TLSCertFile: getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", ""),

		RootUsername: getEnv("ROOT_USERNAME", "root"),
		RootPassword: getRootPassword("ROOT_PASSWORD"),

		JWTSecretKey:         getJWTSecretKey("JWT_SECRET_KEY"),
		JWTRefreshKey:        getJWTSecretKey("JWT_REFRESH_KEY"),
		JWTSigningAlg:        getJWTSigningAlg("JWT_SIGNING_ALG"),
		JWTRSAPrivateKeyPath: getEnv("JWT_RSA_PRIVATE_KEY_PATH", ""),

		ServiceSecrets: getServiceSecrets("SERVICE_SECRETS"),

		HashCost: hashcost,

		PasswordMinLength:      getEnvInt("PASSWORD_MIN_LENGTH", 8),
		PasswordMaxLength:      getEnvInt("PASSWORD_MAX_LENGTH", 72),
		PasswordRequireUpper:   getEnvBool("PASSWORD_REQUIRE_UPPER", false),
		PasswordRequireLower:   getEnvBool("PASSWORD_REQUIRE_LOWER", false),
		PasswordRequireDigit:   getEnvBool("PASSWORD_REQUIRE_DIGIT", false),
		PasswordRequireSpecial: getEnvBool("PASSWORD_REQUIRE_SPECIAL", false),

		RateLimitRPS:   getEnvFloat("RATE_LIMIT_RPS", 2),
		RateLimitBurst: getEnvInt("RATE_LIMIT_BURST", 10),
	}

	return config
}

func getJWTSecretKey(envVar string) []byte {
	secret := os.Getenv(envVar)
	if secret == "" {
		log.Fatalf("%s must not be empty", envVar)
	}
	return []byte(secret)
}

// getJWTSigningAlg validates the configured access-token signing algorithm
// up front (fail fast, same as a missing JWT key) rather than discovering a
// typo the first time a token is signed.
func getJWTSigningAlg(envVar string) string {
	alg := strings.ToUpper(getEnv(envVar, "HS256"))
	switch alg {
	case "HS256", "RS256":
		return alg
	default:
		log.Fatalf("%s must be HS256 or RS256, got %q", envVar, alg)
		return ""
	}
}

// getGinMode validates the configured gin run mode up front, same
// fail-fast contract as getJWTSigningAlg. Defaults to "release" — a
// server booted with no config at all shouldn't leak gin's verbose debug
// route/stack output by default.
func getGinMode(envVar string) string {
	mode := getEnv(envVar, "release")
	switch mode {
	case "debug", "release", "test":
		return mode
	default:
		log.Fatalf("%s must be debug, release, or test, got %q", envVar, mode)
		return ""
	}
}

// getRootPassword returns the configured root password, or generates and
// prominently logs a random one if none is set — a fixed, guessable
// default (the username itself) is the kind of thing that's fine for a
// throwaway local run but not worth defaulting to now that it's easy not
// to.
func getRootPassword(envVar string) string {
	if pw := os.Getenv(envVar); pw != "" {
		return pw
	}

	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("failed to generate a random root password: %v", err)
	}
	generated := base64.RawURLEncoding.EncodeToString(buf)

	log.Printf("[SECURITY] %s not set — generated a one-time root password: %s (save this now, it will not be shown again)", envVar, generated)

	return generated
}

// getServiceSecrets parses "svc:secret,svc2:secret2" into a per-service
// credential map. Fatal if empty: a missing service credential set is a
// misconfiguration, same as a missing JWT key (see getJWTSecretKey).
func getServiceSecrets(envVar string) map[string][]byte {
	secrets := map[string][]byte{}
	for _, entry := range strings.Split(os.Getenv(envVar), ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			log.Fatalf("%s entry %q must be in the form service:secret", envVar, entry)
		}
		secrets[parts[0]] = []byte(parts[1])
	}
	if len(secrets) == 0 {
		log.Fatalf("%s must not be empty", envVar)
	}
	return secrets
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// getEnvs parses a comma-separated env var into a trimmed, non-empty slice.
func getEnvs(key string, fallback []string) []string {
	value, exists := os.LookupEnv(key)
	if !exists || strings.TrimSpace(value) == "" {
		return fallback
	}

	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	if len(result) == 0 {
		return fallback
	}
	return result
}

func getEnvInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if n, err := strconv.Atoi(value); err == nil {
			return n
		}
		log.Printf("invalid int value for %s, using default %d", key, fallback)
	}
	return fallback
}

func getEnvFloat(key string, fallback float64) float64 {
	if value, exists := os.LookupEnv(key); exists {
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return f
		}
		log.Printf("invalid float value for %s, using default %v", key, fallback)
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
		log.Printf("invalid bool value for %s, using default %v", key, fallback)
	}
	return fallback
}

// sensitiveConfigFields lists fields whose values must never be written to logs.
var sensitiveConfigFields = map[string]bool{
	"JWTSecretKey":   true,
	"JWTRefreshKey":  true,
	"ServiceSecrets": true,
	"RootPassword":   true,
}

func (cfg *EnvConfig) ToString() string {
	var strBuilder strings.Builder

	reflectedValues := reflect.ValueOf(cfg).Elem()
	reflectedTypes := reflect.TypeOf(cfg).Elem()

	strBuilder.WriteString(fmt.Sprintf("[CFG]CONFIGURATION: %s\n", cfg.ConfigPath))

	for i := 0; i < reflectedValues.NumField(); i++ {
		fieldName := reflectedTypes.Field(i).Name
		fieldValue := reflectedValues.Field(i).Interface()

		if sensitiveConfigFields[fieldName] {
			fieldValue = "[REDACTED]"
		} else if byteSlice, ok := fieldValue.([]byte); ok {
			fieldValue = string(byteSlice)
		}

		strBuilder.WriteString("[CFG]")
		if i < 9 {
			strBuilder.WriteString(fmt.Sprintf("%d.  ", i+1))
		} else {
			strBuilder.WriteString(fmt.Sprintf("%d. ", i+1))
		}
		if len(fieldName) < 7 {
			strBuilder.WriteString(fmt.Sprintf("%v\t\t-> %v\n", fieldName, fieldValue))
		} else if len(fieldName) < 14 {
			strBuilder.WriteString(fmt.Sprintf("%v\t-> %v\n", fieldName, fieldValue))
		} else {
			strBuilder.WriteString(fmt.Sprintf("%v\t-> %v\n", fieldName, fieldValue))
		}
	}

	return strBuilder.String()
}

func (cfg *EnvConfig) Addr() string {
	return cfg.IP + ":" + cfg.API_PORT
}
