package minioth

import (
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

	DB             string
	JWKS           string
	JWTSecretKey   []byte
	JWTRefreshKey  []byte
	ServiceSecret  []byte
	AllowedOrigins []string
	AllowedHeaders []string
	AllowedMethods []string
	HashCost       int
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
		DB:             getEnv("DP_PATH", "data/database.db"),
		AllowedOrigins: getEnvs("ALLOWED_ORIGINS", []string{"None"}),
		AllowedHeaders: getEnvs("ALLOWED_HEADERS", nil),
		AllowedMethods: getEnvs("ALLOWED_METHODS", nil),
		JWTSecretKey:   getJWTSecretKey("JWT_SECRET_KEY"),
		JWTRefreshKey:  getJWTSecretKey("JWT_REFRESH_KEY"),
		JWKS:           getEnv("JWKS", "jwks.json"),
		ServiceSecret:  getJWTSecretKey("SERVICE_SECRET"),
		HashCost:       hashcost,
	}

	return config
}

func getJWTSecretKey(envVar string) []byte {
	secret := os.Getenv(envVar)
	if secret == "" {
		log.Fatalf("%s must not be empty", secret)
	}
	return []byte(secret)
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvs(key string, fallback []string) []string {
	if value, exists := os.LookupEnv(key); exists {
		values := strings.SplitAfter(value, ",")
		return values
	}

	return fallback
}

// CertFile string, KeyFile string, HTTPPort string, HTTPSPort string, IP string, DBfile string, AllowedOrigins []string, AllowedHeaders []string
// AllowedMethods []string
func (cfg *EnvConfig) ToString() string {
	var strBuilder strings.Builder

	reflectedValues := reflect.ValueOf(cfg).Elem()
	reflectedTypes := reflect.TypeOf(cfg).Elem()

	strBuilder.WriteString(fmt.Sprintf("[CFG]CONFIGURATION: %s\n", cfg.ConfigPath))

	for i := 0; i < reflectedValues.NumField(); i++ {
		fieldName := reflectedTypes.Field(i).Name
		fieldValue := reflectedValues.Field(i).Interface()

		if byteSlice, ok := fieldValue.([]byte); ok {
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
