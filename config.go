package minioth

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"

	"github.com/joho/godotenv"
)

type EnvConfig struct {
	ConfigPath     string
	CertFile       string
	KeyFile        string
	HTTPPort       string
	HTTPSPort      string
	IP             string
	DBfile         string
	AllowedOrigins []string
	AllowedHeaders []string
	AllowedMethods []string
}

func LoadConfig(path string) *EnvConfig {
	if err := godotenv.Load(path); err != nil {
		log.Printf("Could not load %s config file. Using default variables", path)
	}

	split := strings.Split(path, "/")

	config := &EnvConfig{
		ConfigPath:     split[len(split)-1],
		CertFile:       getEnv("CERTFILE", "f4k3"),
		KeyFile:        getEnv("KEYFILE", "f4k3"),
		HTTPPort:       getEnv("HTTP_PORT", "80"),
		HTTPSPort:      getEnv("HTTPS_PORT", "443"),
		IP:             getEnv("IP", "localhost"),
		DBfile:         getEnv("DB_NAME", "data/database.db"),
		AllowedOrigins: getEnvs("ALLOWED_ORIGINS", []string{"None"}),
		AllowedHeaders: getEnvs("ALLOWED_HEADERS", nil),
		AllowedMethods: getEnvs("ALLOWED_METHODS", nil),
	}

	return config
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
	return cfg.IP + ":" + cfg.HTTPPort
}

func (cfg *EnvConfig) TLSAddr() string {
	return cfg.IP + ":" + cfg.HTTPSPort
}
