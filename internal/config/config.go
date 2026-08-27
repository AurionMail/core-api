package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	Port           string
	Env            string
	DBConn         string
	JWTSecret      string
	LDAPURL        string
	LDAPBaseDN     string
	LDAPUserAttr   string
	AllowedOrigins []string
	InternalSecret string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	rawOrigins := getEnv("ALLOWED_ORIGINS", "http://localhost:3000")
	var origins []string
	for _, o := range strings.Split(rawOrigins, ",") {
		if trimmed := strings.TrimSpace(o); trimmed != "" {
			origins = append(origins, trimmed)
		}
	}

	dbConn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s",
		getEnv("DB_USER", "aurion"),
		getEnv("DB_PASSWORD", "aurion_secret_pass"),
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_NAME", "aurion_db"),
		getEnv("DB_SSLMODE", "disable"),
	)

	return &Config{
		Port:           getEnv("PORT", "8080"),
		Env:            getEnv("ENV", "development"),
		DBConn:         dbConn,
		JWTSecret:      getEnv("JWT_SECRET", "super-secret-key-change-in-production"),
		LDAPURL:        getEnv("LDAP_URL", "ldap://localhost:389"),
		LDAPBaseDN:     getEnv("LDAP_BASE_DN", "ou=users,dc=aurion,dc=io"),
		LDAPUserAttr:   getEnv("LDAP_USER_ATTR", "mail"),
		AllowedOrigins: origins,
		InternalSecret: getEnv("INTERNAL_SECRET", "internal-secret-key-change-in-production"),
	}, nil
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
