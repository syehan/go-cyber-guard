package config

import (
	"log"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	AppName               string        `mapstructure:"APP_NAME"`
	AppVersion            string        `mapstructure:"APP_VERSION"`
	AppPort               string        `mapstructure:"APP_PORT"`
	AppEnv                string        `mapstructure:"APP_ENV"`
	AppDefaultTimeout     time.Duration `mapstructure:"APP_DEFAULT_TIMEOUT"`
	SecurityBlockBirthdate bool          `mapstructure:"SECURITY_BLOCK_BIRTHDATE"`
	HeaderBlocklistRaw    string        `mapstructure:"SECURITY_HEADER_BLOCKLIST"`
	HeaderWhitelistRaw    string        `mapstructure:"SECURITY_HEADER_WHITELIST"`
	HeaderBlocklist       []string
	HeaderWhitelist       []string
}

func LoadConfig(path string) *Config {
	v := viper.New()
	v.AddConfigPath(path)
	v.AddConfigPath("./")
	v.AddConfigPath("../")
	v.SetConfigName(".env")
	v.SetConfigType("env")

	v.SetDefault("APP_NAME", "cyber-mobile-guard")
	v.SetDefault("APP_VERSION", "1.0.0")
	v.SetDefault("APP_PORT", "8085")
	v.SetDefault("APP_ENV", "local")
	v.SetDefault("APP_DEFAULT_TIMEOUT", "5s")
	v.SetDefault("SECURITY_BLOCK_BIRTHDATE", true)

	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		log.Printf("[config] Info: .env file not found or error: %v, using defaults / env vars", err)
	}

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		log.Fatalf("[config] Error unmarshalling config: %v", err)
	}

	cfg.HeaderBlocklist = splitAndTrim(cfg.HeaderBlocklistRaw)
	cfg.HeaderWhitelist = splitAndTrim(cfg.HeaderWhitelistRaw)

	return cfg
}

func splitAndTrim(raw string) []string {
	var result []string
	if raw == "" {
		return result
	}
	parts := strings.Split(raw, ",")
	for _, p := range parts {
		trimmed := strings.ToLower(strings.TrimSpace(p))
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
