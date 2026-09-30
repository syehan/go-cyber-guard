package config

import (
	"log"
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
}

func LoadConfig(path string) *Config {
	v := viper.New()
	v.AddConfigPath(path)
	v.SetConfigName(".env")
	v.SetConfigType("env")

	v.SetDefault("APP_NAME", "plnmobile-cyber-guard")
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

	return cfg
}
