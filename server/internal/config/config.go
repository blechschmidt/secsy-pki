package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	OIDC     OIDCConfig     `yaml:"oidc"`
	RootUser RootUserConfig `yaml:"root_user"`
	PKCS11   PKCS11Config   `yaml:"pkcs11"`
}

type ServerConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	TLSCert  string `yaml:"tls_cert"`
	TLSKey   string `yaml:"tls_key"`
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type OIDCConfig struct {
	IssuerURL   string `yaml:"issuer_url"`
	ClientID    string `yaml:"client_id"`
	RedirectURL string `yaml:"redirect_url"`
}

type RootUserConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type PKCS11Config struct {
	ModulePath string `yaml:"module_path"`
	Pin        string `yaml:"pin"`
	TokenLabel string `yaml:"token_label"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg := &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8443,
		},
		Database: DatabaseConfig{
			Driver: "sqlite",
			DSN:    "ssh-pki.db",
		},
		RootUser: RootUserConfig{
			Username: "root",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if cfg.RootUser.Password == "" {
		return nil, fmt.Errorf("root_user.password is required")
	}

	return cfg, nil
}
