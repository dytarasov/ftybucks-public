package config

import (
	"encoding/base64"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    string        `yaml:"server"`
	Listen    string        `yaml:"listen"`
	SNI       string        `yaml:"sni"`
	TunName   string        `yaml:"tun_name"`
	TunCIDR   string        `yaml:"tun_cidr"`
	DNS       string        `yaml:"dns"`
	PSK       string        `yaml:"psk"`
	Gateway   string        `yaml:"gateway"`
	Padding   PaddingConfig `yaml:"padding"`
	JitterMs  int           `yaml:"jitter_ms"`
}

type PaddingConfig struct {
	Min int `yaml:"min"`
	Max int `yaml:"max"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.PSK == "" {
		return fmt.Errorf("psk is required")
	}
	pskBytes, err := base64.StdEncoding.DecodeString(c.PSK)
	if err != nil {
		return fmt.Errorf("psk must be valid base64: %w", err)
	}
	if len(pskBytes) < 32 {
		return fmt.Errorf("psk must be at least 32 bytes (got %d)", len(pskBytes))
	}
	if c.Padding.Min < 0 || c.Padding.Max < 0 {
		return fmt.Errorf("padding min/max must be non-negative")
	}
	if c.Padding.Max > 0 && c.Padding.Min > c.Padding.Max {
		return fmt.Errorf("padding min must be <= max")
	}
	return nil
}

func (c *Config) PSKBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(c.PSK)
}
