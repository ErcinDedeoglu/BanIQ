package main

import (
	"os"
)

type Config struct {
	DockerSocket      string
	Fail2BanConfigDir string
	Fail2BanJailDir   string
	Fail2BanFilterDir string
}

func NewConfig() (*Config, error) {
	// Default configuration
	config := &Config{
		DockerSocket:      "/var/run/docker.sock",
		Fail2BanConfigDir: "/etc/fail2ban",
		Fail2BanJailDir:   "/etc/fail2ban/jail.d",
		Fail2BanFilterDir: "/etc/fail2ban/filter.d",
	}

	// Ensure directories exist
	dirs := []string{config.Fail2BanJailDir, config.Fail2BanFilterDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}

	return config, nil
}
