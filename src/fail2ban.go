// src/fail2ban.go

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

type JailConfig struct {
	Name          string
	ContainerName string
	LogPath       string
	Filter        string
	FindTime      string
	MaxRetry      string
	BanTime       string
	Port          string
	Protocol      string

	// NEW FIELDS for inline filters
	CustomFilterName string
	FailRegex        string
	IgnoreRegex      string
}

type Fail2BanManager struct {
	config         *Config
	containerJails map[string][]string // maps container ID to jail conf file names
	mu             sync.Mutex
}

func NewFail2BanManager(cfg *Config) (*Fail2BanManager, error) {
	// Ensure Fail2Ban is installed and running
	if err := exec.Command("fail2ban-client", "ping").Run(); err != nil {
		return nil, fmt.Errorf("fail2ban is not running: %w", err)
	}

	return &Fail2BanManager{
		config:         cfg,
		containerJails: make(map[string][]string),
		mu:             sync.Mutex{},
	}, nil
}

// GenerateCustomFilter writes an inline filter specification to /etc/fail2ban/filter.d/<filterName>.conf
func (m *Fail2BanManager) GenerateCustomFilter(filterName string, failRegex string, ignoreRegex string) (string, error) {
	// If no filterName or failRegex, skip
	if filterName == "" || failRegex == "" {
		return "", nil
	}
	// The path for the new filter
	filterFilePath := filepath.Join(m.config.Fail2BanFilterDir, filterName+".conf")

	// Build the file contents
	filterContent := "[Definition]\n"
	filterContent += fmt.Sprintf("failregex = %s\n", failRegex)
	if ignoreRegex != "" {
		filterContent += fmt.Sprintf("ignoreregex = %s\n", ignoreRegex)
	}

	// Write the file
	err := os.WriteFile(filterFilePath, []byte(filterContent), 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write custom filter file: %w", err)
	}

	log.Printf("Created custom filter file %s for inline filter: %s", filterFilePath, filterName)
	return filterName, nil
}

func (m *Fail2BanManager) AddJail(containerId string, jailConfig JailConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Set defaults if not provided
	if jailConfig.FindTime == "" {
		jailConfig.FindTime = "10m"
	}
	if jailConfig.MaxRetry == "" {
		jailConfig.MaxRetry = "5"
	}
	if jailConfig.BanTime == "" {
		jailConfig.BanTime = "1h"
	}
	if jailConfig.Port == "" {
		jailConfig.Port = "0:65535"
	}
	if jailConfig.Protocol == "" {
		jailConfig.Protocol = "tcp"
	}

	// Create jail file name
	jailFileName := fmt.Sprintf("%s-%s.conf", containerId[:12], jailConfig.Name)
	jailFilePath := filepath.Join(m.config.Fail2BanJailDir, jailFileName)

	// Create jail configuration content
	jailContent := fmt.Sprintf(`
[%s]
enabled = true
filter = %s
logpath = %s
findtime = %s
maxretry = %s
bantime = %s
port = %s
protocol = %s
`,
		jailConfig.Name,
		jailConfig.Filter,
		jailConfig.LogPath,
		jailConfig.FindTime,
		jailConfig.MaxRetry,
		jailConfig.BanTime,
		jailConfig.Port,
		jailConfig.Protocol,
	)

	// Write jail configuration to file
	if err := os.WriteFile(jailFilePath, []byte(jailContent), 0644); err != nil {
		return fmt.Errorf("failed to write jail configuration: %w", err)
	}

	// Add jail to container jails map
	m.containerJails[containerId] = append(m.containerJails[containerId], jailFileName)

	// Reload Fail2Ban
	if err := m.reloadFail2Ban(); err != nil {
		return fmt.Errorf("failed to reload Fail2Ban: %w", err)
	}

	log.Printf("Added jail %s for container %s (filter=%s)", jailConfig.Name, containerId[:12], jailConfig.Filter)
	return nil
}

func (m *Fail2BanManager) RemoveJailsForContainer(containerId string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	jailFiles, exists := m.containerJails[containerId]
	if !exists {
		return nil // No jails for this container
	}

	// Remove each jail file
	for _, jailFile := range jailFiles {
		jailPath := filepath.Join(m.config.Fail2BanJailDir, jailFile)
		if err := os.Remove(jailPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove jail file %s: %w", jailPath, err)
		}
	}

	// Remove container from map
	delete(m.containerJails, containerId)

	// Reload Fail2Ban
	if err := m.reloadFail2Ban(); err != nil {
		return fmt.Errorf("failed to reload Fail2Ban: %w", err)
	}

	log.Printf("Removed jails for container %s", containerId[:12])
	return nil
}

func (m *Fail2BanManager) reloadFail2Ban() error {
	cmd := exec.Command("fail2ban-client", "reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("fail2ban reload failed: %s, %w", output, err)
	}
	log.Printf("Fail2Ban reloaded successfully")
	return nil
}
