// src/dockermonitor.go

package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

const (
	labelPrefix  = "baniq."
	labelEnabled = "baniq.enabled"
)

type DockerMonitor struct {
	client     *client.Client
	f2bManager *Fail2BanManager
	config     *Config
}

func NewDockerMonitor(cfg *Config, f2bManager *Fail2BanManager) (*DockerMonitor, error) {
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix://"+cfg.DockerSocket),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	return &DockerMonitor{
		client:     cli,
		f2bManager: f2bManager,
		config:     cfg,
	}, nil
}

func (m *DockerMonitor) Start(ctx context.Context) error {
	// Set up filter for container events
	filter := filters.NewArgs()
	filter.Add("type", "container")
	filter.Add("event", "start")
	filter.Add("event", "die")
	filter.Add("event", "stop")
	filter.Add("event", "destroy")

	// Listen for Docker events
	eventsCh, errCh := m.client.Events(ctx, types.EventsOptions{
		Filters: filter,
	})

	for {
		select {
		case event := <-eventsCh:
			if err := m.handleEvent(ctx, event); err != nil {
				log.Printf("Error handling event: %v", err)
			}
		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("error from Docker events: %w", err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *DockerMonitor) handleEvent(ctx context.Context, event events.Message) error {
	containerId := event.Actor.ID
	log.Printf("Received event %s for container %s", event.Action, containerId)

	switch event.Action {
	case "start":
		return m.handleContainerStart(ctx, containerId)
	case "die", "stop", "destroy":
		return m.handleContainerStop(containerId)
	}
	return nil
}

func (m *DockerMonitor) handleContainerStart(ctx context.Context, containerId string) error {
	container, err := m.client.ContainerInspect(ctx, containerId)
	if err != nil {
		return fmt.Errorf("failed to inspect container %s: %w", containerId, err)
	}

	// Check if BanIQ is enabled for this container
	if enabled, ok := container.Config.Labels[labelEnabled]; !ok || enabled != "true" {
		log.Printf("BanIQ not enabled for container %s (%s), skipping",
			containerId[:12], container.Name)
		return nil
	}

	// Extract jail configurations from labels
	jailConfigs := extractJailConfigs(container.Config.Labels, container.Name)
	if len(jailConfigs) == 0 {
		log.Printf("No jail configurations found for container %s", containerId)
		return nil
	}

	// Apply jail configurations
	for _, jailConfig := range jailConfigs {
		// If there's a custom inline filter (failregex is set), create a new filter file
		if jailConfig.FailRegex != "" {
			// If no filtername is provided, fallback to the normal jailConfig.Filter
			customName := jailConfig.CustomFilterName
			if customName == "" {
				// if neither is set, generate something, e.g. containerId[:12] + "_" + jailConfig.Name
				if jailConfig.Filter != "" {
					customName = jailConfig.Filter
				} else {
					customName = containerId[:12] + "_" + jailConfig.Name
				}
			}
			newFilterName, err := m.f2bManager.GenerateCustomFilter(
				customName,
				jailConfig.FailRegex,
				jailConfig.IgnoreRegex,
			)
			if err != nil {
				return fmt.Errorf("failed to create custom filter for container %s: %w", containerId, err)
			}
			// Override jailConfig.Filter to the newly generated filter name
			jailConfig.Filter = newFilterName
		}

		if err := m.f2bManager.AddJail(containerId, jailConfig); err != nil {
			return fmt.Errorf("failed to add jail for container %s: %w", containerId, err)
		}
	}

	return nil
}

func (m *DockerMonitor) handleContainerStop(containerId string) error {
	// Remove all jails for this container
	if err := m.f2bManager.RemoveJailsForContainer(containerId); err != nil {
		return fmt.Errorf("failed to remove jails for container %s: %w", containerId, err)
	}
	return nil
}

func (m *DockerMonitor) ProcessExistingContainers(ctx context.Context) error {
	containers, err := m.client.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	for _, container := range containers {
		if err := m.handleContainerStart(ctx, container.ID); err != nil {
			log.Printf("Error processing existing container %s: %v", container.ID, err)
		}
	}
	return nil
}

func extractJailConfigs(labels map[string]string, containerName string) []JailConfig {
	var jailConfigs []JailConfig
	jails := make(map[string]JailConfig)

	// First pass: identify all jail names
	for label := range labels {
		if !strings.HasPrefix(label, labelPrefix) {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(label, labelPrefix), ".", 2)
		if len(parts) != 2 {
			continue
		}

		jailName := parts[0]
		if jailName == "enabled" {
			// skip
			continue
		}
		// If we haven't seen this jailName yet, init a JailConfig
		if _, exists := jails[jailName]; !exists {
			jails[jailName] = JailConfig{
				Name:          jailName,
				ContainerName: strings.TrimPrefix(containerName, "/"),
			}
		}
	}

	// Second pass: fill in jail configurations
	for label, value := range labels {
		if !strings.HasPrefix(label, labelPrefix) {
			continue
		}
		trimmed := strings.TrimPrefix(label, labelPrefix)
		parts := strings.SplitN(trimmed, ".", 2)
		if len(parts) != 2 {
			continue
		}
		jailName := parts[0]
		if jailName == "enabled" {
			// skip
			continue
		}
		property := parts[1]
		jailConfig := jails[jailName]

		switch property {
		case "logpath":
			jailConfig.LogPath = value
		case "filter":
			// Typically the name of a pre-existing filter
			jailConfig.Filter = value
		case "filtername":
			// Our new custom filter name label
			jailConfig.CustomFilterName = value
		case "failregex":
			jailConfig.FailRegex = value
		case "ignoreregex":
			jailConfig.IgnoreRegex = value
		case "findtime":
			jailConfig.FindTime = value
		case "maxretry":
			jailConfig.MaxRetry = value
		case "bantime":
			jailConfig.BanTime = value
		case "port":
			jailConfig.Port = value
		case "protocol":
			jailConfig.Protocol = value
		}
		jails[jailName] = jailConfig
	}

	// Convert jails map to a slice
	for _, config := range jails {
		// If there's no logpath, it's effectively incomplete
		// However, you might allow empty logpath if you want
		// We'll skip if filter and logpath are both blank
		if config.LogPath == "" && config.Filter == "" && config.FailRegex == "" {
			log.Printf("Skipping incomplete jail configuration for %s", config.Name)
			continue
		}
		jailConfigs = append(jailConfigs, config)
	}

	return jailConfigs
}
