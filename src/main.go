package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	log.Println("Starting BanIQ - Fail2Ban and iptables container manager")

	// Initialize configuration
	cfg, err := NewConfig()
	if err != nil {
		log.Fatalf("Failed to initialize configuration: %v", err)
	}

	// Initialize Fail2Ban manager
	f2bManager, err := NewFail2BanManager(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize Fail2Ban manager: %v", err)
	}

	// Initialize Docker monitor
	dockerMonitor, err := NewDockerMonitor(cfg, f2bManager)
	if err != nil {
		log.Fatalf("Failed to initialize Docker monitor: %v", err)
	}

	// Create context that can be canceled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitoring Docker events
	go func() {
		if err := dockerMonitor.Start(ctx); err != nil {
			log.Fatalf("Docker monitor failed: %v", err)
		}
	}()

	// Process existing containers
	if err := dockerMonitor.ProcessExistingContainers(ctx); err != nil {
		log.Fatalf("Failed to process existing containers: %v", err)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Received shutdown signal, stopping BanIQ...")
	cancel()
}
