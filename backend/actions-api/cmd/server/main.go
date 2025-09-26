package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"backend/actions-api/internal/api"
)

func main() {
	var (
		addr = flag.String("addr", ":8083", "Server address")
	)
	flag.Parse()

	// Create and configure server
	server := api.NewServer()
	server.SetupRoutes()

	// Start server in goroutine
	go func() {
		if err := server.Start(*addr); err != nil {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down server...")
}



