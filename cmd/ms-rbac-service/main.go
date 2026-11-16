package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	srv, err := bootstrap()
	if err != nil {
		log.Fatalf("bootstrap failed: %v", err)
	}

	serverFailure := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverFailure <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	failed := false
	select {
	case <-sigCh:
	case <-mentorOwnerRuntime.Done():
		failed = true
		log.Print("mentor owner transport stopped; shutting down")
	case <-serverFailure:
		failed = true
		log.Print("HTTP listener stopped; shutting down")
	}

	if err := shutdown(context.Background(), srv); err != nil {
		log.Printf("shutdown error: %v", err)
	}
	if failed {
		os.Exit(1)
	}
}
