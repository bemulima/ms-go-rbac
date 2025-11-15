package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/ms-rbac-service/internal/app"
)

func main() {
	srv, err := app.Bootstrap()
	if err != nil {
		log.Fatalf("bootstrap failed: %v", err)
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	if err := app.Shutdown(context.Background(), srv); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
