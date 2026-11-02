package main

import (
	"log"
	"net/http"
	"time"

	"github.com/avaargsh/agent-decision/internal/api"
	"github.com/avaargsh/agent-decision/internal/decision"
)

func main() {
	// Deliberately fail closed: this development binary has neither an
	// authenticated principal resolver nor an ACP snapshot verifier.
	service := decision.NewService(decision.NewMemoryStore(), nil)
	handler := api.NewHandler(service, nil)
	server := &http.Server{
		Addr:              "127.0.0.1:8080",
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("agent-decision dev server on %s; decision calls fail closed until auth and ACP verification are configured", server.Addr)
	log.Fatal(server.ListenAndServe())
}
