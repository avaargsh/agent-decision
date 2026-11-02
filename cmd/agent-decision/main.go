package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/avaargsh/agent-decision/internal/api"
	"github.com/avaargsh/agent-decision/internal/decision"
	"github.com/avaargsh/agent-decision/internal/store"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var decisionStore decision.Store
	var database *sql.DB
	if databaseURL := os.Getenv("DATABASE_URL"); databaseURL != "" {
		migrationURL := os.Getenv("MIGRATOR_DATABASE_URL")
		if migrationURL == "" {
			migrationURL = databaseURL
			log.Print("WARNING: MIGRATOR_DATABASE_URL is unset; applying migrations with DATABASE_URL credentials")
		}
		migrator, err := store.OpenPostgres(ctx, migrationURL)
		if err != nil {
			log.Fatal(err)
		}
		if err := store.Migrate(ctx, migrator); err != nil {
			log.Fatalf("migrate PostgreSQL: %v", err)
		}
		if migrationURL == databaseURL {
			database = migrator
		} else {
			if err := migrator.Close(); err != nil {
				log.Fatalf("close migrator connection: %v", err)
			}
			database, err = store.OpenPostgres(ctx, databaseURL)
			if err != nil {
				log.Fatal(err)
			}
		}
		defer database.Close()
		decisionStore = store.NewPostgresStore(database)
	} else {
		log.Print("WARNING: using in-memory development store; records are lost on restart")
		decisionStore = decision.NewMemoryStore()
	}

	// Intentionally no principal resolver or ACP authority adapter is wired here.
	// Decision requests fail closed until trusted production adapters are configured.
	service := decision.NewService(decisionStore, nil)
	server := &http.Server{
		Addr:              "127.0.0.1:8080",
		Handler:           api.NewHandler(service),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("agent-decision development server on %s (loopback only; decision endpoint fails closed without trusted adapters)", server.Addr)
	log.Fatal(server.ListenAndServe())
}
