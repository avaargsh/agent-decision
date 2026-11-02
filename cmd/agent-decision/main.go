package main

import (
	"log"
	"net/http"
	"time"

	"github.com/avaargsh/agent-decision/internal/api"
	"github.com/avaargsh/agent-decision/internal/decision"
)

func main() {
	// No authentication/persistent store yet: never bind to a public interface.
	srv := &http.Server{Addr: "127.0.0.1:8080", Handler: api.NewHandler(decision.NewService(decision.NewMemoryStore())), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("agent-decision dev server on %s (loopback only)", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}
