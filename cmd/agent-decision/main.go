package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/avaargsh/agent-decision/internal/api"
	"github.com/avaargsh/agent-decision/internal/decision"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	port := flag.Int("port", 8080, "loopback HTTP port (0 chooses a free port)")
	flag.Parse()
	if *port < 0 || *port > 65535 || flag.NArg() != 0 {
		log.Fatal("usage: agent-decision [-port 0..65535]")
	}

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(*port))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("cannot listen on %s (choose another --port): %v", addr, err)
	}
	defer listener.Close()

	// Deliberately fail closed: this development binary has neither an
	// authenticated principal resolver nor an ACP snapshot verifier.
	service := decision.NewService(decision.NewMemoryStore(), nil)
	handler := api.NewHandler(service, nil)
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("agent-decision dev server on %s; decision calls fail closed until auth and ACP verification are configured", listener.Addr())
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	select {
	case err := <-served:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case <-ctx.Done():
		drain, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(drain); err != nil {
			_ = server.Close()
			log.Fatalf("shutdown agent-decision: %v", err)
		}
	}
}
