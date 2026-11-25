package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/avaargsh/agent-decision/internal/api"
	"github.com/avaargsh/agent-decision/internal/decision"
)

func main() {
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
	log.Fatal(server.Serve(listener))
}
