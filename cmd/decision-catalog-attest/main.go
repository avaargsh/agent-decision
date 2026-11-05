// Command decision-catalog-attest runs an isolated, read-only PostgreSQL
// deployment acceptance check. It never applies migrations or repairs drift.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func attest(ctx context.Context, dsn, schema string) error {
	if strings.TrimSpace(dsn) == "" {
		return errors.New("missing DECISION_ATTEST_DATABASE_URL")
	}
	if strings.TrimSpace(schema) == "" {
		return errors.New("missing explicit DECISION_ATTEST_SCHEMA")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open attestation connection: %w", err)
	}
	defer db.Close()
	return decision.VerifyInstalledCatalogInSchema(ctx, db, schema)
}

func main() {
	ctx, cancelSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelSignal()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if err := attest(ctx, os.Getenv("DECISION_ATTEST_DATABASE_URL"), os.Getenv("DECISION_ATTEST_SCHEMA")); err != nil {
		// Error details can include PostgreSQL identifiers. Do not emit DSNs,
		// secrets or record payloads in an unattended deployment log.
		fmt.Fprintln(os.Stderr, "Decision catalog attestation FAILED; deployment remains blocked")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "Decision catalog attestation PASS")
}
