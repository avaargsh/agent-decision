package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestAttestRejectsMissingConfiguration(t *testing.T) {
	if err := attest(context.Background(), "", "public"); err == nil {
		t.Fatal("must reject missing DSN")
	}
	if err := attest(context.Background(), "unused-dsn", ""); err == nil {
		t.Fatal("must reject missing explicit target schema")
	}
}

func TestAttestCommandCheckAgainstInstalledSchema(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil { t.Fatal(err) }
	defer db.Close()
	schema := fmt.Sprintf("attest_cli_%d", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil { t.Fatal(err) }
	defer db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	if err := decision.MigrateInSchema(ctx, db, schema); err != nil { t.Fatal(err) }
	if err := attest(ctx, dsn, schema); err != nil { t.Fatalf("approved schema: %v", err) }
	if _, err := db.ExecContext(ctx, "ALTER TABLE "+schema+".outbox_events DISABLE TRIGGER outbox_events_no_truncate"); err != nil { t.Fatal(err) }
	if err := attest(ctx, dsn, schema); err == nil { t.Fatal("CLI attestation accepted disabled TRUNCATE guard") }
}
