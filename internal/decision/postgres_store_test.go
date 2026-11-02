package decision

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresStoreRequiresDatabase(t *testing.T) {
	store := NewPostgresStore(nil)
	_, _, err := store.SaveOrGet(context.Background(), Record{})
	if !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("expected ErrStoreUnavailable, got %v", err)
	}
}

func TestPostgresStoreIdempotencyAndTenantIsolation(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS decision_records (
			tenant_id TEXT NOT NULL,
			idempotency_key TEXT NOT NULL,
			decision_id TEXT NOT NULL,
			request_sha256 CHAR(64) NOT NULL,
			record JSONB NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (tenant_id, idempotency_key),
			UNIQUE (tenant_id, decision_id)
		)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			"DELETE FROM decision_records WHERE tenant_id = $1", "store-integration-test")
	})

	store := NewPostgresStore(db)
	record := Record{
		DecisionID: "dec_integration_001",
		TenantID: "store-integration-test",
		IdempotencyKey: "same-key",
		RequestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Status: StatusProposed,
		ReasonCodes: []string{},
		Evidence: []EvidenceRef{},
		Plan: PlanCandidate{PlanID: "plan_integration_001", SchemaVersion: SchemaVersion, Steps: []PlanStep{}},
	}
	first, created, err := store.SaveOrGet(ctx, record)
	if err != nil || !created {
		t.Fatalf("first save: created=%v err=%v", created, err)
	}
	second, created, err := store.SaveOrGet(ctx, record)
	if err != nil || created || second.DecisionID != first.DecisionID {
		t.Fatalf("replay: created=%v err=%v record=%+v", created, err, second)
	}
	changed := record
	changed.RequestSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, _, err := store.SaveOrGet(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}

	otherTenant := record
	otherTenant.TenantID = "store-integration-test-other"
	otherTenant.DecisionID = "dec_integration_002"
	if _, created, err := store.SaveOrGet(ctx, otherTenant); err != nil || !created {
		t.Fatalf("tenant isolation: created=%v err=%v", created, err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			"DELETE FROM decision_records WHERE tenant_id = $1", "store-integration-test-other")
	})
}
