package decision

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
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
	migration, err := os.ReadFile("../../migrations/0001_create_decision_records.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(migration)); err != nil {
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

	concurrent := record
	concurrent.IdempotencyKey = "concurrent-key"
	concurrent.DecisionID = "dec_integration_003"
	const workers = 12
	var wg sync.WaitGroup
	createdResults := make(chan bool, workers)
	errResults := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, created, err := store.SaveOrGet(ctx, concurrent)
			createdResults <- created
			errResults <- err
		}()
	}
	wg.Wait()
	close(createdResults)
	close(errResults)
	winners := 0
	for created := range createdResults {
		if created {
			winners++
		}
	}
	for err := range errResults {
		if err != nil {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("expected exactly one concurrent insert winner, got %d", winners)
	}

}
