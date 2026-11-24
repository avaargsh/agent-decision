package decision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresStoreRejectsZeroNormalizedCreationTime(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("write_timestamp_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	if err := MigrateInSchema(ctx, admin, schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema + ", pg_catalog, pg_temp"
	db := stdlib.OpenDB(*cfg)
	defer db.Close()

	store := NewPostgresStore(db)
	p := testPrincipal()
	req := validRequest()
	record, err := recordFromVerifiedRequest(p, req, SREReadOnlyStrategy{}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	counts := func(want int) {
		t.Helper()
		var records, events int
		err := db.QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM decision_records WHERE tenant_id=$1 AND invocation_id=$2),
			(SELECT count(*) FROM outbox_events WHERE tenant_id=$1 AND aggregate_id=$3)`,
			record.TenantID, record.InvocationID, record.DecisionID).Scan(&records, &events)
		if err != nil || records != want || events != want {
			t.Fatalf("durable rows: record=%d event=%d want=%d err=%v", records, events, want, err)
		}
	}
	for _, stamp := range []time.Time{time.Time{}, time.Time{}.Add(time.Nanosecond)} {
		invalid := record
		invalid.CreatedAt = stamp
		if _, created, err := store.SaveOrGet(ctx, invalid); created || !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("zero normalized timestamp must be rejected: created=%t err=%v", created, err)
		}
		counts(0)
		if _, err := store.GetByInvocation(ctx, record.TenantID, record.InvocationID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("rejected write occupied invocation: %v", err)
		}
	}
	// A subsequent valid write must remain possible and readable after restart.
	saved, created, err := store.SaveOrGet(ctx, record)
	if err != nil || !created {
		t.Fatalf("valid retry: created=%t err=%v", created, err)
	}
	counts(1)
	restarted := NewPostgresStore(db)
	loaded, err := restarted.GetByInvocation(ctx, record.TenantID, record.InvocationID)
	if err != nil || digest(loaded) != digest(saved) {
		t.Fatalf("read after write mismatch: %v", err)
	}
	replayed, created, err := restarted.SaveOrGet(ctx, record)
	if err != nil || created || digest(replayed) != digest(saved) {
		t.Fatalf("idempotent replay: created=%t err=%v", created, err)
	}
	counts(1)
}
