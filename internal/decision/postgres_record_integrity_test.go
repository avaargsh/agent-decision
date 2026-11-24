package decision

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// A valid JSON identity CHECK does not constrain created_at. If the indexed
// timestamp and immutable JSON timestamp disagree, an accepted ledger cursor
// could skip or duplicate records. Reject that record on all read/replay paths.
func TestPostgresStoreRejectsIndexedCreatedAtDrift(t *testing.T) {
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
	schema := fmt.Sprintf("ledger_drift_%d", time.Now().UnixNano())
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

	record := Record{
		TenantID: fmt.Sprintf("index-drift-%d", time.Now().UnixNano()),
		InvocationID: "drift-invocation",
		DecisionID: "dec_" + strings.Repeat("4", 64),
		AgentID: "drift-agent",
		SessionID: "drift-session",
		RunID: "drift-run",
		RequestSHA256: strings.Repeat("5", 64),
		Status: StatusProposed,
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
		ReasonCodes: []string{},
		Evidence: []EvidenceRef{},
		Plan: PlanCandidate{PlanID: "plan_drift", SchemaVersion: SchemaVersion, Steps: []PlanStep{}},
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	// This insert is accepted by v0001-v0004: identity CHECKs cover the
	// tenant/invocation/decision/digest but not the index timestamp.
	_, err = db.ExecContext(ctx, `
		INSERT INTO decision_records
			(tenant_id, invocation_id, decision_id, request_sha256, record, created_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
		record.TenantID, record.InvocationID, record.DecisionID,
		record.RequestSHA256, payload, record.CreatedAt.Add(-time.Hour))
	if err != nil {
		t.Fatalf("drift fixture was rejected before read-time verification: %v", err)
	}

	store := NewPostgresStore(db)
	for _, tc := range []struct {
		name string
		read func() error
	}{
		{"GetByInvocation", func() error {
			_, err := store.GetByInvocation(ctx, record.TenantID, record.InvocationID)
			return err
		}},
		{"GetByDecisionID", func() error {
			_, err := store.GetByDecisionID(ctx, record.TenantID, record.AgentID, record.SessionID, record.DecisionID)
			return err
		}},
		{"ListByRun", func() error {
			_, err := store.ListByRun(ctx, record.TenantID, record.AgentID, record.SessionID, record.RunID, nil, 10)
			return err
		}},
		{"SaveOrGet replay", func() error {
			_, _, err := store.SaveOrGet(ctx, record)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.read(); !errors.Is(err, ErrCatalogDrift) {
				t.Fatalf("mismatched indexed created_at must fail closed with ErrCatalogDrift, got %v", err)
			}
		})
	}
}
