package decision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// This fixture tests accidental cross-tenant SQL scope and pool reuse.
// A custom GUC is NOT a trusted identity against arbitrary SQL by the login.
func TestPostgresStoreTransactionTenantContext(t *testing.T) {
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
	seed := fmt.Sprintf("%d", time.Now().UnixNano())
	schema, role := "tenant_ctx_"+seed, "tenant_app_"+seed
	password := "ephemeral_ctx_" + seed
	exec := func(stmt string) {
		t.Helper()
		if _, err := admin.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	exec("CREATE SCHEMA " + schema)
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	exec("CREATE ROLE " + role + " LOGIN PASSWORD '" + password + "'")
	defer func() {
		_, _ = admin.ExecContext(context.Background(), "DROP OWNED BY "+role)
		_, _ = admin.ExecContext(context.Background(), "DROP ROLE "+role)
	}()
	if err := MigrateInSchema(ctx, admin, schema); err != nil {
		t.Fatal(err)
	}
	exec("GRANT USAGE ON SCHEMA " + schema + " TO " + role)
	exec("GRANT SELECT, INSERT ON " + schema + ".decision_records TO " + role)
	exec("GRANT INSERT ON " + schema + ".outbox_events TO " + role)
	predicate := "tenant_id = nullif(pg_catalog.current_setting('decision.tenant_id', true), '')"
	exec("ALTER TABLE " + schema + ".decision_records ENABLE ROW LEVEL SECURITY")
	exec("CREATE POLICY context_select ON " + schema + ".decision_records FOR SELECT TO " + role + " USING (" + predicate + ")")
	exec("CREATE POLICY context_insert ON " + schema + ".decision_records FOR INSERT TO " + role + " WITH CHECK (" + predicate + ")")
	exec("ALTER TABLE " + schema + ".outbox_events ENABLE ROW LEVEL SECURITY")
	exec("CREATE POLICY context_outbox ON " + schema + ".outbox_events FOR INSERT TO " + role + " WITH CHECK (" + predicate + ")")
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = role, password
	cfg.RuntimeParams["search_path"] = schema + ", pg_catalog, pg_temp"
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var identity string
	if err := db.QueryRowContext(ctx, "SELECT session_user").Scan(&identity); err != nil || identity != role {
		t.Fatalf("expected restricted login: %q %v", identity, err)
	}

	store := NewPostgresStore(db)
	makeRecord := func(tenant, digit string) Record {
		return Record{
			TenantID: tenant, InvocationID: "same-invocation",
			DecisionID: "dec_" + strings.Repeat(digit, 64),
			AgentID: "agent-1", SessionID: "session-1", RunID: "run-1",
			RequestSHA256: strings.Repeat("b", 64), CreatedAt: time.Now().UTC(),
			Status: StatusProposed, ReasonCodes: []string{}, Evidence: []EvidenceRef{},
			Plan: PlanCandidate{PlanID: "plan_ctx", SchemaVersion: SchemaVersion, Steps: []PlanStep{}},
		}
	}
	a, b := makeRecord("tenant-a", "a"), makeRecord("tenant-b", "b")
	assertClean := func() {
		t.Helper()
		var clean bool
		var count int
		if err := db.QueryRowContext(ctx, "SELECT nullif(pg_catalog.current_setting('decision.tenant_id', true), '') IS NULL, (SELECT count(*) FROM decision_records)").Scan(&clean, &count); err != nil || !clean || count != 0 {
			t.Fatalf("tenant context leaked outside transaction: clean=%t visible=%d err=%v", clean, count, err)
		}
	}
	for _, rec := range []Record{a, b} {
		if _, created, err := store.SaveOrGet(ctx, rec); err != nil || !created {
			t.Fatalf("tenant-bound create %s: created=%t err=%v", rec.TenantID, created, err)
		}
		assertClean()
	}
	for _, rec := range []Record{a, b, a} {
		if got, created, err := store.SaveOrGet(ctx, rec); err != nil || created || got.DecisionID != rec.DecisionID {
			t.Fatalf("tenant-bound replay %s: created=%t err=%v", rec.TenantID, created, err)
		}
		assertClean()
		if got, err := store.GetByInvocation(ctx, rec.TenantID, rec.InvocationID); err != nil || got.DecisionID != rec.DecisionID {
			t.Fatalf("tenant-bound invocation %s: %v", rec.TenantID, err)
		}
		assertClean()
		if got, err := store.GetByDecisionID(ctx, rec.TenantID, rec.AgentID, rec.SessionID, rec.DecisionID); err != nil || got.DecisionID != rec.DecisionID {
			t.Fatalf("tenant-bound decision %s: %v", rec.TenantID, err)
		}
		assertClean()
		if got, err := store.ListByRun(ctx, rec.TenantID, rec.AgentID, rec.SessionID, rec.RunID, nil, 10); err != nil || len(got) != 1 || got[0].DecisionID != rec.DecisionID {
			t.Fatalf("tenant-bound listing %s: %v", rec.TenantID, err)
		}
		assertClean()
	}
	if _, err := store.GetByDecisionID(ctx, a.TenantID, a.AgentID, a.SessionID, b.DecisionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant decision must be absent: %v", err)
	}
	assertClean()
	// Force the second insert of the atomic write to fail, then reuse the same
	// pool connection. Neither the ledger nor the tenant setting may survive.
	exec("DROP POLICY context_outbox ON " + schema + ".outbox_events")
	failed := makeRecord("tenant-c", "c")
	if _, created, err := store.SaveOrGet(ctx, failed); err == nil || created {
		t.Fatalf("outbox denial must roll back: created=%t err=%v", created, err)
	}
	assertClean()
	var records, events int
	if err := admin.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM "+schema+".decision_records), (SELECT count(*) FROM "+schema+".outbox_events)").Scan(&records, &events); err != nil || records != 2 || events != 2 {
		t.Fatalf("atomic rollback: records=%d events=%d err=%v", records, events, err)
	}
	if got, err := store.GetByInvocation(ctx, b.TenantID, b.InvocationID); err != nil || got.DecisionID != b.DecisionID {
		t.Fatalf("connection reuse after rollback: %v", err)
	}
	assertClean()
}
