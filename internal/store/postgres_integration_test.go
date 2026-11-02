//go:build postgres

package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-decision/internal/auth"
	"github.com/avaargsh/agent-decision/internal/decision"
	"github.com/avaargsh/agent-decision/internal/outbox"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type integrationVerifier struct{}

func (integrationVerifier) Verify(context.Context, auth.Principal, decision.Request) error {
	return nil
}

func postgresTestDB(t *testing.T) (*sql.DB, string, func()) {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is required for PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	adminConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse DATABASE_URL: %v", err)
	}
	adminDB := stdlib.OpenDB(*adminConfig)
	if err := adminDB.PingContext(ctx); err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	schema := fmt.Sprintf("agent_decision_test_%d", time.Now().UnixNano())
	if _, err := adminDB.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}

	open := func() *sql.DB {
		config, err := pgx.ParseConfig(databaseURL)
		if err != nil {
			t.Fatalf("parse DATABASE_URL: %v", err)
		}
		config.RuntimeParams["search_path"] = schema
		db := stdlib.OpenDB(*config)
		db.SetMaxOpenConns(32)
		db.SetMaxIdleConns(8)
		if err := db.PingContext(ctx); err != nil {
			t.Fatalf("connect scoped database: %v", err)
		}
		return db
	}
	db := open()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cleanup := func() {
		_ = db.Close()
		_, _ = adminDB.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		_ = adminDB.Close()
	}
	return db, schema, cleanup
}

func postgresRequest() decision.Request {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	snapshot := func(id, source, marker string) decision.SnapshotRef {
		return decision.SnapshotRef{ID: id, Version: "v1", SHA256: strings.Repeat(marker, 64), Source: source,
			AttestationRef: "attestation:" + id, TrustLevel: "attested", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	}
	capability := func(id, marker string) decision.CapabilityRef {
		return decision.CapabilityRef{ID: id, Version: "1.0.0", ContractSHA256: strings.Repeat(marker, 64),
			InputSchemaRef: "schema:" + id + ":input", OutputSchemaRef: "schema:" + id + ":output",
			EffectClass: "read_only", Idempotency: "safe", TenantScoped: true}
	}
	return decision.Request{
		SchemaVersion:      decision.RequestSchemaVersion,
		Identity:           decision.Identity{AgentID: "agent-a", SessionID: "session-a", RunID: "run-100"},
		IdempotencyKey:     "incident-100",
		Input:              decision.Input{Objective: "sre_incident_triage", Service: "payments", Signal: "latency"},
		Constraints:        decision.Constraints{DeadlineMS: 10000, MaxTokens: 2048, MaxCostMicros: 50000, MaxCandidates: 1},
		Versions:           decision.Versions{CapabilityCatalogVersion: "catalog-v1", StrategyVersion: decision.PolicyVersion, PromptVersion: "none", ModelProfile: "rule-only"},
		ContextSnapshot:    snapshot("ctx-100", "context-store", "a"),
		CapabilitySnapshot: snapshot("cap-100", "agent-control-panel", "b"),
		Capabilities:       []decision.CapabilityRef{capability("sre.metrics.read", "c"), capability("sre.logs.read", "d"), capability("sre.changes.read", "e")},
		Evidence: []decision.EvidenceRef{{Ref: "slo-100", Source: "slo-monitor", SourceVersion: "slo-v1", SHA256: strings.Repeat("f", 64),
			AttestationRef: "attestation:slo-100", TrustLevel: "attested", ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(10 * time.Minute)}},
	}
}

func postgresPrincipal(tenant string) auth.Principal {
	return auth.Principal{TenantID: tenant, Subject: "integration-subject", AgentID: "agent-a"}
}
func postgresService(db *sql.DB) *decision.Service {
	return decision.NewService(NewPostgresStore(db), integrationVerifier{})
}

func TestPostgresRestartReplayAndTenantScopedRead(t *testing.T) {
	db, schema, cleanup := postgresTestDB(t)
	defer cleanup()
	ctx := context.Background()
	service := postgresService(db)
	created, wasCreated, err := service.Decide(ctx, postgresPrincipal("tenant-a"), postgresRequest())
	if err != nil || !wasCreated {
		t.Fatalf("create: created=%t err=%v", wasCreated, err)
	}
	if _, err := service.Get(ctx, postgresPrincipal("tenant-b"), "agent-a", created.DecisionID); err != decision.ErrNotFound {
		t.Fatalf("cross-tenant read leaked record: %v", err)
	}
	if _, err := service.Get(ctx, postgresPrincipal("tenant-a"), "agent-b", created.DecisionID); err != decision.ErrNotFound {
		t.Fatalf("cross-agent read leaked record: %v", err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = schema
	restartedDB := stdlib.OpenDB(*config)
	restartedDB.SetMaxOpenConns(8)
	defer restartedDB.Close()
	if err := Migrate(ctx, restartedDB); err != nil {
		t.Fatalf("idempotent migrate after restart: %v", err)
	}
	restartedService := postgresService(restartedDB)
	replayed, wasCreated, err := restartedService.Decide(ctx, postgresPrincipal("tenant-a"), postgresRequest())
	if err != nil || wasCreated || replayed.DecisionID != created.DecisionID || !replayed.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("restart replay failed: created=%t record=%+v err=%v", wasCreated, replayed, err)
	}
	changed := postgresRequest()
	changed.Input.Signal = "errors"
	if _, _, err := restartedService.Decide(ctx, postgresPrincipal("tenant-a"), changed); err != decision.ErrConflict {
		t.Fatalf("expected payload conflict, got %v", err)
	}
}

func TestPostgresConcurrentIdempotencyAndSingleOutboxEvent(t *testing.T) {
	db, _, cleanup := postgresTestDB(t)
	defer cleanup()
	service := postgresService(db)
	const workers = 64
	var wait sync.WaitGroup
	created := make(chan bool, workers)
	failures := make(chan error, workers)
	ids := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			record, wasCreated, err := service.Decide(context.Background(), postgresPrincipal("tenant-a"), postgresRequest())
			created <- wasCreated
			ids <- record.DecisionID
			failures <- err
		}()
	}
	wait.Wait()
	close(created)
	close(ids)
	close(failures)
	winners := 0
	var decisionID string
	for wasCreated := range created {
		if wasCreated {
			winners++
		}
	}
	for id := range ids {
		if decisionID == "" {
			decisionID = id
		}
		if id != decisionID {
			t.Fatalf("non-deterministic decision IDs: %s != %s", id, decisionID)
		}
	}
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("expected one insert winner, got %d", winners)
	}
	var recordCount, eventCount int
	if err := db.QueryRow(`SELECT count(*) FROM decision_records`).Scan(&recordCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM outbox_events`).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if recordCount != 1 || eventCount != 1 {
		t.Fatalf("expected one record and one outbox event, got records=%d events=%d", recordCount, eventCount)
	}
}

func TestPostgresDecisionAndOutboxRollbackTogether(t *testing.T) {
	db, _, cleanup := postgresTestDB(t)
	defer cleanup()
	_, err := db.Exec(`CREATE FUNCTION fail_outbox_insert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected outbox failure'; END; $$`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TRIGGER fail_outbox BEFORE INSERT ON outbox_events
		FOR EACH ROW EXECUTE FUNCTION fail_outbox_insert()`)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = postgresService(db).Decide(context.Background(), postgresPrincipal("tenant-a"), postgresRequest())
	if err == nil {
		t.Fatal("expected injected outbox failure")
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM decision_records`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("record survived failed outbox transaction: count=%d", count)
	}
}

func TestPostgresDecisionRecordIsAppendOnly(t *testing.T) {
	db, _, cleanup := postgresTestDB(t)
	defer cleanup()
	record, _, err := postgresService(db).Decide(context.Background(), postgresPrincipal("tenant-a"), postgresRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE decision_records SET record_json = '{}'::jsonb WHERE tenant_id = $1 AND decision_id = $2`, record.TenantID, record.DecisionID); err == nil {
		t.Fatal("expected append-only update trigger to reject mutation")
	}
	if _, err := db.Exec(`DELETE FROM decision_records WHERE tenant_id = $1 AND decision_id = $2`, record.TenantID, record.DecisionID); err == nil {
		t.Fatal("expected append-only delete trigger to reject mutation")
	}
	var eventID string
	if err := db.QueryRow(`SELECT event_id FROM outbox_events WHERE tenant_id = $1 AND aggregate_id = $2`, record.TenantID, record.DecisionID).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE outbox_events SET payload = '{}'::jsonb WHERE event_id = $1`, eventID); err == nil {
		t.Fatal("expected outbox payload trigger to reject mutation")
	}
}

func TestPostgresOutboxLeaseRetryAndAck(t *testing.T) {
	db, _, cleanup := postgresTestDB(t)
	defer cleanup()
	_, _, err := postgresService(db).Decide(context.Background(), postgresPrincipal("tenant-a"), postgresRequest())
	if err != nil {
		t.Fatal(err)
	}
	store := NewPostgresStore(db)
	first, err := store.Claim(context.Background(), "worker-a", 10, time.Second)
	if err != nil || len(first) != 1 || first[0].Attempts != 1 {
		t.Fatalf("first claim: events=%+v err=%v", first, err)
	}
	if err := store.Retry(context.Background(), first[0].ID, "worker-a", 0, "temporary failure"); err != nil {
		t.Fatal(err)
	}
	second, err := store.Claim(context.Background(), "worker-b", 10, time.Second)
	if err != nil || len(second) != 1 || second[0].ID != first[0].ID || second[0].Attempts != 2 {
		t.Fatalf("retry claim: events=%+v err=%v", second, err)
	}
	if err := store.Ack(context.Background(), second[0].ID, "worker-b"); err != nil {
		t.Fatal(err)
	}
	if err := store.Ack(context.Background(), second[0].ID, "worker-a"); err != outbox.ErrLeaseLost {
		t.Fatalf("stale worker ack should fail, got %v", err)
	}
	third, err := store.Claim(context.Background(), "worker-c", 10, time.Second)
	if err != nil || len(third) != 0 {
		t.Fatalf("acked event must not be redelivered: %+v err=%v", third, err)
	}
}
