package outbox_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
	"github.com/avaargsh/agent-decision/internal/outbox"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresOutboxClaimLeaseRetryAndAck(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := admin.PingContext(ctx); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	schema := fmt.Sprintf("outbox_test_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		_, _ = admin.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*config)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		_, _ = admin.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
		t.Fatal(err)
	}
	defer func() {
		_ = db.Close()
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
	}()

	if err := decision.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := decision.Migrate(ctx, db); err != nil {
		t.Fatalf("migration re-entry should be safe: %v", err)
	}
	// Applied migrations must be byte-pinned and contiguous. A version-only
	// presence check silently accepts a tampered name, changed checksum or
	// missing earlier migration while claiming that the schema is current.
	var name, checksum string
	if err := db.QueryRowContext(ctx,
		"SELECT name, checksum FROM schema_migrations WHERE version = 2",
	).Scan(&name, &checksum); err != nil {
		t.Fatalf("migration history must persist content checksum: %v", err)
	}
	if len(checksum) != 64 {
		t.Fatalf("migration checksum missing: %q", checksum)
	}
	if _, err := db.ExecContext(ctx, "UPDATE schema_migrations SET name = 'substituted.sql' WHERE version = 2"); err != nil {
		t.Fatal(err)
	}
	if err := decision.Migrate(ctx, db); err == nil {
		t.Fatal("migration name substitution must fail closed")
	}
	if _, err := db.ExecContext(ctx, "UPDATE schema_migrations SET name = $1 WHERE version = 2", name); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE schema_migrations SET checksum = repeat('0', 64) WHERE version = 2"); err != nil {
		t.Fatal(err)
	}
	if err := decision.Migrate(ctx, db); err == nil {
		t.Fatal("migration checksum substitution must fail closed")
	}
	if _, err := db.ExecContext(ctx, "UPDATE schema_migrations SET checksum = $1 WHERE version = 2", checksum); err != nil {
		t.Fatal(err)
	}
	var checksum0001 string
	if err := db.QueryRowContext(ctx,
		"SELECT checksum FROM schema_migrations WHERE version = 1",
	).Scan(&checksum0001); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version = 1"); err != nil {
		t.Fatal(err)
	}
	if err := decision.Migrate(ctx, db); err == nil {
		t.Fatal("missing earlier migration must not be silently re-applied")
	}
	if _, err := db.ExecContext(ctx,
		"INSERT INTO schema_migrations(version, name, checksum) VALUES (1, $1, $2)",
		"0001_create_decision_records.sql", checksum0001,
	); err != nil {
		t.Fatal(err)
	}
	if err := decision.Migrate(ctx, db); err != nil {
		t.Fatalf("restored authentic migration history must be accepted: %v", err)
	}
	store := decision.NewPostgresStore(db)

	record := decision.Record{
		DecisionID: "dec_" + strings.Repeat("a", 64),
		TenantID: "outbox-test-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		AgentID: "agent-1",
		SessionID: "session-1",
		RunID: "run-1",
		InvocationID: "invocation-1",
		RequestSHA256: strings.Repeat("b", 64),
		CreatedAt: time.Now().UTC(),
		Status: decision.StatusProposed,
		ReasonCodes: []string{},
		Evidence: []decision.EvidenceRef{},
		Plan: decision.PlanCandidate{PlanID: "plan-1", SchemaVersion: decision.SchemaVersion, Steps: []decision.PlanStep{}},
	}
	if _, created, err := store.SaveOrGet(ctx, record); err != nil || !created {
		t.Fatalf("SaveOrGet: created=%v err=%v", created, err)
	}
	if _, created, err := store.SaveOrGet(ctx, record); err != nil || created {
		t.Fatalf("idempotent SaveOrGet: created=%v err=%v", created, err)
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM outbox_events WHERE tenant_id = $1 AND aggregate_id = $2",
		record.TenantID, record.DecisionID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("outbox event count=%d err=%v, want exactly one", count, err)
	}

	claimed, err := store.Claim(ctx, "worker-a", 10, 25*time.Millisecond)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("first claim: events=%d err=%v", len(claimed), err)
	}
	if claimed[0].Type != "decision.recorded.v1" || claimed[0].AggregateID != record.DecisionID ||
		claimed[0].SchemaVersion != 1 || claimed[0].Attempts != 1 {
		t.Fatalf("unexpected event envelope: %+v", claimed[0])
	}
	unavailable, err := store.Claim(ctx, "worker-b", 10, time.Second)
	if err != nil || len(unavailable) != 0 {
		t.Fatalf("leased event claimed by another worker: events=%d err=%v", len(unavailable), err)
	}

	time.Sleep(40 * time.Millisecond)
	reclaimed, err := store.Claim(ctx, "worker-b", 10, 25*time.Millisecond)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].ID != claimed[0].ID || reclaimed[0].Attempts != 2 {
		t.Fatalf("expired lease reclaim: events=%+v err=%v", reclaimed, err)
	}
	if err := store.Ack(ctx, reclaimed[0].ID, "worker-a", claimed[0].Attempts); !errors.Is(err, outbox.ErrLeaseLost) {
		t.Fatalf("stale owner ack=%v, want ErrLeaseLost", err)
	}
	if err := store.Retry(ctx, reclaimed[0].ID, "worker-a", claimed[0].Attempts, 0, outbox.ReasonPublishFailed); !errors.Is(err, outbox.ErrLeaseLost) {
		t.Fatalf("stale owner retry=%v, want ErrLeaseLost", err)
	}
	// A stable worker identity can be reused after a lease expires. The
	// prior attempt must not be able to ACK or Retry its successor's lease.
	time.Sleep(40 * time.Millisecond)
	sameWorkerReclaim, err := store.Claim(ctx, "worker-b", 10, time.Second)
	if err != nil || len(sameWorkerReclaim) != 1 || sameWorkerReclaim[0].Attempts != 3 {
		t.Fatalf("same-worker next attempt claim: events=%+v err=%v", sameWorkerReclaim, err)
	}
	if err := store.Ack(ctx, reclaimed[0].ID, "worker-b", reclaimed[0].Attempts); !errors.Is(err, outbox.ErrLeaseLost) {
		t.Fatalf("previous attempt same worker must not ACK current lease: %v", err)
	}
	if err := store.Retry(ctx, reclaimed[0].ID, "worker-b", reclaimed[0].Attempts, 0, outbox.ReasonPublishFailed); !errors.Is(err, outbox.ErrLeaseLost) {
		t.Fatalf("previous attempt same worker must not Retry current lease: %v", err)
	}
	if err := store.Retry(ctx, sameWorkerReclaim[0].ID, "worker-b", sameWorkerReclaim[0].Attempts, 0, "authorization header bearer secret-sentinel"); err == nil {
		t.Fatal("raw publisher error text must be rejected as a retry reason")
	}
	if err := store.Retry(ctx, sameWorkerReclaim[0].ID, "worker-b", sameWorkerReclaim[0].Attempts, 0, outbox.ReasonPublishFailed); err != nil {
		t.Fatalf("retry event: %v", err)
	}
	var retryReason string
	if err := db.QueryRowContext(ctx, "SELECT last_error_code FROM outbox_events WHERE event_id = $1", sameWorkerReclaim[0].ID).Scan(&retryReason); err != nil || retryReason != outbox.ReasonPublishFailed {
		t.Fatalf("durable retry diagnostic=%q err=%v, want stable reason code", retryReason, err)
	}
	retried, err := store.Claim(ctx, "worker-c", 10, time.Second)
	if err != nil || len(retried) != 1 || retried[0].Attempts != 4 {
		t.Fatalf("claim retried event: events=%+v err=%v", retried, err)
	}
	if err := store.Ack(ctx, retried[0].ID, "worker-c", retried[0].Attempts); err != nil {
		t.Fatalf("ack event: %v", err)
	}
	if err := store.Ack(ctx, retried[0].ID, "worker-c", retried[0].Attempts); !errors.Is(err, outbox.ErrLeaseLost) {
		t.Fatalf("duplicate ack=%v, want ErrLeaseLost", err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE outbox_events SET payload = '{}'::jsonb WHERE event_id = $1", retried[0].ID); err == nil {
		t.Fatal("outbox immutable payload update unexpectedly succeeded")
	}

	// RED: matching checksums cannot authorize a damaged installed catalog.
	// A restart must reject missing immutable triggers, broken foreign keys,
	// and deleted Outbox relations instead of accepting the version ledger.
	if _, err := db.ExecContext(ctx, "DROP TRIGGER outbox_event_identity_immutable ON outbox_events"); err != nil {
		t.Fatal(err)
	}
	if err := decision.Migrate(ctx, db); err == nil {
		t.Fatal("migration accepted an Outbox missing the immutable-identity trigger")
	}
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER outbox_event_identity_immutable BEFORE UPDATE ON outbox_events FOR EACH ROW EXECUTE FUNCTION reject_decision_outbox_identity_mutation()`); err != nil {
		t.Fatal(err)
	}
	if err := decision.Migrate(ctx, db); err != nil {
		t.Fatalf("restored trigger must pass migration re-entry: %v", err)
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE outbox_events DROP CONSTRAINT outbox_decision_fk"); err != nil {
		t.Fatal(err)
	}
	if err := decision.Migrate(ctx, db); err == nil {
		t.Fatal("migration accepted Outbox without tenant-bound Decision foreign key")
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE outbox_events ADD CONSTRAINT outbox_decision_fk FOREIGN KEY (tenant_id, aggregate_id) REFERENCES decision_records (tenant_id, decision_id)`); err != nil {
		t.Fatal(err)
	}
	if err := decision.Migrate(ctx, db); err != nil {
		t.Fatalf("restored foreign key must pass migration re-entry: %v", err)
	}
	// A same-name CREATE OR REPLACE FUNCTION retains the OID and all of the
	// trigger metadata checked above. The installed function body itself must
	// still reject immutable-record writes instead of becoming a no-op.
	for _, procedure := range []string{
		"reject_decision_record_mutation()",
		"reject_decision_outbox_identity_mutation()",
		"reject_decision_outbox_delete()",
	} {
		var approvedDefinition string
		if err := db.QueryRowContext(ctx,
			"SELECT pg_get_functiondef(to_regprocedure($1))", procedure,
		).Scan(&approvedDefinition); err != nil {
			t.Fatalf("load approved trigger definition %s: %v", procedure, err)
		}
		changedDefinition := fmt.Sprintf(
			"CREATE OR REPLACE FUNCTION %s RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END;'",
			procedure,
		)
		if _, err := db.ExecContext(ctx, changedDefinition); err != nil {
			t.Fatalf("weaken same-named trigger body %s: %v", procedure, err)
		}
		if err := decision.Migrate(ctx, db); err == nil {
			t.Fatalf("migration accepted a same-name no-op trigger function %s", procedure)
		}
		if _, err := db.ExecContext(ctx, approvedDefinition); err != nil {
			t.Fatalf("restore reviewed trigger function %s: %v", procedure, err)
		}
		if err := decision.Migrate(ctx, db); err != nil {
			t.Fatalf("restored trigger function %s rejected: %v", procedure, err)
		}
	}
	// A matching migration ledger and same-name CHECK are insufficient
	// when the installed predicate has been replaced by a permissive one.
	for _, tc := range []struct {
		name, table, constraint string
	}{
		{"decision JSON identity binding", "decision_records", "decision_records_json_identity_ck"},
		{"decision request SHA256", "decision_records", "decision_records_request_sha256_check"},
		{"outbox lease owner and expiry pairing", "outbox_events", "outbox_lease_pair_ck"},
		{"outbox aggregate kind", "outbox_events", "outbox_events_aggregate_type_check"},
		{"outbox sanitized error code", "outbox_events", "outbox_events_last_error_code_check"},
	} {
		t.Run("same_name_weakened_"+tc.constraint, func(t *testing.T) {
			var approvedDefinition, approvedExpression string
			if err := db.QueryRowContext(ctx, `
				SELECT pg_get_constraintdef(c.oid), pg_get_expr(c.conbin, c.conrelid)
				FROM pg_constraint c
				WHERE c.conrelid=to_regclass($1) AND c.conname=$2 AND c.contype='c'
			`, tc.table, tc.constraint).Scan(&approvedDefinition, &approvedExpression); err != nil {
				t.Fatalf("load canonical %s CHECK: %v", tc.name, err)
			}
			t.Logf("approved PostgreSQL 16 expression %s: %s", tc.constraint, approvedExpression)
			if _, err := db.ExecContext(ctx,
				fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT %s", tc.table, tc.constraint),
			); err != nil {
				t.Fatalf("remove original %s CHECK: %v", tc.name, err)
			}
			if _, err := db.ExecContext(ctx,
				fmt.Sprintf("ALTER TABLE %s ADD CONSTRAINT %s CHECK (true)", tc.table, tc.constraint),
			); err != nil {
				t.Fatalf("install same-name weakened %s CHECK: %v", tc.name, err)
			}
			if err := decision.Migrate(ctx, db); !errors.Is(err, decision.ErrCatalogDrift) {
				t.Errorf("same-name weakened %s CHECK was not rejected as catalog drift: %v", tc.name, err)
			}
			if _, err := db.ExecContext(ctx,
				fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT %s", tc.table, tc.constraint),
			); err != nil {
				t.Fatalf("remove weakened %s CHECK: %v", tc.name, err)
			}
			if _, err := db.ExecContext(ctx,
				fmt.Sprintf("ALTER TABLE %s ADD CONSTRAINT %s %s", tc.table, tc.constraint, approvedDefinition),
			); err != nil {
				t.Fatalf("restore approved %s CHECK: %v", tc.name, err)
			}
			if err := decision.Migrate(ctx, db); err != nil {
				t.Fatalf("restored %s CHECK should be accepted: %v", tc.name, err)
			}
		})
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE outbox_events"); err != nil {
		t.Fatal(err)
	}
	if err := decision.Migrate(ctx, db); err == nil {
		t.Fatal("migration accepted recorded v2 with the Outbox relation missing")
	}
}

func TestDispatchOnceRetriesPublishFailure(t *testing.T) {
	store := &fakeStore{events: []outbox.Event{{ID: "event-1"}}}
	publisher := fakePublisher{err: errors.New("authorization header bearer secret-sentinel")}
	published, err := outbox.DispatchOnce(context.Background(), store, publisher, "worker-a", 1, time.Minute, 5*time.Second)
	if published != 0 || !errors.Is(err, publisher.err) || store.retries != 1 || store.acks != 0 {
		t.Fatalf("DispatchOnce: published=%d err=%v retries=%d acks=%d", published, err, store.retries, store.acks)
	}
	if store.retryCause != "publish_failed" {
		t.Fatalf("unsafe publisher error was persisted as retry cause: %q", store.retryCause)
	}
	if strings.Contains(store.retryCause, "secret-sentinel") {
		t.Fatal("publisher error detail leaked into durable Outbox metadata")
	}
}

type fakeStore struct {
	events     []outbox.Event
	acks       int
	retries    int
	retryCause string
}

func (s *fakeStore) Claim(context.Context, string, int, time.Duration) ([]outbox.Event, error) {
	return s.events, nil
}
func (s *fakeStore) Ack(context.Context, string, string, int) error {
	s.acks++
	return nil
}
func (s *fakeStore) Retry(_ context.Context, _ string, _ string, _ int, _ time.Duration, cause string) error {
	s.retries++
	s.retryCause = cause
	return nil
}

type fakePublisher struct{ err error }

func (p fakePublisher) Publish(context.Context, outbox.Event) error { return p.err }
