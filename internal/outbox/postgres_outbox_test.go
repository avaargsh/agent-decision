package outbox_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
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

	if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
		t.Fatal(err)
	}
	if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
		t.Fatalf("migration re-entry should be safe: %v", err)
	}

	// The catalog gate must execute its four-field behavioral probe, not only
	// compare the deparsed CHECK expression. A probe-specific BEFORE INSERT
	// denial forces migration to stop while the approved CHECK remains intact.
	t.Run("identity_probe_is_part_of_migration_gate", func(t *testing.T) {
		const install = `CREATE FUNCTION deny_decision_catalog_probe() RETURNS trigger
			LANGUAGE plpgsql AS $probe$
			BEGIN
				IF NEW.tenant_id LIKE '__decision_catalog_probe_%' THEN
					RAISE EXCEPTION 'blocked catalog probe';
				END IF;
				RETURN NEW;
			END;
			$probe$;
			CREATE TRIGGER deny_decision_catalog_probe
			BEFORE INSERT ON decision_records FOR EACH ROW
			EXECUTE FUNCTION deny_decision_catalog_probe();`
		if _, err := db.ExecContext(ctx, install); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), "DROP TRIGGER IF EXISTS deny_decision_catalog_probe ON decision_records")
			_, _ = db.ExecContext(context.Background(), "DROP FUNCTION IF EXISTS deny_decision_catalog_probe()")
		})
		if err := decision.MigrateInSchema(ctx, db, schema); err == nil {
			t.Fatal("migration bypassed the behavior probe and accepted a probe-specific INSERT denial")
		}
		if _, err := db.ExecContext(ctx, "DROP TRIGGER deny_decision_catalog_probe ON decision_records"); err != nil {
			t.Fatal(err)
		}
		if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
			t.Fatalf("migration should succeed after removing probe denial: %v", err)
		}
	})
	// A correct migration-history checksum does not prove that its installed
	// PostgreSQL triggers are still enabled. Fail closed on disabled append-only
	// protections even when all schema_migrations rows remain unchanged.
	for _, tc := range []struct {
		name string
		table string
		trigger string
	}{
		{name: "DecisionRecord UPDATE", table: "decision_records", trigger: "decision_records_no_update"},
		{name: "DecisionRecord DELETE", table: "decision_records", trigger: "decision_records_no_delete"},
		{name: "Outbox payload UPDATE", table: "outbox_events", trigger: "outbox_event_identity_immutable"},
		{name: "Outbox DELETE", table: "outbox_events", trigger: "outbox_events_no_delete"},
	} {
		t.Run("disabled_trigger_"+strings.ReplaceAll(tc.name, " ", "_"), func(t *testing.T) {
			// Names are a closed list of repository-defined identifiers, not caller input.
			if _, err := db.ExecContext(ctx, "ALTER TABLE "+tc.table+" DISABLE TRIGGER "+tc.trigger); err != nil {
				t.Fatal(err)
			}
			if err := decision.MigrateInSchema(ctx, db, schema); err == nil {
				t.Fatalf("disabled %s trigger must reject migration history", tc.name)
			}
			if _, err := db.ExecContext(ctx, "ALTER TABLE "+tc.table+" ENABLE TRIGGER "+tc.trigger); err != nil {
				t.Fatal(err)
			}
			if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
				t.Fatalf("re-enabled %s trigger must restore valid migration: %v", tc.name, err)
			}
		})
	}
	// The trigger's name/OID/event bits can remain correct while its handler
	// body is overwritten, or a WHEN/UPDATE OF clause disables protection.
	// These are live catalog drifts not detected by a migration filename hash.
	t.Run("rewritten_trigger_function", func(t *testing.T) {
		var original string
		if err := db.QueryRowContext(ctx,
			"SELECT pg_get_functiondef(to_regprocedure('reject_decision_record_mutation()'))",
		).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `CREATE OR REPLACE FUNCTION reject_decision_record_mutation()
			RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END;'`); err != nil {
			t.Fatal(err)
		}
		if err := decision.MigrateInSchema(ctx, db, schema); err == nil {
			t.Fatal("rewritten trigger handler with unchanged OID must fail closed")
		}
		if _, err := db.ExecContext(ctx, original); err != nil {
			t.Fatal(err)
		}
		if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
			t.Fatalf("restored handler must pass migration integrity: %v", err)
		}
	})
	for _, tc := range []struct {
		name string
		replacement string
	}{
		{"conditional_when_false", `BEFORE UPDATE ON decision_records
			FOR EACH ROW WHEN (false) EXECUTE FUNCTION reject_decision_record_mutation()`},
		{"restricted_update_columns", `BEFORE UPDATE OF created_at ON decision_records
			FOR EACH ROW EXECUTE FUNCTION reject_decision_record_mutation()`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.ExecContext(ctx, "DROP TRIGGER decision_records_no_update ON decision_records"); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx,
				"CREATE TRIGGER decision_records_no_update "+tc.replacement); err != nil {
				t.Fatal(err)
			}
			if err := decision.MigrateInSchema(ctx, db, schema); err == nil {
				t.Fatalf("modified trigger definition (%s) must fail closed", tc.name)
			}
			if _, err := db.ExecContext(ctx, `DROP TRIGGER decision_records_no_update ON decision_records;
				CREATE TRIGGER decision_records_no_update BEFORE UPDATE ON decision_records
				FOR EACH ROW EXECUTE FUNCTION reject_decision_record_mutation()`); err != nil {
				t.Fatal(err)
			}
			if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
				t.Fatalf("restored trigger (%s) must pass migration integrity: %v", tc.name, err)
			}
		})
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
	if err := decision.MigrateInSchema(ctx, db, schema); err == nil {
		t.Fatal("migration name substitution must fail closed")
	}
	if _, err := db.ExecContext(ctx, "UPDATE schema_migrations SET name = $1 WHERE version = 2", name); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE schema_migrations SET checksum = repeat('0', 64) WHERE version = 2"); err != nil {
		t.Fatal(err)
	}
	if err := decision.MigrateInSchema(ctx, db, schema); err == nil {
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
	if err := decision.MigrateInSchema(ctx, db, schema); err == nil {
		t.Fatal("missing earlier migration must not be silently re-applied")
	}
	if _, err := db.ExecContext(ctx,
		"INSERT INTO schema_migrations(version, name, checksum) VALUES (1, $1, $2)",
		"0001_create_decision_records.sql", checksum0001,
	); err != nil {
		t.Fatal(err)
	}
	if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
		t.Fatalf("restored authentic migration history must be accepted: %v", err)
	}
	store := decision.NewPostgresStore(db)

	t.Run("outbox_insert_failure_rolls_back_decision", func(t *testing.T) {
		// Reject the event after the DecisionRecord INSERT has succeeded.
		// PostgreSQL must undo both writes; a same-invocation retry after
		// removing the fault must produce one durable record and one event.
		faulty := decision.Record{
			DecisionID: "dec_" + strings.Repeat("f", 64),
			TenantID: fmt.Sprintf("outbox-rollback-%d", time.Now().UnixNano()),
			AgentID: "agent-1",
			SessionID: "session-1",
			RunID: "run-1",
			InvocationID: "outbox-insert-fault",
			RequestSHA256: strings.Repeat("e", 64),
			CreatedAt: time.Now().UTC(),
			Status: decision.StatusProposed,
			ReasonCodes: []string{},
			Evidence: []decision.EvidenceRef{},
			Plan: decision.PlanCandidate{PlanID: "fault-plan", SchemaVersion: decision.SchemaVersion, Steps: []decision.PlanStep{}},
		}
		if _, err := db.ExecContext(ctx, `CREATE FUNCTION reject_outbox_insert_test()
			RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''injected outbox insert failure''; END;'`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER reject_outbox_insert_test
			BEFORE INSERT ON outbox_events FOR EACH ROW
			EXECUTE FUNCTION reject_outbox_insert_test()`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), "DROP TRIGGER IF EXISTS reject_outbox_insert_test ON outbox_events")
			_, _ = db.ExecContext(context.Background(), "DROP FUNCTION IF EXISTS reject_outbox_insert_test()")
		})
		if _, created, err := store.SaveOrGet(ctx, faulty); !errors.Is(err, decision.ErrStoreUnavailable) || created {
			t.Fatalf("injected Outbox INSERT failure must rollback DecisionRecord: created=%t err=%v", created, err)
		}
		var records, events int
		if err := db.QueryRowContext(ctx,
			"SELECT count(*) FROM decision_records WHERE tenant_id=$1 AND invocation_id=$2",
			faulty.TenantID, faulty.InvocationID).Scan(&records); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx,
			"SELECT count(*) FROM outbox_events WHERE tenant_id=$1 AND aggregate_id=$2",
			faulty.TenantID, faulty.DecisionID).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if records != 0 || events != 0 {
			t.Fatalf("partial commit after Outbox failure: records=%d events=%d", records, events)
		}
		if _, err := db.ExecContext(ctx, "DROP TRIGGER reject_outbox_insert_test ON outbox_events"); err != nil {
			t.Fatal(err)
		}
		got, created, err := store.SaveOrGet(ctx, faulty)
		if err != nil || !created || got.DecisionID != faulty.DecisionID {
			t.Fatalf("same-invocation retry after rollback must create record: created=%t err=%v", created, err)
		}
		if _, created, err := store.SaveOrGet(ctx, faulty); err != nil || created {
			t.Fatalf("idempotent replay after recovery: created=%t err=%v", created, err)
		}
		if err := db.QueryRowContext(ctx,
			"SELECT count(*) FROM decision_records WHERE tenant_id=$1 AND invocation_id=$2",
			faulty.TenantID, faulty.InvocationID).Scan(&records); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx,
			"SELECT count(*) FROM outbox_events WHERE tenant_id=$1 AND aggregate_id=$2",
			faulty.TenantID, faulty.DecisionID).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if records != 1 || events != 1 {
			t.Fatalf("recovered invocation must have one record/event: records=%d events=%d", records, events)
		}
		// Finish this subtest's own Outbox event before the parent test
		// exercises its single-event lease/retry protocol.
		pending, err := store.Claim(ctx, "rollback-recovery-worker", 1, time.Minute)
		if err != nil || len(pending) != 1 || pending[0].AggregateID != faulty.DecisionID {
			t.Fatalf("recovered Outbox event must be claimable: events=%+v err=%v", pending, err)
		}
		if err := store.Ack(ctx, pending[0].ID, "rollback-recovery-worker", pending[0].Attempts); err != nil {
			t.Fatalf("ack recovered Outbox event: %v", err)
		}
	})

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

	// Simulate an existing v2 installation with a committed Decision and
	// Outbox event. Upgrading to v4 must preserve both while applying the
	// append-only TRUNCATE guards and tenant RLS policies in order.
	for _, tableTrigger := range []struct{ table, trigger string }{
		{"decision_records", "decision_records_no_truncate"},
		{"outbox_events", "outbox_events_no_truncate"},
	} {
		if _, err := db.ExecContext(ctx,
			fmt.Sprintf("DROP TRIGGER %s ON %s", tableTrigger.trigger, tableTrigger.table),
		); err != nil {
			t.Fatalf("simulate v2 trigger state: %v", err)
		}
	}
	// Remove the v0004 policies and mapping table as well, then rewind the
	// checksummed ledger to v2. The real upgrade must recreate both versions.
	for _, policy := range []struct{ table, name string }{
		{"decision_records", "decision_records_tenant_select"},
		{"decision_records", "decision_records_tenant_insert"},
		{"outbox_events", "outbox_events_tenant_insert"},
		{"outbox_events", "outbox_events_dispatcher_select"},
		{"outbox_events", "outbox_events_dispatcher_update"},
	} {
		if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP POLICY %s ON %s", policy.name, policy.table)); err != nil {
			t.Fatalf("remove v0004 policy: %v", err)
		}
	}
	for _, table := range []string{"decision_records", "outbox_events"} {
		if _, err := db.ExecContext(ctx, "ALTER TABLE "+table+" DISABLE ROW LEVEL SECURITY"); err != nil {
			t.Fatalf("remove v0004 RLS flag: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE decision_tenant_logins"); err != nil {
		t.Fatalf("remove v0004 mapping table: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version >= 3"); err != nil {
		t.Fatalf("simulate v2 migration ledger: %v", err)
	}
	if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
		t.Fatalf("v2-to-v4 in-place migration: %v", err)
	}
	var appliedVersions, preservedDecisions, preservedEvents int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations").Scan(&appliedVersions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM decision_records WHERE tenant_id=$1 AND invocation_id=$2",
		record.TenantID, record.InvocationID,
	).Scan(&preservedDecisions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM outbox_events WHERE tenant_id=$1 AND aggregate_id=$2",
		record.TenantID, record.DecisionID,
	).Scan(&preservedEvents); err != nil {
		t.Fatal(err)
	}
	if appliedVersions != 4 || preservedDecisions != 1 || preservedEvents != 1 {
		t.Fatalf("v2-to-v4 migration lost data/history: versions=%d records=%d events=%d",
			appliedVersions, preservedDecisions, preservedEvents)
	}
	if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
		t.Fatalf("v4 upgrade idempotent replay: %v", err)
	}

	// Use a long active lease for the negative Claim assertion. A 25ms lease
	// can expire under CI scheduling or database load before the second query,
	// turning a valid reclaim into a misleading test failure.
	const activeLease = 5 * time.Minute
	claimed, err := store.Claim(ctx, "worker-a", 10, activeLease)
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

	// Expire leases by moving the database timestamp, not by sleeping. This
	// keeps the test deterministic while still exercising Claim's <= now()
	// boundary against PostgreSQL's own clock.
	expireLease := func(eventID, owner string, attempt int) {
		t.Helper()
		result, err := db.ExecContext(ctx, `UPDATE outbox_events
			SET lease_until = now() - interval '1 millisecond'
			WHERE event_id = $1 AND lease_owner = $2 AND attempts = $3
			  AND published_at IS NULL`, eventID, owner, attempt)
		if err != nil {
			t.Fatalf("expire lease for worker %s attempt %d: %v", owner, attempt, err)
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			t.Fatalf("expire lease affected rows=%d err=%v, want exactly one", rows, err)
		}
	}
	expireLease(claimed[0].ID, "worker-a", claimed[0].Attempts)
	reclaimed, err := store.Claim(ctx, "worker-b", 10, activeLease)
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
	expireLease(reclaimed[0].ID, "worker-b", reclaimed[0].Attempts)
	sameWorkerReclaim, err := store.Claim(ctx, "worker-b", 10, activeLease)
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
	if err := decision.MigrateInSchema(ctx, db, schema); err == nil {
		t.Fatal("migration accepted an Outbox missing the immutable-identity trigger")
	}
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER outbox_event_identity_immutable BEFORE UPDATE ON outbox_events FOR EACH ROW EXECUTE FUNCTION reject_decision_outbox_identity_mutation()`); err != nil {
		t.Fatal(err)
	}
	if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
		t.Fatalf("restored trigger must pass migration re-entry: %v", err)
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE outbox_events DROP CONSTRAINT outbox_decision_fk"); err != nil {
		t.Fatal(err)
	}
	if err := decision.MigrateInSchema(ctx, db, schema); err == nil {
		t.Fatal("migration accepted Outbox without tenant-bound Decision foreign key")
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE outbox_events ADD CONSTRAINT outbox_decision_fk FOREIGN KEY (tenant_id, aggregate_id) REFERENCES decision_records (tenant_id, decision_id)`); err != nil {
		t.Fatal(err)
	}
	if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
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
		if err := decision.MigrateInSchema(ctx, db, schema); err == nil {
			t.Fatalf("migration accepted a same-name no-op trigger function %s", procedure)
		}
		if _, err := db.ExecContext(ctx, approvedDefinition); err != nil {
			t.Fatalf("restore reviewed trigger function %s: %v", procedure, err)
		}
		if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
			t.Fatalf("restored trigger function %s rejected: %v", procedure, err)
		}
	}

	// Same-name constraints can be replaced with permissive predicates while
	// retaining their name, CHECK type and validated catalog flag.
	t.Run("weakened_decision_identity_check", func(t *testing.T) {
		var approved string
		if err := db.QueryRowContext(ctx, `SELECT pg_get_constraintdef(oid)
			FROM pg_constraint WHERE conrelid = 'decision_records'::regclass
			  AND conname = 'decision_records_json_identity_ck'`).Scan(&approved); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `ALTER TABLE decision_records
			DROP CONSTRAINT decision_records_json_identity_ck;
			ALTER TABLE decision_records ADD CONSTRAINT decision_records_json_identity_ck CHECK (true)`); err != nil {
			t.Fatal(err)
		}
		if err := decision.MigrateInSchema(ctx, db, schema); err == nil {
			t.Fatal("migration accepted a same-name always-true Decision identity CHECK")
		}
		if _, err := db.ExecContext(ctx, `ALTER TABLE decision_records
			DROP CONSTRAINT decision_records_json_identity_ck`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "ALTER TABLE decision_records ADD CONSTRAINT decision_records_json_identity_ck "+approved); err != nil {
			t.Fatal(err)
		}
		if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
			t.Fatalf("restored identity CHECK must pass: %v", err)
		}
	})
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
			if err := decision.MigrateInSchema(ctx, db, schema); !errors.Is(err, decision.ErrCatalogDrift) {
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
			if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
				t.Fatalf("restored %s CHECK should be accepted: %v", tc.name, err)
			}
		})
	}
	// PostgreSQL TRUNCATE skips DELETE row triggers. Use a rollback-only
	// transaction so a vulnerable migration cannot erase test evidence while
	// proving the append-only contract is not actually enforced.
	for _, tc := range []struct {
		name, command string
	}{
		{"outbox", "TRUNCATE TABLE outbox_events"},
		{"decision_and_outbox", "TRUNCATE TABLE decision_records, outbox_events"},
	} {
		t.Run("truncate_guard_"+tc.name, func(t *testing.T) {
			truncateTx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, truncateErr := truncateTx.ExecContext(ctx, tc.command)
			if err := truncateTx.Rollback(); err != nil {
				t.Fatalf("rollback destructive probe: %v", err)
			}
			if truncateErr == nil {
				t.Errorf("append-only Decision/Outbox accepted %q", tc.command)
			}
		})
	}
	// Once v3 is installed, a missing TRUNCATE guard must be detected on
	// migration re-entry instead of trusting the migration checksum ledger.
	for _, tc := range []struct {
		table, trigger, function string
	}{
		{"decision_records", "decision_records_no_truncate", "reject_decision_record_mutation"},
		{"outbox_events", "outbox_events_no_truncate", "reject_decision_outbox_delete"},
	} {
		t.Run("catalog_truncate_guard_"+tc.table, func(t *testing.T) {
			if _, err := db.ExecContext(ctx,
				fmt.Sprintf("DROP TRIGGER %s ON %s", tc.trigger, tc.table),
			); err != nil {
				t.Fatalf("drop installed guard %s: %v", tc.trigger, err)
			}
			if err := decision.MigrateInSchema(ctx, db, schema); !errors.Is(err, decision.ErrCatalogDrift) {
				t.Errorf("migration accepted missing TRUNCATE guard on %s: %v", tc.table, err)
			}
			if _, err := db.ExecContext(ctx, fmt.Sprintf(
				"CREATE TRIGGER %s BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION %s()",
				tc.trigger, tc.table, tc.function,
			)); err != nil {
				t.Fatalf("restore TRUNCATE guard %s: %v", tc.trigger, err)
			}
			if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
				t.Fatalf("restore %s TRUNCATE protection: %v", tc.table, err)
			}
		})
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE outbox_events"); err != nil {
		t.Fatal(err)
	}
	if err := decision.MigrateInSchema(ctx, db, schema); err == nil {
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


// TestPostgresOutboxTruncateGuardRestoreUnderSameSchemaDDL exercises the
// exact DROP/CREATE TRUNCATE-guard restoration path that historically
// preceded an intermittent tenant LOGIN mapping-constraint attestation
// failure. It deliberately uses the same pgx search_path runtime parameter
// as the Outbox integration suite, while unrelated DDL churns the target
// schema's shared PostgreSQL catalogs.
func TestPostgresOutboxTruncateGuardRestoreUnderSameSchemaDDL(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin.SetMaxOpenConns(24)
	if err := admin.PingContext(ctx); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}

	schema := fmt.Sprintf("outbox_restore_stress_%d", time.Now().UnixNano())
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
	db.SetMaxOpenConns(24)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		_, _ = admin.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
		t.Fatal(err)
	}
	restoreTrigger := "CREATE TRIGGER decision_records_no_truncate " +
		"BEFORE TRUNCATE ON decision_records FOR EACH STATEMENT " +
		"EXECUTE FUNCTION reject_decision_record_mutation()"
	defer func() {
		// Always restore the protected trigger before dropping the isolated
		// schema, including when an assertion fails mid-cycle.
		_, _ = db.ExecContext(context.Background(), "DROP TRIGGER IF EXISTS decision_records_no_truncate ON decision_records")
		_, _ = db.ExecContext(context.Background(), restoreTrigger)
		_ = db.Close()
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
	}()

	if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
		t.Fatalf("install target schema: %v", err)
	}

	const ddlWorkers = 4
	const ddlIterations = 96
	const attestationWorkers = 2
	const attestationsPerWorker = 48
	const restoreIterations = 48

	for worker := 0; worker < ddlWorkers; worker++ {
		table := fmt.Sprintf("%s.catalog_churn_%d", schema, worker)
		if _, err := admin.ExecContext(ctx, "CREATE TABLE "+table+" (id integer NOT NULL)"); err != nil {
			t.Fatalf("create same-schema catalog churn table %d: %v", worker, err)
		}
	}

	// Establish the exact Outbox pool/search_path path before introducing DDL
	// concurrency. This also warms pgx's per-connection statement cache.
	for i := 0; i < 3; i++ {
		if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
			t.Fatalf("sequential migration baseline %d: %v", i, err)
		}
		if err := decision.VerifyInstalledCatalogInSchema(ctx, db, schema); err != nil {
			t.Fatalf("sequential read-only baseline %d: %v", i, err)
		}
	}

	var catalogGate sync.RWMutex
	errs := make(chan error, ddlWorkers+attestationWorkers+1)
	var wg sync.WaitGroup
	report := func(err error) {
		if err == nil {
			return
		}
		select {
		case errs <- err:
		default:
		}
		cancel()
	}

	// The write-side worker mirrors the historical test exactly: remove the
	// TRUNCATE guard, require migration re-entry to fail at that trigger check,
	// restore it, then require the mapping catalog and all other guards to pass.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			_, _ = db.ExecContext(context.Background(), "DROP TRIGGER IF EXISTS decision_records_no_truncate ON decision_records")
			_, _ = db.ExecContext(context.Background(), restoreTrigger)
		}()
		for i := 0; i < restoreIterations; i++ {
			if ctx.Err() != nil {
				return
			}
			catalogGate.Lock()
			if _, err := db.ExecContext(ctx, "DROP TRIGGER decision_records_no_truncate ON decision_records"); err != nil {
				catalogGate.Unlock()
				if ctx.Err() == nil {
					report(fmt.Errorf("drop TRUNCATE guard iteration %d: %w", i, err))
				}
				return
			}
			err := decision.MigrateInSchema(ctx, db, schema)
			expected := "trigger decision_records.decision_records_no_truncate missing"
			if !errors.Is(err, decision.ErrCatalogDrift) || !strings.Contains(err.Error(), expected) {
				_, _ = db.ExecContext(context.Background(), "DROP TRIGGER IF EXISTS decision_records_no_truncate ON decision_records")
				_, _ = db.ExecContext(context.Background(), restoreTrigger)
				catalogGate.Unlock()
				report(fmt.Errorf("missing TRUNCATE guard must fail at its own check, iteration %d: %v", i, err))
				return
			}
			if _, err := db.ExecContext(ctx, restoreTrigger); err != nil {
				catalogGate.Unlock()
				if ctx.Err() == nil {
					report(fmt.Errorf("restore TRUNCATE guard iteration %d: %w", i, err))
				}
				return
			}
			err = decision.MigrateInSchema(ctx, db, schema)
			catalogGate.Unlock()
			if err != nil {
				if ctx.Err() == nil {
					report(fmt.Errorf("restored TRUNCATE guard migration iteration %d: %w", i, err))
				}
				return
			}
		}
	}()

	// Each worker mutates a different relation. This creates real pg_class and
	// pg_constraint catalog churn without introducing table-lock contention
	// against the DecisionRecord or tenant LOGIN mapping relations.
	for worker := 0; worker < ddlWorkers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			table := fmt.Sprintf("%s.catalog_churn_%d", schema, worker)
			for i := 0; i < ddlIterations; i++ {
				if ctx.Err() != nil {
					return
				}
				constraint := fmt.Sprintf("catalog_churn_ck_%d", i)
				add := fmt.Sprintf("ALTER TABLE %s ADD CONSTRAINT %s CHECK (id >= %d)", table, constraint, i)
				drop := fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT %s", table, constraint)
				if _, err := admin.ExecContext(ctx, add); err != nil {
					if ctx.Err() == nil {
						report(fmt.Errorf("same-schema unrelated DDL add worker %d iteration %d: %w", worker, i, err))
					}
					return
				}
				if _, err := admin.ExecContext(ctx, drop); err != nil {
					if ctx.Err() == nil {
						report(fmt.Errorf("same-schema unrelated DDL drop worker %d iteration %d: %w", worker, i, err))
					}
					return
				}
			}
		}()
	}

	// Attestors use the same pgx pool with a schema-specific runtime search_path.
	// The RW gate prevents them from observing the intentionally absent trigger.
	for worker := 0; worker < attestationWorkers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < attestationsPerWorker; i++ {
				if ctx.Err() != nil {
					return
				}
				catalogGate.RLock()
				err := decision.VerifyInstalledCatalogInSchema(ctx, db, schema)
				catalogGate.RUnlock()
				if err != nil {
					if ctx.Err() == nil {
						report(fmt.Errorf("read-only attestation worker %d iteration %d: %w", worker, i, err))
					}
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("TRUNCATE-guard/catalog-DDL stress test exceeded its 90-second deadline")
	}
	if ctx.Err() == nil {
		if err := decision.MigrateInSchema(ctx, db, schema); err != nil {
			t.Errorf("final restored migration attestation: %v", err)
		}
		if err := decision.VerifyInstalledCatalogInSchema(ctx, db, schema); err != nil {
			t.Errorf("final restored read-only attestation: %v", err)
		}
		t.Logf("stress completed: TRUNCATE guard restore cycles=%d; same-schema DDL=%d workers x %d add/drop pairs; read-only attestation=%d workers x %d checks", restoreIterations, ddlWorkers, ddlIterations, attestationWorkers, attestationsPerWorker)
	}
}
