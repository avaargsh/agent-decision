package decision

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avaargsh/agent-decision/internal/outbox"
	schemamigrations "github.com/avaargsh/agent-decision/migrations"
)

// ErrCatalogDrift means migration checksums match but the live PostgreSQL
// tables, tenant-bound foreign key, or append-only triggers are not intact.
var ErrCatalogDrift = errors.New("Decision PostgreSQL catalog integrity drift")

const migrationLockClass int32 = 71002
const migrationLockObject int32 = 1

// Migrate applies the immutable Decision ledger and transactional Outbox
// schema under one transaction and advisory lock. Run with a migration-capable
// database role.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return ErrStoreUnavailable
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return storeUnavailable("begin migrations", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1, $2)", migrationLockClass, migrationLockObject); err != nil {
		return storeUnavailable("lock migrations", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		checksum TEXT NOT NULL CHECK (checksum ~ '^[a-f0-9]{64}$'),
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return storeUnavailable("create schema_migrations", err)
	}
	// A previous draft's table had no checksum. Add a nullable column only
	// to allow inspection; existing NULL rows deliberately fail closed.
	// An operator must independently verify a legacy schema before recording
	// a checksum, rather than the binary silently trusting historical DDL.
	if _, err := tx.ExecContext(ctx,
		"ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum TEXT"); err != nil {
		return storeUnavailable("inspect legacy migration history", err)
	}

	migrations := []struct {
		version int
		name string
		source []byte
		checksum string
	}{
		{version: 1, name: "0001_create_decision_records.sql"},
		{version: 2, name: "0002_decision_outbox.sql"},
		{version: 3, name: "0003_append_only_truncate_guards.sql"},
	}
	for i := range migrations {
		source, err := schemamigrations.FS.ReadFile(migrations[i].name)
		if err != nil {
			return fmt.Errorf("read migration %d (%s): %w",
				migrations[i].version, migrations[i].name, err)
		}
		sum := sha256.Sum256(source)
		migrations[i].source = source
		migrations[i].checksum = hex.EncodeToString(sum[:])
	}

	rows, err := tx.QueryContext(ctx,
		"SELECT version, name, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return storeUnavailable("read migration history", err)
	}
	applied := 0
	for rows.Next() {
		var version int
		var name string
		var checksum sql.NullString
		if err := rows.Scan(&version, &name, &checksum); err != nil {
			rows.Close()
			return storeUnavailable("scan migration history", err)
		}
		if applied >= len(migrations) {
			rows.Close()
			return fmt.Errorf("unrecognized future migration version %d", version)
		}
		expected := migrations[applied]
		if version != expected.version || name != expected.name ||
			!checksum.Valid || checksum.String != expected.checksum {
			rows.Close()
			return fmt.Errorf("migration history integrity mismatch at version %d: expected version/name/SHA-256 of approved SQL; manual attestation required for legacy unchecksummed rows", version)
		}
		applied++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return storeUnavailable("iterate migration history", err)
	}
	if err := rows.Close(); err != nil {
		return storeUnavailable("close migration history", err)
	}
	for _, migration := range migrations[applied:] {
		if _, err := tx.ExecContext(ctx, string(migration.source)); err != nil {
			return storeUnavailable(fmt.Sprintf("apply migration %d (%s)", migration.version, migration.name), err)
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations(version, name, checksum) VALUES ($1, $2, $3)",
			migration.version, migration.name, migration.checksum); err != nil {
			return storeUnavailable("record checksummed schema migration", err)
		}
	}
	if err := verifyDecisionCatalog(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return storeUnavailable("commit migrations", err)
	}
	return nil
}

// verifyDecisionCatalog checks the *installed* schema in the caller's
// migration-locked transaction. A correct historical SQL digest does not
// prove an operator has not dropped a table, FK, or append-only trigger.
func verifyDecisionCatalog(ctx context.Context, tx *sql.Tx) error {
	var relationsOK bool
	if err := tx.QueryRowContext(ctx, `
		SELECT to_regclass('decision_records') IS NOT NULL
			AND to_regclass('outbox_events') IS NOT NULL
	`).Scan(&relationsOK); err != nil {
		return fmt.Errorf("%w: inspect Decision relations: %v", ErrCatalogDrift, err)
	}
	if !relationsOK {
		return fmt.Errorf("%w: missing Decision ledger or Outbox relation", ErrCatalogDrift)
	}

	// The Outbox can only describe a Decision owned by the same tenant.
	// Compare the actual column bindings, not just a same-name constraint.
	var fkOK bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_constraint c
			WHERE c.conrelid=to_regclass('outbox_events')
				AND c.conname='outbox_decision_fk'
				AND c.contype='f' AND c.convalidated
				AND NOT c.condeferrable AND NOT c.condeferred
				AND c.confrelid=to_regclass('decision_records')
				AND (
					SELECT string_agg(a.attname, ',' ORDER BY k.ord)
					FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum,ord)
					JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
				)='tenant_id,aggregate_id'
				AND (
					SELECT string_agg(a.attname, ',' ORDER BY k.ord)
					FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum,ord)
					JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum
				)='tenant_id,decision_id'
		)
	`).Scan(&fkOK); err != nil {
		return fmt.Errorf("%w: inspect tenant-bound Decision Outbox FK: %v", ErrCatalogDrift, err)
	}
	if !fkOK {
		return fmt.Errorf("%w: tenant-bound Decision Outbox FK missing or rebound", ErrCatalogDrift)
	}

	// pg_trigger.tgtype exact bitmasks: BEFORE=2, ROW=1, UPDATE=16,
	// DELETE=8, TRUNCATE=32 (statement=34). Checking enabled state, event
	// and function catches same-name
	// replacements as well as completely missing immutability triggers.
	var validTriggers int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM (
			VALUES
				('decision_records','decision_records_no_update',19,'reject_decision_record_mutation()'),
				('decision_records','decision_records_no_delete',11,'reject_decision_record_mutation()'),
				('outbox_events','outbox_event_identity_immutable',19,'reject_decision_outbox_identity_mutation()'),
				('outbox_events','outbox_events_no_delete',11,'reject_decision_outbox_delete()'),
				('decision_records','decision_records_no_truncate',34,'reject_decision_record_mutation()'),
				('outbox_events','outbox_events_no_truncate',34,'reject_decision_outbox_delete()')
		) AS expected(table_name,trigger_name,event_bits,proc_name)
		JOIN pg_trigger t
			ON t.tgrelid=to_regclass(expected.table_name)
			AND t.tgname=expected.trigger_name
			AND t.tgtype=expected.event_bits
			AND t.tgfoid=to_regprocedure(expected.proc_name)
			AND NOT t.tgisinternal
			AND t.tgenabled='O'
	`).Scan(&validTriggers); err != nil {
		return fmt.Errorf("%w: inspect Decision immutability triggers: %v", ErrCatalogDrift, err)
	}
	if validTriggers != 6 {
		return fmt.Errorf("%w: Decision immutable trigger missing, disabled, or rebound", ErrCatalogDrift)
	}

	var identityConstraintOK bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_constraint c
			WHERE c.conrelid=to_regclass('decision_records')
				AND c.conname='decision_records_json_identity_ck'
				AND c.contype='c' AND c.convalidated
		)
	`).Scan(&identityConstraintOK); err != nil {
		return fmt.Errorf("%w: inspect Decision identity CHECK: %v", ErrCatalogDrift, err)
	}
	if !identityConstraintOK {
		return fmt.Errorf("%w: Decision JSON identity CHECK missing", ErrCatalogDrift)
	}


	// Same-name CHECK constraints can be recreated with a permissive body.
	// Pin critical expressions to the reviewed v1/v2 SQL as parsed by PG16.
	// An unreviewed PostgreSQL deparser change fails closed and requires a
	// deliberate compatibility review rather than implicit acceptance.
	criticalChecks := []struct {
		table, name, expression string
	}{
		{
			"decision_records",
			"decision_records_json_identity_ck",
			`((NOT ((record ->> 'tenant_id'::text) IS DISTINCT FROM tenant_id)) AND (NOT ((record ->> 'invocation_id'::text) IS DISTINCT FROM invocation_id)) AND (NOT ((record ->> 'decision_id'::text) IS DISTINCT FROM decision_id)) AND (NOT ((record ->> 'request_sha256'::text) IS DISTINCT FROM (request_sha256)::text)))`,
		},
		{
			"decision_records",
			"decision_records_request_sha256_check",
			`(request_sha256 ~ '^[a-f0-9]{64}$'::text)`,
		},
		{
			"outbox_events",
			"outbox_lease_pair_ck",
			`((lease_owner IS NULL) = (lease_until IS NULL))`,
		},
		{
			"outbox_events",
			"outbox_events_aggregate_type_check",
			`(aggregate_type = 'decision_record'::text)`,
		},
		{
			"outbox_events",
			"outbox_events_last_error_code_check",
			`((last_error_code IS NULL) OR (last_error_code = 'publish_failed'::text))`,
		},
	}
	for _, expected := range criticalChecks {
		var installed string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_get_expr(c.conbin, c.conrelid)
			FROM pg_constraint c
			WHERE c.conrelid = to_regclass($1)
			  AND c.conname = $2
			  AND c.contype = 'c'
			  AND c.convalidated
			  AND NOT c.connoinherit
		`, expected.table, expected.name).Scan(&installed)
		if err != nil || installed != expected.expression {
			return fmt.Errorf("%w: altered CHECK predicate %s.%s", ErrCatalogDrift,
				expected.table, expected.name)
		}
	}

	// A same-name CREATE OR REPLACE FUNCTION preserves the function OID and
	// every trigger binding checked above. Validate the *actual* installed
	// source against the immutable v1/v2 migration's reviewed function bodies.
	// Privileged schema owners can still alter these between checks; this is
	// startup drift detection, not a claim of privileged-user tamper resistance.
	immutableFunctions := []struct {
		name string
		body string
	}{
		{
			name: "reject_decision_record_mutation()",
			body: `BEGIN
    RAISE EXCEPTION 'decision_records are append-only';
END;`,
		},
		{
			name: "reject_decision_outbox_delete()",
			body: `BEGIN
    RAISE EXCEPTION 'outbox events are append-only';
END;`,
		},
		{
			name: "reject_decision_outbox_identity_mutation()",
			body: `BEGIN
    IF NEW.event_id IS DISTINCT FROM OLD.event_id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.aggregate_type IS DISTINCT FROM OLD.aggregate_type
       OR NEW.aggregate_id IS DISTINCT FROM OLD.aggregate_id
       OR NEW.aggregate_version IS DISTINCT FROM OLD.aggregate_version
       OR NEW.event_type IS DISTINCT FROM OLD.event_type
       OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
       OR NEW.payload IS DISTINCT FROM OLD.payload
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'outbox event identity and payload are immutable';
    END IF;
    RETURN NEW;
END;`,
		},
	}
	for _, expected := range immutableFunctions {
		var actualSource string
		err := tx.QueryRowContext(ctx, `
			SELECT p.prosrc FROM pg_proc p
			WHERE p.oid=to_regprocedure($1)
			  AND p.pronargs=0
			  AND p.prokind='f'
			  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
			  AND p.prorettype='pg_catalog.trigger'::regtype
			  AND p.provolatile='v'
			  AND NOT p.prosecdef AND p.proconfig IS NULL
		`, expected.name).Scan(&actualSource)
		if err != nil || strings.TrimSpace(actualSource) != expected.body {
			return fmt.Errorf("%w: Decision trigger function drift: %s", ErrCatalogDrift, expected.name)
		}
	}
	return nil
}

func decisionEventID(record Record) string {
	sum := sha256.Sum256([]byte("decision.recorded.v1\x00" + record.TenantID + "\x00" + record.DecisionID))
	return "evt_" + hex.EncodeToString(sum[:])
}

// Claim atomically leases a bounded batch. SKIP LOCKED lets concurrent
// publishers claim independent events without serializing the queue.
func (s *PostgresStore) Claim(ctx context.Context, workerID string, limit int, lease time.Duration) ([]outbox.Event, error) {
	if s == nil || s.db == nil {
		return nil, ErrStoreUnavailable
	}
	if workerID == "" || len(workerID) > 128 || limit < 1 || limit > 500 ||
		lease <= 0 || lease > 10*time.Minute {
		return nil, errors.New("invalid outbox claim parameters")
	}
	query := "WITH candidates AS (" +
		" SELECT event_id FROM outbox_events" +
		" WHERE published_at IS NULL AND available_at <= now()" +
		" AND (lease_until IS NULL OR lease_until <= now())" +
		" ORDER BY created_at, event_id LIMIT $1 FOR UPDATE SKIP LOCKED" +
		") UPDATE outbox_events AS event" +
		" SET lease_owner = $2, lease_until = now() + ($3 * interval '1 second')," +
		" attempts = event.attempts + 1" +
		" FROM candidates WHERE event.event_id = candidates.event_id" +
		" RETURNING event.event_id, event.tenant_id, event.aggregate_type, event.aggregate_id," +
		" event.aggregate_version, event.event_type, event.schema_version," +
		" event.payload, event.attempts, event.created_at"
	rows, err := s.db.QueryContext(ctx, query, limit, workerID, lease.Seconds())
	if err != nil {
		return nil, storeUnavailable("claim Decision outbox events", err)
	}
	defer rows.Close()

	events := make([]outbox.Event, 0, limit)
	for rows.Next() {
		var event outbox.Event
		if err := rows.Scan(&event.ID, &event.TenantID, &event.AggregateType, &event.AggregateID,
			&event.AggregateVersion, &event.Type, &event.SchemaVersion,
			&event.Payload, &event.Attempts, &event.CreatedAt); err != nil {
			return nil, storeUnavailable("scan Decision outbox event", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, storeUnavailable("iterate Decision outbox events", err)
	}
	return events, nil
}

// Ack requires the current unexpired worker lease and exact claim attempt.
// The attempt fences stale ACKs even when a worker ID is reused.
func (s *PostgresStore) Ack(ctx context.Context, eventID, workerID string, attempt int) error {
	if s == nil || s.db == nil {
		return ErrStoreUnavailable
	}
	if attempt < 1 {
		return outbox.ErrLeaseLost
	}
	result, err := s.db.ExecContext(ctx,
		"UPDATE outbox_events SET published_at = now(), lease_owner = NULL, lease_until = NULL "+
			"WHERE event_id = $1 AND lease_owner = $2 AND attempts = $3 AND lease_until > now() AND published_at IS NULL",
		eventID, workerID, attempt)
	if err != nil {
		return storeUnavailable("ack Decision outbox event", err)
	}
	return requireOutboxLease(result)
}

// Retry releases a failed event after a bounded delay. Lease owner,
// claim attempt and expiry fence stale workers, including reused worker IDs.
func (s *PostgresStore) Retry(ctx context.Context, eventID, workerID string, attempt int, delay time.Duration, reasonCode string) error {
	if s == nil || s.db == nil {
		return ErrStoreUnavailable
	}
	if attempt < 1 {
		return outbox.ErrLeaseLost
	}
	if delay < 0 || delay > 24*time.Hour {
		return errors.New("invalid outbox retry delay")
	}
	if reasonCode != outbox.ReasonPublishFailed {
		return errors.New("invalid outbox retry reason code")
	}
	result, err := s.db.ExecContext(ctx,
		"UPDATE outbox_events SET available_at = now() + ($3 * interval '1 second'), "+
			"last_error_code = $4, lease_owner = NULL, lease_until = NULL "+
			"WHERE event_id = $1 AND lease_owner = $2 AND attempts = $5 AND lease_until > now() AND published_at IS NULL",
		eventID, workerID, delay.Seconds(), reasonCode, attempt)
	if err != nil {
		return storeUnavailable("retry Decision outbox event", err)
	}
	return requireOutboxLease(result)
}

func requireOutboxLease(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return outbox.ErrLeaseLost
	}
	return nil
}
