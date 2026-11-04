package decision

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"strings"

	"github.com/avaargsh/agent-decision/internal/outbox"
	schemamigrations "github.com/avaargsh/agent-decision/migrations"
)

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
	// The migration ledger attests approved SQL bytes, not live catalog state.
	// A disabled or replaced trigger would compromise append-only guarantees
	// even if the schema_migrations metadata has not changed.
	if err := verifyLedgerProtectionTriggers(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return storeUnavailable("commit migrations", err)
	}
	return nil
}


// verifyLedgerProtectionTriggers checks that the live PostgreSQL safeguards
// still match the approved DDL. SQL-byte migration hashes alone cannot detect
// edits to trigger WHEN/UPDATE OF clauses or CREATE OR REPLACE FUNCTION bodies.
// PostgreSQL tgtype flags: ROW (1), BEFORE (2), DELETE (8), UPDATE (16).
func verifyLedgerProtectionTriggers(ctx context.Context, tx *sql.Tx) error {
	const recordMutationBody = `BEGIN
    RAISE EXCEPTION 'decision_records are append-only';
END;`
	const outboxMutationBody = `BEGIN
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
END;`
	const outboxDeleteBody = `BEGIN
    RAISE EXCEPTION 'outbox events are append-only';
END;`
	required := []struct {
		table string
		name string
		function string
		triggerType int
		body string
	}{
		{"decision_records", "decision_records_no_update", "reject_decision_record_mutation()", 19, recordMutationBody},
		{"decision_records", "decision_records_no_delete", "reject_decision_record_mutation()", 11, recordMutationBody},
		{"outbox_events", "outbox_event_identity_immutable", "reject_decision_outbox_identity_mutation()", 19, outboxMutationBody},
		{"outbox_events", "outbox_events_no_delete", "reject_decision_outbox_delete()", 11, outboxDeleteBody},
	}
	const query = `SELECT t.tgenabled::text, t.tgtype::integer,
		t.tgfoid = to_regprocedure($3),
		t.tgqual IS NULL, t.tgattr::text,
		p.prosrc, l.lanname, p.prosecdef
		FROM pg_trigger AS t
		JOIN pg_proc AS p ON p.oid = t.tgfoid
		JOIN pg_language AS l ON l.oid = p.prolang
		WHERE t.tgrelid = to_regclass($1)
		  AND t.tgname = $2 AND NOT t.tgisinternal`
	for _, item := range required {
		var enabled, updateColumns, handlerBody, language string
		var triggerType int
		var expectedFunction sql.NullBool
		var noWhen bool
		var securityDefiner bool
		err := tx.QueryRowContext(ctx, query, item.table, item.name, item.function).
			Scan(&enabled, &triggerType, &expectedFunction, &noWhen,
				&updateColumns, &handlerBody, &language, &securityDefiner)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("critical ledger protection trigger %s.%s missing", item.table, item.name)
		}
		if err != nil {
			return storeUnavailable("inspect ledger protection trigger", err)
		}
		if (enabled != "O" && enabled != "A") || triggerType != item.triggerType ||
			!expectedFunction.Valid || !expectedFunction.Bool || !noWhen ||
			updateColumns != "" || language != "plpgsql" || securityDefiner ||
			strings.TrimSpace(handlerBody) != strings.TrimSpace(item.body) {
			return fmt.Errorf("critical ledger protection trigger %s.%s disabled or altered", item.table, item.name)
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
