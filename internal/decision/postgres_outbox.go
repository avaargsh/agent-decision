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
	if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"); err != nil {
		return storeUnavailable("create schema_migrations", err)
	}

	migrations := []struct {
		version int
		name    string
	}{
		{1, "0001_create_decision_records.sql"},
		{2, "0002_decision_outbox.sql"},
	}
	var latest int
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&latest); err != nil {
		return storeUnavailable("read schema version", err)
	}
	if latest > migrations[len(migrations)-1].version {
		return fmt.Errorf("database schema version %d is newer than this binary", latest)
	}

	for _, migration := range migrations {
		var applied bool
		if err := tx.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)",
			migration.version).Scan(&applied); err != nil {
			return storeUnavailable("read migration history", err)
		}
		if applied {
			continue
		}
		source, err := schemamigrations.FS.ReadFile(migration.name)
		if err != nil {
			return fmt.Errorf("read migration %d (%s): %w", migration.version, migration.name, err)
		}
		if _, err := tx.ExecContext(ctx, string(source)); err != nil {
			return storeUnavailable(fmt.Sprintf("apply migration %d (%s)", migration.version, migration.name), err)
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations(version, name) VALUES ($1, $2)",
			migration.version, migration.name); err != nil {
			return storeUnavailable("record schema migration", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return storeUnavailable("commit migrations", err)
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

// Ack accepts acknowledgements only from the current, unexpired lease owner.
func (s *PostgresStore) Ack(ctx context.Context, eventID, workerID string) error {
	if s == nil || s.db == nil {
		return ErrStoreUnavailable
	}
	result, err := s.db.ExecContext(ctx,
		"UPDATE outbox_events SET published_at = now(), lease_owner = NULL, lease_until = NULL "+
			"WHERE event_id = $1 AND lease_owner = $2 AND lease_until > now() AND published_at IS NULL",
		eventID, workerID)
	if err != nil {
		return storeUnavailable("ack Decision outbox event", err)
	}
	return requireOutboxLease(result)
}

// Retry releases a failed event after a bounded delay. Lease ownership and
// expiry checks prevent a previous worker overwriting a later claim.
func (s *PostgresStore) Retry(ctx context.Context, eventID, workerID string, delay time.Duration, cause string) error {
	if s == nil || s.db == nil {
		return ErrStoreUnavailable
	}
	if delay < 0 || delay > 24*time.Hour {
		return errors.New("invalid outbox retry delay")
	}
	cause = strings.ToValidUTF8(cause, "�")
	if len(cause) > 1024 {
		runes := []rune(cause)
		if len(runes) > 256 {
			cause = string(runes[:256])
		}
	}
	result, err := s.db.ExecContext(ctx,
		"UPDATE outbox_events SET available_at = now() + ($3 * interval '1 second'), "+
			"last_error = $4, lease_owner = NULL, lease_until = NULL "+
			"WHERE event_id = $1 AND lease_owner = $2 AND lease_until > now() AND published_at IS NULL",
		eventID, workerID, delay.Seconds(), cause)
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
