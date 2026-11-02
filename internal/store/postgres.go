package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/avaargsh/agent-decision/internal/decision"
	"github.com/avaargsh/agent-decision/internal/outbox"
)

const decisionRecordedEventType = "decision.recorded.v1"

//go:embed migrations/*.sql
var migrationFiles embed.FS

type PostgresStore struct{ db *sql.DB }

func NewPostgresStore(db *sql.DB) *PostgresStore { return &PostgresStore{db: db} }

// Migrate serializes schema upgrades with a transaction-scoped advisory lock.
// Run this with a migration-capable database role before serving traffic.
func Migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(71001, 1)`); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	migrations := []struct {
		version int
		name    string
	}{
		{1, "0001_decision_records.up.sql"},
		{2, "0002_decision_records_immutable.up.sql"},
		{3, "0003_decision_records_trigger.up.sql"},
		{4, "0004_outbox_events.up.sql"},
		{5, "0005_outbox_pending_index.up.sql"},
		{6, "0006_outbox_payload_immutable.up.sql"},
		{7, "0007_outbox_payload_trigger.up.sql"},
	}
	var latestVersion int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&latestVersion); err != nil {
		return err
	}
	if latestVersion > migrations[len(migrations)-1].version {
		return fmt.Errorf("database schema version %d is newer than this binary", latestVersion)
	}
	for _, migration := range migrations {
		var applied bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, migration.version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		content, err := migrationFiles.ReadFile("migrations/" + migration.name)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(content)); err != nil {
			return fmt.Errorf("apply migration %d (%s): %w", migration.version, migration.name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name) VALUES ($1, $2)`, migration.version, migration.name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) SaveOrGet(ctx context.Context, record decision.Record) (decision.Record, bool, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return decision.Record{}, false, err
	}
	defer tx.Rollback()

	encoded, err := json.Marshal(record)
	if err != nil {
		return decision.Record{}, false, fmt.Errorf("marshal decision record: %w", err)
	}
	var stored []byte
	err = tx.QueryRowContext(ctx, `
		INSERT INTO decision_records (
			tenant_id, decision_id, idempotency_key, schema_version, subject,
			agent_id, session_id, run_id, parent_decision_id,
			request_sha256, policy_version, record_json, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $11, $12::jsonb, $13)
		ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
		RETURNING record_json`,
		record.TenantID, record.DecisionID, record.IdempotencyKey, record.SchemaVersion, record.Subject,
		record.Identity.AgentID, record.Identity.SessionID, record.Identity.RunID, record.ParentDecisionID,
		record.RequestSHA256, record.PolicyVersion, string(encoded), record.CreatedAt,
	).Scan(&stored)

	if errors.Is(err, sql.ErrNoRows) {
		var existingHash string
		err = tx.QueryRowContext(ctx, `
			SELECT request_sha256, record_json
			FROM decision_records
			WHERE tenant_id = $1 AND idempotency_key = $2
			FOR UPDATE`, record.TenantID, record.IdempotencyKey,
		).Scan(&existingHash, &stored)
		if err != nil {
			return decision.Record{}, false, fmt.Errorf("load idempotent decision: %w", err)
		}
		if existingHash != record.RequestSHA256 {
			return decision.Record{}, false, decision.ErrConflict
		}
		var existing decision.Record
		if err := json.Unmarshal(stored, &existing); err != nil {
			return decision.Record{}, false, fmt.Errorf("decode stored decision record: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return decision.Record{}, false, err
		}
		return existing, false, nil
	}
	if err != nil {
		return decision.Record{}, false, fmt.Errorf("insert decision record: %w", err)
	}

	eventPayload := string(stored)
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO outbox_events (event_id, tenant_id, aggregate_id, event_type, payload)
		VALUES ($1, $2, $3, $4, $5::jsonb)`,
		decisionEventID(record), record.TenantID, record.DecisionID, decisionRecordedEventType, eventPayload,
	); err != nil {
		return decision.Record{}, false, fmt.Errorf("insert decision outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return decision.Record{}, false, err
	}
	var persisted decision.Record
	if err := json.Unmarshal(stored, &persisted); err != nil {
		return decision.Record{}, false, fmt.Errorf("decode inserted decision record: %w", err)
	}
	return persisted, true, nil
}

func (s *PostgresStore) GetByID(ctx context.Context, tenantID, agentID, decisionID string) (decision.Record, error) {
	var encoded []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT record_json FROM decision_records WHERE tenant_id = $1 AND agent_id = $2 AND decision_id = $3`,
		tenantID, agentID, decisionID,
	).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return decision.Record{}, decision.ErrNotFound
	}
	if err != nil {
		return decision.Record{}, err
	}
	var record decision.Record
	if err := json.Unmarshal(encoded, &record); err != nil {
		return decision.Record{}, fmt.Errorf("decode decision record: %w", err)
	}
	return record, nil
}

func decisionEventID(record decision.Record) string {
	input := "decision.recorded.v1\x00" + record.TenantID + "\x00" + record.DecisionID
	sum := sha256Sum([]byte(input))
	return "evt_" + hex.EncodeToString(sum[:])
}

func sha256Sum(value []byte) [32]byte { return sha256.Sum256(value) }

func (s *PostgresStore) Claim(ctx context.Context, workerID string, limit int, lease time.Duration) ([]outbox.Event, error) {
	if workerID == "" || len(workerID) > 128 || limit < 1 || limit > 500 || lease <= 0 || lease > 10*time.Minute {
		return nil, errors.New("invalid outbox claim parameters")
	}
	rows, err := s.db.QueryContext(ctx, `
		WITH candidates AS (
			SELECT event_id FROM outbox_events
			WHERE published_at IS NULL AND available_at <= now()
			  AND (lease_until IS NULL OR lease_until <= now())
			ORDER BY created_at, event_id
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE outbox_events AS event
		SET lease_owner = $2,
		    lease_until = now() + ($3 * interval '1 second'),
		    attempts = event.attempts + 1
		FROM candidates
		WHERE event.event_id = candidates.event_id
		RETURNING event.event_id, event.tenant_id, event.aggregate_id,
		          event.event_type, event.payload, event.attempts`,
		limit, workerID, lease.Seconds(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []outbox.Event
	for rows.Next() {
		var event outbox.Event
		if err := rows.Scan(&event.ID, &event.TenantID, &event.AggregateID, &event.Type, &event.Payload, &event.Attempts); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *PostgresStore) Ack(ctx context.Context, eventID, workerID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE outbox_events
		SET published_at = now(), lease_owner = NULL, lease_until = NULL
		WHERE event_id = $1 AND lease_owner = $2 AND lease_until > now() AND published_at IS NULL`, eventID, workerID)
	if err != nil {
		return err
	}
	return requireOneRow(result)
}

func (s *PostgresStore) Retry(ctx context.Context, eventID, workerID string, delay time.Duration, cause string) error {
	if delay < 0 || delay > 24*time.Hour {
		return errors.New("invalid outbox retry delay")
	}
	cause = strings.ToValidUTF8(cause, "�")
	if len(cause) > 1024 {
		cause = cause[:1024]
		for !utf8.ValidString(cause) {
			cause = cause[:len(cause)-1]
		}
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE outbox_events
		SET available_at = now() + ($3 * interval '1 second'),
		    last_error = $4, lease_owner = NULL, lease_until = NULL
		WHERE event_id = $1 AND lease_owner = $2 AND lease_until > now() AND published_at IS NULL`,
		eventID, workerID, delay.Seconds(), cause)
	if err != nil {
		return err
	}
	return requireOneRow(result)
}

func requireOneRow(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return outbox.ErrLeaseLost
	}
	return nil
}
