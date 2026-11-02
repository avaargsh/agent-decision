package decision

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrStoreUnavailable = errors.New("decision store unavailable")

// PostgresStore persists immutable DecisionRecords. The database primary key
// enforces tenant-scoped idempotency across processes and replicas.
type PostgresStore struct { db *sql.DB }

func NewPostgresStore(db *sql.DB) *PostgresStore { return &PostgresStore{db: db} }

func (s *PostgresStore) SaveOrGet(ctx context.Context, record Record) (Record, bool, error) {
	if s == nil || s.db == nil { return Record{}, false, ErrStoreUnavailable }
	if err := ctx.Err(); err != nil { return Record{}, false, err }
	if record.TenantID == "" || record.IdempotencyKey == "" || record.DecisionID == "" ||
		!digestRe.MatchString(record.RequestSHA256) {
		return Record{}, false, fmt.Errorf("invalid record for persistence")
	}
	payload, err := json.Marshal(record)
	if err != nil { return Record{}, false, fmt.Errorf("marshal decision record: %w", err) }

	result, err := s.db.ExecContext(ctx,
		"INSERT INTO decision_records (tenant_id, idempotency_key, decision_id, request_sha256, record, created_at) VALUES ($1, $2, $3, $4, $5::jsonb, $6) ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
		record.TenantID, record.IdempotencyKey, record.DecisionID, record.RequestSHA256, payload, record.CreatedAt)
	if err != nil { return Record{}, false, fmt.Errorf("insert decision record: %w", err) }
	rows, err := result.RowsAffected()
	if err != nil { return Record{}, false, fmt.Errorf("read insert result: %w", err) }
	if rows == 1 { return clone(record), true, nil }
	if rows != 0 { return Record{}, false, fmt.Errorf("unexpected affected row count: %d", rows) }

	var storedFingerprint string
	var storedPayload []byte
	err = s.db.QueryRowContext(ctx,
		"SELECT request_sha256, record FROM decision_records WHERE tenant_id = $1 AND idempotency_key = $2",
		record.TenantID, record.IdempotencyKey).Scan(&storedFingerprint, &storedPayload)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) { return Record{}, false, fmt.Errorf("idempotency row disappeared after conflict: %w", err) }
		return Record{}, false, fmt.Errorf("load existing decision record: %w", err)
	}
	if storedFingerprint != record.RequestSHA256 { return Record{}, false, ErrConflict }
	var stored Record
	if err := json.Unmarshal(storedPayload, &stored); err != nil {
		return Record{}, false, fmt.Errorf("decode stored decision record: %w", err)
	}
	return clone(stored), false, nil
}

func (s *PostgresStore) GetByDecisionID(ctx context.Context, tenantID, agentID, sessionID, decisionID string) (Record, error) {
	if s == nil || s.db == nil {
		return Record{}, ErrStoreUnavailable
	}
	var payload []byte
	err := s.db.QueryRowContext(ctx,
		"SELECT record FROM decision_records WHERE tenant_id = $1 AND decision_id = $2 AND record->>'agent_id' = $3 AND record->>'session_id' = $4",
		tenantID, decisionID, agentID, sessionID).Scan(&payload)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrNotFound
		}
		return Record{}, fmt.Errorf("load decision record: %w", err)
	}
	var record Record
	if err := json.Unmarshal(payload, &record); err != nil {
		return Record{}, fmt.Errorf("decode decision record: %w", err)
	}
	return clone(record), nil
}

func (s *PostgresStore) ListByRun(ctx context.Context, tenantID, agentID, sessionID, runID string, before *DecisionCursor, limit int) ([]Record, error) {
	if s == nil || s.db == nil {
		return nil, ErrStoreUnavailable
	}
	if limit < 1 {
		return nil, fmt.Errorf("ledger query limit must be positive")
	}
	query := "SELECT record FROM decision_records WHERE tenant_id = $1 AND record->>'agent_id' = $2 AND record->>'session_id' = $3 AND record->>'run_id' = $4"
	args := []any{tenantID, agentID, sessionID, runID}
	if before != nil {
		query += " AND (created_at, decision_id) < ($5, $6)"
		args = append(args, before.CreatedAt, before.DecisionID)
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY created_at DESC, decision_id DESC LIMIT $%d", len(args))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list decision records: %w", err)
	}
	defer rows.Close()
	records := make([]Record, 0, limit)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan decision record: %w", err)
		}
		var record Record
		if err := json.Unmarshal(payload, &record); err != nil {
			return nil, fmt.Errorf("decode decision record: %w", err)
		}
		records = append(records, clone(record))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate decision records: %w", err)
	}
	return records, nil
}
