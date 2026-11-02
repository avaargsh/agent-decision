package decision

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var ErrStoreUnavailable = errors.New("decision store unavailable")

// PostgresStore persists immutable DecisionRecords. The database primary key
// enforces tenant-scoped idempotency across processes and replicas.
type PostgresStore struct { db *sql.DB }

func NewPostgresStore(db *sql.DB) *PostgresStore { return &PostgresStore{db: db} }

func storeUnavailable(operation string, err error) error {
	return fmt.Errorf("%w: %s: %v", ErrStoreUnavailable, operation, err)
}

// GetByInvocation resolves an existing immutable invocation result within one tenant.
func (s *PostgresStore) GetByInvocation(ctx context.Context, tenantID, invocationID string) (Record, error) {
	if s == nil || s.db == nil {
		return Record{}, ErrStoreUnavailable
	}
	var fingerprint string
	var payload []byte
	err := s.db.QueryRowContext(ctx,
		"SELECT request_sha256, record FROM decision_records WHERE tenant_id = $1 AND invocation_id = $2",
		tenantID, invocationID).Scan(&fingerprint, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, storeUnavailable("lookup Decision invocation", err)
	}
	var record Record
	if err := json.Unmarshal(payload, &record); err != nil {
		return Record{}, fmt.Errorf("decode stored DecisionRecord: %w", err)
	}
	if record.TenantID != tenantID || record.InvocationID != invocationID ||
		record.RequestSHA256 != fingerprint {
		return Record{}, errors.New("stored DecisionRecord identity does not match indexed columns")
	}
	return clone(record), nil
}

func (s *PostgresStore) SaveOrGet(ctx context.Context, record Record) (Record, bool, error) {
	if s == nil || s.db == nil { return Record{}, false, ErrStoreUnavailable }
	if err := ctx.Err(); err != nil { return Record{}, false, err }
	if record.TenantID == "" || record.InvocationID == "" || record.DecisionID == "" ||
		!digestRe.MatchString(record.RequestSHA256) {
		return Record{}, false, fmt.Errorf("invalid record for persistence")
	}
	record.CreatedAt = record.CreatedAt.UTC().Truncate(time.Microsecond)
	payload, err := json.Marshal(record)
	if err != nil { return Record{}, false, fmt.Errorf("marshal decision record: %w", err) }

	result, err := s.db.ExecContext(ctx,
		"INSERT INTO decision_records (tenant_id, invocation_id, decision_id, request_sha256, record, created_at) VALUES ($1, $2, $3, $4, $5::jsonb, $6) ON CONFLICT (tenant_id, invocation_id) DO NOTHING",
		record.TenantID, record.InvocationID, record.DecisionID, record.RequestSHA256, payload, record.CreatedAt)
	if err != nil { return Record{}, false, storeUnavailable("insert DecisionRecord", err) }
	rows, err := result.RowsAffected()
	if err != nil { return Record{}, false, storeUnavailable("read DecisionRecord insert result", err) }
	if rows == 1 { return clone(record), true, nil }
	if rows != 0 { return Record{}, false, fmt.Errorf("unexpected affected row count: %d", rows) }

	var storedFingerprint string
	var storedPayload []byte
	err = s.db.QueryRowContext(ctx,
		"SELECT request_sha256, record FROM decision_records WHERE tenant_id = $1 AND invocation_id = $2",
		record.TenantID, record.InvocationID).Scan(&storedFingerprint, &storedPayload)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) { return Record{}, false, storeUnavailable("load invocation after uniqueness conflict", err) }
		return Record{}, false, storeUnavailable("load existing DecisionRecord", err)
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
		return Record{}, storeUnavailable("load DecisionRecord", err)
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
		return nil, storeUnavailable("list DecisionRecords", err)
	}
	defer rows.Close()
	records := make([]Record, 0, limit)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, storeUnavailable("scan DecisionRecord", err)
		}
		var record Record
		if err := json.Unmarshal(payload, &record); err != nil {
			return nil, fmt.Errorf("decode decision record: %w", err)
		}
		records = append(records, clone(record))
	}
	if err := rows.Err(); err != nil {
		return nil, storeUnavailable("iterate DecisionRecords", err)
	}
	return records, nil
}
