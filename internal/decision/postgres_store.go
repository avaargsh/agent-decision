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
type PostgresStore struct {
	db *sql.DB
	bound *tenantTransactionBinding
}

// tenantTransactionBinding is supplied by trusted deployment configuration.
// It is not derived from an incoming request. A bound store is private until
// pool routing, policy attestation and dispatcher separation are complete.
type tenantTransactionBinding struct {
	tenantID string
	schema string
	login runtimeLoginBinding
}

func newBoundPostgresStore(db *sql.DB, schema, tenantID string, login runtimeLoginBinding) (*PostgresStore, error) {
	if db == nil {
		return nil, ErrStoreUnavailable
	}
	if !validDecisionSchema(schema) || !nameRe.MatchString(tenantID) ||
		login.Database == "" || login.RoleName == "" || login.RoleOID == 0 {
		return nil, fmt.Errorf("%w: incomplete tenant transaction binding", ErrCatalogDrift)
	}
	return &PostgresStore{db: db, bound: &tenantTransactionBinding{
		tenantID: tenantID, schema: schema, login: login,
	}}, nil
}

func NewPostgresStore(db *sql.DB) *PostgresStore { return &PostgresStore{db: db} }

func storeUnavailable(operation string, err error) error {
	return fmt.Errorf("%w: %s: %v", ErrStoreUnavailable, operation, err)
}

// beginTenantTx binds the authenticated application tenant for the lifetime of
// one transaction. The GUC is a defense-in-depth SQL scope, not a trusted
// identity against a database login capable of executing arbitrary SQL.
// Dispatcher operations deliberately do not use this tenant-scoped helper.
func (s *PostgresStore) beginTenantTx(ctx context.Context, tenantID string, readOnly bool) (*sql.Tx, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("%w: empty tenant context", ErrInvalidRequest)
	}
	if s.bound != nil && s.bound.tenantID != tenantID {
		return nil, fmt.Errorf("%w: tenant transaction binding mismatch", ErrAuthorityRejected)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted, ReadOnly: readOnly})
	if err != nil {
		return nil, storeUnavailable("begin tenant transaction", err)
	}
	// SET LOCAL restores the prior session value on commit or rollback.
	// Reject a contaminated pooled connection before any ledger access,
	// even when its ambient tenant happens to match this request. Do not
	// silently reset it or treat the custom GUC as authenticated identity.
	var ambient string
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(pg_catalog.current_setting('decision.tenant_id', true), '')").Scan(&ambient); err != nil || ambient != "" {
		_ = tx.Rollback()
		return nil, fmt.Errorf("%w: unsafe ambient tenant context", ErrCatalogDrift)
	}
	if s.bound != nil {
		if err := verifyRuntimeTransactionIdentity(ctx, tx, s.bound.schema, &s.bound.login); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		if err := verifyTenantLoginMappingTx(ctx, tx, tenantID, s.bound.login, "application"); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, "SELECT pg_catalog.set_config('decision.tenant_id', $1, true)", tenantID); err != nil {
		_ = tx.Rollback()
		return nil, storeUnavailable("bind transaction tenant context", err)
	}
	return tx, nil
}

// Read the immutable JSON only after proving that its identity and creation
// timestamp match the independently indexed PostgreSQL columns. Ledger
// pagination is ordered by the indexed timestamp, so accepting a conflicting
// JSON timestamp would create an unsound continuation cursor.
func decodeIndexedDecisionRecord(payload []byte, tenantID, invocationID, decisionID, requestSHA256 string, createdAt time.Time) (Record, error) {
	var record Record
	if err := json.Unmarshal(payload, &record); err != nil {
		return Record{}, fmt.Errorf("%w: unreadable indexed DecisionRecord JSON: %v", ErrCatalogDrift, err)
	}
	if record.TenantID != tenantID || record.InvocationID != invocationID ||
		record.DecisionID != decisionID || record.RequestSHA256 != requestSHA256 ||
		record.CreatedAt.IsZero() || !record.CreatedAt.Equal(createdAt) {
		return Record{}, fmt.Errorf("%w: indexed DecisionRecord identity or creation time mismatch", ErrCatalogDrift)
	}
	return clone(record), nil
}

// GetByInvocation resolves an existing immutable invocation result within one tenant.
func (s *PostgresStore) GetByInvocation(ctx context.Context, tenantID, invocationID string) (Record, error) {
	if s == nil || s.db == nil {
		return Record{}, ErrStoreUnavailable
	}
	var decisionID, fingerprint string
	var createdAt time.Time
	var payload []byte
	tx, err := s.beginTenantTx(ctx, tenantID, true)
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx,
		"SELECT decision_id, request_sha256, created_at, record FROM decision_records WHERE tenant_id = $1 AND invocation_id = $2",
		tenantID, invocationID).Scan(&decisionID, &fingerprint, &createdAt, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, storeUnavailable("lookup Decision invocation", err)
	}
	record, err := decodeIndexedDecisionRecord(payload, tenantID, invocationID, decisionID, fingerprint, createdAt)
	if err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, storeUnavailable("commit tenant invocation read", err)
	}
	return record, nil
}

func (s *PostgresStore) SaveOrGet(ctx context.Context, record Record) (Record, bool, error) {
	if s == nil || s.db == nil {
		return Record{}, false, ErrStoreUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Record{}, false, err
	}
	if record.TenantID == "" || record.InvocationID == "" || record.DecisionID == "" ||
		!digestRe.MatchString(record.RequestSHA256) {
		return Record{}, false, fmt.Errorf("invalid record for persistence")
	}
	record.CreatedAt = record.CreatedAt.UTC().Truncate(time.Microsecond)
	// Reads reject zero creation time, including timestamps that normalize
	// to zero at PostgreSQL's microsecond precision. Never commit a record
	// that the ledger cannot subsequently replay.
	if record.CreatedAt.IsZero() {
		return Record{}, false, fmt.Errorf("%w: zero normalized record creation time", ErrInvalidRequest)
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return Record{}, false, fmt.Errorf("marshal decision record: %w", err)
	}

	tx, err := s.beginTenantTx(ctx, record.TenantID, false)
	if err != nil {
		return Record{}, false, err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		"INSERT INTO decision_records (tenant_id, invocation_id, decision_id, request_sha256, record, created_at) VALUES ($1, $2, $3, $4, $5::jsonb, $6) ON CONFLICT (tenant_id, invocation_id) DO NOTHING",
		record.TenantID, record.InvocationID, record.DecisionID, record.RequestSHA256, payload, record.CreatedAt)
	if err != nil {
		return Record{}, false, storeUnavailable("insert DecisionRecord", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Record{}, false, storeUnavailable("read DecisionRecord insert result", err)
	}
	if rows == 1 {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO outbox_events (
				event_id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
				event_type, schema_version, payload
			) VALUES ($1, $2, 'decision_record', $3, 1, 'decision.recorded.v1', 1, $4::jsonb)`,
			decisionEventID(record), record.TenantID, record.DecisionID, payload)
		if err != nil {
			return Record{}, false, storeUnavailable("insert Decision outbox event", err)
		}
		if err := tx.Commit(); err != nil {
			return Record{}, false, storeUnavailable("commit DecisionRecord and outbox", err)
		}
		return clone(record), true, nil
	}
	if rows != 0 {
		return Record{}, false, fmt.Errorf("unexpected affected row count: %d", rows)
	}

	var storedDecisionID, storedFingerprint string
	var storedCreatedAt time.Time
	var storedPayload []byte
	err = tx.QueryRowContext(ctx,
		"SELECT decision_id, request_sha256, created_at, record FROM decision_records WHERE tenant_id = $1 AND invocation_id = $2",
		record.TenantID, record.InvocationID).Scan(&storedDecisionID, &storedFingerprint, &storedCreatedAt, &storedPayload)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, false, storeUnavailable("load invocation after uniqueness conflict", err)
		}
		return Record{}, false, storeUnavailable("load existing DecisionRecord", err)
	}
	if storedFingerprint != record.RequestSHA256 {
		return Record{}, false, ErrConflict
	}
	stored, err := decodeIndexedDecisionRecord(storedPayload, record.TenantID, record.InvocationID,
		storedDecisionID, storedFingerprint, storedCreatedAt)
	if err != nil {
		return Record{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, false, storeUnavailable("commit idempotent DecisionRecord replay", err)
	}
	return stored, false, nil
}

func (s *PostgresStore) GetByDecisionID(ctx context.Context, tenantID, agentID, sessionID, decisionID string) (Record, error) {
	if s == nil || s.db == nil {
		return Record{}, ErrStoreUnavailable
	}
	var invocationID, fingerprint string
	var createdAt time.Time
	var payload []byte
	tx, err := s.beginTenantTx(ctx, tenantID, true)
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx,
		"SELECT invocation_id, request_sha256, created_at, record FROM decision_records WHERE tenant_id = $1 AND decision_id = $2 AND record->>'agent_id' = $3 AND record->>'session_id' = $4",
		tenantID, decisionID, agentID, sessionID).Scan(&invocationID, &fingerprint, &createdAt, &payload)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrNotFound
		}
		return Record{}, storeUnavailable("load DecisionRecord", err)
	}
	record, err := decodeIndexedDecisionRecord(payload, tenantID, invocationID, decisionID, fingerprint, createdAt)
	if err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, storeUnavailable("commit tenant decision read", err)
	}
	return record, nil
}

func (s *PostgresStore) ListByRun(ctx context.Context, tenantID, agentID, sessionID, runID string, before *DecisionCursor, limit int) ([]Record, error) {
	if s == nil || s.db == nil {
		return nil, ErrStoreUnavailable
	}
	if limit < 1 {
		return nil, fmt.Errorf("ledger query limit must be positive")
	}
	query := "SELECT invocation_id, decision_id, request_sha256, created_at, record FROM decision_records WHERE tenant_id = $1 AND record->>'agent_id' = $2 AND record->>'session_id' = $3 AND record->>'run_id' = $4"
	args := []any{tenantID, agentID, sessionID, runID}
	if before != nil {
		query += " AND (created_at, decision_id) < ($5, $6)"
		args = append(args, before.CreatedAt, before.DecisionID)
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY created_at DESC, decision_id DESC LIMIT $%d", len(args))

	tx, err := s.beginTenantTx(ctx, tenantID, true)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, storeUnavailable("list DecisionRecords", err)
	}
	defer rows.Close()
	records := make([]Record, 0, limit)
	for rows.Next() {
		var invocationID, decisionID, fingerprint string
		var createdAt time.Time
		var payload []byte
		if err := rows.Scan(&invocationID, &decisionID, &fingerprint, &createdAt, &payload); err != nil {
			return nil, storeUnavailable("scan DecisionRecord", err)
		}
		record, err := decodeIndexedDecisionRecord(payload, tenantID, invocationID, decisionID, fingerprint, createdAt)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, storeUnavailable("iterate DecisionRecords", err)
	}
	if err := rows.Close(); err != nil {
		return nil, storeUnavailable("close DecisionRecords", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, storeUnavailable("commit tenant ledger read", err)
	}
	return records, nil
}
