// Package evidenceauthority is an independent source-owned publication
// registry, not the DecisionRecord ledger. Only separately provisioned
// source/reader/revoker DB identities may use it; never grant an Agent DML.
package evidenceauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
)

var ErrConflict = errors.New("source evidence reference already has different immutable bytes")
var schemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
var reasonCode = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

func trustedSchema(schema string) bool {
	return schemaName.MatchString(schema) && !strings.HasPrefix(schema, "pg_") && schema != "information_schema"
}

// Install is a fresh-source bootstrap, owned by the source migration role.
// The schema must already exist. No application constructor performs DDL;
// production upgrade, catalog attestation, backup and DB-role gates remain
// separate deployment requirements.
func Install(ctx context.Context, db *sql.DB, schema string) error {
	if db == nil || !trustedSchema(schema) {
		return decision.ErrAuthorityUnavailable
	}
	s := `"` + schema + `"`
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		fmt.Sprintf(`CREATE TABLE %s.evidence_publications (
			source_id text NOT NULL, ref text NOT NULL, tenant_id text NOT NULL,
			agent_id text NOT NULL, run_id text NOT NULL, service text NOT NULL,
			resource_ref text NOT NULL, digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
			proof bytea NOT NULL CHECK (octet_length(proof) BETWEEN 2 AND 524288),
			published_at timestamptz NOT NULL DEFAULT clock_timestamp(),
			PRIMARY KEY(source_id,ref)
		)`, s),
		fmt.Sprintf(`CREATE TABLE %s.evidence_revocations (
			source_id text NOT NULL, ref text NOT NULL,
			reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
			revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
			PRIMARY KEY(source_id,ref),
			FOREIGN KEY(source_id,ref) REFERENCES %s.evidence_publications(source_id,ref)
		)`, s, s),
		fmt.Sprintf(`CREATE FUNCTION %s.reject_evidence_mutation() RETURNS trigger
			LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable source evidence'; END; $$`, s),
		fmt.Sprintf(`REVOKE ALL ON FUNCTION %s.reject_evidence_mutation() FROM PUBLIC`, s),
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	for _, name := range []string{"evidence_publications", "evidence_revocations"} {
		rel := s + "." + name
		for _, stmt := range []string{
			fmt.Sprintf("CREATE TRIGGER evidence_no_mutation BEFORE UPDATE OR DELETE ON %s FOR EACH ROW EXECUTE FUNCTION %s.reject_evidence_mutation()", rel, s),
			fmt.Sprintf("CREATE TRIGGER evidence_no_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION %s.reject_evidence_mutation()", rel, s),
			fmt.Sprintf("ALTER TABLE %s ENABLE ALWAYS TRIGGER evidence_no_mutation", rel),
			fmt.Sprintf("ALTER TABLE %s ENABLE ALWAYS TRIGGER evidence_no_truncate", rel),
			fmt.Sprintf("REVOKE ALL ON TABLE %s FROM PUBLIC", rel),
		} {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

type Registry struct {
	db           *sql.DB
	publications string
	revocations  string
	scope        decision.EvidenceSourceScope
	key          ed25519.PublicKey
}

func New(db *sql.DB, schema string, scope decision.EvidenceSourceScope, key ed25519.PublicKey) (*Registry, error) {
	if db == nil || !trustedSchema(schema) || len(key) != ed25519.PublicKeySize ||
		scope.TenantID == "" || scope.RunID == "" || scope.SourceID == "" {
		return nil, decision.ErrAuthorityUnavailable
	}
	s := `"` + schema + `"`
	return &Registry{db: db, publications: s + ".evidence_publications", revocations: s + ".evidence_revocations",
		scope: scope, key: bytes.Clone(key)}, nil
}

func (r *Registry) scopeMatches(e decision.EvidenceRef) bool {
	return e.Ref != "" && e.SourceID == r.scope.SourceID && e.TenantID == r.scope.TenantID &&
		e.AgentID == r.scope.AgentID && e.RunID == r.scope.RunID && e.Service == r.scope.Service &&
		e.ResourceRef == r.scope.ResourceRef && e.Source == r.scope.Source &&
		e.SourceVersion == r.scope.SourceVersion && e.EvidenceType == r.scope.EvidenceType &&
		e.SchemaVersion == r.scope.SchemaVersion
}

// Publish is a collector-side operation. The source's pinned public key
// verifies every byte before an immutable (source, ref) record is inserted.
// A replay never changes bytes or reactivates revoked evidence.
func (r *Registry) Publish(ctx context.Context, ref decision.EvidenceRef, proof []byte, now time.Time) error {
	if r == nil || r.db == nil {
		return decision.ErrAuthorityUnavailable
	}
	if !r.scopeMatches(ref) || decision.VerifyEvidencePublication(proof, r.key, r.scope, ref, now) != nil {
		return decision.ErrAuthorityRejected
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return decision.ErrAuthorityUnavailable
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s(source_id,ref,tenant_id,agent_id,run_id,service,resource_ref,digest,proof)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT(source_id,ref) DO NOTHING
	`, r.publications), ref.SourceID, ref.Ref, ref.TenantID, ref.AgentID, ref.RunID, ref.Service, ref.ResourceRef, ref.SHA256, proof)
	if err != nil {
		return decision.ErrAuthorityUnavailable
	}
	var saved []byte
	var revoked bool
	err = tx.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT p.proof, EXISTS(SELECT 1 FROM %s v WHERE v.source_id=p.source_id AND v.ref=p.ref)
		FROM %s p WHERE p.source_id=$1 AND p.ref=$2
	`, r.revocations, r.publications), ref.SourceID, ref.Ref).Scan(&saved, &revoked)
	if err != nil {
		return decision.ErrAuthorityUnavailable
	}
	if revoked {
		return decision.ErrAuthorityRejected
	}
	if !bytes.Equal(saved, proof) {
		return ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return decision.ErrAuthorityUnavailable
	}
	return nil
}

// ReadCurrent obtains fresh source-owned evidence and revocation status in
// one statement. A missing, revoked, foreign, expired or corrupted record
// never yields bytes. The observation is point-in-time; never a Permit.
func (r *Registry) ReadCurrent(ctx context.Context, ref decision.EvidenceRef, now time.Time) ([]byte, error) {
	if r == nil || r.db == nil {
		return nil, decision.ErrAuthorityUnavailable
	}
	if !r.scopeMatches(ref) {
		return nil, decision.ErrAuthorityRejected
	}
	var proof []byte
	err := r.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT p.proof FROM %s p
		WHERE p.source_id=$1 AND p.ref=$2 AND p.tenant_id=$3 AND p.agent_id=$4
		  AND p.run_id=$5 AND p.service=$6 AND p.resource_ref=$7 AND p.digest=$8
		  AND NOT EXISTS(SELECT 1 FROM %s v WHERE v.source_id=p.source_id AND v.ref=p.ref)
	`, r.publications, r.revocations), ref.SourceID, ref.Ref, ref.TenantID, ref.AgentID, ref.RunID,
		ref.Service, ref.ResourceRef, ref.SHA256).Scan(&proof)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, decision.ErrAuthorityRejected
	}
	if err != nil {
		return nil, decision.ErrAuthorityUnavailable
	}
	if err := decision.VerifyEvidencePublication(proof, r.key, r.scope, ref, now); err != nil {
		return nil, err
	}
	return proof, nil
}

// Revoke is an operator-side append-only tombstone. The revoker must have
// separate SQL grants; no DELETE/UPDATE path exists to reactivate a ref.
func (r *Registry) Revoke(ctx context.Context, ref decision.EvidenceRef, reason string) error {
	if r == nil || r.db == nil {
		return decision.ErrAuthorityUnavailable
	}
	if !r.scopeMatches(ref) || !reasonCode.MatchString(reason) {
		return decision.ErrAuthorityRejected
	}
	var present bool
	if err := r.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT EXISTS(SELECT 1 FROM %s WHERE source_id=$1 AND ref=$2 AND tenant_id=$3 AND agent_id=$4
		  AND run_id=$5 AND service=$6 AND resource_ref=$7 AND digest=$8)
	`, r.publications), ref.SourceID, ref.Ref, ref.TenantID, ref.AgentID, ref.RunID, ref.Service, ref.ResourceRef, ref.SHA256).Scan(&present); err != nil {
		return decision.ErrAuthorityUnavailable
	}
	if !present {
		return decision.ErrAuthorityRejected
	}
	if _, err := r.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s(source_id,ref,reason_code) VALUES($1,$2,$3)
		ON CONFLICT(source_id,ref) DO NOTHING
	`, r.revocations), ref.SourceID, ref.Ref, reason); err != nil {
		return decision.ErrAuthorityUnavailable
	}
	return nil
}
