package decision

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"

	schemamigrations "github.com/avaargsh/agent-decision/migrations"
)

// VerifyInstalledCatalogInSchema is a non-mutating deployment/readiness gate.
// It requires SELECT on schema_migrations and catalog visibility, but NO DDL
// privileges, and does not call migration-only INSERT behavior probes.
//
// The caller must supply a deployment-reviewed schema identifier. This is
// point-in-time evidence; it cannot prevent a privileged actor changing the
// catalog after the check. Do not use as a substitute for restricted roles,
// authenticated provenance or continuous audit.
func VerifyInstalledCatalogInSchema(ctx context.Context, db *sql.DB, schema string) error {
	if db == nil {
		return ErrStoreUnavailable
	}
	if !validDecisionSchema(schema) {
		return fmt.Errorf("%w: invalid attestation schema", ErrCatalogDrift)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("%w: begin read-only catalog attestation: %v", ErrCatalogDrift, err)
	}
	defer tx.Rollback()

	// Set only transaction-local lookup behavior. Explicitly put pg_temp last
	// to defeat temp-table shadowing; pg_catalog functions are qualified.
	if _, err := tx.ExecContext(ctx, `SELECT pg_catalog.set_config('search_path',
		pg_catalog.format('%I, pg_catalog, pg_temp', $1::text), true)`, schema); err != nil {
		return fmt.Errorf("%w: pin read-only attestation schema: %v", ErrCatalogDrift, err)
	}
	var selected string
	if err := tx.QueryRowContext(ctx, "SELECT pg_catalog.current_schema()").Scan(&selected); err != nil || selected != schema {
		return fmt.Errorf("%w: inaccessible or mismatched attestation schema %q", ErrCatalogDrift, schema)
	}

	// All three approved migration versions must exist in a contiguous,
	// exact-name, exact-SHA256 history. A missing or future version fails
	// closed; this path never creates/repairs schema_migrations.
	approved := []string{
		"0001_create_decision_records.sql",
		"0002_decision_outbox.sql",
		"0003_append_only_truncate_guards.sql",
	}
	expectedDigests := make([]string, len(approved))
	for i, name := range approved {
		source, err := schemamigrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("%w: read approved migration %s: %v", ErrCatalogDrift, name, err)
		}
		hash := sha256.Sum256(source)
		expectedDigests[i] = hex.EncodeToString(hash[:])
	}

	rows, err := tx.QueryContext(ctx, "SELECT version, name, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("%w: read migration history: %v", ErrCatalogDrift, err)
	}
	seen := 0
	for rows.Next() {
		var version int
		var name string
		var checksum sql.NullString
		if err := rows.Scan(&version, &name, &checksum); err != nil {
			rows.Close()
			return fmt.Errorf("%w: scan migration history: %v", ErrCatalogDrift, err)
		}
		if seen >= len(approved) || version != seen+1 ||
			name != approved[seen] || !checksum.Valid || checksum.String != expectedDigests[seen] {
			rows.Close()
			return fmt.Errorf("%w: unexpected version/name/checksum in migration history", ErrCatalogDrift)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("%w: iterate migration history: %v", ErrCatalogDrift, err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("%w: close migration history: %v", ErrCatalogDrift, err)
	}
	if seen != len(approved) {
		return fmt.Errorf("%w: incomplete migration history (%d of %d)", ErrCatalogDrift, seen, len(approved))
	}
	if err := verifyDecisionCatalogReadOnly(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: complete read-only attestation: %v", ErrCatalogDrift, err)
	}
	return nil
}
