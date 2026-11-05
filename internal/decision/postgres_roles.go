package decision

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// RuntimeDatabaseRole specifies exactly one database permission boundary.
// The migration owner and catalog-attestation identity are deliberately NOT
// accepted as an application or outbox dispatcher.
type RuntimeDatabaseRole string

const (
	RuntimeRoleApplication RuntimeDatabaseRole = "application"
	RuntimeRoleDispatcher  RuntimeDatabaseRole = "dispatcher"
)

// VerifyRuntimeDatabaseRole checks effective PostgreSQL grants, including
// inherited/table-wide/column-specific permissions, rather than merely
// inspecting named GRANT statements. The caller must use the actual restricted
// connection pool and a deployment-controlled, trusted schema identifier.
//
// This does NOT provide RLS or prove tenant isolation. A successful role check
// must be combined with catalog attestation, real TLS/identity, and tenant
// authorization at the service/database boundary.
func VerifyRuntimeDatabaseRole(ctx context.Context, db *sql.DB, schema string, role RuntimeDatabaseRole) error {
	if db == nil {
		return ErrStoreUnavailable
	}
	if !validDecisionSchema(schema) || (role != RuntimeRoleApplication && role != RuntimeRoleDispatcher) {
		return fmt.Errorf("%w: unrecognized database role or schema contract", ErrCatalogDrift)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("%w: begin role privilege check: %v", ErrCatalogDrift, err)
	}
	defer tx.Rollback()

	// Never rely on ambient search_path or an untrusted current_schema value.
	if _, err := tx.ExecContext(ctx, `SELECT pg_catalog.set_config('search_path',
		pg_catalog.format('%I, pg_catalog, pg_temp', $1::text), true)`, schema); err != nil {
		return fmt.Errorf("%w: bind runtime role schema: %v", ErrCatalogDrift, err)
	}
	var identityOK bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR
		            r.rolreplication OR r.rolbypassrls)
		       AND pg_catalog.has_schema_privilege(current_user, $1, 'USAGE')
		       AND NOT pg_catalog.has_schema_privilege(current_user, $1, 'CREATE')
		       AND NOT pg_catalog.has_database_privilege(current_user, current_database(), 'CREATE')
		       AND NOT pg_catalog.pg_has_role(current_user, n.nspowner, 'MEMBER')
		FROM pg_catalog.pg_roles AS r
		JOIN pg_catalog.pg_namespace AS n ON n.nspname = $1
		WHERE r.rolname = current_user
	`, schema).Scan(&identityOK); err != nil || !identityOK {
		return fmt.Errorf("%w: unsafe runtime database role identity/ownership", ErrCatalogDrift)
	}

	// Every table and column grant is checked. A table-wide UPDATE grant is
	// detected because has_column_privilege covers its resulting effective
	// column privileges. This also catches grants inherited from other roles.
	type policy struct {
		table, selectMode, insertMode, updateMode string
	}
	var policies []policy
	if role == RuntimeRoleApplication {
		policies = []policy{
			{"schema_migrations", "", "", ""},
			{"decision_records", "all", "all", ""},
			{"outbox_events", "", "all", ""},
		}
	} else {
		policies = []policy{
			{"schema_migrations", "", "", ""},
			{"decision_records", "", "", ""},
			{"outbox_events", "all", "", "attempts,available_at,last_error_code,lease_owner,lease_until,published_at"},
		}
	}
	for _, item := range policies {
		var n int
		var all, selected, inserted, updated string
		var anyForbidden bool
		err := tx.QueryRowContext(ctx, `
			WITH rel AS (
				SELECT pg_catalog.to_regclass(pg_catalog.format('%I.%I', $1::text, $2::text)) AS oid
			), rights AS (
				SELECT a.attname,
				       pg_catalog.has_column_privilege(current_user, a.attrelid, a.attname, 'SELECT') AS can_read,
				       pg_catalog.has_column_privilege(current_user, a.attrelid, a.attname, 'INSERT') AS can_insert,
				       pg_catalog.has_column_privilege(current_user, a.attrelid, a.attname, 'UPDATE') AS can_update
				FROM pg_catalog.pg_attribute AS a, rel
				WHERE a.attrelid = rel.oid AND a.attnum > 0 AND NOT a.attisdropped
			)
			SELECT (SELECT COUNT(*) FROM rights)::integer,
			       COALESCE((SELECT string_agg(attname, ',' ORDER BY attname) FROM rights), ''),
			       COALESCE((SELECT string_agg(attname, ',' ORDER BY attname) FROM rights WHERE can_read), ''),
			       COALESCE((SELECT string_agg(attname, ',' ORDER BY attname) FROM rights WHERE can_insert), ''),
			       COALESCE((SELECT string_agg(attname, ',' ORDER BY attname) FROM rights WHERE can_update), ''),
			       COALESCE((
			        SELECT
			           pg_catalog.has_table_privilege(current_user, oid, 'DELETE')
			           OR pg_catalog.has_table_privilege(current_user, oid, 'TRUNCATE')
			           OR pg_catalog.has_table_privilege(current_user, oid, 'REFERENCES')
			           OR pg_catalog.has_table_privilege(current_user, oid, 'TRIGGER')
			        FROM rel
			       ), true)
		`, schema, item.table).Scan(&n, &all, &selected, &inserted, &updated, &anyForbidden)
		if err != nil || n == 0 || anyForbidden {
			return fmt.Errorf("%w: missing table or forbidden privilege on %s", ErrCatalogDrift, item.table)
		}
		want := func(mode string) string {
			if mode == "all" {
				return all
			}
			return mode
		}
		if selected != want(item.selectMode) || inserted != want(item.insertMode) ||
			updated != want(item.updateMode) {
			return fmt.Errorf("%w: unexpected effective table/column grants on %s", ErrCatalogDrift, item.table)
		}
	}
	// Explicitly reject schema owners via owner-membership check above.
	// Additional tables in the same schema require a separate review.
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: complete runtime role privilege check: %v", ErrCatalogDrift, err)
	}
	return nil
}

var _ = strings.TrimSpace
