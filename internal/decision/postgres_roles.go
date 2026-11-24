package decision

import (
	"context"
	"database/sql"
	"fmt"
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
// This verifies effective ACLs, not the installed RLS predicates or mapping
// contents. Pair it with VerifyInstalledCatalogInSchema, per-transaction
// LOGIN-to-tenant mapping checks, and authenticated service authorization.
func VerifyRuntimeDatabaseRole(ctx context.Context, db *sql.DB, schema string, role RuntimeDatabaseRole) error {
	return verifyRuntimeDatabaseRole(ctx, db, schema, role, nil)
}

// runtimeLoginBinding is a deployment-owned identity pin, not an HTTP
// credential or tenant claim. Role OIDs are local to a PostgreSQL cluster;
// TLS/server identity and re-provisioning after restore are separate checks.
type runtimeLoginBinding struct {
	Database string
	RoleName string
	RoleOID  uint32
}

func verifyBoundRuntimeDatabaseRole(ctx context.Context, db *sql.DB, schema string, role RuntimeDatabaseRole, binding runtimeLoginBinding) error {
	if binding.Database == "" || binding.RoleName == "" || binding.RoleOID == 0 {
		return fmt.Errorf("%w: incomplete runtime login binding", ErrCatalogDrift)
	}
	return verifyRuntimeDatabaseRole(ctx, db, schema, role, &binding)
}

// verifyRuntimeLoginKindTx requires every runtime LOGIN to have exactly the
// deployment-provisioned database role class before it can pass the preflight.
func verifyRuntimeLoginKindTx(ctx context.Context, tx *sql.Tx, kind string) error {
	if tx == nil || (kind != "application" && kind != "dispatcher") {
		return fmt.Errorf("%w: invalid runtime LOGIN kind", ErrCatalogDrift)
	}
	var mappingCount int
	var tenant sql.NullString
	var actualKind string
	err := tx.QueryRowContext(ctx, `
		SELECT count(*), max(tenant_id), max(login_kind)
		FROM decision_tenant_logins
		WHERE login_role = SESSION_USER
	`).Scan(&mappingCount, &tenant, &actualKind)
	if err != nil || mappingCount != 1 || actualKind != kind ||
		(kind == "application" && (!tenant.Valid || tenant.String == "")) ||
		(kind == "dispatcher" && tenant.Valid) {
		return fmt.Errorf("%w: runtime LOGIN is not provisioned as %s", ErrCatalogDrift, kind)
	}
	return nil
}

// verifyTenantLoginMappingTx binds the configured tenant to the authenticated
// PostgreSQL LOGIN on the same transaction that will read or write ledger data.
// A caller-controlled GUC alone is never accepted as tenant authority.
func verifyTenantLoginMappingTx(ctx context.Context, tx *sql.Tx, tenantID string, binding runtimeLoginBinding, kind string) error {
	if tx == nil || tenantID == "" || binding.RoleName == "" || kind != "application" {
		return fmt.Errorf("%w: incomplete tenant LOGIN mapping check", ErrCatalogDrift)
	}
	var mappingCount int
	var loginRole, mappedTenant, loginKind string
	err := tx.QueryRowContext(ctx, `
		SELECT count(*), max(login_role::text), max(tenant_id), max(login_kind)
		FROM decision_tenant_logins
		WHERE login_role = SESSION_USER
	`).Scan(&mappingCount, &loginRole, &mappedTenant, &loginKind)
	if err != nil || mappingCount != 1 || loginRole != binding.RoleName || mappedTenant != tenantID || loginKind != kind {
		return fmt.Errorf("%w: authenticated LOGIN is not mapped to the requested tenant", ErrCatalogDrift)
	}
	return nil
}

// verifyTenantLoginMapping checks the immutable deployment mapping at pool
// startup. Every actual bound transaction repeats the check before GUC binding.
func verifyTenantLoginMapping(ctx context.Context, db *sql.DB, schema, tenantID string, binding runtimeLoginBinding) error {
	if db == nil {
		return ErrStoreUnavailable
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("%w: begin tenant LOGIN mapping check: %v", ErrCatalogDrift, err)
	}
	defer tx.Rollback()
	if err := verifyRuntimeTransactionIdentity(ctx, tx, schema, &binding); err != nil {
		return err
	}
	if err := verifyTenantLoginMappingTx(ctx, tx, tenantID, binding, "application"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: finish tenant LOGIN mapping check: %v", ErrCatalogDrift, err)
	}
	return nil
}

func verifyRuntimeDatabaseRole(ctx context.Context, db *sql.DB, schema string, role RuntimeDatabaseRole, binding *runtimeLoginBinding) error {
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

	if err := verifyRuntimeTransactionIdentity(ctx, tx, schema, binding); err != nil {
		return err
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
			{"decision_tenant_logins", "all", "", ""},
			{"decision_records", "all", "all", ""},
			{"outbox_events", "", "all", ""},
		}
	} else {
		policies = []policy{
			{"schema_migrations", "", "", ""},
			{"decision_tenant_logins", "all", "", ""},
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
				       pg_catalog.has_column_privilege(current_user, a.attrelid, a.attname, 'UPDATE') AS can_update,
				       pg_catalog.has_column_privilege(current_user, a.attrelid, a.attname, 'REFERENCES') AS can_reference
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
			           OR EXISTS (SELECT 1 FROM rights WHERE can_reference)
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
	// An allowlisted table ACL alone is insufficient: a second table, view,
	// foreign table, materialized view or sequence in the same schema could
	// expose additional tenant data through an unintended grant. Check effective
	// table, column and sequence rights, including grants via PUBLIC or inherited
	// roles. Extra objects with no effective privileges need no special grant.
	var unreviewedAccess bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_class AS rel
			JOIN pg_catalog.pg_namespace AS ns ON ns.oid = rel.relnamespace
			WHERE ns.nspname = $1
			  AND rel.relname NOT IN ('schema_migrations', 'decision_tenant_logins', 'decision_records', 'outbox_events')
			  AND CASE
			    WHEN rel.relkind = 'S' THEN
			      pg_catalog.has_sequence_privilege(current_user, rel.oid, 'USAGE')
			      OR pg_catalog.has_sequence_privilege(current_user, rel.oid, 'SELECT')
			      OR pg_catalog.has_sequence_privilege(current_user, rel.oid, 'UPDATE')
			    WHEN rel.relkind IN ('r', 'p', 'v', 'm', 'f') THEN
			      pg_catalog.has_table_privilege(current_user, rel.oid, 'SELECT')
			      OR pg_catalog.has_table_privilege(current_user, rel.oid, 'INSERT')
			      OR pg_catalog.has_table_privilege(current_user, rel.oid, 'UPDATE')
			      OR pg_catalog.has_table_privilege(current_user, rel.oid, 'DELETE')
			      OR pg_catalog.has_table_privilege(current_user, rel.oid, 'TRUNCATE')
			      OR pg_catalog.has_table_privilege(current_user, rel.oid, 'REFERENCES')
			      OR pg_catalog.has_table_privilege(current_user, rel.oid, 'TRIGGER')
			      OR EXISTS (
			        SELECT 1 FROM pg_catalog.pg_attribute AS attr
			        WHERE attr.attrelid = rel.oid
			          AND attr.attnum > 0 AND NOT attr.attisdropped
			          AND (pg_catalog.has_column_privilege(current_user, rel.oid, attr.attnum, 'SELECT')
			            OR pg_catalog.has_column_privilege(current_user, rel.oid, attr.attnum, 'INSERT')
			            OR pg_catalog.has_column_privilege(current_user, rel.oid, attr.attnum, 'UPDATE')
			            OR pg_catalog.has_column_privilege(current_user, rel.oid, attr.attnum, 'REFERENCES'))
			      )
			    ELSE false
			  END
		)
	`, schema).Scan(&unreviewedAccess); err != nil || unreviewedAccess {
		return fmt.Errorf("%w: unexpected effective access to unreviewed schema relation", ErrCatalogDrift)
	}


	// PostgreSQL grants EXECUTE on new routines to PUBLIC by default. An
	// unreviewed SECURITY DEFINER routine can read DecisionRecords under its
	// owner's privileges even when the dispatcher has no table SELECT grant.
	// Only migration-owned trigger callbacks (which cannot be called directly
	// with SELECT) are excluded; their source is separately catalog-attested.
	// Check routine signature and properties, not its name alone.
	var unreviewedExecutable bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_proc AS fn
			JOIN pg_catalog.pg_namespace AS ns ON ns.oid = fn.pronamespace
			WHERE ns.nspname = $1
			  AND pg_catalog.has_function_privilege(current_user, fn.oid, 'EXECUTE')
			  AND NOT (
			    fn.prokind = 'f'
			    AND fn.pronargs = 0
			    AND fn.prolang = (SELECT oid FROM pg_catalog.pg_language WHERE lanname = 'plpgsql')
			    AND fn.prorettype = 'pg_catalog.trigger'::pg_catalog.regtype
			    AND fn.provolatile = 'v'
			    AND NOT fn.prosecdef
			    AND fn.proconfig IS NULL
			    AND (
			      (fn.proname = 'reject_decision_record_mutation' AND fn.prosrc = $2)
			      OR (fn.proname = 'reject_decision_outbox_delete' AND fn.prosrc = $3)
			      OR (fn.proname = 'reject_decision_outbox_identity_mutation' AND fn.prosrc = $4)
			    )
			  )
		)
	`, schema, decisionRecordMutationTriggerBody, decisionOutboxDeleteTriggerBody,
		decisionOutboxIdentityMutationTriggerBody).Scan(&unreviewedExecutable); err != nil || unreviewedExecutable {
		return fmt.Errorf("%w: unexpected effective EXECUTE on unreviewed schema routine", ErrCatalogDrift)
	}

	// A foreign namespace need not contain any objects (or grant USAGE)
	// to permit persistent DDL. Deny effective CREATE independently of
	// object access, including grants inherited via PUBLIC or other roles.
	var externalCreate bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_namespace AS ns
			WHERE ns.nspname <> $1
			  AND ns.nspname <> 'information_schema'
			  AND pg_catalog.left(ns.nspname, 3) <> 'pg_'
			  AND pg_catalog.has_schema_privilege(current_user, ns.oid, 'CREATE')
		)
	`, schema).Scan(&externalCreate); err != nil || externalCreate {
		return fmt.Errorf("%w: effective CREATE on unreviewed external schema", ErrCatalogDrift)
	}

	// search_path pinning protects unqualified runtime SQL, but a role may
	// invoke schema-qualified functions, views, tables or sequences elsewhere.
	// Audit effective privileges only in reachable, non-system namespaces:
	// the default public namespace is fine if it offers no usable objects.
	// This includes implicit PUBLIC grants and inherited role memberships.
	var externalAccess bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_namespace AS ns
			WHERE ns.nspname <> $1
			  AND ns.nspname <> 'information_schema'
			  AND pg_catalog.left(ns.nspname, 3) <> 'pg_'
			  AND pg_catalog.has_schema_privilege(current_user, ns.oid, 'USAGE')
			  AND (
			    EXISTS (
			      SELECT 1 FROM pg_catalog.pg_proc AS fn
			      WHERE fn.pronamespace = ns.oid
			        AND pg_catalog.has_function_privilege(current_user, fn.oid, 'EXECUTE')
			        AND NOT (
			          fn.prokind = 'f'
			          AND fn.pronargs = 0
			          AND fn.prolang = (SELECT oid FROM pg_catalog.pg_language WHERE lanname = 'plpgsql')
			          AND fn.prorettype = 'pg_catalog.trigger'::pg_catalog.regtype
			          AND fn.provolatile = 'v'
			          AND NOT fn.prosecdef
			          AND fn.proconfig IS NULL
			          AND (
			            (fn.proname = 'reject_decision_record_mutation' AND fn.prosrc = $2)
			            OR (fn.proname = 'reject_decision_outbox_delete' AND fn.prosrc = $3)
			            OR (fn.proname = 'reject_decision_outbox_identity_mutation' AND fn.prosrc = $4)
			          )
			        )
			    ) OR EXISTS (
			      SELECT 1 FROM pg_catalog.pg_class AS rel
			      WHERE rel.relnamespace = ns.oid
			        AND CASE
			          WHEN rel.relkind = 'S' THEN
			            pg_catalog.has_sequence_privilege(current_user, rel.oid, 'USAGE')
			            OR pg_catalog.has_sequence_privilege(current_user, rel.oid, 'SELECT')
			            OR pg_catalog.has_sequence_privilege(current_user, rel.oid, 'UPDATE')
			          WHEN rel.relkind IN ('r', 'p', 'v', 'm', 'f') THEN
			            pg_catalog.has_table_privilege(current_user, rel.oid, 'SELECT')
			            OR pg_catalog.has_table_privilege(current_user, rel.oid, 'INSERT')
			            OR pg_catalog.has_table_privilege(current_user, rel.oid, 'UPDATE')
			            OR pg_catalog.has_table_privilege(current_user, rel.oid, 'DELETE')
			            OR pg_catalog.has_table_privilege(current_user, rel.oid, 'TRUNCATE')
			            OR pg_catalog.has_table_privilege(current_user, rel.oid, 'REFERENCES')
			            OR pg_catalog.has_table_privilege(current_user, rel.oid, 'TRIGGER')
			            OR EXISTS (
			              SELECT 1 FROM pg_catalog.pg_attribute AS attr
			              WHERE attr.attrelid = rel.oid
			                AND attr.attnum > 0 AND NOT attr.attisdropped
			                AND (pg_catalog.has_column_privilege(current_user, rel.oid, attr.attnum, 'SELECT')
			                  OR pg_catalog.has_column_privilege(current_user, rel.oid, attr.attnum, 'INSERT')
			                  OR pg_catalog.has_column_privilege(current_user, rel.oid, attr.attnum, 'UPDATE')
			                  OR pg_catalog.has_column_privilege(current_user, rel.oid, attr.attnum, 'REFERENCES'))
			            )
			          ELSE false
			        END
			    )
			  )
		)
	`, schema, decisionRecordMutationTriggerBody, decisionOutboxDeleteTriggerBody,
		decisionOutboxIdentityMutationTriggerBody).Scan(&externalAccess); err != nil || externalAccess {
		return fmt.Errorf("%w: effective access to an unreviewed external schema object", ErrCatalogDrift)
	}

	if err := verifyRuntimeLoginKindTx(ctx, tx, string(role)); err != nil {
		return err
	}

	// Explicitly reject schema owners via owner-membership check above.
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: complete runtime role privilege check: %v", ErrCatalogDrift, err)
	}
	return nil
}


// verifyRuntimeTransactionIdentity verifies the actual backend of tx, not
// a separate pool checkout. The role/ownership checks are shared with the
// startup ACL audit. This is not a full per-transaction ACL or RLS audit.
func verifyRuntimeTransactionIdentity(ctx context.Context, tx *sql.Tx, schema string, binding *runtimeLoginBinding) error {
	// The application/dispatcher use unqualified SQL after this audit. Check
	// the connection's original lookup path BEFORE pinning our own read-only
	// inspection transaction; otherwise an unsafe runtime pool can pass.
	// This is a point-in-time check on this authenticated connection, not
	// proof that every pooled connection or a later session is unchanged.
	var configuredPath string
	if err := tx.QueryRowContext(ctx, "SELECT pg_catalog.current_setting('search_path')").Scan(&configuredPath); err != nil {
		return fmt.Errorf("%w: inspect runtime pool search_path: %v", ErrCatalogDrift, err)
	}
	if configuredPath != schema+", pg_catalog, pg_temp" {
		return fmt.Errorf("%w: runtime pool search_path is not exclusively pinned to approved schema", ErrCatalogDrift)
	}

	// Never rely on ambient search_path or an untrusted current_schema value.
	if _, err := tx.ExecContext(ctx, `SELECT pg_catalog.set_config('search_path',
		pg_catalog.format('%I, pg_catalog, pg_temp', $1::text), true)`, schema); err != nil {
		return fmt.Errorf("%w: bind runtime role schema: %v", ErrCatalogDrift, err)
	}
	// pg_stat_activity.usesysid identifies the originally authenticated login,
	// unlike session_user/current_user, both of which a superuser may reset.
	// Disallow ADMIN membership even without current SET or INHERIT access.
	var identityOK bool
	if err := tx.QueryRowContext(ctx, `
		SELECT r.rolcanlogin
		       AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR
		            r.rolreplication OR r.rolbypassrls)
		       AND session_user = current_user
		       AND EXISTS (
		           SELECT 1 FROM pg_catalog.pg_stat_activity AS login
		           WHERE login.pid = pg_catalog.pg_backend_pid()
		             AND login.usesysid = r.oid
		       )
		       AND pg_catalog.has_schema_privilege(current_user, $1, 'USAGE')
		       AND NOT pg_catalog.has_schema_privilege(current_user, $1, 'CREATE')
		       AND NOT pg_catalog.has_database_privilege(current_user, pg_catalog.current_database(), 'CREATE')
		       AND NOT pg_catalog.pg_has_role(current_user, n.nspowner, 'MEMBER')
		       AND NOT EXISTS (
		           SELECT 1
		           FROM pg_catalog.pg_class AS protected
		           WHERE protected.relnamespace = n.oid
		             AND protected.relname IN ('decision_records', 'outbox_events', 'decision_tenant_logins', 'schema_migrations')
		             AND (protected.relowner = r.oid
		               OR pg_catalog.pg_has_role(r.oid, protected.relowner, 'MEMBER'))
		       )
		       AND NOT EXISTS (
		           SELECT 1 FROM pg_catalog.pg_roles AS reachable
		           WHERE reachable.rolname <> current_user
		             AND pg_catalog.pg_has_role(current_user, reachable.oid, 'SET')
		       )
		       AND NOT EXISTS (
		           SELECT 1 FROM pg_catalog.pg_auth_members AS membership
		           WHERE membership.admin_option
		             AND pg_catalog.pg_has_role(r.oid, membership.member, 'MEMBER')
		       )
		FROM pg_catalog.pg_roles AS r
		JOIN pg_catalog.pg_namespace AS n ON n.nspname = $1
		WHERE r.rolname = current_user
	`, schema).Scan(&identityOK); err != nil || !identityOK {
		return fmt.Errorf("%w: unsafe runtime database role identity/ownership", ErrCatalogDrift)
	}

	// Check the pin on the same transaction and authenticated backend as
	// the original LOGIN and ACL audit; a second pool checkout is unsafe.
	if binding != nil {
		var bound bool
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.current_database()::text = $1
				AND session_user::text = $2
				AND current_user::text = $2
				AND EXISTS (
					SELECT 1 FROM pg_catalog.pg_stat_activity AS login
					JOIN pg_catalog.pg_roles AS r ON r.oid = login.usesysid
					WHERE login.pid = pg_catalog.pg_backend_pid()
					  AND r.rolname::text = $2
					  AND r.oid = $3::pg_catalog.oid
				)
		`, binding.Database, binding.RoleName, int64(binding.RoleOID)).Scan(&bound)
		if err != nil || !bound {
			return fmt.Errorf("%w: runtime login binding mismatch", ErrCatalogDrift)
		}
	}

	return nil
}
