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
	"github.com/jackc/pgx/v5/pgconn"
	schemamigrations "github.com/avaargsh/agent-decision/migrations"
)

// ErrCatalogDrift means migration checksums match but the live PostgreSQL
// tables, tenant-bound foreign key, or append-only triggers are not intact.
var ErrCatalogDrift = errors.New("Decision PostgreSQL catalog integrity drift")

const migrationLockClass int32 = 71002
const migrationLockObject int32 = 1

// validDecisionSchema is intentionally narrower than PostgreSQL identifiers:
// only deployment-reviewed lowercase ASCII schemas are eligible, avoiding
// truncation, quoting ambiguities and reserved internal namespaces.
func validDecisionSchema(schema string) bool {
	if schema == "" || len(schema) > 63 || strings.HasPrefix(schema, "pg_") ||
		schema == "information_schema" {
		return false
	}
	for i := 0; i < len(schema); i++ {
		ch := schema[i]
		if (ch < 'a' || ch > 'z') && ch != '_' && (i == 0 || ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}

// Migrate applies the immutable Decision ledger to the explicit default
// schema "public", never to a schema supplied by the connection search_path.
// Deployments using another trusted schema must call MigrateInSchema.
func Migrate(ctx context.Context, db *sql.DB) error {
	return MigrateInSchema(ctx, db, "public")
}

// MigrateInSchema applies the ledger within a trusted, caller-configured
// PostgreSQL schema. The schema must come from deployment configuration, never
// from an HTTP request or untrusted data. All unqualified migration v1-v4 DDL
// resolves inside a transaction-local schema-first search_path, with pg_temp
// explicitly LAST so temporary tables cannot shadow protected relations.
func MigrateInSchema(ctx context.Context, db *sql.DB, schema string) error {
	if db == nil {
		return ErrStoreUnavailable
	}
	if !validDecisionSchema(schema) {
		return fmt.Errorf("%w: invalid or untrusted migration schema", ErrCatalogDrift)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return storeUnavailable("begin migrations", err)
	}
	defer tx.Rollback()

	// Bind the schema before any DDL, catalog lookup or advisory lock.
	// Qualified pg_catalog functions prevent ambient function shadowing;
	// format(%I) safely quotes the configured SQL identifier.
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_catalog.set_config('search_path',
		    pg_catalog.format('%I, pg_catalog, pg_temp', $1::text), true)`,
		schema); err != nil {
		return storeUnavailable("pin trusted migration schema", err)
	}
	var resolvedSchema string
	if err := tx.QueryRowContext(ctx, "SELECT pg_catalog.current_schema()").Scan(&resolvedSchema); err != nil {
		return storeUnavailable("resolve trusted migration schema", err)
	}
	if resolvedSchema != schema {
		return fmt.Errorf("%w: trusted migration schema %q is not accessible", ErrCatalogDrift, schema)
	}
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
		{version: 3, name: "0003_append_only_truncate_guards.sql"},
		{version: 4, name: "0004_tenant_row_level_security.sql"},
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
	if err := verifyDecisionCatalog(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return storeUnavailable("commit migrations", err)
	}
	return nil
}


// verifyLedgerProtectionTriggers fails closed if a named trigger is disabled,
// conditional, limited to UPDATE OF a subset of columns, or rebound. Handler
// source and execution attributes are checked by verifyDecisionCatalog.
func verifyLedgerProtectionTriggers(ctx context.Context, tx *sql.Tx) error {
	required := []struct {
		table, name, function string
		triggerType int
	}{
		{"decision_records", "decision_records_no_update", "reject_decision_record_mutation()", 19},
		{"decision_records", "decision_records_no_delete", "reject_decision_record_mutation()", 11},
		{"outbox_events", "outbox_event_identity_immutable", "reject_decision_outbox_identity_mutation()", 19},
		{"outbox_events", "outbox_events_no_delete", "reject_decision_outbox_delete()", 11},
		{"decision_records", "decision_records_no_truncate", "reject_decision_record_mutation()", 34},
		{"outbox_events", "outbox_events_no_truncate", "reject_decision_outbox_delete()", 34},
	}
	const query = `SELECT t.tgenabled::text, t.tgtype::integer,
		t.tgfoid = to_regprocedure($3), t.tgqual IS NULL, t.tgattr::text
		FROM pg_trigger AS t
		WHERE t.tgrelid = to_regclass($1)
		  AND t.tgname = $2 AND NOT t.tgisinternal`
	for _, item := range required {
		var enabled, restrictedColumns string
		var eventType int
		var expectedFunction sql.NullBool
		var unconditional bool
		err := tx.QueryRowContext(ctx, query, item.table, item.name, item.function).
			Scan(&enabled, &eventType, &expectedFunction, &unconditional, &restrictedColumns)
		if errors.Is(err, sql.ErrNoRows) {
			return catalogAttestationMismatch("trigger " + item.table + "." + item.name + " missing")
		}
		if err != nil {
			return catalogAttestationQueryFailure("trigger "+item.table+"."+item.name, err)
		}
		if enabled != "O" || eventType != item.triggerType ||
			!expectedFunction.Valid || !expectedFunction.Bool || !unconditional ||
			restrictedColumns != "" {
			return catalogAttestationMismatch("trigger " + item.table + "." + item.name + " definition")
		}
	}
	return nil
}

// verifyDecisionCatalog performs the read-only catalog attestation followed
// by the migration-only, rollback-safe INSERT behavior probes. Never call the
// behavioral probes from a restricted application-role readiness check.
func verifyDecisionCatalog(ctx context.Context, tx *sql.Tx) error {
	if err := verifyDecisionCatalogReadOnly(ctx, tx); err != nil {
		return err
	}
	return probeDecisionIdentityConstraint(ctx, tx)
}

// catalogAttestationQueryFailure preserves the public fail-closed error while
// exposing only a stable check name and PostgreSQL SQLSTATE. It deliberately
// omits server messages, query text, role names, and row contents.
func catalogAttestationQueryFailure(check string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return fmt.Errorf("%w: %s query failed (SQLSTATE %s)", ErrCatalogDrift, check, pgErr.Code)
	}
	return fmt.Errorf("%w: %s query failed (%T)", ErrCatalogDrift, check, err)
}

func catalogAttestationMismatch(check string) error {
	return fmt.Errorf("%w: %s mismatch", ErrCatalogDrift, check)
}

// verifyTenantRLSPolicies pins the exact v0004 RLS surface. Runtime tenant
// authority comes from the authenticated PostgreSQL session_user mapping;
// decision.tenant_id is only a transaction-local equality guard.
func verifyTenantRLSPolicies(ctx context.Context, tx *sql.Tx) error {
	for _, expected := range []struct {
		table string
		enabled bool
		forced bool
	}{
		{"decision_records", true, false},
		{"outbox_events", true, false},
		{"decision_tenant_logins", false, false},
		{"schema_migrations", false, false},
	} {
		var enabled, forced bool
		err := tx.QueryRowContext(ctx, `
			SELECT c.relrowsecurity, c.relforcerowsecurity
			FROM pg_catalog.pg_class AS c
			WHERE c.oid = pg_catalog.to_regclass($1)
		`, expected.table).Scan(&enabled, &forced)
		if errors.Is(err, sql.ErrNoRows) {
			return catalogAttestationMismatch("RLS relation " + expected.table + " missing")
		}
		if err != nil {
			return catalogAttestationQueryFailure("RLS flags for "+expected.table, err)
		}
		if enabled != expected.enabled || forced != expected.forced {
			return catalogAttestationMismatch("RLS flags for " + expected.table)
		}
	}

	// The mapping table is deliberately outside RLS so policy subqueries can
	// read it. Its only runtime grant is SELECT; the migrator owns its contents.
	var mappingShapeOK bool
	if err := tx.QueryRowContext(ctx, `
		SELECT
			(SELECT count(*) = 3 FROM pg_catalog.pg_attribute AS a
			 WHERE a.attrelid = pg_catalog.to_regclass('decision_tenant_logins')
			   AND a.attnum > 0 AND NOT a.attisdropped)
			AND (SELECT count(*) = 1 FROM pg_catalog.pg_attribute AS a
			 WHERE a.attrelid = pg_catalog.to_regclass('decision_tenant_logins')
			   AND a.attname = 'login_role' AND a.atttypid = 'pg_catalog.name'::pg_catalog.regtype AND a.attnotnull)
			AND (SELECT count(*) = 1 FROM pg_catalog.pg_attribute AS a
			 WHERE a.attrelid = pg_catalog.to_regclass('decision_tenant_logins')
			   AND a.attname = 'tenant_id' AND a.atttypid = 'pg_catalog.text'::pg_catalog.regtype AND NOT a.attnotnull)
			AND (SELECT count(*) = 1 FROM pg_catalog.pg_attribute AS a
			 WHERE a.attrelid = pg_catalog.to_regclass('decision_tenant_logins')
			   AND a.attname = 'login_kind' AND a.atttypid = 'pg_catalog.text'::pg_catalog.regtype AND a.attnotnull)
	`).Scan(&mappingShapeOK); err != nil {
		return catalogAttestationQueryFailure("tenant LOGIN mapping table shape", err)
	}
	if !mappingShapeOK {
		return catalogAttestationMismatch("tenant LOGIN mapping table shape")
	}
	var mappingOwnerOK bool
	if err := tx.QueryRowContext(ctx, `
		SELECT
			(SELECT count(*) = 4
			 FROM pg_catalog.pg_class AS c
			 JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
			 WHERE n.nspname = pg_catalog.current_schema()
			   AND c.relname IN ('decision_records', 'outbox_events', 'decision_tenant_logins', 'schema_migrations')
			   AND c.relowner = (
			       SELECT history.relowner
			       FROM pg_catalog.pg_class AS history
			       WHERE history.oid = pg_catalog.to_regclass('schema_migrations')
			   ))
	`).Scan(&mappingOwnerOK); err != nil {
		return catalogAttestationQueryFailure("protected Decision relation owners", err)
	}
	if !mappingOwnerOK {
		return catalogAttestationMismatch("protected Decision relation owners")
	}
	var mappingPublicAccessOK bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_class AS relation,
			     LATERAL pg_catalog.aclexplode(
			         COALESCE(relation.relacl, pg_catalog.acldefault('r', relation.relowner))
			     ) AS privilege
			WHERE relation.oid = pg_catalog.to_regclass('decision_tenant_logins')
			  AND privilege.grantee = 0
		)
	`).Scan(&mappingPublicAccessOK); err != nil {
		return catalogAttestationQueryFailure("tenant LOGIN mapping PUBLIC ACL", err)
	}
	if !mappingPublicAccessOK {
		return catalogAttestationMismatch("tenant LOGIN mapping PUBLIC ACL")
	}
	// Materialize only the pinned relation's constraints before deparsing.
	// Other schemas may undergo concurrent DDL; never deparse their OIDs.
	// Pin the complete PostgreSQL 16 deparsed CHECK definitions. Substring
	// matching is unsafe: a same-name expression can retain every expected
	// token and append OR TRUE, silently disabling the invariant.
	const expectedIdentityCheck = `CHECK ((((login_role)::text <> ''::text) AND (((login_kind = 'application'::text) AND (tenant_id IS NOT NULL) AND (tenant_id <> ''::text)) OR ((login_kind = 'dispatcher'::text) AND (tenant_id IS NULL)))))`
	const expectedLoginKindCheck = `CHECK ((login_kind = ANY (ARRAY['application'::text, 'dispatcher'::text])))`
	var mappingConstraintCountOK, mappingPrimaryKeyOK, mappingIdentityCheckOK bool
	var mappingLoginKindCheckOK, mappingTenantUniqueOK bool
	if err := tx.QueryRowContext(ctx, `
		WITH mapping_constraints AS MATERIALIZED (
			SELECT c.* FROM pg_catalog.pg_constraint AS c
			WHERE c.conrelid = pg_catalog.to_regclass('decision_tenant_logins')
		)
		SELECT
			(SELECT count(*) = 4 FROM mapping_constraints),
			(SELECT count(*) = 1 FROM mapping_constraints AS c
			 WHERE c.conname = 'decision_tenant_logins_pkey'
			   AND c.contype = 'p' AND c.convalidated
			   AND c.conkey = ARRAY[(
			       SELECT a.attnum FROM pg_catalog.pg_attribute AS a
			       WHERE a.attrelid = c.conrelid AND a.attname = 'login_role' AND a.attnum > 0
			   )]::smallint[]),
			(SELECT count(*) = 1 FROM mapping_constraints AS c
			 WHERE c.conname = 'decision_tenant_logins_identity_ck'
			   AND c.contype = 'c' AND c.convalidated
			   AND pg_catalog.pg_get_constraintdef(c.oid) = $1),
			(SELECT count(*) = 1 FROM mapping_constraints AS c
			 WHERE c.conname = 'decision_tenant_logins_login_kind_check'
			   AND c.contype = 'c' AND c.convalidated
			   AND pg_catalog.pg_get_constraintdef(c.oid) = $2),
			(SELECT count(*) = 1
			 FROM mapping_constraints AS c
			 JOIN pg_catalog.pg_index AS i ON i.indexrelid = c.conindid
			 WHERE c.conname = 'decision_tenant_logins_tenant_uq'
			   AND c.contype = 'u' AND c.convalidated
			   AND c.conkey = ARRAY[(
			       SELECT a.attnum FROM pg_catalog.pg_attribute AS a
			       WHERE a.attrelid = c.conrelid AND a.attname = 'tenant_id' AND a.attnum > 0
			   )]::smallint[]
			   AND i.indisunique AND i.indnullsnotdistinct AND i.indisvalid AND i.indisready
			   AND i.indnkeyatts = 1 AND i.indnatts = 1)
	`, expectedIdentityCheck, expectedLoginKindCheck).Scan(
		&mappingConstraintCountOK, &mappingPrimaryKeyOK, &mappingIdentityCheckOK,
		&mappingLoginKindCheckOK, &mappingTenantUniqueOK,
	); err != nil {
		return catalogAttestationQueryFailure("tenant LOGIN mapping constraints", err)
	}
	if !mappingConstraintCountOK {
		return catalogAttestationMismatch("tenant LOGIN mapping constraint count")
	}
	if !mappingPrimaryKeyOK {
		return catalogAttestationMismatch("tenant LOGIN mapping primary key")
	}
	if !mappingIdentityCheckOK {
		return catalogAttestationMismatch("tenant LOGIN mapping identity CHECK")
	}
	if !mappingLoginKindCheckOK {
		return catalogAttestationMismatch("tenant LOGIN mapping login_kind CHECK")
	}
	if !mappingTenantUniqueOK {
		return catalogAttestationMismatch("tenant LOGIN mapping tenant uniqueness constraint")
	}

	type expectedPolicy struct {
		command string
		andCount int
		qualTokens []string
		checkTokens []string
	}
	expected := map[string]expectedPolicy{
		"decision_records_tenant_select": {
			command: "r",
			andCount: 3,
			qualTokens: []string{"decision_tenant_logins", "login.login_role = session_user", "login.login_kind = 'application'", "login.tenant_id =", "decision_records.tenant_id", "tenant_id = nullif", "current_setting('decision.tenant_id'"},
		},
		"decision_records_tenant_insert": {
			command: "a",
			andCount: 3,
			checkTokens: []string{"decision_tenant_logins", "login.login_role = session_user", "login.login_kind = 'application'", "login.tenant_id =", "decision_records.tenant_id", "tenant_id = nullif", "current_setting('decision.tenant_id'"},
		},
		"outbox_events_tenant_insert": {
			command: "a",
			andCount: 3,
			checkTokens: []string{"decision_tenant_logins", "login.login_role = session_user", "login.login_kind = 'application'", "login.tenant_id =", "outbox_events.tenant_id", "tenant_id = nullif", "current_setting('decision.tenant_id'"},
		},
		"outbox_events_dispatcher_select": {
			command: "r",
			andCount: 2,
			qualTokens: []string{"decision_tenant_logins", "login.login_role = session_user", "login.login_kind = 'dispatcher'", "login.tenant_id is null"},
		},
		"outbox_events_dispatcher_update": {
			command: "w",
			andCount: 2,
			qualTokens: []string{"decision_tenant_logins", "login.login_role = session_user", "login.login_kind = 'dispatcher'", "login.tenant_id is null"},
			checkTokens: []string{"decision_tenant_logins", "login.login_role = session_user", "login.login_kind = 'dispatcher'", "login.tenant_id is null"},
		},
	}
	for _, table := range []string{"decision_records", "outbox_events"} {
		rows, err := tx.QueryContext(ctx, `
			SELECT p.polname, p.polcmd::text, p.polpermissive, p.polroles::text,
			       COALESCE(pg_catalog.pg_get_expr(p.polqual, p.polrelid), ''),
			       COALESCE(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')
			FROM pg_catalog.pg_policy AS p
			WHERE p.polrelid = pg_catalog.to_regclass($1)
			ORDER BY p.polname
		`, table)
		if err != nil {
			return catalogAttestationQueryFailure("RLS policies for "+table, err)
		}
		seen := 0
		for rows.Next() {
			var name, command, roles, qual, check string
			var permissive bool
			if err := rows.Scan(&name, &command, &permissive, &roles, &qual, &check); err != nil {
				_ = rows.Close()
				return catalogAttestationQueryFailure("RLS policy row for "+table, err)
			}
			policy, ok := expected[name]
			if !ok || policy.command != command || !permissive || roles != "{0}" {
				rows.Close()
				return fmt.Errorf("%w: unreviewed RLS policy %s on %s", ErrCatalogDrift, name, table)
			}
			normalize := func(value string) string {
				return strings.Join(strings.Fields(strings.ToLower(value)), " ")
			}
			containsAll := func(value string, tokens []string) bool {
				normalized := normalize(value)
				if normalized == "" || strings.HasPrefix(normalized, "or ") ||
					strings.Contains(normalized, " or ") || strings.HasPrefix(normalized, "not ") ||
					strings.Contains(normalized, " not ") || strings.Contains(normalized, "not (") ||
					strings.Contains(normalized, "case ") || strings.Contains(normalized, "<>") ||
					strings.Contains(normalized, "!=") || strings.Contains(normalized, " is distinct from ") ||
					strings.Count(normalized, " and ") != policy.andCount {
					return false
				}
				for _, token := range tokens {
					if !strings.Contains(normalized, normalize(token)) {
						return false
					}
				}
				return true
			}
			if len(policy.qualTokens) == 0 {
				if qual != "" {
					rows.Close()
					return fmt.Errorf("%w: unexpected USING expression on RLS policy %s", ErrCatalogDrift, name)
				}
			} else if !containsAll(qual, policy.qualTokens) {
				rows.Close()
				return fmt.Errorf("%w: weakened USING expression on RLS policy %s", ErrCatalogDrift, name)
			}
			if len(policy.checkTokens) == 0 {
				if check != "" {
					rows.Close()
					return fmt.Errorf("%w: unexpected WITH CHECK expression on RLS policy %s", ErrCatalogDrift, name)
				}
			} else if !containsAll(check, policy.checkTokens) {
				rows.Close()
				return fmt.Errorf("%w: weakened WITH CHECK expression on RLS policy %s", ErrCatalogDrift, name)
			}
			if command == "w" && normalize(qual) != normalize(check) {
				rows.Close()
				return fmt.Errorf("%w: dispatcher UPDATE USING/WITH CHECK mismatch", ErrCatalogDrift)
			}
			seen++
			delete(expected, name)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return catalogAttestationQueryFailure("iterate RLS policies for "+table, err)
		}
		if err := rows.Close(); err != nil {
			return catalogAttestationQueryFailure("close RLS policies for "+table, err)
		}
		want := 2
		if table == "outbox_events" {
			want = 3
		}
		if seen != want {
			return fmt.Errorf("%w: incomplete RLS policy set on %s", ErrCatalogDrift, table)
		}
	}
	if len(expected) != 0 {
		return fmt.Errorf("%w: missing approved RLS policy", ErrCatalogDrift)
	}
	for _, table := range []string{"decision_tenant_logins", "schema_migrations"} {
		var noPolicies bool
		if err := tx.QueryRowContext(ctx, `
			SELECT NOT EXISTS (
				SELECT 1 FROM pg_catalog.pg_policy
				WHERE polrelid = pg_catalog.to_regclass($1)
			)
		`, table).Scan(&noPolicies); err != nil {
			return catalogAttestationQueryFailure("RLS absence for "+table, err)
		}
		if !noPolicies {
			return catalogAttestationMismatch("unexpected RLS policy on " + table)
		}
	}
	return nil
}

// verifyDecisionCatalogReadOnly examines only installed PostgreSQL catalog
// metadata; it may run inside a READ ONLY transaction with a restricted role.
func verifyDecisionCatalogReadOnly(ctx context.Context, tx *sql.Tx) error {
	var relationsOK bool
	if err := tx.QueryRowContext(ctx, `
		SELECT to_regclass('decision_records') IS NOT NULL
			AND to_regclass('outbox_events') IS NOT NULL
			AND to_regclass('decision_tenant_logins') IS NOT NULL
	`).Scan(&relationsOK); err != nil {
		return catalogAttestationQueryFailure("Decision relation presence", err)
	}
	if !relationsOK {
		return fmt.Errorf("%w: missing Decision ledger or Outbox relation", ErrCatalogDrift)
	}

	if err := verifyTenantRLSPolicies(ctx, tx); err != nil {
		return err
	}

	// The Outbox can only describe a Decision owned by the same tenant.
	// Compare the actual column bindings, not just a same-name constraint.
	var fkOK bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_constraint c
			WHERE c.conrelid=to_regclass('outbox_events')
				AND c.conname='outbox_decision_fk'
				AND c.contype='f' AND c.convalidated
				AND NOT c.condeferrable AND NOT c.condeferred
				AND c.confrelid=to_regclass('decision_records')
				AND (
					SELECT string_agg(a.attname, ',' ORDER BY k.ord)
					FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum,ord)
					JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
				)='tenant_id,aggregate_id'
				AND (
					SELECT string_agg(a.attname, ',' ORDER BY k.ord)
					FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum,ord)
					JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum
				)='tenant_id,decision_id'
		)
	`).Scan(&fkOK); err != nil {
		return catalogAttestationQueryFailure("tenant-bound Decision Outbox FK", err)
	}
	if !fkOK {
		return catalogAttestationMismatch("tenant-bound Decision Outbox FK missing or rebound")
	}

	// Trigger events, conditions, enabled state and handler identity are checked
	// separately from table/FK/CHECK and installed function-body attestations.
	if err := verifyLedgerProtectionTriggers(ctx, tx); err != nil {
		return err
	}

	var identityConstraintOK bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_constraint c
			WHERE c.conrelid=to_regclass('decision_records')
				AND c.conname='decision_records_json_identity_ck'
				AND c.contype='c' AND c.convalidated
		)
	`).Scan(&identityConstraintOK); err != nil {
		return catalogAttestationQueryFailure("Decision JSON identity CHECK", err)
	}
	if !identityConstraintOK {
		return catalogAttestationMismatch("Decision JSON identity CHECK missing")
	}


	// Same-name CHECK constraints can be recreated with a permissive body.
	// Pin critical expressions to the reviewed v1/v2 SQL as parsed by PG16.
	// An unreviewed PostgreSQL deparser change fails closed and requires a
	// deliberate compatibility review rather than implicit acceptance.
	criticalChecks := []struct {
		table, name, expression string
	}{
		{
			"decision_records",
			"decision_records_json_identity_ck",
			`((NOT ((record ->> 'tenant_id'::text) IS DISTINCT FROM tenant_id)) AND (NOT ((record ->> 'invocation_id'::text) IS DISTINCT FROM invocation_id)) AND (NOT ((record ->> 'decision_id'::text) IS DISTINCT FROM decision_id)) AND (NOT ((record ->> 'request_sha256'::text) IS DISTINCT FROM (request_sha256)::text)))`,
		},
		{
			"decision_records",
			"decision_records_request_sha256_check",
			`(request_sha256 ~ '^[a-f0-9]{64}$'::text)`,
		},
		{
			"outbox_events",
			"outbox_lease_pair_ck",
			`((lease_owner IS NULL) = (lease_until IS NULL))`,
		},
		{
			"outbox_events",
			"outbox_events_aggregate_type_check",
			`(aggregate_type = 'decision_record'::text)`,
		},
		{
			"outbox_events",
			"outbox_events_last_error_code_check",
			`((last_error_code IS NULL) OR (last_error_code = 'publish_failed'::text))`,
		},
	}
	for _, expected := range criticalChecks {
		var installed string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_get_expr(c.conbin, c.conrelid)
			FROM pg_constraint c
			WHERE c.conrelid = to_regclass($1)
			  AND c.conname = $2
			  AND c.contype = 'c'
			  AND c.convalidated
			  AND NOT c.connoinherit
		`, expected.table, expected.name).Scan(&installed)
		checkName := "critical CHECK " + expected.table + "." + expected.name
		if errors.Is(err, sql.ErrNoRows) {
			return catalogAttestationMismatch(checkName + " missing")
		}
		if err != nil {
			return catalogAttestationQueryFailure(checkName, err)
		}
		if installed != expected.expression {
			return catalogAttestationMismatch(checkName + " predicate")
		}
	}

	// A same-name CREATE OR REPLACE FUNCTION preserves the function OID and
	// every trigger binding checked above. Validate the *actual* installed
	// source against the immutable v1/v2 migration's reviewed function bodies.
	// Privileged schema owners can still alter these between checks; this is
	// startup drift detection, not a claim of privileged-user tamper resistance.
	immutableFunctions := []struct {
		name string
		body string
	}{
		{
			name: "reject_decision_record_mutation()",
			body: `BEGIN
    RAISE EXCEPTION 'decision_records are append-only';
END;`,
		},
		{
			name: "reject_decision_outbox_delete()",
			body: `BEGIN
    RAISE EXCEPTION 'outbox events are append-only';
END;`,
		},
		{
			name: "reject_decision_outbox_identity_mutation()",
			body: `BEGIN
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
END;`,
		},
	}
	for _, expected := range immutableFunctions {
		var actualSource string
		err := tx.QueryRowContext(ctx, `
			SELECT p.prosrc FROM pg_proc p
			WHERE p.oid=to_regprocedure($1)
			  AND p.pronargs=0
			  AND p.prokind='f'
			  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
			  AND p.prorettype='pg_catalog.trigger'::regtype
			  AND p.provolatile='v'
			  AND NOT p.prosecdef AND p.proconfig IS NULL
		`, expected.name).Scan(&actualSource)
		checkName := "Decision trigger function " + expected.name
		if errors.Is(err, sql.ErrNoRows) {
			return catalogAttestationMismatch(checkName + " missing or invalid")
		}
		if err != nil {
			return catalogAttestationQueryFailure(checkName, err)
		}
		if strings.TrimSpace(actualSource) != expected.body {
			return catalogAttestationMismatch(checkName + " source")
		}
	}
	return nil
}

// probeDecisionIdentityConstraint verifies the identity CHECK's *behavior*.
// Same-name CHECK(true) catalog drift still has contype='c' and convalidated.
// Every synthetic write is undone via a savepoint, including successful
// inserts that would otherwise demonstrate weakened protection.
func probeDecisionIdentityConstraint(ctx context.Context, tx *sql.Tx) error {
	const insert = `INSERT INTO decision_records (
		tenant_id, invocation_id, decision_id, request_sha256, record, created_at
	) VALUES ($1, $2, $3, $4,
		jsonb_build_object(
			'tenant_id', $5::text, 'invocation_id', $6::text,
			'decision_id', $7::text, 'request_sha256', $8::text
		), now())`
	const savepoint = "decision_identity_constraint_probe"
	for i, field := range []string{"tenant_id", "invocation_id", "decision_id", "request_sha256"} {
		tenant := fmt.Sprintf("__decision_catalog_probe_%d_%d", time.Now().UnixNano(), i)
		invocation := fmt.Sprintf("catalog-probe-invocation-%d", i)
		decisionID := fmt.Sprintf("catalog-probe-decision-%d", i)
		digest := strings.Repeat("a", 64)
		jsonTenant, jsonInvocation, jsonDecision, jsonDigest := tenant, invocation, decisionID, digest
		switch field {
		case "tenant_id":
			jsonTenant += "-mismatch"
		case "invocation_id":
			jsonInvocation += "-mismatch"
		case "decision_id":
			jsonDecision += "-mismatch"
		case "request_sha256":
			jsonDigest = strings.Repeat("b", 64)
		}
		if _, err := tx.ExecContext(ctx, "SAVEPOINT "+savepoint); err != nil {
			return storeUnavailable("start Decision identity CHECK probe", err)
		}
		_, insertErr := tx.ExecContext(ctx, insert, tenant, invocation, decisionID, digest,
			jsonTenant, jsonInvocation, jsonDecision, jsonDigest)
		if _, err := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+savepoint); err != nil {
			return storeUnavailable("undo Decision identity CHECK probe", err)
		}
		if _, err := tx.ExecContext(ctx, "RELEASE SAVEPOINT "+savepoint); err != nil {
			return storeUnavailable("release Decision identity CHECK probe", err)
		}
		var pgErr *pgconn.PgError
		if !errors.As(insertErr, &pgErr) || pgErr.Code != "23514" ||
			pgErr.ConstraintName != "decision_records_json_identity_ck" {
			return fmt.Errorf("%w: Decision JSON identity CHECK did not reject mismatched %s",
				ErrCatalogDrift, field)
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
