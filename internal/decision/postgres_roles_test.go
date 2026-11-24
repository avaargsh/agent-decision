package decision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Exercise PostgreSQL 16 *effective* ACLs via distinct restricted session identities.
// CI simulates NOLOGIN roles under one privileged test connection; it does
// not prove production identities, TLS, RLS or secret separation.
func TestRuntimeDatabaseRolePrivileges(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", dsn)
	if err != nil { t.Fatal(err) }
	defer admin.Close()
	seed := fmt.Sprintf("%d", time.Now().UnixNano())
	schema := "decision_roles_" + seed
	appRole := "decision_app_" + seed
	dispatcherRole := "decision_dispatch_" + seed
	exec := func(sqlText string) {
		t.Helper()
		if _, err := admin.ExecContext(ctx, sqlText); err != nil {
			t.Fatalf("%s: %v", sqlText, err)
		}
	}
	exec("CREATE SCHEMA "+schema)
	defer func() { _, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	// A separate schema may host unrelated, ordinary SECURITY INVOKER
	// trigger callbacks. PUBLIC USAGE makes those routines visible to the
	// restricted login, but they do not elevate its privileges.
	externalSchema := "decision_external_triggers_" + seed
	exec("CREATE SCHEMA " + externalSchema)
	defer func() { _, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+externalSchema+" CASCADE") }()
	if err := MigrateInSchema(ctx, admin, externalSchema); err != nil {
		t.Fatalf("create unrelated external schema fixture: %v", err)
	}
	exec("GRANT USAGE ON SCHEMA " + externalSchema + " TO PUBLIC")
	password := "ephemeral_role_gate_" + seed
	exec("CREATE ROLE "+appRole+" LOGIN PASSWORD '"+password+"'")
	exec("CREATE ROLE "+dispatcherRole+" LOGIN PASSWORD '"+password+"'")
	defer func() {
		_, _ = admin.ExecContext(context.Background(), "DROP OWNED BY "+appRole)
		_, _ = admin.ExecContext(context.Background(), "DROP OWNED BY "+dispatcherRole)
		_, _ = admin.ExecContext(context.Background(), "DROP ROLE "+appRole)
		_, _ = admin.ExecContext(context.Background(), "DROP ROLE "+dispatcherRole)
	}()
	if err := MigrateInSchema(ctx, admin, schema); err != nil { t.Fatal(err) }
	tenantID := "roles-tenant-" + seed
	exec("GRANT USAGE ON SCHEMA "+schema+" TO "+appRole+", "+dispatcherRole)
	exec("GRANT SELECT ON "+schema+".decision_tenant_logins TO "+appRole+", "+dispatcherRole)
	if _, err := admin.ExecContext(ctx, "INSERT INTO "+schema+".decision_tenant_logins (login_role, tenant_id, login_kind) VALUES ($1, $2, 'application'), ($3, NULL, 'dispatcher')", appRole, tenantID, dispatcherRole); err != nil {
		t.Fatalf("seed trusted LOGIN mapping: %v", err)
	}
	exec("GRANT SELECT, INSERT ON "+schema+".decision_records TO "+appRole)
	exec("GRANT INSERT ON "+schema+".outbox_events TO "+appRole)
	exec("GRANT SELECT ON "+schema+".outbox_events TO "+dispatcherRole)
	exec("GRANT UPDATE (lease_owner, lease_until, attempts, available_at, published_at, last_error_code) ON "+
		schema+".outbox_events TO "+dispatcherRole)

	// Positive security acceptance must use actual PostgreSQL LOGIN roles,
	// never a privileged session with SET SESSION AUTHORIZATION.
	openRole := func(name string) *sql.DB {
		t.Helper()
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil { t.Fatal(err) }
		cfg.User = name
		cfg.Password = password
		db := stdlib.OpenDB(*cfg)
		db.SetMaxOpenConns(1)
		var who string
		if err := db.QueryRowContext(ctx, "SELECT current_user").Scan(&who); err != nil || who != name {
			db.Close()
			t.Fatalf("restricted login identity mismatch %q: %v", who, err)
		}
		if _, err := db.ExecContext(ctx, "SET search_path TO "+schema+", pg_catalog, pg_temp"); err != nil {
			db.Close()
			t.Fatal(err)
		}
		return db
	}

	// An elevated login that merely switches current_user is not a restricted
	// login: SET ROLE NONE can restore its original privileges.
	roleSwitched, err := sql.Open("pgx", dsn)
	if err != nil { t.Fatal(err) }
	roleSwitched.SetMaxOpenConns(1)
	if _, err := roleSwitched.ExecContext(ctx, "SET ROLE "+appRole); err != nil {
		roleSwitched.Close()
		t.Fatal(err)
	}
	if err := VerifyRuntimeDatabaseRole(ctx, roleSwitched, schema, RuntimeRoleApplication); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("accepted privileged session_user after SET ROLE: %v", err)
	}
	roleSwitched.Close()

	// A privileged originally authenticated login can reset session
	// authorization even when current_user == session_user.
	resettable, err := sql.Open("pgx", dsn)
	if err != nil { t.Fatal(err) }
	resettable.SetMaxOpenConns(1)
	if _, err := resettable.ExecContext(ctx, "SET SESSION AUTHORIZATION "+appRole); err != nil {
		resettable.Close()
		t.Fatal(err)
	}
	if err := VerifyRuntimeDatabaseRole(ctx, resettable, schema, RuntimeRoleApplication); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("accepted resettable privileged session authorization: %v", err)
	}
	resettable.Close()

	app := openRole(appRole)
	defer app.Close()
	dispatcher := openRole(dispatcherRole)
	defer dispatcher.Close()
	check := func(db *sql.DB, role RuntimeDatabaseRole) {
		t.Helper()
		if err := VerifyRuntimeDatabaseRole(ctx, db, schema, role); err != nil { t.Fatal(err) }
	}
	var publicTriggerCallbacks int
	if err := admin.QueryRowContext(ctx, `
		SELECT count(*)
		FROM pg_catalog.pg_proc AS fn
		JOIN pg_catalog.pg_namespace AS ns ON ns.oid = fn.pronamespace
		WHERE ns.nspname = $1
		  AND fn.proname IN (
		    'reject_decision_record_mutation',
		    'reject_decision_outbox_identity_mutation',
		    'reject_decision_outbox_delete'
		  )
		  AND fn.prokind = 'f'
		  AND fn.pronargs = 0
		  AND fn.prorettype = 'pg_catalog.trigger'::pg_catalog.regtype
		  AND NOT fn.prosecdef
		  AND pg_catalog.has_function_privilege($2, fn.oid, 'EXECUTE')
	`, externalSchema, appRole).Scan(&publicTriggerCallbacks); err != nil || publicTriggerCallbacks != 3 {
		t.Fatalf("fixture must expose exactly three safe trigger callbacks to PUBLIC: count=%d err=%v", publicTriggerCallbacks, err)
	}
	check(app, RuntimeRoleApplication)
	check(dispatcher, RuntimeRoleDispatcher)

	// An ordinary external SECURITY INVOKER function is still an unreviewed
	// callable object and must be rejected; only the three non-callable,
	// migration-owned trigger callbacks above are exempt.
	for _, tc := range []struct {
		name, ddl, signature string
	}{
		{
			name: "external_invoker_routine",
			ddl: "CREATE FUNCTION " + externalSchema + ".unreviewed_invoker() RETURNS integer LANGUAGE sql SECURITY INVOKER AS 'SELECT 1'",
			signature: externalSchema + ".unreviewed_invoker()",
		},
		{
			name: "external_definer_routine",
			ddl: "CREATE FUNCTION " + externalSchema + ".unreviewed_definer() RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'",
			signature: externalSchema + ".unreviewed_definer()",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec(tc.ddl)
			exec("GRANT EXECUTE ON FUNCTION " + tc.signature + " TO PUBLIC")
			for _, identity := range []struct {
				name string
				db *sql.DB
				role RuntimeDatabaseRole
			}{
				{name: "application", db: app, role: RuntimeRoleApplication},
				{name: "dispatcher", db: dispatcher, role: RuntimeRoleDispatcher},
			} {
				if err := VerifyRuntimeDatabaseRole(ctx, identity.db, schema, identity.role); !errors.Is(err, ErrCatalogDrift) {
					t.Errorf("%s accepted an unreviewed external %s routine: %v", identity.name, tc.name, err)
				}
			}
			exec("DROP FUNCTION " + tc.signature)
			check(app, RuntimeRoleApplication)
			check(dispatcher, RuntimeRoleDispatcher)
		})
	}

	// The same permission class is not sufficient for a provisioned login
	// binding. Pin the deployment-reviewed database, role name and role OID.
	t.Run("pinned_login_identity", func(t *testing.T) {
		var database string
		var appOID, dispatcherOID uint32
		if err := admin.QueryRowContext(ctx, "SELECT current_database(), (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1), (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$2)", appRole, dispatcherRole).Scan(&database, &appOID, &dispatcherOID); err != nil {
			t.Fatal(err)
		}
		pin := runtimeLoginBinding{Database: database, RoleName: appRole, RoleOID: appOID}
		if err := verifyBoundRuntimeDatabaseRole(ctx, app, schema, RuntimeRoleApplication, pin); err != nil {
			t.Fatalf("valid provisioned application login: %v", err)
		}
		dispatcherPin := runtimeLoginBinding{Database: database, RoleName: dispatcherRole, RoleOID: dispatcherOID}
		if err := verifyBoundRuntimeDatabaseRole(ctx, dispatcher, schema, RuntimeRoleDispatcher, dispatcherPin); err != nil {
			t.Fatalf("valid provisioned dispatcher login: %v", err)
		}
		for _, tc := range []struct {
			name string
			pin runtimeLoginBinding
		}{
			{"wrong_database", runtimeLoginBinding{Database: database+"_other", RoleName: appRole, RoleOID: appOID}},
			{"wrong_role_name", runtimeLoginBinding{Database: database, RoleName: dispatcherRole, RoleOID: appOID}},
			{"wrong_role_oid", runtimeLoginBinding{Database: database, RoleName: appRole, RoleOID: dispatcherOID}},
			{"wrong_identity", dispatcherPin},
			{"empty_binding", runtimeLoginBinding{}},
			{"missing_oid", runtimeLoginBinding{Database: database, RoleName: appRole}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := verifyBoundRuntimeDatabaseRole(ctx, app, schema, RuntimeRoleApplication, tc.pin); !errors.Is(err, ErrCatalogDrift) {
					t.Fatalf("untrusted login binding accepted: %v", err)
				}
			})
		}
		// A valid pin must not bypass existing effective-ACL restrictions.
		exec("GRANT SELECT ON "+schema+".outbox_events TO "+appRole)
		defer exec("REVOKE SELECT ON "+schema+".outbox_events FROM "+appRole)
		if err := verifyBoundRuntimeDatabaseRole(ctx, app, schema, RuntimeRoleApplication, pin); !errors.Is(err, ErrCatalogDrift) {
			t.Fatalf("pinned login bypassed privilege check: %v", err)
		}
	})
	check(app, RuntimeRoleApplication)

	// A role must not be able to create persistent objects outside the
	// approved schema, even when the foreign namespace has no objects or
	// USAGE grant. This tests effective CREATE rather than existing ACLs.
	t.Run("external_schema_create_denied", func(t *testing.T) {
		external := "decision_create_" + seed
		exec("CREATE SCHEMA "+external)
		t.Cleanup(func() {
			_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+external+" CASCADE")
		})
		for _, identity := range []struct {
			name string
			db *sql.DB
			role RuntimeDatabaseRole
		}{
			{appRole, app, RuntimeRoleApplication},
			{dispatcherRole, dispatcher, RuntimeRoleDispatcher},
		} {
			t.Run(string(identity.role), func(t *testing.T) {
				check(identity.db, identity.role)
				exec("GRANT CREATE ON SCHEMA "+external+" TO "+identity.name)
				var create, usage bool
				if err := identity.db.QueryRowContext(ctx,
					"SELECT pg_catalog.has_schema_privilege(current_user, $1, 'CREATE'), pg_catalog.has_schema_privilege(current_user, $1, 'USAGE')",
					external).Scan(&create, &usage); err != nil || !create || usage {
					t.Fatalf("fixture requires CREATE without USAGE: create=%t usage=%t err=%v", create, usage, err)
				}
				if err := VerifyRuntimeDatabaseRole(ctx, identity.db, schema, identity.role); !errors.Is(err, ErrCatalogDrift) {
					t.Errorf("external CREATE without USAGE passed role audit: %v", err)
				}
				exec("GRANT USAGE ON SCHEMA "+external+" TO "+identity.name)
				if err := VerifyRuntimeDatabaseRole(ctx, identity.db, schema, identity.role); !errors.Is(err, ErrCatalogDrift) {
					t.Errorf("external CREATE with USAGE passed role audit: %v", err)
				}
				exec("REVOKE CREATE ON SCHEMA "+external+" FROM "+identity.name)
				check(identity.db, identity.role)
				exec("REVOKE USAGE ON SCHEMA "+external+" FROM "+identity.name)
			})
		}
	})

	// The role audit must verify the actual connection pool's lookup path.
	// The store uses unqualified SQL; a temporary transaction-local override
	// during the audit cannot make a misconfigured runtime pool safe.
	for _, identity := range []struct {
		name string
		role RuntimeDatabaseRole
	}{
		{appRole, RuntimeRoleApplication},
		{dispatcherRole, RuntimeRoleDispatcher},
	} {
		for _, unsafePath := range []string{
			"public, pg_catalog, pg_temp",
			schema + ", public, pg_catalog, pg_temp",
		} {
			t.Run(string(identity.role)+"/"+unsafePath, func(t *testing.T) {
				cfg, err := pgx.ParseConfig(dsn)
				if err != nil { t.Fatal(err) }
				cfg.User, cfg.Password = identity.name, password
				cfg.RuntimeParams["search_path"] = unsafePath
				wrongPool := stdlib.OpenDB(*cfg)
				defer wrongPool.Close()
				wrongPool.SetMaxOpenConns(1)
				var got string
				if err := wrongPool.QueryRowContext(ctx, "SELECT pg_catalog.current_setting('search_path')").Scan(&got); err != nil || got != unsafePath {
					t.Fatalf("test must run against misbound pool: path=%q err=%v", got, err)
				}
				if err := VerifyRuntimeDatabaseRole(ctx, wrongPool, schema, identity.role); !errors.Is(err, ErrCatalogDrift) {
					t.Fatalf("accepted runtime %s pool with untrusted search_path %q: %v", identity.role, unsafePath, err)
				}
			})
		}
	}

	// Unknown objects must not grant runtime identities more data access
	// than the exact three reviewed Decision tables, even when the normal
	// table/column grant matrix still passes. Objects with no grants are OK.
	exec("CREATE TABLE "+schema+".unreviewed_tenant_data (secret text)")
	exec("CREATE VIEW "+schema+".unreviewed_tenant_view AS SELECT secret FROM "+schema+".unreviewed_tenant_data")
	exec("CREATE SEQUENCE "+schema+".unreviewed_tenant_seq")
	check(app, RuntimeRoleApplication)
	check(dispatcher, RuntimeRoleDispatcher)
	for _, tc := range []struct {
		name, grant, revoke string
		db *sql.DB
		role RuntimeDatabaseRole
	}{
		{
			"app reads extra table",
			"GRANT SELECT ON "+schema+".unreviewed_tenant_data TO "+appRole,
			"REVOKE SELECT ON "+schema+".unreviewed_tenant_data FROM "+appRole,
			app, RuntimeRoleApplication,
		},
		{
			"dispatcher inserts extra table",
			"GRANT INSERT ON "+schema+".unreviewed_tenant_data TO "+dispatcherRole,
			"REVOKE INSERT ON "+schema+".unreviewed_tenant_data FROM "+dispatcherRole,
			dispatcher, RuntimeRoleDispatcher,
		},
		{
			"app reads only extra table column",
			"GRANT SELECT (secret) ON "+schema+".unreviewed_tenant_data TO "+appRole,
			"REVOKE SELECT (secret) ON "+schema+".unreviewed_tenant_data FROM "+appRole,
			app, RuntimeRoleApplication,
		},
		{
			"dispatcher reads extra view",
			"GRANT SELECT ON "+schema+".unreviewed_tenant_view TO "+dispatcherRole,
			"REVOKE SELECT ON "+schema+".unreviewed_tenant_view FROM "+dispatcherRole,
			dispatcher, RuntimeRoleDispatcher,
		},
		{
			"app accesses extra sequence",
			"GRANT USAGE ON SEQUENCE "+schema+".unreviewed_tenant_seq TO "+appRole,
			"REVOKE USAGE ON SEQUENCE "+schema+".unreviewed_tenant_seq FROM "+appRole,
			app, RuntimeRoleApplication,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec(tc.grant)
			if err := VerifyRuntimeDatabaseRole(ctx, tc.db, schema, tc.role); !errors.Is(err, ErrCatalogDrift) {
				t.Errorf("effective privilege on unreviewed relation passed %s audit: %v", tc.role, err)
			}
			exec(tc.revoke)
			check(tc.db, tc.role)
		})
	}

	// Exercise actual runtime SQL under the effective role rather than
	// assuming the GRANT matrix is sufficient for SaveOrGet/Claim/Ack.
	record := Record{
		TenantID: tenantID,
		InvocationID: "roles-invocation",
		DecisionID: "dec_"+strings.Repeat("a", 64),
		AgentID: "roles-agent",
		SessionID: "roles-session",
		RunID: "roles-run",
		RequestSHA256: strings.Repeat("b", 64),
		CreatedAt: time.Now().UTC(),
		Status: StatusProposed,
		ReasonCodes: []string{},
		Evidence: []EvidenceRef{},
		Plan: PlanCandidate{PlanID: "plan_roles", SchemaVersion: SchemaVersion, Steps: []PlanStep{}},
	}
	appStore := NewPostgresStore(app)
	if _, created, err := appStore.SaveOrGet(ctx, record); err != nil || !created {
		t.Fatalf("restricted application SaveOrGet: created=%t err=%v", created, err)
	}
	if _, created, err := appStore.SaveOrGet(ctx, record); err != nil || created {
		t.Fatalf("restricted application replay: created=%t err=%v", created, err)
	}
	if _, err := dispatcher.ExecContext(ctx, "SELECT record FROM decision_records LIMIT 1"); err == nil {
		t.Fatal("dispatcher must not directly read the immutable DecisionRecord payload")
	}
	worker := NewPostgresStore(dispatcher)
	events, err := worker.Claim(ctx, "roles-dispatcher", 1, 2*time.Minute)
	if err != nil || len(events) != 1 {
		t.Fatalf("restricted dispatcher Claim: events=%d err=%v", len(events), err)
	}
	if err := worker.Ack(ctx, events[0].ID, "roles-dispatcher", events[0].Attempts); err != nil {
		t.Fatalf("restricted dispatcher Ack: %v", err)
	}
	if _, err := app.ExecContext(ctx, "SELECT event_id FROM outbox_events LIMIT 1"); err == nil {
		t.Fatal("application must not list the Outbox")
	}
	if err := VerifyRuntimeDatabaseRole(ctx, admin, schema, RuntimeRoleApplication); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("privileged migrator incorrectly accepted as application: %v", err)
	}
	if err := VerifyRuntimeDatabaseRole(ctx, admin, schema, RuntimeRoleDispatcher); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("privileged migrator incorrectly accepted as dispatcher: %v", err)
	}

	// An application must not be allowed to steal/ack Outbox leases.
	exec("GRANT UPDATE (lease_owner) ON "+schema+".outbox_events TO "+appRole)
	if err := VerifyRuntimeDatabaseRole(ctx, app, schema, RuntimeRoleApplication); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("app accepted with Outbox lease UPDATE: %v", err)
	}
	exec("REVOKE UPDATE (lease_owner) ON "+schema+".outbox_events FROM "+appRole)
	check(app, RuntimeRoleApplication)

	// The dispatcher must not be able to forge an Outbox event or read a
	// DecisionRecord's immutable tenant payload.
	exec("GRANT INSERT ON "+schema+".outbox_events TO "+dispatcherRole)
	if err := VerifyRuntimeDatabaseRole(ctx, dispatcher, schema, RuntimeRoleDispatcher); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("dispatcher accepted with Outbox INSERT: %v", err)
	}
	exec("REVOKE INSERT ON "+schema+".outbox_events FROM "+dispatcherRole)
	check(dispatcher, RuntimeRoleDispatcher)
	exec("GRANT SELECT ON "+schema+".decision_records TO "+dispatcherRole)
	if err := VerifyRuntimeDatabaseRole(ctx, dispatcher, schema, RuntimeRoleDispatcher); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("dispatcher accepted with DecisionRecord SELECT: %v", err)
	}
	exec("REVOKE SELECT ON "+schema+".decision_records FROM "+dispatcherRole)
	check(dispatcher, RuntimeRoleDispatcher)

	// Non-inheriting membership still allows SET ROLE and must fail closed.
	exec("GRANT "+dispatcherRole+" TO "+appRole+" WITH INHERIT FALSE, SET TRUE")
	if err := VerifyRuntimeDatabaseRole(ctx, app, schema, RuntimeRoleApplication); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("application accepted SET ROLE access to dispatcher: %v", err)
	}
	exec("REVOKE "+dispatcherRole+" FROM "+appRole)
	check(app, RuntimeRoleApplication)

	// ADMIN TRUE can allow a role to re-grant itself SET TRUE later.
	// The initial membership deliberately has no inherited/SET access.
	exec("GRANT "+dispatcherRole+" TO "+appRole+" WITH INHERIT FALSE, SET FALSE, ADMIN TRUE")
	if err := VerifyRuntimeDatabaseRole(ctx, app, schema, RuntimeRoleApplication); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("application accepted ADMIN membership with SET FALSE: %v", err)
	}
	exec("REVOKE "+dispatcherRole+" FROM "+appRole)
	check(app, RuntimeRoleApplication)

	// REFERENCES may be granted on a single column without a table-wide ACL.
	exec("GRANT REFERENCES (event_id) ON "+schema+".outbox_events TO "+appRole)
	if err := VerifyRuntimeDatabaseRole(ctx, app, schema, RuntimeRoleApplication); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("application accepted column REFERENCES grant: %v", err)
	}
	exec("REVOKE REFERENCES (event_id) ON "+schema+".outbox_events FROM "+appRole)
	check(app, RuntimeRoleApplication)

	// A SQL SECURITY DEFINER function owned by the migrator can expose rows
	// even to the dispatcher, which has NO direct DecisionRecord SELECT grant.
	// PostgreSQL grants EXECUTE to PUBLIC on new functions by default.
	exec("CREATE FUNCTION "+schema+".unreviewed_tenant_count() RETURNS bigint LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS 'SELECT count(*) FROM "+schema+".decision_records'")
	var leaked int64
	if err := dispatcher.QueryRowContext(ctx, "SELECT "+schema+".unreviewed_tenant_count()").Scan(&leaked); err != nil || leaked < 1 {
		t.Fatalf("test must demonstrate callable definer function leaking DecisionRecord row count: count=%d err=%v", leaked, err)
	}
	if err := VerifyRuntimeDatabaseRole(ctx, dispatcher, schema, RuntimeRoleDispatcher); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("dispatcher passed role audit while able to EXECUTE unreviewed SECURITY DEFINER function: %v", err)
	}
	exec("REVOKE EXECUTE ON FUNCTION "+schema+".unreviewed_tenant_count() FROM PUBLIC")
	check(dispatcher, RuntimeRoleDispatcher)

	// Explicit direct EXECUTE grants must also be detected, not merely PUBLIC.
	exec("GRANT EXECUTE ON FUNCTION "+schema+".unreviewed_tenant_count() TO "+appRole)
	if err := VerifyRuntimeDatabaseRole(ctx, app, schema, RuntimeRoleApplication); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("app passed role audit with direct EXECUTE on unreviewed definer function: %v", err)
	}
	exec("REVOKE EXECUTE ON FUNCTION "+schema+".unreviewed_tenant_count() FROM "+appRole)
	check(app, RuntimeRoleApplication)

	// A same-name overload must not inherit the approved trigger-only
	// function's exclusion from the effective privilege audit.
	exec("CREATE FUNCTION "+schema+".reject_decision_record_mutation(integer) RETURNS integer LANGUAGE sql AS 'SELECT 1'")
	if err := VerifyRuntimeDatabaseRole(ctx, app, schema, RuntimeRoleApplication); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("app passed role audit with executable same-name overload: %v", err)
	}
	exec("REVOKE EXECUTE ON FUNCTION "+schema+".reject_decision_record_mutation(integer) FROM PUBLIC")
	check(app, RuntimeRoleApplication)

	// A pinned search_path protects unqualified application SQL, but PostgreSQL
	// also permits schema-qualified calls. A second accessible schema can carry
	// a SECURITY DEFINER function callable by a restricted dispatcher identity.
	foreign := "decision_foreign_" + seed
	exec("CREATE SCHEMA "+foreign)
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+foreign+" CASCADE")
	exec("CREATE FUNCTION "+foreign+".read_decision_count() RETURNS bigint LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS 'SELECT count(*) FROM "+schema+".decision_records'")
	exec("CREATE TABLE "+foreign+".extra_rows (secret text)")
	exec("CREATE SEQUENCE "+foreign+".extra_counter")
	exec("GRANT USAGE ON SCHEMA "+foreign+" TO "+dispatcherRole)
	var count int64
	if err := dispatcher.QueryRowContext(ctx, "SELECT "+foreign+".read_decision_count()").Scan(&count); err != nil || count < 1 {
		t.Fatalf("test must demonstrate qualified cross-schema SECURITY DEFINER read: count=%d err=%v", count, err)
	}
	if err := VerifyRuntimeDatabaseRole(ctx, dispatcher, schema, RuntimeRoleDispatcher); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("role audit accepted a cross-schema owner-privileged EXECUTE: %v", err)
	}
	exec("REVOKE USAGE ON SCHEMA "+foreign+" FROM "+dispatcherRole)
	check(dispatcher, RuntimeRoleDispatcher)
	// Isolate subsequent relation/sequence cases from the default PUBLIC
	// EXECUTE grant on the function created for the first negative case.
	exec("REVOKE EXECUTE ON FUNCTION "+foreign+".read_decision_count() FROM PUBLIC")

	// Direct SELECT on a foreign table is equally outside the reviewed ACL.
	exec("GRANT USAGE ON SCHEMA "+foreign+" TO "+appRole)
	exec("GRANT SELECT (secret) ON "+foreign+".extra_rows TO "+appRole)
	if err := VerifyRuntimeDatabaseRole(ctx, app, schema, RuntimeRoleApplication); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("role audit accepted column-only SELECT in foreign schema: %v", err)
	}
	exec("REVOKE SELECT (secret) ON "+foreign+".extra_rows FROM "+appRole)
	check(app, RuntimeRoleApplication)
	exec("GRANT USAGE ON SEQUENCE "+foreign+".extra_counter TO "+appRole)
	if err := VerifyRuntimeDatabaseRole(ctx, app, schema, RuntimeRoleApplication); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("role audit accepted foreign sequence USAGE: %v", err)
	}
	exec("REVOKE USAGE ON SEQUENCE "+foreign+".extra_counter FROM "+appRole)
	check(app, RuntimeRoleApplication)
	exec("REVOKE USAGE ON SCHEMA "+foreign+" FROM "+appRole)
	check(app, RuntimeRoleApplication)
}
