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
	password := "ephemeral_role_gate_" + seed
	exec("CREATE ROLE "+appRole+" LOGIN PASSWORD \'"+password+"\'")
	exec("CREATE ROLE "+dispatcherRole+" LOGIN PASSWORD \'"+password+"\'")
	defer func() {
		_, _ = admin.ExecContext(context.Background(), "DROP OWNED BY "+appRole)
		_, _ = admin.ExecContext(context.Background(), "DROP OWNED BY "+dispatcherRole)
		_, _ = admin.ExecContext(context.Background(), "DROP ROLE "+appRole)
		_, _ = admin.ExecContext(context.Background(), "DROP ROLE "+dispatcherRole)
	}()
	if err := MigrateInSchema(ctx, admin, schema); err != nil { t.Fatal(err) }
	exec("GRANT USAGE ON SCHEMA "+schema+" TO "+appRole+", "+dispatcherRole)
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
	check(app, RuntimeRoleApplication)
	check(dispatcher, RuntimeRoleDispatcher)

	// Exercise actual runtime SQL under the effective role rather than
	// assuming the GRANT matrix is sufficient for SaveOrGet/Claim/Ack.
	record := Record{
		TenantID: "roles-tenant-"+seed,
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
}
