package decision

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Distinct PostgreSQL LOGIN identities exercise real password authentication.
// This is CI infrastructure, not a production IAM/mTLS or tenant RLS audit.
func TestDatabaseRolesUseDistinctLoginCredentials(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", dsn)
	if err != nil { t.Fatal(err) }
	defer admin.Close()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil { t.Fatal(err) }
	seed := fmt.Sprintf("%d", time.Now().UnixNano())
	schema := "decision_logins_" + seed
	appName := "decision_app_login_" + seed
	workerName := "decision_dispatch_login_" + seed
	attestName := "decision_attest_login_" + seed
	type login struct { name, password string }
	logins := []login{}
	run := func(q string) {
		t.Helper()
		if _, err := admin.ExecContext(ctx, q); err != nil { t.Fatalf("SQL setup: %v", err) }
	}
	run("CREATE SCHEMA "+schema)
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	if err := MigrateInSchema(ctx, admin, schema); err != nil { t.Fatal(err) }
	for _, name := range []string{appName, workerName, attestName} {
		random := make([]byte, 24)
		if _, err := rand.Read(random); err != nil { t.Fatal(err) }
		password := hex.EncodeToString(random)
		run("CREATE ROLE "+name+" LOGIN PASSWORD '"+password+"'")
		logins = append(logins, login{name: name, password: password})
	}
	defer func() {
		for _, l := range logins {
			_, _ = admin.ExecContext(context.Background(), "DROP OWNED BY "+l.name)
			_, _ = admin.ExecContext(context.Background(), "DROP ROLE "+l.name)
		}
	}()
	run("GRANT USAGE ON SCHEMA "+schema+" TO "+appName+", "+workerName+", "+attestName)
	run("GRANT SELECT, INSERT ON "+schema+".decision_records TO "+appName)
	run("GRANT INSERT ON "+schema+".outbox_events TO "+appName)
	run("GRANT SELECT ON "+schema+".outbox_events TO "+workerName)
	run("GRANT UPDATE (lease_owner,lease_until,attempts,available_at,published_at,last_error_code) ON "+schema+".outbox_events TO "+workerName)
	run("GRANT SELECT ON "+schema+".schema_migrations TO "+attestName)

	open := func(l login) *sql.DB {
		t.Helper()
		other := cfg.Copy()
		other.User = l.name
		other.Password = l.password
		other.RuntimeParams["search_path"] = schema+", pg_catalog, pg_temp"
		db := stdlib.OpenDB(*other)
		db.SetMaxOpenConns(2)
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			t.Fatalf("separate login %s unable to connect: %v", l.name, err)
		}
		var current, session string
		if err := db.QueryRowContext(ctx, "SELECT current_user, session_user").Scan(&current, &session); err != nil || current != l.name || session != l.name {
			db.Close()
			t.Fatalf("non-independent login %s: current=%s session=%s err=%v", l.name, current, session, err)
		}
		return db
	}
	app := open(logins[0])
	defer app.Close()
	worker := open(logins[1])
	defer worker.Close()
	attestor := open(logins[2])
	defer attestor.Close()

	if err := VerifyRuntimeDatabaseRole(ctx, app, schema, RuntimeRoleApplication); err != nil { t.Fatal(err) }
	if err := VerifyRuntimeDatabaseRole(ctx, worker, schema, RuntimeRoleDispatcher); err != nil { t.Fatal(err) }
	if err := VerifyInstalledCatalogInSchema(ctx, attestor, schema); err != nil { t.Fatal(err) }
	if err := MigrateInSchema(ctx, app, schema); err == nil { t.Fatal("application LOGIN unexpectedly has migrator DDL privileges") }
	if err := VerifyInstalledCatalogInSchema(ctx, app, schema); err == nil { t.Fatal("app LOGIN unexpectedly has attestor migration history SELECT") }
	if err := VerifyRuntimeDatabaseRole(ctx, attestor, schema, RuntimeRoleApplication); err == nil { t.Fatal("read-only attestor passed application role check") }
	if _, err := worker.ExecContext(ctx, "SELECT record FROM decision_records LIMIT 1"); err == nil { t.Fatal("dispatcher LOGIN can read DecisionRecord payload") }

	record := Record{
		TenantID: "login-tenant-"+seed, InvocationID: "login-invocation",
		DecisionID: "dec_"+strings.Repeat("c", 64),
		AgentID: "login-agent", SessionID: "login-session", RunID: "login-run",
		RequestSHA256: strings.Repeat("d", 64), CreatedAt: time.Now().UTC(),
		Status: StatusProposed, ReasonCodes: []string{}, Evidence: []EvidenceRef{},
		Plan: PlanCandidate{PlanID: "plan_logins", SchemaVersion: SchemaVersion, Steps: []PlanStep{}},
	}
	if _, created, err := NewPostgresStore(app).SaveOrGet(ctx, record); err != nil || !created {
		t.Fatalf("restricted LOGIN atomic save: created=%v err=%v", created, err)
	}
	if _, created, err := NewPostgresStore(app).SaveOrGet(ctx, record); err != nil || created {
		t.Fatalf("restricted LOGIN replay: created=%v err=%v", created, err)
	}
	events, err := NewPostgresStore(worker).Claim(ctx, "login-worker", 1, time.Minute)
	if err != nil || len(events) != 1 { t.Fatalf("restricted LOGIN claim events=%d err=%v", len(events), err) }
	if err := NewPostgresStore(worker).Ack(ctx, events[0].ID, "login-worker", events[0].Attempts); err != nil { t.Fatalf("restricted LOGIN ack: %v", err) }
	if _, err := attestor.ExecContext(ctx, "DELETE FROM outbox_events"); err == nil { t.Fatal("attestor LOGIN can DELETE Outbox") }
}
