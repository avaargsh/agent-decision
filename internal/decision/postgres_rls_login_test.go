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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// TestPostgresTenantLoginBoundRLS is a disposable policy prototype, not the
// production migration or catalog attestation. Each tenant has a distinct
// authenticated login; the custom GUC is not the authority.
func TestPostgresTenantLoginBoundRLS(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	seed := fmt.Sprintf("%d", time.Now().UnixNano())
	schema, roleA, roleB, workerRole := "rls_login_"+seed, "rls_a_"+seed, "rls_b_"+seed, "rls_worker_"+seed
	passwordFor := func(role string) string { return "ephemeral_login_" + role }
	exec := func(stmt string) {
		t.Helper()
		if _, err := admin.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	exec("CREATE SCHEMA " + schema)
	defer func() {
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		for _, role := range []string{roleA, roleB, workerRole} {
			_, _ = admin.ExecContext(context.Background(), "DROP OWNED BY "+role)
			_, _ = admin.ExecContext(context.Background(), "DROP ROLE "+role)
		}
	}()
	for _, role := range []string{roleA, roleB, workerRole} {
		exec("CREATE ROLE " + role + " LOGIN PASSWORD '" + passwordFor(role) + "'")
	}
	if err := MigrateInSchema(ctx, admin, schema); err != nil {
		t.Fatal(err)
	}
	ledger, events := schema+".decision_records", schema+".outbox_events"
	exec("ALTER TABLE " + ledger + " ENABLE ROW LEVEL SECURITY")
	exec("ALTER TABLE " + events + " ENABLE ROW LEVEL SECURITY")
	for i, role := range []string{roleA, roleB} {
		tenant := []string{"tenant-a", "tenant-b"}[i]
		suffix := []string{"a", "b"}[i]
		exec("GRANT USAGE ON SCHEMA " + schema + " TO " + role)
		exec("GRANT SELECT, INSERT ON " + ledger + " TO " + role)
		exec("GRANT INSERT ON " + events + " TO " + role)
		// All identifiers and literals here are generated/fixed test values.
		predicate := "session_user = '" + role + "' AND tenant_id = '" + tenant +
			"' AND tenant_id = nullif(pg_catalog.current_setting('decision.tenant_id', true), '')"
		exec("CREATE POLICY ledger_read_" + suffix + " ON " + ledger + " FOR SELECT TO " + role + " USING (" + predicate + ")")
		exec("CREATE POLICY ledger_write_" + suffix + " ON " + ledger + " FOR INSERT TO " + role + " WITH CHECK (" + predicate + ")")
		exec("CREATE POLICY outbox_write_" + suffix + " ON " + events + " FOR INSERT TO " + role + " WITH CHECK (" + predicate + ")")
	}
	exec("GRANT USAGE ON SCHEMA " + schema + " TO " + workerRole)
	exec("GRANT SELECT ON " + events + " TO " + workerRole)
	exec("GRANT UPDATE (lease_owner, lease_until, attempts, available_at, published_at, last_error_code) ON " + events + " TO " + workerRole)
	workerPredicate := "session_user = '" + workerRole + "'"
	exec("CREATE POLICY worker_read ON " + events + " FOR SELECT TO " + workerRole + " USING (" + workerPredicate + ")")
	exec("CREATE POLICY worker_update ON " + events + " FOR UPDATE TO " + workerRole + " USING (" + workerPredicate + ") WITH CHECK (" + workerPredicate + ")")
	open := func(role string) *sql.DB {
		t.Helper()
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.User, cfg.Password = role, passwordFor(role)
		cfg.RuntimeParams["search_path"] = schema + ", pg_catalog, pg_temp"
		db := stdlib.OpenDB(*cfg)
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		var actual string
		if err := db.QueryRowContext(ctx, "SELECT session_user").Scan(&actual); err != nil || actual != role {
			db.Close()
			t.Fatalf("restricted login %s: %q %v", role, actual, err)
		}
		return db
	}
	// Exercise the pool ownership boundary using distinct actual LOGINs.
	// These fixture policies are disposable; this is not production routing.
	t.Run("tenant_pool_registry", func(t *testing.T) {
		pin := func(role string) runtimeLoginBinding {
			t.Helper()
			var p runtimeLoginBinding
			p.RoleName = role
			if err := admin.QueryRowContext(ctx, "SELECT current_database(), oid FROM pg_catalog.pg_roles WHERE rolname=$1", role).Scan(&p.Database, &p.RoleOID); err != nil {
				t.Fatal(err)
			}
			return p
		}
		a, b, dispatcher := pin(roleA), pin(roleB), pin(workerRole)
		logins, err := newTenantLoginRegistry(dispatcher, []tenantLoginEntry{
			{TenantID: "tenant-a", Login: a},
			{TenantID: "tenant-b", Login: b},
		}, 2)
		if err != nil {
			t.Fatal(err)
		}
		principal := Principal{TenantID: "tenant-a", SubjectID: "subject", AgentID: "agent", SessionID: "session", CallerID: "agent-runtime"}
		var opened []*sql.DB
		factory := func(_ context.Context, p runtimeLoginBinding) (*sql.DB, error) {
			db := open(p.RoleName)
			opened = append(opened, db)
			return db, nil
		}
		registry, err := newTenantPoolRegistry(ctx, logins, schema, 2, 4, factory)
		if err != nil {
			t.Fatal(err)
		}
		defer registry.close()
		first, err := registry.resolve(principal)
		if err != nil || first != opened[0] {
			t.Fatalf("tenant-a pool: %v", err)
		}
		principal.TenantID = "tenant-b"
		second, err := registry.resolve(principal)
		if err != nil || second != opened[1] || second == first {
			t.Fatalf("tenant-b pool: %v", err)
		}
		for i, db := range []*sql.DB{first, second} {
			var actual string
			if err := db.QueryRowContext(ctx, "SELECT session_user").Scan(&actual); err != nil || actual != []string{roleA, roleB}[i] || db.Stats().MaxOpenConnections != 2 {
				t.Fatalf("pool identity/budget mismatch: %q %v", actual, err)
			}
		}
		principal.TenantID = "tenant-unknown"
		if db, err := registry.resolve(principal); db != nil || !errors.Is(err, ErrAuthorityRejected) {
			t.Fatalf("unknown tenant got pool: %v", err)
		}
		if err := registry.close(); err != nil {
			t.Fatal(err)
		}
		if err := registry.close(); err != nil {
			t.Fatal(err)
		}
		principal.TenantID = "tenant-a"
		if db, err := registry.resolve(principal); db != nil || !errors.Is(err, ErrStoreUnavailable) {
			t.Fatalf("closed registry resolved: %v", err)
		}
		for _, db := range opened {
			if err := db.PingContext(ctx); err == nil {
				t.Fatal("owned pool not closed")
			}
		}
		opened = nil
		if got, err := newTenantPoolRegistry(ctx, logins, schema, 2, 3, factory); got != nil || !errors.Is(err, ErrCatalogDrift) || len(opened) != 0 {
			t.Fatalf("over-budget config opened connections: %v", err)
		}
		for _, mode := range []string{"wrong_login", "alias", "factory_error"} {
			t.Run(mode, func(t *testing.T) {
				opened = nil
				got, err := newTenantPoolRegistry(ctx, logins, schema, 1, 2, func(ctx context.Context, p runtimeLoginBinding) (*sql.DB, error) {
					if len(opened) == 0 {
						return factory(ctx, p)
					}
					if mode == "alias" {
						return opened[0], nil
					}
					if mode == "wrong_login" {
						return factory(ctx, a)
					}
					db, _ := factory(ctx, p)
					return db, errors.New("factory failure")
				})
				if got != nil || err == nil {
					t.Fatalf("partial or misrouted registry accepted: %v", err)
				}
				for _, db := range opened {
					if err := db.PingContext(ctx); err == nil {
						t.Fatal("initialization failure leaked pool")
					}
				}
			})
		}
	})

	dbA, dbB, worker := open(roleA), open(roleB), open(workerRole)
	defer dbA.Close()
	defer dbB.Close()
	defer worker.Close()
	makeRecord := func(tenant, digit string) Record {
		return Record{
			TenantID: tenant, InvocationID: "same-invocation",
			DecisionID: "dec_" + strings.Repeat(digit, 64),
			AgentID: "agent-1", SessionID: "session-1", RunID: "run-1",
			RequestSHA256: strings.Repeat("b", 64), CreatedAt: time.Now().UTC(),
			Status: StatusProposed, ReasonCodes: []string{}, Evidence: []EvidenceRef{},
			Plan: PlanCandidate{PlanID: "plan_login", SchemaVersion: SchemaVersion, Steps: []PlanStep{}},
		}
	}
	a, b := makeRecord("tenant-a", "a"), makeRecord("tenant-b", "b")
	// The private bound store must reject a mismatched authenticated backend
	// before business SQL, rather than relying on fixture RLS or a startup
	// sample. The legacy constructor remains unchanged in this slice.
	t.Run("bound_transaction_identity", func(t *testing.T) {
		var pin runtimeLoginBinding
		pin.RoleName = roleA
		if err := admin.QueryRowContext(ctx, "SELECT current_database(), oid FROM pg_catalog.pg_roles WHERE rolname=$1", roleA).Scan(&pin.Database, &pin.RoleOID); err != nil {
			t.Fatal(err)
		}
		store, err := newBoundPostgresStore(dbA, schema, a.TenantID, pin)
		if err != nil {
			t.Fatal(err)
		}
		for _, readOnly := range []bool{false, true} {
			tx, err := store.beginTenantTx(ctx, a.TenantID, readOnly)
			if err != nil {
				t.Fatal(err)
			}
			var login, tenant string
			err = tx.QueryRowContext(ctx, "SELECT session_user, pg_catalog.current_setting('decision.tenant_id', true)").Scan(&login, &tenant)
			_ = tx.Rollback()
			if err != nil || login != roleA || tenant != a.TenantID {
				t.Fatalf("bound transaction mismatch: %q %q %v", login, tenant, err)
			}
		}
		if tx, err := store.beginTenantTx(ctx, b.TenantID, true); tx != nil || !errors.Is(err, ErrAuthorityRejected) {
			if tx != nil { _ = tx.Rollback() }
			t.Fatalf("foreign tenant accepted: %v", err)
		}
		wrong, err := newBoundPostgresStore(dbB, schema, a.TenantID, pin)
		if err != nil {
			t.Fatal(err)
		}
		if _, created, err := wrong.SaveOrGet(ctx, a); created || !errors.Is(err, ErrCatalogDrift) {
			t.Fatalf("wrong login write not rejected by preflight: %v", err)
		}
		if _, err := wrong.GetByInvocation(ctx, a.TenantID, a.InvocationID); !errors.Is(err, ErrCatalogDrift) {
			t.Fatalf("wrong login invocation: %v", err)
		}
		if _, err := wrong.GetByDecisionID(ctx, a.TenantID, a.AgentID, a.SessionID, a.DecisionID); !errors.Is(err, ErrCatalogDrift) {
			t.Fatalf("wrong login decision: %v", err)
		}
		if got, err := wrong.ListByRun(ctx, a.TenantID, a.AgentID, a.SessionID, a.RunID, nil, 10); got != nil || !errors.Is(err, ErrCatalogDrift) {
			t.Fatalf("wrong login list: %v", err)
		}
		for _, altered := range []runtimeLoginBinding{
			{Database: pin.Database+"_wrong", RoleName: pin.RoleName, RoleOID: pin.RoleOID},
			{Database: pin.Database, RoleName: pin.RoleName, RoleOID: pin.RoleOID+1},
		} {
			wrong, err := newBoundPostgresStore(dbA, schema, a.TenantID, altered)
			if err != nil {
				t.Fatal(err)
			}
			if tx, err := wrong.beginTenantTx(ctx, a.TenantID, true); tx != nil || !errors.Is(err, ErrCatalogDrift) {
				if tx != nil { _ = tx.Rollback() }
				t.Fatalf("wrong pin accepted: %v", err)
			}
		}
		if _, err := dbA.ExecContext(ctx, "SET search_path TO pg_catalog, pg_temp"); err != nil {
			t.Fatal(err)
		}
		if tx, err := store.beginTenantTx(ctx, a.TenantID, true); tx != nil || !errors.Is(err, ErrCatalogDrift) {
			if tx != nil { _ = tx.Rollback() }
			t.Errorf("unsafe schema path accepted: %v", err)
		}
		if _, err := dbA.ExecContext(ctx, "SET search_path TO "+schema+", pg_catalog, pg_temp"); err != nil {
			t.Fatal(err)
		}
		if _, err := dbA.ExecContext(ctx, "SELECT pg_catalog.set_config('decision.tenant_id', $1, false)", a.TenantID); err != nil {
			t.Fatal(err)
		}
		if tx, err := store.beginTenantTx(ctx, a.TenantID, true); tx != nil || !errors.Is(err, ErrCatalogDrift) {
			if tx != nil { _ = tx.Rollback() }
			t.Errorf("dirty context accepted by bound store: %v", err)
		}
		if _, err := dbA.ExecContext(ctx, "RESET decision.tenant_id"); err != nil {
			t.Fatal(err)
		}
		if tx, err := store.beginTenantTx(ctx, a.TenantID, true); err != nil {
			t.Fatalf("clean bound recovery: %v", err)
		} else {
			_ = tx.Rollback()
		}
		var records, events int
		if err := admin.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM "+ledger+"), (SELECT count(*) FROM "+events+")").Scan(&records, &events); err != nil || records != 0 || events != 0 {
			t.Fatalf("rejected transactions produced side effects: %d %d %v", records, events, err)
		}
	})
	// A direct foreign Outbox INSERT must fail at its own policy, not at
	// Ledger INSERT or an existing unique key. The referenced foreign ledger
	// exists and the probe uses a distinct event ID/type. Roll back even if a
	// broken policy unexpectedly permits the INSERT.
	requireDeniedOutbox := func(db *sql.DB, rec Record) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, "SELECT pg_catalog.set_config('decision.tenant_id', $1, true)", rec.TenantID); err != nil {
			t.Fatal(err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO outbox_events
			(event_id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
			 event_type, schema_version, payload)
			VALUES ($1, $2, 'decision_record', $3, 1, 'decision.rls-probe.v1', 1, '{}'::jsonb)`,
			"rls-probe-"+rec.TenantID, rec.TenantID, rec.DecisionID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("expected Outbox permission/policy denial for %s, got %v", rec.TenantID, err)
		}
	}
	for _, tc := range []struct {
		db *sql.DB
		own, other Record
		otherRole string
	}{
		{dbA, a, b, roleB},
		{dbB, b, a, roleA},
	} {
		store := NewPostgresStore(tc.db)
		if _, created, err := store.SaveOrGet(ctx, tc.own); err != nil || !created {
			t.Fatalf("own write %s: created=%t err=%v", tc.own.TenantID, created, err)
		}
	}
	for _, tc := range []struct {
		db *sql.DB
		own, other Record
		otherRole string
	}{
		{dbA, a, b, roleB},
		{dbB, b, a, roleA},
	} {
		store := NewPostgresStore(tc.db)
		if got, created, err := store.SaveOrGet(ctx, tc.own); err != nil || created || got.DecisionID != tc.own.DecisionID {
			t.Fatalf("own replay: created=%t err=%v", created, err)
		}
		if _, err := store.GetByInvocation(ctx, tc.other.TenantID, tc.other.InvocationID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("wrong-login invocation exposed: %v", err)
		}
		if got, err := store.ListByRun(ctx, tc.other.TenantID, tc.other.AgentID, tc.other.SessionID, tc.other.RunID, nil, 10); err != nil || len(got) != 0 {
			t.Fatalf("wrong-login listing: rows=%d err=%v", len(got), err)
		}
		// New foreign invocation must not be inserted, even with a matching
		// transaction GUC selected by the store on the wrong login.
		foreign := tc.other
		foreign.InvocationID = "forged-invocation"
		foreign.DecisionID = "dec_" + strings.Repeat("c", 64)
		if _, created, err := store.SaveOrGet(ctx, foreign); err == nil || created {
			t.Fatalf("wrong-login write accepted: created=%t err=%v", created, err)
		}
		requireDeniedOutbox(tc.db, tc.other)
		if _, err := tc.db.ExecContext(ctx, "SELECT event_id FROM outbox_events"); err == nil {
			t.Fatal("application can directly read Outbox")
		}
		if _, err := tc.db.ExecContext(ctx, "SET ROLE "+tc.otherRole); err == nil {
			t.Fatal("tenant login can switch to another tenant role")
		}
		// Unfiltered direct SQL is the real RLS test. Forging the custom
		// tenant GUC must still not confer another login's authority.
		for _, scope := range []string{"", tc.own.TenantID, tc.other.TenantID} {
			tx, err := tc.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.ExecContext(ctx, "SELECT pg_catalog.set_config('decision.tenant_id', $1, true)", scope); err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
			var count int
			var visible string
			err = tx.QueryRowContext(ctx, "SELECT count(*), coalesce(min(tenant_id), '') FROM decision_records").Scan(&count, &visible)
			_ = tx.Rollback()
			want, wantTenant := 0, ""
			if scope == tc.own.TenantID {
				want, wantTenant = 1, tc.own.TenantID
			}
			if err != nil || count != want || visible != wantTenant {
				t.Fatalf("unfiltered scope %q: count=%d tenant=%q err=%v", scope, count, visible, err)
			}
		}
		var clean bool
		if err := tc.db.QueryRowContext(ctx, "SELECT nullif(pg_catalog.current_setting('decision.tenant_id', true), '') IS NULL").Scan(&clean); err != nil || !clean {
			t.Fatalf("tenant context persisted: %t %v", clean, err)
		}
	}
	var records, eventCount int
	if err := admin.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM "+ledger+"), (SELECT count(*) FROM "+events+")").Scan(&records, &eventCount); err != nil || records != 2 || eventCount != 2 {
		t.Fatalf("denied write changed atomic rows: %d %d %v", records, eventCount, err)
	}
	if _, err := worker.ExecContext(ctx, "SELECT record FROM decision_records"); err == nil {
		t.Fatal("dispatcher can read ledger")
	}
	requireDeniedOutbox(worker, a)
	dispatcher := NewPostgresStore(worker)
	claimed, err := dispatcher.Claim(ctx, "rls-worker", 10, time.Minute)
	if err != nil || len(claimed) != 2 {
		t.Fatalf("explicit cross-tenant dispatch: events=%d err=%v", len(claimed), err)
	}
	for _, event := range claimed {
		if err := dispatcher.Ack(ctx, event.ID, "rls-worker", event.Attempts); err != nil {
			t.Fatalf("dispatcher ACK: %v", err)
		}
	}
}
