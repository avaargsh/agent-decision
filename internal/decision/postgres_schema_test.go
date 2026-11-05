package decision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Migrate's default schema is public; an ambient per-connection search_path
// must never redirect privileged migration DDL into a lookalike schema.
func TestMigrateDoesNotFollowShadowSearchPath(t *testing.T) {
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
	shadow := fmt.Sprintf("decision_shadow_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+shadow); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+shadow+" CASCADE")
	}()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = shadow
	shadowDB := stdlib.OpenDB(*config)
	defer shadowDB.Close()
	if err := Migrate(ctx, shadowDB); err != nil {
		t.Fatalf("trusted default schema migration: %v", err)
	}
	var shadowObjects int
	if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM pg_class AS c
		JOIN pg_namespace AS n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname IN
		('schema_migrations', 'decision_records', 'outbox_events')`,
		shadow).Scan(&shadowObjects); err != nil {
		t.Fatal(err)
	}
	if shadowObjects != 0 {
		t.Fatalf("untrusted search_path redirected migration into %d shadow objects", shadowObjects)
	}
}


func TestMigrateResistsTemporaryTableShadow(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Keep the temporary table and Migrate on the same PostgreSQL session.
	db.SetMaxOpenConns(1)
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "CREATE TEMP TABLE decision_records (shadow_id integer) ON COMMIT PRESERVE ROWS"); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), "DROP TABLE IF EXISTS pg_temp.decision_records")
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("a session-local pg_temp table must not shadow the approved Decision ledger: %v", err)
	}
}

func TestMigrateInSchemaRejectsInvalidOrMissingTargets(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, schema := range []string{
		"", "pg_catalog", "pg_temp", "information_schema",
		"public; drop schema public", "MixedCase", "nonexistent_decision_schema_for_test",
	} {
		t.Run(schema, func(t *testing.T) {
			if err := MigrateInSchema(context.Background(), db, schema); !errors.Is(err, ErrCatalogDrift) {
				t.Fatalf("must reject untrusted/unavailable schema %q, got %v", schema, err)
			}
		})
	}
}
