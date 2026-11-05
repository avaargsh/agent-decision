package decision

import (
	"context"
	"database/sql"
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
