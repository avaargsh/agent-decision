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

// TestCatalogAttestationRebindsAfterSchemaRecreation exercises a pooled pgx
// connection whose cached catalog statements have already resolved the same
// schema name. It drops and recreates that schema (therefore replacing relation
// OIDs) and verifies that migration and read-only attestation bind to the new
// decision_tenant_logins relation rather than a stale catalog OID.
func TestCatalogAttestationRebindsAfterSchemaRecreation(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	admin.SetMaxOpenConns(4)
	if err := admin.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	schema := fmt.Sprintf("attest_recreate_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := admin.ExecContext(cleanup, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
			t.Errorf("drop recreated schema: %v", err)
		}
	}()

	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*config)
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	var backendPID int
	if err := db.QueryRowContext(ctx, "SELECT pg_catalog.pg_backend_pid()").Scan(&backendPID); err != nil {
		t.Fatal(err)
	}
	if err := MigrateInSchema(ctx, db, schema); err != nil {
		t.Fatalf("install first schema generation: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := VerifyInstalledCatalogInSchema(ctx, db, schema); err != nil {
			t.Fatalf("warm catalog statement cache %d: %v", i, err)
		}
	}

	var firstMappingOID uint32
	if err := admin.QueryRowContext(ctx, "SELECT pg_catalog.to_regclass($1)::oid", schema+".decision_tenant_logins").Scan(&firstMappingOID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
		t.Fatalf("drop first schema generation: %v", err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("recreate same schema name: %v", err)
	}

	var reusedBackendPID int
	if err := db.QueryRowContext(ctx, "SELECT pg_catalog.pg_backend_pid()").Scan(&reusedBackendPID); err != nil {
		t.Fatal(err)
	}
	if reusedBackendPID != backendPID {
		t.Fatalf("test did not reuse the warmed PostgreSQL connection: before=%d after=%d", backendPID, reusedBackendPID)
	}
	if err := MigrateInSchema(ctx, db, schema); err != nil {
		t.Fatalf("install recreated schema on warmed connection: %v", err)
	}
	var secondMappingOID uint32
	if err := admin.QueryRowContext(ctx, "SELECT pg_catalog.to_regclass($1)::oid", schema+".decision_tenant_logins").Scan(&secondMappingOID); err != nil {
		t.Fatal(err)
	}
	if secondMappingOID == firstMappingOID {
		t.Fatalf("schema recreation reused mapping relation OID unexpectedly: %d", secondMappingOID)
	}
	if err := VerifyInstalledCatalogInSchema(ctx, db, schema); err != nil {
		t.Fatalf("attest recreated schema with warmed connection: %v", err)
	}

	target := schema + ".decision_tenant_logins"
	var approvedDefinition string
	if err := admin.QueryRowContext(ctx, `
		SELECT pg_catalog.pg_get_constraintdef(c.oid)
		FROM pg_catalog.pg_constraint AS c
		WHERE c.conrelid = pg_catalog.to_regclass($1)
		  AND c.conname = 'decision_tenant_logins_login_kind_check'
		  AND c.contype = 'c'
	`, target).Scan(&approvedDefinition); err != nil {
		t.Fatalf("read recreated mapping CHECK: %v", err)
	}
	if _, err := admin.ExecContext(ctx,
		"ALTER TABLE "+target+" DROP CONSTRAINT decision_tenant_logins_login_kind_check; "+
			"ALTER TABLE "+target+" ADD CONSTRAINT decision_tenant_logins_login_kind_check CHECK (true)",
	); err != nil {
		t.Fatalf("inject local mapping CHECK drift: %v", err)
	}
	err = VerifyInstalledCatalogInSchema(ctx, db, schema)
	if !errors.Is(err, ErrCatalogDrift) || !strings.Contains(err.Error(), "tenant LOGIN mapping login_kind CHECK mismatch") {
		t.Fatalf("recreated schema drift must fail at the local named predicate: %v", err)
	}
	if _, err := admin.ExecContext(ctx,
		"ALTER TABLE "+target+" DROP CONSTRAINT decision_tenant_logins_login_kind_check; "+
			"ALTER TABLE "+target+" ADD CONSTRAINT decision_tenant_logins_login_kind_check "+approvedDefinition,
	); err != nil {
		t.Fatalf("restore approved mapping CHECK: %v", err)
	}
	if err := VerifyInstalledCatalogInSchema(ctx, db, schema); err != nil {
		t.Fatalf("restored recreated schema rejected: %v", err)
	}

	// Repeat schema-name reuse on the same warmed backend to increase the
	// chance of exposing stale relation OIDs across catalog invalidations.
	for generation := 0; generation < 2; generation++ {
		var previousOID uint32
		if err := admin.QueryRowContext(ctx, "SELECT pg_catalog.to_regclass($1)::oid", target).Scan(&previousOID); err != nil {
			t.Fatalf("read mapping OID before recreation %d: %v", generation, err)
		}
		if _, err := admin.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Fatalf("drop schema generation %d: %v", generation, err)
		}
		if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
			t.Fatalf("recreate schema generation %d: %v", generation, err)
		}
		if err := MigrateInSchema(ctx, db, schema); err != nil {
			t.Fatalf("migrate schema generation %d on warmed connection: %v", generation, err)
		}
		var currentOID uint32
		if err := admin.QueryRowContext(ctx, "SELECT pg_catalog.to_regclass($1)::oid", target).Scan(&currentOID); err != nil {
			t.Fatalf("read mapping OID after recreation %d: %v", generation, err)
		}
		if currentOID == previousOID {
			t.Fatalf("schema generation %d retained relation OID %d", generation, currentOID)
		}
		if err := db.QueryRowContext(ctx, "SELECT pg_catalog.pg_backend_pid()").Scan(&reusedBackendPID); err != nil {
			t.Fatal(err)
		}
		if reusedBackendPID != backendPID {
			t.Fatalf("schema generation %d switched warmed backend: before=%d after=%d", generation, backendPID, reusedBackendPID)
		}
		if err := VerifyInstalledCatalogInSchema(ctx, db, schema); err != nil {
			t.Fatalf("attest schema generation %d on warmed connection: %v", generation, err)
		}
	}
}
