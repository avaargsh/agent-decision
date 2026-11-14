package decision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// A separate, non-owner login must be able to verify the installed ledger
// using only SELECT on the migration history and PostgreSQL catalog access.
func TestVerifyInstalledCatalogReadOnly(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", dsn)
	if err != nil { t.Fatal(err) }
	defer admin.Close()

	schema := fmt.Sprintf("decision_attest_%d", time.Now().UnixNano())
	role := fmt.Sprintf("decision_attest_role_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil { t.Fatal(err) }
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	if _, err := admin.ExecContext(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil { t.Fatal(err) }
	defer func() {
		// Grants on the test schema/table are dependencies of the role.
		// Revoke them before dropping the role to avoid leaking CI roles.
		_, _ = admin.ExecContext(context.Background(), "DROP OWNED BY "+role)
		_, _ = admin.ExecContext(context.Background(), "DROP ROLE "+role)
	}()
	if err := MigrateInSchema(ctx, admin, schema); err != nil { t.Fatal(err) }
	if _, err := admin.ExecContext(ctx, "GRANT USAGE ON SCHEMA "+schema+" TO "+role); err != nil { t.Fatal(err) }
	if _, err := admin.ExecContext(ctx, "GRANT SELECT ON "+schema+".schema_migrations TO "+role); err != nil { t.Fatal(err) }

	restricted, err := sql.Open("pgx", dsn)
	if err != nil { t.Fatal(err) }
	defer restricted.Close()
	restricted.SetMaxOpenConns(1)
	if _, err := restricted.ExecContext(ctx, "SET ROLE "+role); err != nil { t.Fatal(err) }
	defer restricted.ExecContext(context.Background(), "RESET ROLE")
	var canCreate bool
	if err := restricted.QueryRowContext(ctx, "SELECT pg_catalog.has_schema_privilege(current_user, $1, 'CREATE')", schema).Scan(&canCreate); err != nil { t.Fatal(err) }
	if canCreate { t.Fatal("test attestation role unexpectedly can CREATE objects") }

	if err := VerifyInstalledCatalogInSchema(ctx, restricted, schema); err != nil {
		t.Fatalf("read-only restricted attestation should pass: %v", err)
	}
	if err := VerifyInstalledCatalogInSchema(ctx, restricted, "missing_attestation_schema"); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("missing schema must fail closed: %v", err)
	}

	// The same-name installed trigger must be checked without any DDL/repair
	// by the restricted verifier. The owner deliberately tampers and restores.
	target := schema+".decision_records"
	if _, err := admin.ExecContext(ctx, "ALTER TABLE "+target+" DISABLE TRIGGER decision_records_no_update"); err != nil { t.Fatal(err) }
	if err := VerifyInstalledCatalogInSchema(ctx, restricted, schema); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("disabled trigger must fail read-only attestation: %v", err)
	}
	if _, err := admin.ExecContext(ctx, "ALTER TABLE "+target+" ENABLE TRIGGER decision_records_no_update"); err != nil { t.Fatal(err) }
	if err := VerifyInstalledCatalogInSchema(ctx, restricted, schema); err != nil { t.Fatalf("restored trigger: %v", err) }

	if _, err := admin.ExecContext(ctx, "UPDATE "+schema+".schema_migrations SET name='tampered.sql' WHERE version=2"); err != nil { t.Fatal(err) }
	if err := VerifyInstalledCatalogInSchema(ctx, restricted, schema); !errors.Is(err, ErrCatalogDrift) {
		t.Fatalf("tampered migration history must fail closed: %v", err)
	}
	if _, err := admin.ExecContext(ctx, "UPDATE "+schema+".schema_migrations SET name='0002_decision_outbox.sql' WHERE version=2"); err != nil { t.Fatal(err) }
	if err := VerifyInstalledCatalogInSchema(ctx, restricted, schema); err != nil { t.Fatalf("restored history: %v", err) }
}
