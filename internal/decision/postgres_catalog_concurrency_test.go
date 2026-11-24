package decision

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// TestCatalogAttestationIsStableDuringUnrelatedSchemaDDL compares a sequential
// baseline with concurrent read-only attestation and migration re-entry while
// another schema continuously changes its constraint catalog. The DDL is
// deliberately unrelated to the attested schema; it must never make the
// target schema's LOGIN mapping appear to drift.
func TestCatalogAttestationIsStableDuringUnrelatedSchemaDDL(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(12)
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	targetSchema := "decision_catalog_target_" + suffix
	ddlSchema := "decision_catalog_ddl_" + suffix
	for _, schema := range []string{targetSchema, ddlSchema} {
		if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = db.ExecContext(context.Background(), "DROP SCHEMA "+targetSchema+" CASCADE")
		_, _ = db.ExecContext(context.Background(), "DROP SCHEMA "+ddlSchema+" CASCADE")
	}()

	if err := MigrateInSchema(ctx, db, targetSchema); err != nil {
		t.Fatalf("initial target migration: %v", err)
	}
	if err := MigrateInSchema(ctx, db, ddlSchema); err != nil {
		t.Fatalf("initial unrelated-schema migration: %v", err)
	}

	// Establish a clean sequential baseline before introducing catalog churn.
	for i := 0; i < 8; i++ {
		if err := VerifyInstalledCatalogInSchema(ctx, db, targetSchema); err != nil {
			t.Fatalf("sequential baseline attestation %d: %v", i, err)
		}
		if err := MigrateInSchema(ctx, db, targetSchema); err != nil {
			t.Fatalf("sequential baseline migration %d: %v", i, err)
		}
	}

	start := make(chan struct{})
	errs := make(chan error, 3)
	var workers sync.WaitGroup
	run := func(name string, iterations int, operation func(int) error) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for i := 0; i < iterations; i++ {
				if err := operation(i); err != nil {
					errs <- fmt.Errorf("%s iteration %d: %w", name, i, err)
					return
				}
			}
		}()
	}

	run("read-only attestation", 64, func(int) error {
		return VerifyInstalledCatalogInSchema(ctx, db, targetSchema)
	})
	run("migration re-entry", 32, func(int) error {
		return MigrateInSchema(ctx, db, targetSchema)
	})
	run("unrelated catalog DDL", 64, func(int) error {
		if _, err := db.ExecContext(ctx, "ALTER TABLE "+ddlSchema+".decision_tenant_logins ADD CONSTRAINT decision_catalog_stress_probe CHECK (login_role::text <> '')"); err != nil {
			return fmt.Errorf("add unrelated CHECK: %w", err)
		}
		if _, err := db.ExecContext(ctx, "ALTER TABLE "+ddlSchema+".decision_tenant_logins DROP CONSTRAINT decision_catalog_stress_probe"); err != nil {
			return fmt.Errorf("drop unrelated CHECK: %w", err)
		}
		return nil
	})

	close(start)
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}

	for _, schema := range []string{targetSchema, ddlSchema} {
		if err := VerifyInstalledCatalogInSchema(ctx, db, schema); err != nil {
			t.Fatalf("final attestation for %s: %v", schema, err)
		}
	}
}
