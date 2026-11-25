package outbox_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Exercise same-name mapping constraints in separate schemas, unlike the
// existing same-schema unrelated-relation stress workloads for issue #56.
func TestPostgresCatalogAttestationIgnoresCrossSchemaMappingDDL(t *testing.T) {
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

	suffix := time.Now().UnixNano()
	target := fmt.Sprintf("catalog_target_%d", suffix)
	decoy := fmt.Sprintf("catalog_decoy_%d", suffix)
	for _, schema := range []string{target, decoy} {
		if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
			t.Fatal(err)
		}
		// Register cleanup immediately, including if the second schema fails.
		defer func(schema string) {
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			if _, err := admin.ExecContext(cleanup, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
				t.Errorf("drop test schema %s: %v", schema, err)
			}
		}(schema)
		if err := decision.MigrateInSchema(ctx, admin, schema); err != nil {
			t.Fatalf("install %s: %v", schema, err)
		}
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = target
	db := stdlib.OpenDB(*config)
	defer db.Close()
	db.SetMaxOpenConns(4)

	for _, schema := range []string{target, decoy} {
		if err := decision.VerifyInstalledCatalogInSchema(ctx, db, schema); err != nil {
			t.Fatalf("valid baseline %s: %v", schema, err)
		}
	}
	const constraint = "decision_tenant_logins_login_kind_check"
	replace := func(schema, predicate string) error {
		tx, err := admin.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		table := schema + ".decision_tenant_logins"
		if _, err := tx.ExecContext(ctx, "ALTER TABLE "+table+" DROP CONSTRAINT "+constraint); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "ALTER TABLE "+table+" ADD CONSTRAINT "+constraint+" CHECK ("+predicate+")"); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := replace(decoy, "true"); err != nil {
		t.Fatal(err)
	}
	assertDrift := func(schema string) {
		t.Helper()
		err := decision.VerifyInstalledCatalogInSchema(ctx, db, schema)
		if !errors.Is(err, decision.ErrCatalogDrift) || !strings.Contains(err.Error(), "tenant LOGIN mapping login_kind CHECK") {
			t.Fatalf("local weakened CHECK in %s must fail at its named predicate: %v", schema, err)
		}
	}
	assertDrift(decoy)
	if err := decision.VerifyInstalledCatalogInSchema(ctx, db, target); err != nil {
		t.Fatalf("decoy drift contaminated valid target: %v", err)
	}

	// Recreate the same-name constraint in the decoy while the target pool
	// repeatedly re-enters migration and read-only attestation. The decoy
	// stays invalid throughout, so a wrong relation binding cannot pass.
	const cycles = 24
	start := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		<-start
		for i := 0; i < cycles; i++ {
			predicate := "true"
			if i%2 == 0 {
				predicate = "login_kind IS NOT NULL"
			}
			if err := replace(decoy, predicate); err != nil {
				done <- fmt.Errorf("decoy constraint cycle %d: %w", i, err)
				return
			}
		}
		done <- nil
	}()
	close(start)
	var targetErr error
	for i := 0; i < cycles; i++ {
		if err := decision.MigrateInSchema(ctx, db, target); err != nil {
			targetErr = fmt.Errorf("target migration cycle %d: %w", i, err)
			break
		}
		if err := decision.VerifyInstalledCatalogInSchema(ctx, db, target); err != nil {
			targetErr = fmt.Errorf("target attestation cycle %d: %w", i, err)
			break
		}
	}
	if targetErr != nil {
		cancel()
	}
	if err := <-done; err != nil {
		t.Error(err)
	}
	if targetErr != nil {
		t.Fatal(targetErr)
	}
	if t.Failed() {
		return
	}
	assertDrift(decoy)
	// Positive control: identical drift in the target itself is rejected.
	if err := replace(target, "true"); err != nil {
		t.Fatal(err)
	}
	assertDrift(target)
	t.Logf("cross-schema constraint isolation: %d decoy replacements and %d target migration/attestation cycles", cycles, cycles)
}
