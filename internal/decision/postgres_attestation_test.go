package decision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
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

	// v0004 approves only the exact tenant policies on the two data tables.
	// Dormant/extra policies, disabled RLS, forced-owner RLS, or any RLS on the
	// mapping/history tables must fail both startup attestation and migration
	// re-entry. The verifier is read-only and never repairs catalog drift.
	for _, table := range []string{"decision_records", "outbox_events", "decision_tenant_logins", "schema_migrations"} {
		t.Run("rls_drift_"+table, func(t *testing.T) {
			target := schema + "." + table
			changes := []struct {
				name, install, restore string
			}{
				{"extra_policy", "CREATE POLICY unreviewed_policy ON "+target+" FOR SELECT USING (true)", "DROP POLICY unreviewed_policy ON "+target},
			}
			if table == "decision_records" || table == "outbox_events" {
				changes = append(changes,
					struct{ name, install, restore string }{"disabled", "ALTER TABLE "+target+" DISABLE ROW LEVEL SECURITY", "ALTER TABLE "+target+" ENABLE ROW LEVEL SECURITY"},
					struct{ name, install, restore string }{"forced", "ALTER TABLE "+target+" FORCE ROW LEVEL SECURITY", "ALTER TABLE "+target+" NO FORCE ROW LEVEL SECURITY"},
				)
			} else {
				changes = append(changes,
					struct{ name, install, restore string }{"enabled", "ALTER TABLE "+target+" ENABLE ROW LEVEL SECURITY", "ALTER TABLE "+target+" DISABLE ROW LEVEL SECURITY"},
					struct{ name, install, restore string }{"forced", "ALTER TABLE "+target+" FORCE ROW LEVEL SECURITY", "ALTER TABLE "+target+" NO FORCE ROW LEVEL SECURITY"},
				)
			}
			for _, tc := range changes {
				t.Run(tc.name, func(t *testing.T) {
					if _, err := admin.ExecContext(ctx, tc.install); err != nil {
						t.Fatal(err)
					}
					defer func() {
						if _, err := admin.ExecContext(context.Background(), tc.restore); err != nil {
							t.Errorf("restore fixture: %v", err)
						}
					}()
					if err := VerifyInstalledCatalogInSchema(ctx, restricted, schema); !errors.Is(err, ErrCatalogDrift) {
						t.Errorf("attestation accepted RLS drift %s on %s: %v", tc.name, table, err)
					}
					if err := MigrateInSchema(ctx, admin, schema); !errors.Is(err, ErrCatalogDrift) {
						t.Errorf("migration re-entry accepted RLS drift %s on %s: %v", tc.name, table, err)
					}
				})
				if err := VerifyInstalledCatalogInSchema(ctx, restricted, schema); err != nil {
					t.Fatalf("restored catalog: %v", err)
				}
				if err := MigrateInSchema(ctx, admin, schema); err != nil {
					t.Fatalf("restored migration re-entry: %v", err)
				}
			}
		})
	}

	// A same-name permissive replacement must not pass merely because the
	// approved policy name and command still exist.
	t.Run("weakened_same_name_tenant_policy", func(t *testing.T) {
		target := schema + ".decision_records"
		if _, err := admin.ExecContext(ctx, "DROP POLICY decision_records_tenant_select ON "+target); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.ExecContext(ctx, "CREATE POLICY decision_records_tenant_select ON "+target+" AS PERMISSIVE FOR SELECT TO PUBLIC USING (true)"); err != nil {
			t.Fatal(err)
		}
		if err := VerifyInstalledCatalogInSchema(ctx, restricted, schema); !errors.Is(err, ErrCatalogDrift) {
			t.Fatalf("weakened same-name RLS policy passed attestation: %v", err)
		}
		if err := MigrateInSchema(ctx, admin, schema); !errors.Is(err, ErrCatalogDrift) {
			t.Fatalf("migration re-entry accepted weakened same-name RLS policy: %v", err)
		}
		if _, err := admin.ExecContext(ctx, "DROP POLICY decision_records_tenant_select ON "+target); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.ExecContext(ctx, `CREATE POLICY decision_records_tenant_select
			ON `+target+` AS PERMISSIVE FOR SELECT TO PUBLIC
			USING (
				tenant_id = NULLIF(pg_catalog.current_setting('decision.tenant_id', true), '')
				AND EXISTS (
					SELECT 1 FROM `+schema+`.decision_tenant_logins AS login
					WHERE login.login_role = SESSION_USER
					  AND login.login_kind = 'application'
					  AND login.tenant_id = decision_records.tenant_id
				)
			)`); err != nil {
			t.Fatal(err)
		}
		if err := VerifyInstalledCatalogInSchema(ctx, restricted, schema); err != nil {
			t.Fatalf("restored exact tenant policy: %v", err)
		}
		if err := MigrateInSchema(ctx, admin, schema); err != nil {
			t.Fatalf("restored migration re-entry: %v", err)
		}
	})

	t.Run("mapping_public_grant", func(t *testing.T) {
		target := schema + ".decision_tenant_logins"
		if _, err := admin.ExecContext(ctx, "GRANT SELECT ON "+target+" TO PUBLIC"); err != nil {
			t.Fatal(err)
		}
		if err := VerifyInstalledCatalogInSchema(ctx, restricted, schema); !errors.Is(err, ErrCatalogDrift) {
			t.Fatalf("PUBLIC mapping grant passed catalog attestation: %v", err)
		}
		if _, err := admin.ExecContext(ctx, "REVOKE ALL ON "+target+" FROM PUBLIC"); err != nil {
			t.Fatal(err)
		}
		if err := VerifyInstalledCatalogInSchema(ctx, restricted, schema); err != nil {
			t.Fatalf("restored mapping ACL: %v", err)
		}
		if err := MigrateInSchema(ctx, admin, schema); err != nil {
			t.Fatalf("restored migration re-entry: %v", err)
		}
	})

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

	// A same-name CHECK can retain every expected keyword while adding an
	// unconditional TRUE branch. The read-only attestor must compare the
	// complete predicate, not merely search for required substrings.
	t.Run("weakened_mapping_identity_check_or_true", func(t *testing.T) {
		target := schema + ".decision_tenant_logins"
		var before string
		if err := admin.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_constraintdef(c.oid)
			FROM pg_catalog.pg_constraint AS c
			WHERE c.conrelid = pg_catalog.to_regclass($1)
			  AND c.conname = 'decision_tenant_logins_identity_ck'
		`, target).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.ExecContext(ctx, "ALTER TABLE "+target+" DROP CONSTRAINT decision_tenant_logins_identity_ck"); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.ExecContext(ctx, `ALTER TABLE `+target+` ADD CONSTRAINT decision_tenant_logins_identity_ck CHECK (
			(login_role::text <> ''
			 AND (
				(login_kind = 'application' AND tenant_id IS NOT NULL AND tenant_id <> '')
				OR (login_kind = 'dispatcher' AND tenant_id IS NULL)
			 )
			) OR TRUE
		)`); err != nil {
			t.Fatal(err)
		}
		login := fmt.Sprintf("attest_bypass_%d", time.Now().UnixNano())
		if _, err := admin.ExecContext(ctx, "INSERT INTO "+target+" (login_role, tenant_id, login_kind) VALUES ($1::name, NULL, 'application')", login); err != nil {
			t.Fatalf("weakened CHECK did not demonstrate the expected bypass: %v", err)
		}
		if _, err := admin.ExecContext(ctx, "DELETE FROM "+target+" WHERE login_role = $1::name", login); err != nil {
			t.Fatal(err)
		}
		verifyErr := VerifyInstalledCatalogInSchema(ctx, restricted, schema)
		migrationErr := MigrateInSchema(ctx, admin, schema)
		if _, err := admin.ExecContext(ctx, "ALTER TABLE "+target+" DROP CONSTRAINT decision_tenant_logins_identity_ck"); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.ExecContext(ctx, "ALTER TABLE "+target+" ADD CONSTRAINT decision_tenant_logins_identity_ck "+before); err != nil {
			t.Fatal(err)
		}
		if err := VerifyInstalledCatalogInSchema(ctx, restricted, schema); err != nil {
			t.Fatalf("restored identity CHECK did not pass: %v", err)
		}
		if !errors.Is(verifyErr, ErrCatalogDrift) {
			t.Fatalf("read-only attestation accepted a same-name mapping CHECK with OR TRUE: %v", verifyErr)
		}
		if !errors.Is(migrationErr, ErrCatalogDrift) {
			t.Fatalf("migration re-entry accepted a same-name mapping CHECK with OR TRUE: %v", migrationErr)
		}
	})

	t.Run("weakened_mapping_login_kind_check_or_true", func(t *testing.T) {
		target := schema + ".decision_tenant_logins"
		var before string
		if err := admin.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_constraintdef(c.oid)
			FROM pg_catalog.pg_constraint AS c
			WHERE c.conrelid = pg_catalog.to_regclass($1)
			  AND c.conname = 'decision_tenant_logins_login_kind_check'
		`, target).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.ExecContext(ctx, "ALTER TABLE "+target+" DROP CONSTRAINT decision_tenant_logins_login_kind_check"); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.ExecContext(ctx, `ALTER TABLE `+target+` ADD CONSTRAINT decision_tenant_logins_login_kind_check CHECK (
			(login_kind IN ('application', 'dispatcher')) OR TRUE
		)`); err != nil {
			t.Fatal(err)
		}
		verifyErr := VerifyInstalledCatalogInSchema(ctx, restricted, schema)
		migrationErr := MigrateInSchema(ctx, admin, schema)
		if _, err := admin.ExecContext(ctx, "ALTER TABLE "+target+" DROP CONSTRAINT decision_tenant_logins_login_kind_check"); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.ExecContext(ctx, "ALTER TABLE "+target+" ADD CONSTRAINT decision_tenant_logins_login_kind_check "+before); err != nil {
			t.Fatal(err)
		}
		if err := VerifyInstalledCatalogInSchema(ctx, restricted, schema); err != nil {
			t.Fatalf("restored login_kind CHECK did not pass: %v", err)
		}
		if !errors.Is(verifyErr, ErrCatalogDrift) {
			t.Fatalf("read-only attestation accepted a same-name login_kind CHECK with OR TRUE: %v", verifyErr)
		}
		if !errors.Is(migrationErr, ErrCatalogDrift) {
			t.Fatalf("migration re-entry accepted a same-name login_kind CHECK with OR TRUE: %v", migrationErr)
		}
	})
}


// TestCatalogAttestationStableDuringUnrelatedDDL exercises the migration and
// read-only attestation paths while PostgreSQL's shared catalogs are changing
// in a different schema. A sequential baseline runs first so any failure is
// attributable to the concurrent phase rather than an invalid fixture.
func TestCatalogAttestationStableDuringUnrelatedDDL(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	admin.SetMaxOpenConns(16)
	if err := admin.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	targetSchema := "attest_stress_" + suffix
	noiseSchema := "catalog_noise_" + suffix
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+targetSchema); err != nil {
		t.Fatal(err)
	}
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+targetSchema+" CASCADE")
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+noiseSchema); err != nil {
		t.Fatal(err)
	}
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+noiseSchema+" CASCADE")

	if err := MigrateInSchema(ctx, admin, targetSchema); err != nil {
		t.Fatalf("install target schema: %v", err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE TABLE "+noiseSchema+".catalog_churn (id integer NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := MigrateInSchema(ctx, admin, targetSchema); err != nil {
			t.Fatalf("sequential migration baseline %d: %v", i, err)
		}
		if err := VerifyInstalledCatalogInSchema(ctx, admin, targetSchema); err != nil {
			t.Fatalf("sequential read-only baseline %d: %v", i, err)
		}
	}

	const ddlIterations = 24
	const workers = 4
	const attestationsPerWorker = 8
	errs := make(chan error, workers+1)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < ddlIterations; i++ {
			constraint := fmt.Sprintf("catalog_churn_ck_%d", i)
			add := fmt.Sprintf("ALTER TABLE %s.catalog_churn ADD CONSTRAINT %s CHECK (id >= %d)", noiseSchema, constraint, i)
			drop := fmt.Sprintf("ALTER TABLE %s.catalog_churn DROP CONSTRAINT %s", noiseSchema, constraint)
			if _, err := admin.ExecContext(ctx, add); err != nil {
				errs <- fmt.Errorf("unrelated DDL add %d: %w", i, err)
				return
			}
			if _, err := admin.ExecContext(ctx, drop); err != nil {
				errs <- fmt.Errorf("unrelated DDL drop %d: %w", i, err)
				return
			}
		}
	}()

	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < attestationsPerWorker; i++ {
				if err := VerifyInstalledCatalogInSchema(ctx, admin, targetSchema); err != nil {
					errs <- fmt.Errorf("read-only attestation worker %d iteration %d: %w", worker, i, err)
					return
				}
				if err := MigrateInSchema(ctx, admin, targetSchema); err != nil {
					errs <- fmt.Errorf("migration re-entry worker %d iteration %d: %w", worker, i, err)
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
