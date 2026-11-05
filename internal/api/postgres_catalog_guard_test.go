package api

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// This is a repository-level PostgreSQL 16 integration of the real catalog
// verifier, HTTP write gate and durable DecisionStore. The admin and app
// sessions here share CI credentials; production role isolation is separate.
func TestPostgresCatalogGuardedDecisionWrite(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", dsn)
	if err != nil { t.Fatal(err) }
	defer admin.Close()
	schema := fmt.Sprintf("decision_gate_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil { t.Fatal(err) }
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	if err := decision.MigrateInSchema(ctx, admin, schema); err != nil { t.Fatal(err) }

	cfg, err := pgx.ParseConfig(dsn)
	if err != nil { t.Fatal(err) }
	cfg.RuntimeParams["search_path"] = schema+", pg_catalog, pg_temp"
	storeDB := stdlib.OpenDB(*cfg)
	defer storeDB.Close()
	service := decision.NewService(decision.NewPostgresStore(storeDB), apiAuthority{})
	h := NewCatalogGuardedHandler(service, resolverFor(apiPrincipal()), func(ctx context.Context) error {
		return decision.VerifyInstalledCatalogInSchema(ctx, storeDB, schema)
	})
	ready := func() int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return w.Code
	}
	if got := ready(); got != http.StatusNoContent { t.Fatalf("verified ready=%d", got) }
	first := send(h, validBody(), "application/json")
	if first.Code != http.StatusCreated {
		t.Fatalf("attested durable write got %d: %s", first.Code, first.Body.String())
	}
	if _, err := admin.ExecContext(ctx, "ALTER TABLE "+schema+".decision_records DISABLE TRIGGER decision_records_no_update"); err != nil { t.Fatal(err) }
	if got := ready(); got != http.StatusServiceUnavailable {
		t.Fatalf("disabled trigger must close readiness, got %d", got)
	}
	nextBody := bytes.Replace(validBody(), []byte(`"invocation_id":"alert-17"`), []byte(`"invocation_id":"alert-18"`), 1)
	if bytes.Equal(nextBody, validBody()) { t.Fatal("fixture invocation_id was not changed") }
	if w := send(h, nextBody, "application/json"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("catalog drift allowed durable POST: %d", w.Code)
	}
	if _, err := admin.ExecContext(ctx, "ALTER TABLE "+schema+".decision_records ENABLE TRIGGER decision_records_no_update"); err != nil { t.Fatal(err) }
	if got := ready(); got != http.StatusNoContent { t.Fatalf("restored readiness=%d", got) }
	if w := send(h, nextBody, "application/json"); w.Code != http.StatusCreated {
		t.Fatalf("restored attest/gate failed durable POST: %d: %s", w.Code, w.Body.String())
	}
}
