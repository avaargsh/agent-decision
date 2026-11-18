package evidenceauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestIndependentSourceRegistryLiveObservationAndRevocation(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("real source PostgreSQL integration only")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	schema := fmt.Sprintf("source_evidence_%d", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	if err := Install(ctx, db, schema); err != nil {
		t.Fatal(err)
	}

	// Actual disposable service and network observation. The metrics bytes
	// reflect the three real HTTP failures below, not invented tool output.
	var failures atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/checkout", func(w http.ResponseWriter, _ *http.Request) {
		failures.Add(1)
		http.Error(w, "isolated test failure", http.StatusInternalServerError)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "http_requests_failed_total %d\n", failures.Load())
	})
	service := httptest.NewServer(mux)
	defer service.Close()
	started := time.Now().UTC()
	for i := 0; i < 3; i++ {
		res, err := service.Client().Get(service.URL + "/checkout")
		if err != nil || res.StatusCode != http.StatusInternalServerError {
			t.Fatalf("actual observation control failed: %v", err)
		}
		res.Body.Close()
	}
	res, err := service.Client().Get(service.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || string(raw) != "http_requests_failed_total 3\n" {
		t.Fatalf("unexpected real source observation: %q %v", raw, err)
	}
	now := time.Now().UTC()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := decision.EvidenceSourceScope{
		TenantID: "tenant-a", AgentID: "agent-1", RunID: "11111111-1111-4111-8111-111111111111",
		Service: "payments", ResourceRef: "service:payments", SourceID: "isolated-collector",
		Source: "http-metrics", SourceVersion: "1.0.0", EvidenceType: "metrics", SchemaVersion: "1.0.0",
		MaxAge: time.Hour, MaxLifetime: time.Hour,
	}
	obs := decision.EvidenceObservation{Ref: "actual-failures", ObservedFrom: started, ObservedTo: now,
		ObservedAt: now, CollectedAt: now, ExpiresAt: now.Add(time.Minute)}
	ref, wire, err := decision.PublishEvidence(scope, obs, raw, key, now)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := New(db, schema, scope, pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Publish(ctx, ref, wire, now); err != nil {
		t.Fatal(err)
	}
	if err := registry.Publish(ctx, ref, wire, now); err != nil {
		t.Fatal("exact replay changed publication")
	}
	got, err := registry.ReadCurrent(ctx, ref, now)
	if err != nil || decision.VerifyEvidencePublication(got, pub, scope, ref, now) != nil {
		t.Fatal("actual observation was not independently verifiable")
	}
	changed, forged, err := decision.PublishEvidence(scope, obs, append(raw, ' '), key, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Publish(ctx, changed, forged, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed immutable evidence replay: %v", err)
	}
	if err := registry.Revoke(ctx, ref, "SOURCE_REVOKED"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ReadCurrent(ctx, ref, now); !errors.Is(err, decision.ErrAuthorityRejected) {
		t.Fatalf("revoked evidence read accepted: %v", err)
	}
	if err := registry.Publish(ctx, ref, wire, now); !errors.Is(err, decision.ErrAuthorityRejected) {
		t.Fatalf("replay reactivated revoked evidence: %v", err)
	}
	for _, stmt := range []string{
		"UPDATE "+schema+".evidence_publications SET proof=proof",
		"DELETE FROM "+schema+".evidence_publications",
		"TRUNCATE "+schema+".evidence_publications CASCADE",
		"DELETE FROM "+schema+".evidence_revocations",
		"TRUNCATE "+schema+".evidence_revocations",
	} {
		if _, err := db.ExecContext(ctx, stmt); err == nil {
			t.Fatal("source immutable publication/revocation guard allowed mutation")
		}
	}
	t.Log("actual HTTP metrics observation, independently signed source registry, immutable replay and durable revocation verified")
}
