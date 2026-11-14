package decision

import (
	"context"
	"database/sql"
	"strings"
	"time"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresStoreRequiresDatabase(t *testing.T) {
	store := NewPostgresStore(nil)
	if _, _, err := store.SaveOrGet(context.Background(), Record{}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("SaveOrGet: expected ErrStoreUnavailable, got %v", err)
	}
	if _, err := store.GetByInvocation(context.Background(), "tenant-a", "invocation-a"); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("GetByInvocation: expected ErrStoreUnavailable, got %v", err)
	}
	if _, err := store.GetByDecisionID(context.Background(), "tenant-a", "agent-a", "session-a", "decision-a"); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("GetByDecisionID: expected ErrStoreUnavailable, got %v", err)
	}
	if _, err := store.ListByRun(context.Background(), "tenant-a", "agent-a", "session-a", "run-a", nil, 10); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("ListByRun: expected ErrStoreUnavailable, got %v", err)
	}
}

func TestPostgresStoreRecordsAreAppendOnly(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := NewPostgresStore(db)
	record := Record{
		DecisionID: "dec_" + strings.Repeat("d", 64),
		TenantID: fmt.Sprintf("append-only-%d", time.Now().UnixNano()),
		AgentID: "agent-1",
		SessionID: "session-1",
		RunID: "run-17",
		InvocationID: "append-only-key",
		RequestSHA256: strings.Repeat("e", 64),
		CreatedAt: time.Now().UTC(),
		Status: StatusProposed,
		ReasonCodes: []string{},
		Evidence: []EvidenceRef{},
		Plan: PlanCandidate{PlanID: "plan_append_only", SchemaVersion: SchemaVersion, Steps: []PlanStep{}},
	}
	if _, created, err := store.SaveOrGet(ctx, record); err != nil || !created {
		t.Fatalf("save append-only record: created=%v err=%v", created, err)
	}

	// The normalized columns used for idempotency and lookups must remain
	// consistent with the immutable JSONB DecisionRecord.
	mismatchCases := []string{"tenant", "invocation", "decision", "request digest"}
	for i, field := range mismatchCases {
		t.Run("json_identity_"+strings.ReplaceAll(field, " ", "_"), func(t *testing.T) {
			rowTenant := record.TenantID
			rowInvocation := fmt.Sprintf("mismatch-%d", i)
			rowDecision := "dec_" + strings.Repeat(string(rune('1'+i)), 64)
			rowDigest := record.RequestSHA256
			jsonTenant, jsonInvocation := rowTenant, rowInvocation
			jsonDecision, jsonDigest := rowDecision, rowDigest
			switch field {
			case "tenant":
				jsonTenant = "other-tenant"
			case "invocation":
				jsonInvocation = "other-invocation"
			case "decision":
				jsonDecision = "dec_" + strings.Repeat("f", 64)
			case "request digest":
				jsonDigest = strings.Repeat("f", 64)
			}
			_, err := db.ExecContext(ctx, `INSERT INTO decision_records (
				tenant_id, invocation_id, decision_id, request_sha256, record, created_at
			) VALUES ($1, $2, $3, $4,
				jsonb_build_object(
					'tenant_id', $5::text, 'invocation_id', $6::text, 'decision_id', $7::text, 'request_sha256', $8::text
				), now())`,
				rowTenant, rowInvocation, rowDecision, rowDigest,
				jsonTenant, jsonInvocation, jsonDecision, jsonDigest)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "decision_records_json_identity_ck" {
				t.Fatalf("mismatched %s must fail the JSON identity CHECK constraint, got %v", field, err)
			}
		})
	}

	for name, statement := range map[string]string{
		"update": "UPDATE decision_records SET record = '{}'::jsonb WHERE tenant_id = $1 AND decision_id = $2",
		"delete": "DELETE FROM decision_records WHERE tenant_id = $1 AND decision_id = $2",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := db.ExecContext(ctx, statement, record.TenantID, record.DecisionID); err == nil {
				t.Fatalf("%s must be rejected by the append-only trigger", name)
			}
		})
	}
}

func TestPostgresServiceReplaysCompletedInvocationAfterVerifierUnavailable(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	store := NewPostgresStore(db)
	principal := testPrincipal()
	request := validRequest()
	firstService := NewService(store, allowAuthority{})
	created, wasCreated, err := firstService.Decide(ctx, principal, request)
	if err != nil || !wasCreated {
		t.Fatalf("initial decision: created=%t err=%v", wasCreated, err)
	}

	// A fresh service instance models a process restart. A completed invocation
	// must replay its immutable result even when the external verifier is down.
	restartedService := NewService(NewPostgresStore(db), nil)
	replayed, wasCreated, err := restartedService.Decide(ctx, principal, request)
	if err != nil || wasCreated {
		t.Fatalf("restart replay: created=%t err=%v", wasCreated, err)
	}
	if replayed.DecisionID != created.DecisionID ||
		replayed.RequestSHA256 != created.RequestSHA256 ||
		replayed.Plan.PlanHash != created.Plan.PlanHash {
		t.Fatalf("restart replay changed immutable result: first=%+v replay=%+v", created, replayed)
	}

	changed := request
	changed.Constraints.MaxTokens++
	if _, _, err := restartedService.Decide(ctx, principal, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed request under existing invocation must conflict before verifier lookup, got %v", err)
	}
}

func TestPostgresStoreIdempotencyAndTenantIsolation(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Bound database connections independently of concurrent callers.
	db.SetMaxOpenConns(16)
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	store := NewPostgresStore(db)
	record := Record{
		DecisionID: "dec_"+strings.Repeat("a",64),
		AgentID: "agent-1",
		SessionID: "session-1",
		RunID: "run-17",
		CreatedAt: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC),
		TenantID: fmt.Sprintf("store-integration-%d", time.Now().UnixNano()),
		InvocationID: "same-key",
		RequestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Status: StatusProposed,
		ReasonCodes: []string{},
		Evidence: []EvidenceRef{},
		Plan: PlanCandidate{PlanID: "plan_integration_001", SchemaVersion: SchemaVersion, Steps: []PlanStep{}},
	}
	first, created, err := store.SaveOrGet(ctx, record)
	if err != nil || !created {
		t.Fatalf("first save: created=%v err=%v", created, err)
	}
	stored, err := store.GetByInvocation(ctx, record.TenantID, record.InvocationID)
	if err != nil || stored.DecisionID != record.DecisionID || stored.RequestSHA256 != record.RequestSHA256 {
		t.Fatalf("lookup completed invocation: record=%+v err=%v", stored, err)
	}
	if _, err := store.GetByInvocation(ctx, record.TenantID, "missing-invocation"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing invocation should return ErrNotFound, got %v", err)
	}
	freshStore := NewPostgresStore(db)
	second, created, err := freshStore.SaveOrGet(ctx, record)
	if err != nil || created || second.DecisionID != first.DecisionID {
		t.Fatalf("replay: created=%v err=%v record=%+v", created, err, second)
	}
	changed := record
	changed.RequestSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, _, err := store.SaveOrGet(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}

	loaded, err := store.GetByDecisionID(ctx, record.TenantID, record.AgentID, record.SessionID, record.DecisionID)
	if err != nil || loaded.DecisionID != record.DecisionID {
		t.Fatalf("get persisted decision: record=%+v err=%v", loaded, err)
	}
	ledger, err := store.ListByRun(ctx, record.TenantID, record.AgentID, record.SessionID, record.RunID, nil, 10)
	if err != nil || len(ledger) != 1 || ledger[0].DecisionID != record.DecisionID {
		t.Fatalf("list persisted run decisions: records=%+v err=%v", ledger, err)
	}
	if _, err := store.GetByDecisionID(ctx, record.TenantID, record.AgentID, "other-session", record.DecisionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-session lookup must be hidden, got %v", err)
	}

	otherTenant := record
	otherTenant.TenantID = record.TenantID + "-other"
	otherTenant.DecisionID = "dec_"+strings.Repeat("c",64)
	if _, created, err := store.SaveOrGet(ctx, otherTenant); err != nil || !created {
		t.Fatalf("tenant isolation: created=%v err=%v", created, err)
	}

	// Issue #4 requires 50+ concurrently arriving invocations. Exercise 64
	// callers across a bounded pool, with a single commit and one Outbox event.
	concurrent := record
	concurrent.InvocationID = "concurrent-key"
	concurrent.DecisionID = "dec_" + strings.Repeat("b", 64)
	concurrent.CreatedAt = record.CreatedAt
	const workers = 64
	start := make(chan struct{})
	type result struct {
		record Record
		created bool
		err error
	}
	results := make(chan result, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec, created, err := store.SaveOrGet(ctx, concurrent)
			results <- result{record: rec, created: created, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	winners, replays := 0, 0
	for outcome := range results {
		if outcome.err != nil {
			t.Fatalf("contended same-fingerprint invocation failed: %v", outcome.err)
		}
		if outcome.record.DecisionID != concurrent.DecisionID ||
			outcome.record.RequestSHA256 != concurrent.RequestSHA256 {
			t.Fatalf("contended invocation returned wrong record: %+v", outcome.record)
		}
		if outcome.created {
			winners++
		} else {
			replays++
		}
	}
	if winners != 1 || replays != workers-1 {
		t.Fatalf("64 concurrent identical requests: created=%d replayed=%d, want 1 and 63", winners, replays)
	}
	var decisionRows, eventRows int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM decision_records WHERE tenant_id=$1 AND invocation_id=$2",
		concurrent.TenantID, concurrent.InvocationID).Scan(&decisionRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM outbox_events WHERE tenant_id=$1 AND aggregate_id=$2",
		concurrent.TenantID, concurrent.DecisionID).Scan(&eventRows); err != nil {
		t.Fatal(err)
	}
	if decisionRows != 1 || eventRows != 1 {
		t.Fatalf("contended invocation must atomically persist one record and one event: records=%d events=%d", decisionRows, eventRows)
	}

	// A changed fingerprint on the completed invocation is always a conflict;
	// contention must not create or replace an immutable record or Outbox event.
	changedConcurrent := concurrent
	changedConcurrent.RequestSHA256 = strings.Repeat("f", 64)
	conflictStart := make(chan struct{})
	conflictResults := make(chan result, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-conflictStart
			rec, created, err := store.SaveOrGet(ctx, changedConcurrent)
			conflictResults <- result{record: rec, created: created, err: err}
		}()
	}
	close(conflictStart)
	wg.Wait()
	close(conflictResults)
	conflicts := 0
	for outcome := range conflictResults {
		if !errors.Is(outcome.err, ErrConflict) || outcome.created {
			t.Fatalf("contended changed fingerprint must conflict: %+v", outcome)
		}
		conflicts++
	}
	if conflicts != workers {
		t.Fatalf("concurrent changed-fingerprint conflicts=%d, want %d", conflicts, workers)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM outbox_events WHERE tenant_id=$1 AND aggregate_id=$2",
		concurrent.TenantID, concurrent.DecisionID).Scan(&eventRows); err != nil || eventRows != 1 {
		t.Fatalf("conflicting request created a duplicate Outbox event: events=%d err=%v", eventRows, err)
	}

	firstPage, err := store.ListByRun(ctx, record.TenantID, record.AgentID, record.SessionID, record.RunID, nil, 1)
	if err != nil || len(firstPage) != 1 || firstPage[0].DecisionID != concurrent.DecisionID {
		t.Fatalf("first same-timestamp ledger page: records=%+v err=%v", firstPage, err)
	}
	secondPage, err := store.ListByRun(ctx, record.TenantID, record.AgentID, record.SessionID, record.RunID,
		&DecisionCursor{CreatedAt: firstPage[0].CreatedAt, DecisionID: firstPage[0].DecisionID}, 1)
	if err != nil || len(secondPage) != 1 || secondPage[0].DecisionID != record.DecisionID {
		t.Fatalf("second same-timestamp ledger page: records=%+v err=%v", secondPage, err)
	}

}
