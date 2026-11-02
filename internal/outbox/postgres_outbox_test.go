package outbox_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
	"github.com/avaargsh/agent-decision/internal/outbox"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresOutboxClaimLeaseRetryAndAck(t *testing.T) {
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
	if err := decision.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := decision.Migrate(ctx, db); err != nil {
		t.Fatalf("migration re-entry should be safe: %v", err)
	}
	store := decision.NewPostgresStore(db)

	record := decision.Record{
		DecisionID: "dec_" + strings.Repeat("a", 64),
		TenantID: "outbox-test-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		AgentID: "agent-1",
		SessionID: "session-1",
		RunID: "run-1",
		InvocationID: "invocation-1",
		RequestSHA256: strings.Repeat("b", 64),
		CreatedAt: time.Now().UTC(),
		Status: decision.StatusProposed,
		ReasonCodes: []string{},
		Evidence: []decision.EvidenceRef{},
		Plan: decision.PlanCandidate{PlanID: "plan-1", SchemaVersion: decision.SchemaVersion, Steps: []decision.PlanStep{}},
	}
	if _, created, err := store.SaveOrGet(ctx, record); err != nil || !created {
		t.Fatalf("SaveOrGet: created=%v err=%v", created, err)
	}
	if _, created, err := store.SaveOrGet(ctx, record); err != nil || created {
		t.Fatalf("idempotent SaveOrGet: created=%v err=%v", created, err)
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM outbox_events WHERE tenant_id = $1 AND aggregate_id = $2",
		record.TenantID, record.DecisionID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("outbox event count=%d err=%v, want exactly one", count, err)
	}

	claimed, err := store.Claim(ctx, "worker-a", 10, 25*time.Millisecond)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("first claim: events=%d err=%v", len(claimed), err)
	}
	if claimed[0].Type != "decision.recorded.v1" || claimed[0].AggregateID != record.DecisionID ||
		claimed[0].SchemaVersion != 1 || claimed[0].Attempts != 1 {
		t.Fatalf("unexpected event envelope: %+v", claimed[0])
	}
	unavailable, err := store.Claim(ctx, "worker-b", 10, time.Second)
	if err != nil || len(unavailable) != 0 {
		t.Fatalf("leased event claimed by another worker: events=%d err=%v", len(unavailable), err)
	}

	time.Sleep(40 * time.Millisecond)
	reclaimed, err := store.Claim(ctx, "worker-b", 10, time.Second)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].ID != claimed[0].ID || reclaimed[0].Attempts != 2 {
		t.Fatalf("expired lease reclaim: events=%+v err=%v", reclaimed, err)
	}
	if err := store.Ack(ctx, reclaimed[0].ID, "worker-a"); !errors.Is(err, outbox.ErrLeaseLost) {
		t.Fatalf("stale owner ack=%v, want ErrLeaseLost", err)
	}
	if err := store.Retry(ctx, reclaimed[0].ID, "worker-a", 0, "stale owner"); !errors.Is(err, outbox.ErrLeaseLost) {
		t.Fatalf("stale owner retry=%v, want ErrLeaseLost", err)
	}
	if err := store.Retry(ctx, reclaimed[0].ID, "worker-b", 0, "publisher timeout"); err != nil {
		t.Fatalf("retry event: %v", err)
	}
	retried, err := store.Claim(ctx, "worker-c", 10, time.Second)
	if err != nil || len(retried) != 1 || retried[0].Attempts != 3 {
		t.Fatalf("claim retried event: events=%+v err=%v", retried, err)
	}
	if err := store.Ack(ctx, retried[0].ID, "worker-c"); err != nil {
		t.Fatalf("ack event: %v", err)
	}
	if err := store.Ack(ctx, retried[0].ID, "worker-c"); !errors.Is(err, outbox.ErrLeaseLost) {
		t.Fatalf("duplicate ack=%v, want ErrLeaseLost", err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE outbox_events SET payload = '{}'::jsonb WHERE event_id = $1", retried[0].ID); err == nil {
		t.Fatal("outbox immutable payload update unexpectedly succeeded")
	}
}

func TestDispatchOnceRetriesPublishFailure(t *testing.T) {
	store := &fakeStore{events: []outbox.Event{{ID: "event-1"}}}
	publisher := fakePublisher{err: errors.New("broker unavailable")}
	published, err := outbox.DispatchOnce(context.Background(), store, publisher, "worker-a", 1, time.Minute, 5*time.Second)
	if published != 0 || !errors.Is(err, publisher.err) || store.retries != 1 || store.acks != 0 {
		t.Fatalf("DispatchOnce: published=%d err=%v retries=%d acks=%d", published, err, store.retries, store.acks)
	}
}

type fakeStore struct {
	events  []outbox.Event
	acks    int
	retries int
}

func (s *fakeStore) Claim(context.Context, string, int, time.Duration) ([]outbox.Event, error) {
	return s.events, nil
}
func (s *fakeStore) Ack(context.Context, string, string) error {
	s.acks++
	return nil
}
func (s *fakeStore) Retry(context.Context, string, string, time.Duration, string) error {
	s.retries++
	return nil
}

type fakePublisher struct{ err error }

func (p fakePublisher) Publish(context.Context, outbox.Event) error { return p.err }
