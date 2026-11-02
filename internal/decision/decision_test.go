package decision

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func validRequest() Request {
	return Request{
		TenantID: "tenant-a", IdempotencyKey: "alert-17", RunID: "run-17", Service: "payment-api", Signal: "latency",
		Snapshot: SnapshotRef{ID: "snapshot-1", SHA256: strings.Repeat("a", 64)}, Capability: SnapshotRef{ID: "capabilities-v1", SHA256: strings.Repeat("c", 64)},
		Evidence: []EvidenceRef{{Ref: "slo-sample-17", SHA256: strings.Repeat("b", 64)}},
	}
}

func TestProposesReadOnlySREPlan(t *testing.T) {
	svc := NewService(NewMemoryStore())
	rec, created, err := svc.Decide(context.Background(), validRequest())
	if err != nil || !created {
		t.Fatalf("decide: created=%t error=%v", created, err)
	}
	if rec.Status != StatusProposed || len(rec.Plan) != 3 {
		t.Fatalf("unexpected record: %+v", rec)
	}
	for _, step := range rec.Plan {
		if !step.ReadOnly || step.Capability == "" {
			t.Fatalf("unsafe/unbound plan: %+v", step)
		}
	}
	if rec.TenantID != "tenant-a" || rec.RequestSHA256 == "" || rec.PolicyVersion == "" {
		t.Fatalf("missing provenance: %+v", rec)
	}
}

func TestMissingEvidenceAbstains(t *testing.T) {
	svc := NewService(NewMemoryStore())
	req := validRequest()
	req.Evidence = nil
	rec, _, err := svc.Decide(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != StatusAbstained || len(rec.Plan) != 0 || rec.Reason != "INSUFFICIENT_EVIDENCE" {
		t.Fatalf("should abstain: %+v", rec)
	}
}

func TestIdempotencyAndPayloadConflict(t *testing.T) {
	svc := NewService(NewMemoryStore())
	a, _, err := svc.Decide(context.Background(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	b, created, err := svc.Decide(context.Background(), validRequest())
	if err != nil || created || a.DecisionID != b.DecisionID || !a.CreatedAt.Equal(b.CreatedAt) {
		t.Fatalf("idempotent replay failed: %+v %+v, %v", a, b, err)
	}
	changed := validRequest()
	changed.Signal = "errors"
	if _, _, err = svc.Decide(context.Background(), changed); err != ErrConflict {
		t.Fatalf("expected conflict got %v", err)
	}
	changed.TenantID = "tenant-b"
	if _, created, err = svc.Decide(context.Background(), changed); err != nil || !created {
		t.Fatalf("cross-tenant key collision: %v", err)
	}
}

func TestConcurrentSameKeyIsAtomic(t *testing.T) {
	svc := NewService(NewMemoryStore())
	const n = 24
	var wg sync.WaitGroup
	successes := make(chan bool, n)
	failures := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, created, err := svc.Decide(context.Background(), validRequest())
			successes <- created
			failures <- err
		}()
	}
	wg.Wait()
	close(successes)
	close(failures)
	count := 0
	for b := range successes {
		if b {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected one winner, got %d", count)
	}
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestValidateRejectsUntrustedReferences(t *testing.T) {
	svc := NewService(NewMemoryStore())
	cases := []struct {
		name   string
		mutate func(*Request)
	}{
		{"invalid tenant", func(r *Request) { r.TenantID = "../other" }},
		{"no key", func(r *Request) { r.IdempotencyKey = "" }},
		{"bad digest", func(r *Request) { r.Snapshot.SHA256 = "x" }},
		{"bad evidence digest", func(r *Request) { r.Evidence[0].SHA256 = "abcd" }},
		{"unknown signal", func(r *Request) { r.Signal = "delete-all" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validRequest()
			tc.mutate(&r)
			if _, _, err := svc.Decide(context.Background(), r); err == nil {
				t.Fatal("wanted validation error")
			}
		})
	}
}

func TestReturnedRecordCannotMutateStoredRecord(t *testing.T) {
	svc := NewService(NewMemoryStore())
	a, _, err := svc.Decide(context.Background(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	a.Plan[0].Capability = "sre.write"
	a.Evidence[0].Ref = "tampered"
	b, _, err := svc.Decide(context.Background(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if b.Plan[0].Capability == "sre.write" || b.Evidence[0].Ref == "tampered" {
		t.Fatal("stored record was mutated")
	}
}
