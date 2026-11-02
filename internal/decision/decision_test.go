package decision

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-decision/internal/auth"
)

type allowVerifier struct{ err error }

func (verifier allowVerifier) Verify(context.Context, auth.Principal, Request) error {
	return verifier.err
}

func validRequest() Request {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	snapshot := func(id, source string, marker string) SnapshotRef {
		return SnapshotRef{ID: id, Version: "v1", SHA256: strings.Repeat(marker, 64), Source: source,
			AttestationRef: "attestation:" + id, TrustLevel: "attested", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	}
	capability := func(id string, marker string) CapabilityRef {
		return CapabilityRef{ID: id, Version: "1.0.0", ContractSHA256: strings.Repeat(marker, 64),
			InputSchemaRef: "schema:" + id + ":input:v1", OutputSchemaRef: "schema:" + id + ":output:v1",
			EffectClass: "read_only", Idempotency: "safe", TenantScoped: true}
	}
	return Request{
		SchemaVersion:      RequestSchemaVersion,
		Identity:           Identity{AgentID: "agent-a", SessionID: "session-a", RunID: "run-17"},
		IdempotencyKey:     "alert-17",
		Input:              Input{Objective: "sre_incident_triage", Service: "payment-api", Signal: "latency"},
		Constraints:        Constraints{DeadlineMS: 10000, MaxTokens: 2048, MaxCostMicros: 50000, MaxCandidates: 1},
		Versions:           Versions{CapabilityCatalogVersion: "catalog-v1", StrategyVersion: PolicyVersion, PromptVersion: "none", ModelProfile: "rule-only"},
		ContextSnapshot:    snapshot("context-v1", "context-store", "a"),
		CapabilitySnapshot: snapshot("capability-v1", "agent-control-panel", "b"),
		Capabilities: []CapabilityRef{
			capability("sre.metrics.read", "c"), capability("sre.logs.read", "d"), capability("sre.changes.read", "e"),
		},
		Evidence: []EvidenceRef{{Ref: "slo-sample-17", Source: "slo-monitor", SourceVersion: "slo-v1", SHA256: strings.Repeat("f", 64),
			AttestationRef: "attestation:slo-17", TrustLevel: "attested", ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(10 * time.Minute)}},
	}
}

func testPrincipal(tenant string) auth.Principal {
	return auth.Principal{TenantID: tenant, Subject: "subject-a", AgentID: "agent-a"}
}

func TestProposesVersionPinnedReadOnlyPlan(t *testing.T) {
	service := NewService(NewMemoryStore(), allowVerifier{})
	record, created, err := service.Decide(context.Background(), testPrincipal("tenant-a"), validRequest())
	if err != nil || !created {
		t.Fatalf("decide: created=%t error=%v", created, err)
	}
	if record.Status != StatusProposed || record.Plan == nil || len(record.Plan.Steps) != 3 {
		t.Fatalf("unexpected record: %+v", record)
	}
	if record.SchemaVersion != RecordSchemaVersion || record.Plan.SchemaVersion != PlanSchemaVersion || !digestRe.MatchString(record.Plan.PlanHash) {
		t.Fatalf("missing version or plan provenance: %+v", record)
	}
	for _, step := range record.Plan.Steps {
		if !step.ReadOnly || step.Capability.EffectClass != "read_only" || step.Capability.Idempotency != "safe" || !step.Capability.TenantScoped {
			t.Fatalf("unsafe/unbound plan step: %+v", step)
		}
	}
}

func TestMissingEvidenceOrCapabilityAbstainsWithoutPartialPlan(t *testing.T) {
	service := NewService(NewMemoryStore(), allowVerifier{})
	withoutEvidence := validRequest()
	withoutEvidence.Evidence = []EvidenceRef{}
	record, _, err := service.Decide(context.Background(), testPrincipal("tenant-a"), withoutEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != StatusAbstained || record.Plan != nil || record.Reason != "INSUFFICIENT_EVIDENCE" {
		t.Fatalf("missing evidence must abstain: %+v", record)
	}
	withoutCapability := validRequest()
	withoutCapability.Capabilities = withoutCapability.Capabilities[:2]
	record, _, err = service.Decide(context.Background(), testPrincipal("tenant-b"), withoutCapability)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != StatusAbstained || record.Plan != nil || record.Reason != "REQUIRED_CAPABILITY_MISSING" {
		t.Fatalf("missing capability must abstain without partial plan: %+v", record)
	}
}

func TestRequestCanonicalizationMakesArrayOrderStable(t *testing.T) {
	service := NewService(NewMemoryStore(), allowVerifier{})
	principal := testPrincipal("tenant-a")
	firstRequest := validRequest()
	first, created, err := service.Decide(context.Background(), principal, firstRequest)
	if err != nil || !created {
		t.Fatalf("first decision: created=%t err=%v", created, err)
	}
	secondRequest := validRequest()
	secondRequest.Capabilities[0], secondRequest.Capabilities[2] = secondRequest.Capabilities[2], secondRequest.Capabilities[0]
	secondRequest.Evidence = append([]EvidenceRef{}, secondRequest.Evidence...)
	second, created, err := service.Decide(context.Background(), principal, secondRequest)
	if err != nil || created || second.DecisionID != first.DecisionID {
		t.Fatalf("canonical replay failed: created=%t err=%v", created, err)
	}
}

func TestFailClosedWithoutAuthorityVerifier(t *testing.T) {
	service := NewService(NewMemoryStore(), nil)
	if _, _, err := service.Decide(context.Background(), testPrincipal("tenant-a"), validRequest()); err != ErrAuthorityUnavailable {
		t.Fatalf("expected fail-closed authority error, got %v", err)
	}
}

func TestAuthorityRejectionStopsPlanning(t *testing.T) {
	service := NewService(NewMemoryStore(), allowVerifier{err: ErrNotAuthorized})
	if _, _, err := service.Decide(context.Background(), testPrincipal("tenant-a"), validRequest()); err != ErrNotAuthorized {
		t.Fatalf("expected authorization rejection, got %v", err)
	}
}

func TestIdempotencyAndTenantScopedRead(t *testing.T) {
	service := NewService(NewMemoryStore(), allowVerifier{})
	principal := testPrincipal("tenant-a")
	first, _, err := service.Decide(context.Background(), principal, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	replay, created, err := service.Decide(context.Background(), principal, validRequest())
	if err != nil || created || first.DecisionID != replay.DecisionID || !first.CreatedAt.Equal(replay.CreatedAt) {
		t.Fatalf("idempotent replay failed: %+v %+v, %v", first, replay, err)
	}
	changed := validRequest()
	changed.Input.Signal = "errors"
	if _, _, err = service.Decide(context.Background(), principal, changed); err != ErrConflict {
		t.Fatalf("expected conflict got %v", err)
	}
	otherTenant := testPrincipal("tenant-b")
	otherRecord, wasCreated, err := service.Decide(context.Background(), otherTenant, changed)
	if err != nil || !wasCreated || otherRecord.DecisionID == first.DecisionID {
		t.Fatalf("cross-tenant idempotency collision: %v", err)
	}
	if _, err := service.Get(context.Background(), otherTenant, "agent-a", first.DecisionID); err != ErrNotFound {
		t.Fatalf("cross-tenant read leaked record: %v", err)
	}
	if got, err := service.Get(context.Background(), principal, "agent-a", first.DecisionID); err != nil || got.DecisionID != first.DecisionID {
		t.Fatalf("tenant-scoped read failed: %+v %v", got, err)
	}
	if _, err := service.Get(context.Background(), principal, "agent-b", first.DecisionID); err != ErrNotFound {
		t.Fatalf("cross-agent read must be hidden as not found, got %v", err)
	}
	if _, _, err := service.Decide(context.Background(), auth.Principal{TenantID: "tenant-a", Subject: "subject-a", AgentID: "agent-b"}, validRequest()); err != ErrNotAuthorized {
		t.Fatalf("agent-scoped principal mismatch must fail closed, got %v", err)
	}
}

func TestConcurrentSameKeyIsAtomic(t *testing.T) {
	service := NewService(NewMemoryStore(), allowVerifier{})
	const count = 64
	var wait sync.WaitGroup
	created := make(chan bool, count)
	failures := make(chan error, count)
	for i := 0; i < count; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, wasCreated, err := service.Decide(context.Background(), testPrincipal("tenant-a"), validRequest())
			created <- wasCreated
			failures <- err
		}()
	}
	wait.Wait()
	close(created)
	close(failures)
	winners := 0
	for wasCreated := range created {
		if wasCreated {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("expected one winner, got %d", winners)
	}
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestValidationRejectsUnboundedOrUnsafeContracts(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Request)
	}{
		{"wrong schema", func(r *Request) { r.SchemaVersion = "decision.v2" }},
		{"unknown objective", func(r *Request) { r.Input.Objective = "execute_shell" }},
		{"deadline too large", func(r *Request) { r.Constraints.DeadlineMS = 120001 }},
		{"bad snapshot digest", func(r *Request) { r.ContextSnapshot.SHA256 = "x" }},
		{"write capability", func(r *Request) { r.Capabilities[0].EffectClass = "write" }},
		{"non-idempotent capability", func(r *Request) { r.Capabilities[0].Idempotency = "unsafe" }},
		{"bad evidence trust", func(r *Request) { r.Evidence[0].TrustLevel = "unverified" }},
		{"invalid replan disposition", func(r *Request) {
			r.Replan = &Replan{ParentDecisionID: "dec_" + strings.Repeat("a", 64), Sequence: 1, MaxReplans: 1, Trigger: "STEP_FAILED", PriorDisposition: "UNKNOWN"}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest()
			test.mutate(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("wanted validation error")
			}
		})
	}
}

func TestReturnedRecordCannotMutateStoredRecord(t *testing.T) {
	service := NewService(NewMemoryStore(), allowVerifier{})
	principal := testPrincipal("tenant-a")
	first, _, err := service.Decide(context.Background(), principal, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	first.Plan.Steps[0].Capability.ID = "sre.write"
	first.Evidence[0].Ref = "tampered"
	replay, _, err := service.Decide(context.Background(), principal, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if replay.Plan.Steps[0].Capability.ID == "sre.write" || replay.Evidence[0].Ref == "tampered" {
		t.Fatal("stored record was mutated")
	}
}
