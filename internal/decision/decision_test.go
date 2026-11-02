package decision

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type allowAuthority struct{}
func (allowAuthority) VerifyDecisionInputs(context.Context, Principal, Request) error { return nil }

type rejectAuthority struct{}
func (rejectAuthority) VerifyDecisionInputs(context.Context, Principal, Request) error { return errors.New("revoked snapshot") }

func testPrincipal() Principal {
	return Principal{TenantID: "tenant-a", SubjectID: "runtime-svc", AgentID: "agent-1", SessionID: "session-1", CallerID: "agent-runtime"}
}

func validRequest() Request {
	issued := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(2 * time.Hour)
	return Request{
		SchemaVersion: SchemaVersion,
		Identity: Identity{AgentID: "agent-1", SessionID: "session-1", RunID: "run-17"},
		IdempotencyKey: "alert-17",
		Input: Input{Objective: "sre_incident_triage", Service: "payment-api", Signal: "latency"},
		Constraints: Constraints{DeadlineMS: 30000, MaxTokens: 2048, MaxCostMicros: 50000, MaxCandidates: 3},
		Versions: VersionSet{CapabilityCatalogVersion: "catalog-12", StrategyVersion: PolicyVersion, PromptVersion: "none", ModelProfile: "rule-only"},
		ContextSnapshot: SnapshotRef{ID: "context-17", Version: "ctx-v1", SHA256: strings.Repeat("a", 64), Source: "context-store", AttestationRef: "att-context-17", TrustLevel: "attested", IssuedAt: issued, ExpiresAt: expires},
		CapabilitySnapshot: SnapshotRef{ID: "capabilities-12", Version: "catalog-12", SHA256: strings.Repeat("c", 64), Source: "agent-control-plane", AttestationRef: "att-cap-12", TrustLevel: "attested", IssuedAt: issued, ExpiresAt: expires},
		Capabilities: []CapabilityRef{
			{ID: "sre.metrics.read", Version: "1.0.0", ContractSHA256: strings.Repeat("1", 64), InputSchemaRef: "schema://metrics/input", OutputSchemaRef: "schema://metrics/output", EffectClass: "read_only", Idempotency: "safe", TenantScoped: true},
			{ID: "sre.logs.read", Version: "1.2.0", ContractSHA256: strings.Repeat("2", 64), InputSchemaRef: "schema://logs/input", OutputSchemaRef: "schema://logs/output", EffectClass: "read_only", Idempotency: "safe", TenantScoped: true},
			{ID: "sre.changes.read", Version: "2.0.0", ContractSHA256: strings.Repeat("3", 64), InputSchemaRef: "schema://changes/input", OutputSchemaRef: "schema://changes/output", EffectClass: "read_only", Idempotency: "safe", TenantScoped: true},
		},
		Evidence: []EvidenceRef{
			{Ref: "slo-sample-17", Source: "slo-adapter", SourceVersion: "v2", SHA256: strings.Repeat("b", 64), AttestationRef: "att-slo-17", TrustLevel: "attested", ObservedAt: issued, ExpiresAt: expires},
		},
	}
}

func TestReadOnlyPlanAndPinnedCapabilities(t *testing.T) {
	svc := NewService(NewMemoryStore(), allowAuthority{})
	record, created, err := svc.Decide(context.Background(), testPrincipal(), validRequest())
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if record.SchemaVersion != RecordSchemaVersion || record.Status != StatusProposed ||
		len(record.Plan.Steps) != 3 || record.Plan.PlanHash == "" {
		t.Fatalf("bad record: %+v", record)
	}
	for _, step := range record.Plan.Steps {
		if !step.ReadOnly || step.Capability.Version == "" ||
			step.Capability.EffectClass != "read_only" || step.Capability.InputSchemaRef == "" ||
			step.Capability.OutputSchemaRef == "" {
			t.Fatalf("bad step: %+v", step)
		}
	}
	if record.TenantID != "tenant-a" || record.SubjectID != "runtime-svc" ||
		record.AgentID != "agent-1" || record.SessionID != "session-1" ||
		record.RequestSHA256 == "" || record.PolicyVersion != PolicyVersion {
		t.Fatalf("missing provenance: %+v", record)
	}
}

func TestAbstainsWithoutEvidenceOrRequiredCapability(t *testing.T) {
	req := validRequest()
	req.Evidence = nil
	record, _, err := NewService(NewMemoryStore(), allowAuthority{}).Decide(context.Background(), testPrincipal(), req)
	if err != nil || record.Status != StatusAbstained || len(record.Plan.Steps) != 0 {
		t.Fatalf("expected evidence abstention: %+v %v", record, err)
	}
	req = validRequest()
	req.Capabilities = req.Capabilities[:2]
	record, _, err = NewService(NewMemoryStore(), allowAuthority{}).Decide(context.Background(), testPrincipal(), req)
	if err != nil || record.Status != StatusAbstained || len(record.Plan.Steps) != 0 {
		t.Fatalf("expected no partial plan: %+v %v", record, err)
	}
}

func TestTenantScopedIdempotencyAndFullFingerprint(t *testing.T) {
	service := NewService(NewMemoryStore(), allowAuthority{})
	principal := testPrincipal()
	first, _, err := service.Decide(context.Background(), principal, validRequest())
	if err != nil { t.Fatal(err) }
	replay, created, err := service.Decide(context.Background(), principal, validRequest())
	if err != nil || created || first.DecisionID != replay.DecisionID || !first.CreatedAt.Equal(replay.CreatedAt) {
		t.Fatalf("replay failed: created=%v err=%v", created, err)
	}
	changed := validRequest()
	changed.Constraints.MaxTokens++
	if _, _, err := service.Decide(context.Background(), principal, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("budget change must conflict, got %v", err)
	}
	changed = validRequest()
	changed.Capabilities[0].Version = "1.0.1"
	if _, _, err := service.Decide(context.Background(), principal, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("capability version change must conflict, got %v", err)
	}
	otherTenant := principal
	otherTenant.TenantID = "tenant-b"
	if _, created, err := service.Decide(context.Background(), otherTenant, validRequest()); err != nil || !created {
		t.Fatalf("tenant keys collided: %v", err)
	}
}

func TestConcurrentSameKeyIsAtomic(t *testing.T) {
	service := NewService(NewMemoryStore(), allowAuthority{})
	const n = 24
	var wait sync.WaitGroup
	created := make(chan bool, n)
	failures := make(chan error, n)
	for i := 0; i < n; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, isCreated, err := service.Decide(context.Background(), testPrincipal(), validRequest())
			created <- isCreated
			failures <- err
		}()
	}
	wait.Wait()
	close(created)
	close(failures)
	winners := 0
	for value := range created { if value { winners++ } }
	if winners != 1 { t.Fatalf("expected one winner, got %d", winners) }
	for err := range failures { if err != nil { t.Fatal(err) } }
}

func TestIdentityAndAuthorityFailClosed(t *testing.T) {
	principal := testPrincipal()
	principal.AgentID = "other-agent"
	if _, _, err := NewService(NewMemoryStore(), allowAuthority{}).Decide(context.Background(), principal, validRequest()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("identity mismatch: %v", err)
	}
	if _, _, err := NewService(NewMemoryStore(), nil).Decide(context.Background(), testPrincipal(), validRequest()); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("missing verifier: %v", err)
	}
	if _, _, err := NewService(NewMemoryStore(), rejectAuthority{}).Decide(context.Background(), testPrincipal(), validRequest()); !errors.Is(err, ErrAuthorityRejected) {
		t.Fatalf("rejected snapshot must fail closed: %v", err)
	}
}

func TestReplanRequiresRuntimeApprovedRetryableFailure(t *testing.T) {
	req := validRequest()
	req.Replan = &ReplanContext{ParentDecisionID: "dec_" + strings.Repeat("a", 64), Sequence: 1, MaxReplans: 2, Trigger: "STEP_FAILED", PriorDisposition: "RETRYABLE_FAILURE"}
	if _, _, err := NewService(NewMemoryStore(), allowAuthority{}).Decide(context.Background(), testPrincipal(), req); err != nil {
		t.Fatalf("valid bounded replan rejected: %v", err)
	}
	for _, disposition := range []string{"UNKNOWN", "GUARD_DENIED", "FAILED"} {
		bad := validRequest()
		bad.Replan = &ReplanContext{ParentDecisionID: "dec_" + strings.Repeat("a", 64), Sequence: 1, MaxReplans: 2, Trigger: "STEP_FAILED", PriorDisposition: disposition}
		if _, _, err := NewService(NewMemoryStore(), allowAuthority{}).Decide(context.Background(), testPrincipal(), bad); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s must not replan, got %v", disposition, err)
		}
	}
	bad := validRequest()
	bad.Replan = &ReplanContext{ParentDecisionID: "dec_" + strings.Repeat("a", 64), Sequence: 3, MaxReplans: 2, Trigger: "STEP_FAILED", PriorDisposition: "RETRYABLE_FAILURE"}
	if _, _, err := NewService(NewMemoryStore(), allowAuthority{}).Decide(context.Background(), testPrincipal(), bad); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("exhausted replan accepted: %v", err)
	}
}

func TestValidateRejectsMalformedOrUnsafeContract(t *testing.T) {
	cases := []struct {
		name string
		mutate func(*Request)
	}{
		{"bad schema", func(r *Request) { r.SchemaVersion = "decision.v0" }},
		{"bad signal", func(r *Request) { r.Input.Signal = "unknown" }},
		{"bad digest", func(r *Request) { r.ContextSnapshot.SHA256 = "x" }},
		{"missing attestation", func(r *Request) { r.Evidence[0].AttestationRef = "" }},
		{"expired metadata window", func(r *Request) { r.ContextSnapshot.ExpiresAt = r.ContextSnapshot.IssuedAt }},
		{"write capability", func(r *Request) { r.Capabilities[0].EffectClass = "write" }},
		{"unsafe idempotency", func(r *Request) { r.Capabilities[0].Idempotency = "unsafe" }},
		{"not tenant scoped", func(r *Request) { r.Capabilities[0].TenantScoped = false }},
		{"duplicate capability", func(r *Request) { r.Capabilities = append(r.Capabilities, r.Capabilities[0]) }},
		{"catalog version mismatch", func(r *Request) { r.Versions.CapabilityCatalogVersion = "catalog-other" }},
		{"invalid replan lineage", func(r *Request) { r.Replan = &ReplanContext{Sequence: 1, MaxReplans: 1, Trigger: "STEP_FAILED", PriorDisposition: "RETRYABLE_FAILURE"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			tc.mutate(&req)
			if err := req.Validate(); err == nil { t.Fatal("wanted validation error") }
		})
	}
}

func TestGetIsTenantAgentAndSessionScoped(t *testing.T) {
	service := NewService(NewMemoryStore(), allowAuthority{})
	created, _, err := service.Decide(context.Background(), testPrincipal(), validRequest())
	if err != nil { t.Fatal(err) }
	if _, err := service.Get(context.Background(), testPrincipal(), created.DecisionID); err != nil { t.Fatal(err) }
	other := testPrincipal()
	other.TenantID = "tenant-b"
	if _, err := service.Get(context.Background(), other, created.DecisionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read leaked: %v", err)
	}
	other = testPrincipal()
	other.SessionID = "session-other"
	if _, err := service.Get(context.Background(), other, created.DecisionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-session read leaked: %v", err)
	}
}

func TestReturnedRecordCannotMutateStoredRecord(t *testing.T) {
	service := NewService(NewMemoryStore(), allowAuthority{})
	first, _, err := service.Decide(context.Background(), testPrincipal(), validRequest())
	if err != nil { t.Fatal(err) }
	first.Plan.Steps[0].Capability.ID = "sre.write"
	first.Evidence[0].Ref = "tampered"
	second, _, err := service.Decide(context.Background(), testPrincipal(), validRequest())
	if err != nil { t.Fatal(err) }
	if second.Plan.Steps[0].Capability.ID == "sre.write" || second.Evidence[0].Ref == "tampered" {
		t.Fatal("stored record was mutated")
	}
}
