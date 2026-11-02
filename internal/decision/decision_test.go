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

func testPrincipal() Principal {
	return Principal{TenantID:"tenant-a", SubjectID:"runtime-svc", AgentID:"agent-1", SessionID:"session-1", CallerID:"agent-runtime"}
}

func validRequest() Request {
	issued := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(2*time.Hour)
	return Request{
		SchemaVersion: SchemaVersion,
		Identity: Identity{AgentID:"agent-1", SessionID:"session-1", RunID:"run-17"},
		InvocationID:"alert-17",
		Input: Input{Objective:"sre_incident_triage", Service:"payment-api", Signal:"latency"},
		Constraints: Constraints{DeadlineMS:30000, MaxTokens:2048, MaxCostMicros:50000, MaxCandidates:3},
		Versions: VersionSet{CapabilityCatalogVersion:"catalog-12", StrategyVersion:PolicyVersion, PromptVersion:"none", ModelProfile:"rule-only"},
		ContextSnapshot: SnapshotRef{ID:"context-17", Version:"ctx-v1", SHA256:strings.Repeat("a",64), Source:"context-store", AttestationRef:"att-context-17", TrustLevel:"attested", IssuedAt:issued, ExpiresAt:expires},
		CapabilitySnapshot: SnapshotRef{ID:"capabilities-12", Version:"catalog-12", SHA256:strings.Repeat("c",64), Source:"agent-control-plane", AttestationRef:"att-cap-12", TrustLevel:"attested", IssuedAt:issued, ExpiresAt:expires},
		Capabilities: []CapabilityRef{
			{ID:"sre.metrics.read", Version:"1.0.0", ContractSHA256:strings.Repeat("1",64), InputSchemaRef:"schema://metrics/input", OutputSchemaRef:"schema://metrics/output", EffectClass:"read_only", Idempotency:"safe", TenantScoped:true},
			{ID:"sre.logs.read", Version:"1.2.0", ContractSHA256:strings.Repeat("2",64), InputSchemaRef:"schema://logs/input", OutputSchemaRef:"schema://logs/output", EffectClass:"read_only", Idempotency:"safe", TenantScoped:true},
			{ID:"sre.changes.read", Version:"2.0.0", ContractSHA256:strings.Repeat("3",64), InputSchemaRef:"schema://changes/input", OutputSchemaRef:"schema://changes/output", EffectClass:"read_only", Idempotency:"safe", TenantScoped:true},
		},
		Evidence: []EvidenceRef{
			{Ref:"slo-sample-17", EvidenceType:"slo", SchemaVersion:"1.0.0", TenantID:"tenant-a", AgentID:"agent-1", RunID:"run-17", Service:"payment-api", ResourceRef:"resource://payment-api/slo", SourceID:"slo-adapter-prod", Source:"slo-adapter", SourceVersion:"v2", SHA256:strings.Repeat("b",64), AttestationRef:"att-slo-17", TrustLevel:"attested", ObservedFrom:issued.Add(-5*time.Minute), ObservedTo:issued, ObservedAt:issued, CollectedAt:issued.Add(time.Minute), ExpiresAt:expires, RevocationState:"active"},
		},
	}
}

func TestReadOnlyPlanAndPinnedCapabilities(t *testing.T) {
	svc := NewService(NewMemoryStore(), allowAuthority{})
	rec, created, err := svc.Decide(context.Background(), testPrincipal(), validRequest())
	if err != nil || !created { t.Fatalf("created=%v err=%v", created, err) }
	if rec.Status != StatusProposed || len(rec.Plan.Steps) != 3 || rec.Plan.PlanHash == "" { t.Fatalf("bad record: %+v", rec) }
	for _, step := range rec.Plan.Steps {
		if !step.ReadOnly || step.Capability.Version == "" || step.Capability.EffectClass != "read_only" { t.Fatalf("bad step: %+v", step) }
	}
	if rec.TenantID != "tenant-a" || rec.RequestSHA256 == "" { t.Fatalf("missing provenance: %+v", rec) }
}

func TestAbstainsWithoutEvidenceOrRequiredCapability(t *testing.T) {
	req := validRequest()
	req.Evidence = []EvidenceRef{}
	rec, _, err := NewService(NewMemoryStore(), allowAuthority{}).Decide(context.Background(), testPrincipal(), req)
	if err != nil || rec.Status != StatusAbstained || len(rec.Plan.Steps) != 0 { t.Fatalf("expected abstention: %+v %v", rec, err) }
	req = validRequest()
	req.Capabilities = req.Capabilities[:2]
	rec, _, err = NewService(NewMemoryStore(), allowAuthority{}).Decide(context.Background(), testPrincipal(), req)
	if err != nil || rec.Status != StatusAbstained || len(rec.Plan.Steps) != 0 { t.Fatalf("expected no partial plan: %+v %v", rec, err) }
}

func TestTenantScopedIdempotencyAndFullFingerprint(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, allowAuthority{})
	p := testPrincipal()
	a, _, err := svc.Decide(context.Background(), p, validRequest())
	if err != nil { t.Fatal(err) }
	b, created, err := svc.Decide(context.Background(), p, validRequest())
	if err != nil || created || a.DecisionID != b.DecisionID { t.Fatalf("replay failed: %v", err) }

	// Exact retries of a completed invocation must return the durable result
	// even when the live evidence verifier is unavailable on the retry.
	replayService := NewService(store, nil)
	replayed, created, err := replayService.Decide(context.Background(), p, validRequest())
	if err != nil || created || replayed.DecisionID != a.DecisionID || replayed.Plan.PlanHash != a.Plan.PlanHash {
		t.Fatalf("completed invocation replay must not depend on a second authority lookup: created=%t err=%v", created, err)
	}

	changed := validRequest()
	changed.Constraints.MaxTokens++
	if _, _, err = svc.Decide(context.Background(), p, changed); err != ErrConflict { t.Fatalf("expected conflict, got %v", err) }

	// Payload changes that also violate the request schema must still produce
	// the invocation conflict, rather than masking prior use as a 400.
	invalidReuse := validRequest()
	invalidReuse.Evidence[0].RevocationState = "revoked"
	if _, _, err = svc.Decide(context.Background(), p, invalidReuse); err != ErrConflict {
		t.Fatalf("invalid payload under a completed invocation must conflict, got %v", err)
	}

	// A malformed payload under a brand-new invocation is still validated as
	// a request error and cannot be persisted.
	newInvalid := validRequest()
	newInvalid.InvocationID = "new-invalid"
	newInvalid.Evidence[0].RevocationState = "revoked"
	if _, _, err = svc.Decide(context.Background(), p, newInvalid); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid new invocation must remain a request error, got %v", err)
	}
	p.TenantID = "tenant-b"
	tenantRequest := validRequest()
	tenantRequest.Evidence[0].TenantID = "tenant-b"
	if _, created, err = svc.Decide(context.Background(), p, tenantRequest); err != nil || !created {
		t.Fatalf("tenant-scoped evidence must bind to the second tenant: created=%t err=%v", created, err)
	}
}

func TestConcurrentSameKeyIsAtomic(t *testing.T) {
	svc := NewService(NewMemoryStore(), allowAuthority{})
	const n = 16
	var wg sync.WaitGroup
	results := make(chan bool, n)
	errs := make(chan error, n)
	for i:=0;i<n;i++ { wg.Add(1); go func(){ defer wg.Done(); _, created, err := svc.Decide(context.Background(), testPrincipal(), validRequest()); results<-created; errs<-err }() }
	wg.Wait(); close(results); close(errs)
	winners:=0
	for created:=range results { if created { winners++ } }
	if winners!=1 { t.Fatalf("expected one winner, got %d", winners) }
	for err:=range errs { if err!=nil { t.Fatal(err) } }
}

func TestIdentityAuthorityAndReplanFailClosed(t *testing.T) {
	p:=testPrincipal()
	p.AgentID="different-agent"
	if _,_,err:=NewService(NewMemoryStore(),allowAuthority{}).Decide(context.Background(),p,validRequest()); err!=ErrUnauthorized { t.Fatalf("identity mismatch: %v",err) }
	if _,_,err:=NewService(NewMemoryStore(),nil).Decide(context.Background(),testPrincipal(),validRequest()); err!=ErrAuthorityUnavailable { t.Fatalf("missing verifier: %v",err) }
	for _, disposition:=range []string{"UNKNOWN","GUARD_DENIED"} {
		req:=validRequest()
		req.Replan=&ReplanContext{ParentDecisionID:"dec_"+strings.Repeat("a",64),Sequence:1,MaxReplans:2,Trigger:"STEP_FAILED",PriorDisposition:disposition}
		if _,_,err:=NewService(NewMemoryStore(),allowAuthority{}).Decide(context.Background(),testPrincipal(),req); !errors.Is(err, ErrInvalidRequest) { t.Errorf("%s should be blocked: %v",disposition,err) }
	}
}

type unsafeTestStrategy struct{}

func (unsafeTestStrategy) Version() string { return PolicyVersion }
func (unsafeTestStrategy) Plan(Request, string) StrategyResult {
	return StrategyResult{
		Status: StatusProposed,
		Steps: []PlanStep{{
			StepID: "step_mutation",
			Capability: CapabilityRef{
				ID: "sre.deploy.write",
				EffectClass: "write",
				Idempotency: "unsafe",
				TenantScoped: true,
			},
			ReadOnly: false,
		}},
	}
}

func TestStrategyOutputIsDeterministicAndReadOnly(t *testing.T) {
	req := validRequest()
	strategy := SREReadOnlyStrategy{}
	first := strategy.Plan(req, "dec_"+strings.Repeat("a", 64))
	second := strategy.Plan(req, "dec_"+strings.Repeat("a", 64))
	if digest(first) != digest(second) {
		t.Fatal("same request and decision identity must produce the same strategy output")
	}
	if len(first.Steps) != 3 {
		t.Fatalf("expected three investigation steps, got %d", len(first.Steps))
	}
	for _, step := range first.Steps {
		if !step.ReadOnly || step.Capability.EffectClass != "read_only" {
			t.Fatalf("strategy emitted unsafe step: %+v", step)
		}
	}
}

func TestCoreRejectsUnsafeStrategyOutput(t *testing.T) {
	svc := NewServiceWithStrategy(NewMemoryStore(), allowAuthority{}, unsafeTestStrategy{})
	_, _, err := svc.Decide(context.Background(), testPrincipal(), validRequest())
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected unsafe strategy output to be rejected, got %v", err)
	}
}

type strategyFunc func(Request, string) StrategyResult

func (f strategyFunc) Version() string { return PolicyVersion }
func (f strategyFunc) Plan(req Request, decisionID string) StrategyResult {
	return f(req, decisionID)
}

func TestCoreRejectsSemanticallyInvalidStrategyOutput(t *testing.T) {
	cases := []struct {
		name string
		plan strategyFunc
	}{
		{
			name: "unknown step kind",
			plan: func(req Request, id string) StrategyResult {
				result := SREReadOnlyStrategy{}.Plan(req, id)
				result.Steps[0].Kind = "SHELL_EXEC"
				return result
			},
		},
		{
			name: "duplicate capability",
			plan: func(req Request, id string) StrategyResult {
				result := SREReadOnlyStrategy{}.Plan(req, id)
				result.Steps[1].Capability = result.Steps[0].Capability
				result.Steps[1].Kind = result.Steps[0].Kind
				return result
			},
		},
		{
			name: "partial read-only plan",
			plan: func(req Request, id string) StrategyResult {
				result := SREReadOnlyStrategy{}.Plan(req, id)
				result.Steps = result.Steps[:1]
				return result
			},
		},
		{
			name: "mutated verified capability input",
			plan: func(req Request, id string) StrategyResult {
				req.Capabilities[0].ContractSHA256 = strings.Repeat("f", 64)
				return SREReadOnlyStrategy{}.Plan(req, id)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewServiceWithStrategy(NewMemoryStore(), allowAuthority{}, tc.plan)
			if _, _, err := svc.Decide(context.Background(), testPrincipal(), validRequest()); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected strategy output rejection, got %v", err)
			}
		})
	}
}

func TestCoreNormalizesNilStrategyReasonCodesToEmptyArray(t *testing.T) {
	plan := strategyFunc(func(req Request, id string) StrategyResult {
		result := SREReadOnlyStrategy{}.Plan(req, id)
		result.ReasonCodes = nil
		return result
	})
	record, _, err := NewServiceWithStrategy(NewMemoryStore(), allowAuthority{}, plan).Decide(
		context.Background(), testPrincipal(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if record.ReasonCodes == nil {
		t.Fatal("reason_codes must serialize as an array, not null")
	}
}


func TestRequestRequiresExplicitEvidenceCollections(t *testing.T) {
	req := validRequest()
	req.Evidence = nil
	if err := req.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil evidence_refs must be rejected, got %v", err)
	}
	req = validRequest()
	req.Capabilities = nil
	if err := req.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil capabilities must be rejected, got %v", err)
	}
}

func TestEvidenceEnvelopeRejectsScopeWindowAndRevocationMismatch(t *testing.T) {
	cases := []struct {
		name string
		mutate func(*EvidenceRef)
	}{
		{"wrong agent", func(e *EvidenceRef) { e.AgentID = "other-agent" }},
		{"wrong run", func(e *EvidenceRef) { e.RunID = "other-run" }},
		{"wrong service", func(e *EvidenceRef) { e.Service = "other-service" }},
		{"inverted observation window", func(e *EvidenceRef) { e.ObservedFrom = e.ObservedTo.Add(time.Minute) }},
		{"observed timestamp before window", func(e *EvidenceRef) { e.ObservedAt = e.ObservedFrom.Add(-time.Second) }},
		{"observed timestamp after window", func(e *EvidenceRef) { e.ObservedAt = e.ObservedTo.Add(time.Second) }},
		{"collection before observation end", func(e *EvidenceRef) { e.CollectedAt = e.ObservedTo.Add(-time.Second) }},
		{"revoked evidence", func(e *EvidenceRef) { e.RevocationState = "revoked" }},
		{"unknown evidence kind", func(e *EvidenceRef) { e.EvidenceType = "arbitrary" }},
		{"unsupported envelope version", func(e *EvidenceRef) { e.SchemaVersion = "v1" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			tc.mutate(&req.Evidence[0])
			if err := req.Validate(); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected invalid evidence envelope, got %v", err)
			}
		})
	}
}

func TestRequestRejectsDuplicateEvidenceFromSameSource(t *testing.T) {
	req := validRequest()
	duplicate := req.Evidence[0]
	duplicate.SHA256 = strings.Repeat("f", 64)
	req.Evidence = append(req.Evidence, duplicate)
	if err := req.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("duplicate source/reference pair must be rejected, got %v", err)
	}
}

func TestEvidenceEnvelopeBindsTenantToTrustedPrincipal(t *testing.T) {
	verifierCalled := false
	verifier := authorityFunc(func(context.Context, Principal, Request) error {
		verifierCalled = true
		return nil
	})
	req := validRequest()
	req.Evidence[0].TenantID = "tenant-other"
	_, _, err := NewService(NewMemoryStore(), verifier).Decide(context.Background(), testPrincipal(), req)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected trusted-principal tenant mismatch rejection, got %v", err)
	}
	if verifierCalled {
		t.Fatal("tenant-mismatched evidence must be rejected before the external verifier is called")
	}
}

type authorityFunc func(context.Context, Principal, Request) error
func (f authorityFunc) VerifyDecisionInputs(ctx context.Context, p Principal, req Request) error {
	return f(ctx, p, req)
}

func TestReadOnlyPlannerAbstainsWhenLogsOrChangesEvidenceMissing(t *testing.T) {
	for _, missingType := range []string{"logs", "change"} {
		t.Run(missingType, func(t *testing.T) {
			req := validRequest()
			filtered := make([]EvidenceRef, 0, len(req.Evidence))
			for _, evidence := range req.Evidence {
				if evidence.EvidenceType != missingType {
					filtered = append(filtered, evidence)
				}
			}
			req.Evidence = filtered
			record, _, err := NewService(NewMemoryStore(), allowAuthority{}).Decide(context.Background(), testPrincipal(), req)
			if err != nil || record.Status != StatusAbstained || len(record.Plan.Steps) != 0 {
				t.Fatalf("missing %s evidence must abstain, got %+v %v", missingType, record, err)
			}
		})
	}
}

func TestStrategyRejectsMissingOrMismatchedStepEvidenceBindings(t *testing.T) {
	cases := []struct {
		name string
		mutate func(*StrategyResult)
	}{
		{
			name: "missing evidence",
			mutate: func(result *StrategyResult) { result.Steps[0].EvidenceRefs = nil },
		},
		{
			name: "unknown evidence reference",
			mutate: func(result *StrategyResult) { result.Steps[0].EvidenceRefs[0].Ref = "unbound-reference" },
		},
		{
			name: "evidence from wrong source type",
			mutate: func(result *StrategyResult) {
				for _, evidence := range validRequest().Evidence {
					if evidence.EvidenceType == "logs" {
						result.Steps[0].EvidenceRefs = []EvidenceBinding{{SourceID:evidence.SourceID, Ref:evidence.Ref}}
						return
					}
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			result := SREReadOnlyStrategy{}.Plan(req, "dec_test")
			tc.mutate(&result)
			if err := validateStrategyResult(req, result); err == nil {
				t.Fatal("invalid step evidence binding was accepted")
			}
		})
	}
}

