package decision

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// This unit test verifies the exact known read-only SRE step contract.
// Live multi-service source authority is tested separately; no fake permit
// or claimed production authorization is inferred from this fixture.
func TestGuardPlanStepRejectsForgedOrUnsafeSubmission(t *testing.T) {
	p, req := testPrincipal(), validRequest()
	record, _, err := NewService(NewMemoryStore(), allowAuthority{}).Decide(context.Background(), p, req)
	if err != nil {
		t.Fatal(err)
	}
	step := record.Plan.Steps[0]
	good := GuardPlanStepRequest{
		SchemaVersion: GuardPlanStepSchema,
		RunID: record.RunID, AgentID: record.AgentID, AgentReleaseID: "release-1",
		SessionID: record.SessionID, DecisionID: record.DecisionID,
		PlanID: record.Plan.PlanID, PlanHash: record.Plan.PlanHash,
		StepID: step.StepID, CapabilityID: step.Capability.ID,
		CapabilityVersion: step.Capability.Version,
		ResourceRef: step.TargetRef, Arguments: json.RawMessage("{}"),
		BreakerEpoch: 1, BreakerVersion: 1,
	}
	if err := matchGuardPlanStep(record, good); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		mutate func(*GuardPlanStepRequest)
	}{
		{"different Run", func(r *GuardPlanStepRequest) { r.RunID = "other-run" }},
		{"different agent", func(r *GuardPlanStepRequest) { r.AgentID = "other-agent" }},
		{"different session", func(r *GuardPlanStepRequest) { r.SessionID = "other-session" }},
		{"changed decision", func(r *GuardPlanStepRequest) { r.DecisionID = "dec_" + strings.Repeat("a", 64) }},
		{"changed plan identity", func(r *GuardPlanStepRequest) { r.PlanID = "other-plan" }},
		{"changed plan hash", func(r *GuardPlanStepRequest) { r.PlanHash = strings.Repeat("f", 64) }},
		{"unknown step", func(r *GuardPlanStepRequest) { r.StepID = "unknown" }},
		{"other capability", func(r *GuardPlanStepRequest) { r.CapabilityID = "workspace.write" }},
		{"capability version drift", func(r *GuardPlanStepRequest) { r.CapabilityVersion = "9.9.9" }},
		{"resource drift", func(r *GuardPlanStepRequest) { r.ResourceRef = "other-service" }},
		{"arguments", func(r *GuardPlanStepRequest) { r.Arguments = json.RawMessage(`{"shell":"rm -rf /"}`) }},
		{"noncanonical arguments", func(r *GuardPlanStepRequest) { r.Arguments = json.RawMessage("{ }") }},
		{"stale breaker", func(r *GuardPlanStepRequest) { r.BreakerEpoch = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := good
			tc.mutate(&bad)
			if err := matchGuardPlanStep(record, bad); !errors.Is(err, ErrAuthorityRejected) {
				t.Fatalf("unsafe step accepted: %v", err)
			}
		})
	}
	unsafeRecord := clone(record)
	unsafeRecord.Plan.Steps[0].ReadOnly = false
	unsafeRecord.Plan.PlanHash = planHash(unsafeRecord.Plan)
	unsafe := good
	unsafe.PlanHash = unsafeRecord.Plan.PlanHash
	if err := matchGuardPlanStep(unsafeRecord, unsafe); !errors.Is(err, ErrAuthorityRejected) {
		t.Fatal("mutating a read-only step and recomputing plan hash bypassed guard provenance")
	}
}

func TestGuardPlanStepReceiptCarriesRuntimeIdentitySelectorsOnly(t *testing.T) {
	receipt := GuardPlanStepReceipt{
		SchemaVersion: GuardPlanStepSchema,
		RunID: "11111111-1111-4111-8111-111111111111",
		RunAttemptID: "22222222-2222-4222-8222-222222222222",
		TurnID: "33333333-3333-4333-8333-333333333333",
		DecisionID: "dec_" + strings.Repeat("a", 64),
		PlanHash: strings.Repeat("b", 64),
		StepID: "step-1",
		RecordSHA256: strings.Repeat("c", 64),
		BreakerEpoch: 1,
		BreakerVersion: 1,
		Status: "VERIFIED",
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema_version", "run_id", "run_attempt_id", "turn_id", "decision_id", "plan_hash", "step_id", "record_sha256", "breaker_epoch", "breaker_version", "status"} {
		if len(fields[key]) == 0 {
			t.Fatalf("Guard receipt omitted %s: %s", key, raw)
		}
	}
	for _, forbidden := range []string{"permit", "approval", "risk", "authorization", "token", "credential"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("Guard receipt leaked %s: %s", forbidden, raw)
		}
	}
}
