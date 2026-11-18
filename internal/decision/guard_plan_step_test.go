package decision

import (
	"encoding/json"
	"strings"
	"testing"
)

func guardPlanFixture() (Record, ContinuationReceipt, GuardPlanStepRequest) {
	capability := CapabilityRef{ID: "sre.metrics.read", Version: "1.0.0",
		ContractSHA256: strings.Repeat("a", 64), InputSchemaRef: "schema:metrics",
		OutputSchemaRef: "schema:observations", EffectClass: "read_only",
		Idempotency: "safe", TenantScoped: true}
	record := Record{
		DecisionID: "dec_" + strings.Repeat("a", 64),
		RunID: "12345678-1234-4234-8234-123456789abc",
		AgentID: "agent-a", SessionID: "session-a", Status: StatusProposed,
		Plan: PlanCandidate{PlanID: "plan-1", PlanHash: strings.Repeat("b", 64),
			Steps: []PlanStep{{StepID: "step-1", Kind: "OBSERVE_METRICS",
				Capability: capability, TargetRef: "payments", ReadOnly: true}}},
	}
	runtime := RuntimeDecisionAuthority{
		TenantID: "tenant-a", RunID: record.RunID, AgentID: record.AgentID,
		AgentReleaseID: "release-a", SessionID: record.SessionID,
		BreakerEpoch: 1, BreakerVersion: 2,
	}
	receipt := ContinuationReceipt{SchemaVersion: "decision.continuation.v1", Authority: runtime,
		DecisionID: record.DecisionID, RecordSHA256: digest(record), PlanHash: record.Plan.PlanHash}
	req := GuardPlanStepRequest{SchemaVersion: "decision.guard-plan-step.v1",
		RunID: record.RunID, AgentID: record.AgentID, AgentReleaseID: runtime.AgentReleaseID,
		SessionID: record.SessionID, DecisionID: record.DecisionID, PlanID: record.Plan.PlanID,
		PlanHash: record.Plan.PlanHash, StepID: "step-1",
		CapabilityID: capability.ID, CapabilityVersion: capability.Version,
		ResourceRef: "payments", Arguments: json.RawMessage(`{}`),
		BreakerEpoch: runtime.BreakerEpoch, BreakerVersion: runtime.BreakerVersion,
	}
	return record, receipt, req
}

func TestGuardPlanStepBindsRealCommittedRecordAndRuntimeFence(t *testing.T) {
	record, receipt, req := guardPlanFixture()
	got, err := MatchGuardPlanStep(record, receipt, req)
	if err != nil || got.Status != "VERIFIED" || got.RecordSHA256 != receipt.RecordSHA256 ||
		got.StepID != req.StepID || got.BreakerVersion != req.BreakerVersion {
		t.Fatalf("verified Step receipt = %+v error = %v", got, err)
	}
	tests := []struct {
		name string
		edit func(*Record, *ContinuationReceipt, *GuardPlanStepRequest)
	}{
		{"different decision", func(_ *Record, _ *ContinuationReceipt, r *GuardPlanStepRequest) { r.DecisionID = "dec_"+strings.Repeat("c",64) }},
		{"stale plan", func(_ *Record, _ *ContinuationReceipt, r *GuardPlanStepRequest) { r.PlanHash = strings.Repeat("c",64) }},
		{"wrong step", func(_ *Record, _ *ContinuationReceipt, r *GuardPlanStepRequest) { r.StepID = "step-forged" }},
		{"wrong target", func(_ *Record, _ *ContinuationReceipt, r *GuardPlanStepRequest) { r.ResourceRef = "other-service" }},
		{"different capability", func(_ *Record, _ *ContinuationReceipt, r *GuardPlanStepRequest) { r.CapabilityID = "workspace.write" }},
		{"different version", func(_ *Record, _ *ContinuationReceipt, r *GuardPlanStepRequest) { r.CapabilityVersion = "2.0.0" }},
		{"effectful step", func(rec *Record, rc *ContinuationReceipt, _ *GuardPlanStepRequest) { rec.Plan.Steps[0].ReadOnly=false; rc.RecordSHA256=digest(*rec) }},
		{"effectful capability", func(rec *Record, rc *ContinuationReceipt, _ *GuardPlanStepRequest) { rec.Plan.Steps[0].Capability.EffectClass="write"; rc.RecordSHA256=digest(*rec) }},
		{"args not empty", func(_ *Record, _ *ContinuationReceipt, r *GuardPlanStepRequest) { r.Arguments=json.RawMessage(`{"command":"delete"}`) }},
		{"breaker epoch changed", func(_ *Record, _ *ContinuationReceipt, r *GuardPlanStepRequest) { r.BreakerEpoch++ }},
		{"breaker version changed", func(_ *Record, _ *ContinuationReceipt, r *GuardPlanStepRequest) { r.BreakerVersion++ }},
		{"different release", func(_ *Record, _ *ContinuationReceipt, r *GuardPlanStepRequest) { r.AgentReleaseID="untrusted-release" }},
		{"record digest drift", func(_ *Record, rc *ContinuationReceipt, _ *GuardPlanStepRequest) { rc.RecordSHA256=strings.Repeat("d",64) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, verified, input := guardPlanFixture()
			tc.edit(&rec, &verified, &input)
			if _, err := MatchGuardPlanStep(rec, verified, input); err == nil {
				t.Fatal("untrusted or stale Step unexpectedly verified")
			}
		})
	}
}
