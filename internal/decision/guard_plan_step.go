package decision

import (
	"bytes"
	"context"
	"encoding/json"
)

// GuardPlanStepRequest is an untrusted selector. The tenant, subject,
// current Run, original Decision and capability registry come exclusively
// from independently authenticated authorities, never from these fields.
type GuardPlanStepRequest struct {
	SchemaVersion     string          `json:"schema_version"`
	RunID             string          `json:"run_id"`
	AgentID           string          `json:"agent_id"`
	AgentReleaseID    string          `json:"agent_release_id"`
	SessionID         string          `json:"session_id"`
	DecisionID        string          `json:"decision_id"`
	PlanID            string          `json:"plan_id"`
	PlanHash          string          `json:"plan_hash"`
	StepID            string          `json:"step_id"`
	CapabilityID      string          `json:"capability_id"`
	CapabilityVersion string          `json:"capability_version"`
	ResourceRef       string          `json:"resource_ref"`
	Arguments         json.RawMessage `json:"arguments"`
	BreakerEpoch      int64           `json:"breaker_epoch"`
	BreakerVersion    int64           `json:"breaker_version"`
}

type GuardPlanStepReceipt struct {
	SchemaVersion  string `json:"schema_version"`
	RunID          string `json:"run_id"`
	DecisionID     string `json:"decision_id"`
	PlanHash       string `json:"plan_hash"`
	StepID         string `json:"step_id"`
	RecordSHA256   string `json:"record_sha256"`
	BreakerEpoch   int64  `json:"breaker_epoch"`
	BreakerVersion int64  `json:"breaker_version"`
	Status         string `json:"status"`
}

const GuardPlanStepSchema = "decision.guard-plan-step.v1"

func (r GuardPlanStepRequest) Validate() error {
	if r.SchemaVersion != GuardPlanStepSchema || !acpUUID.MatchString(r.RunID) ||
		!nameRe.MatchString(r.AgentID) || !nameRe.MatchString(r.AgentReleaseID) ||
		!nameRe.MatchString(r.SessionID) || !decisionIDRe.MatchString(r.DecisionID) ||
		!validOpaque(r.PlanID) || !digestRe.MatchString(r.PlanHash) ||
		!validOpaque(r.StepID) || !nameRe.MatchString(r.CapabilityID) ||
		!semverRe.MatchString(r.CapabilityVersion) || !nameRe.MatchString(r.ResourceRef) ||
		!bytes.Equal(r.Arguments, []byte("{}")) ||
		r.BreakerEpoch < 1 || r.BreakerVersion < 1 {
		return ErrAuthorityRejected
	}
	return nil
}

// MatchGuardPlanStep only checks exact immutable correlations. It cannot
// verify that the receipt is fresh or authentic: only VerifyGuardPlanStep
// can obtain one from live Runtime/ACP/Evidence by revalidating the ledger.
func MatchGuardPlanStep(record Record, fresh ContinuationReceipt, req GuardPlanStepRequest) (GuardPlanStepReceipt, error) {
	var empty GuardPlanStepReceipt
	if req.Validate() != nil || record.Status != StatusProposed ||
		record.DecisionID != req.DecisionID || record.RunID != req.RunID ||
		record.AgentID != req.AgentID || record.SessionID != req.SessionID ||
		record.Plan.PlanID != req.PlanID || record.Plan.PlanHash != req.PlanHash ||
		fresh.SchemaVersion != "decision.continuation.v1" ||
		fresh.DecisionID != req.DecisionID || fresh.RecordSHA256 != digest(record) ||
		fresh.PlanHash != req.PlanHash || fresh.Authority.RunID != req.RunID ||
		fresh.Authority.AgentID != req.AgentID || fresh.Authority.AgentReleaseID != req.AgentReleaseID ||
		fresh.Authority.SessionID != req.SessionID ||
		fresh.Authority.BreakerEpoch != req.BreakerEpoch ||
		fresh.Authority.BreakerVersion != req.BreakerVersion {
		return empty, ErrAuthorityRejected
	}
	matched := 0
	for _, step := range record.Plan.Steps {
		if step.StepID != req.StepID {
			continue
		}
		matched++
		expectedKind, known := requiredSREStepKinds[step.Capability.ID]
		if !known || step.Kind != expectedKind || !step.ReadOnly ||
			step.Capability.EffectClass != "read_only" ||
			step.Capability.Idempotency != "safe" || !step.Capability.TenantScoped ||
			step.Capability.ID != req.CapabilityID ||
			step.Capability.Version != req.CapabilityVersion ||
			step.TargetRef != req.ResourceRef {
			return empty, ErrAuthorityRejected
		}
	}
	if matched != 1 {
		return empty, ErrAuthorityRejected
	}
	return GuardPlanStepReceipt{
		SchemaVersion: GuardPlanStepSchema, RunID: req.RunID,
		DecisionID: req.DecisionID, PlanHash: req.PlanHash,
		StepID: req.StepID, RecordSHA256: fresh.RecordSHA256,
		BreakerEpoch: req.BreakerEpoch, BreakerVersion: req.BreakerVersion,
		Status: "VERIFIED",
	}, nil
}

// VerifyGuardPlanStep uses the immutable ledger to discover the invocation,
// then independently revalidates the SAME committed record against fresh
// Runtime, ACP and every original evidence source. This never issues a Permit.
func (a *LiveAuthority) VerifyGuardPlanStep(ctx context.Context, store Store, req GuardPlanStepRequest) (GuardPlanStepReceipt, error) {
	var empty GuardPlanStepReceipt
	if a == nil || store == nil || req.Validate() != nil {
		return empty, ErrAuthorityRejected
	}
	stored, err := store.GetByDecisionID(ctx, a.tenant, req.AgentID, req.SessionID, req.DecisionID)
	if err != nil {
		return empty, err
	}
	if stored.DecisionID != req.DecisionID || stored.RunID != req.RunID ||
		!acpUUID.MatchString(stored.InvocationID) {
		return empty, ErrAuthorityRejected
	}
	fresh, err := a.VerifyCommittedTurn(ctx, store, req.RunID, stored.InvocationID)
	if err != nil {
		return empty, err
	}
	// Defend against a ledger swap between the decision_id and invocation
	// reads, even if both individually looked structurally valid.
	if fresh.RecordSHA256 != digest(stored) {
		return empty, ErrAuthorityRejected
	}
	return MatchGuardPlanStep(stored, fresh, req)
}
