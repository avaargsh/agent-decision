package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
)

// GuardPlanStepSchema is a narrow, read-only SRE provenance check.
// This is NOT a Permit, execution authorization, or binding for a write tool.
const GuardPlanStepSchema = "decision.guard-plan-step.v1"

// GuardPlanStepRequest contains correlation selectors from an authenticated
// Guard workload. Tenant scope is bound by the listener, not this request.
// Runtime and ACP remain independently authoritative.
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

// GuardPlanStepReceipt represents a fresh source check, never authorization
// for a protected effect. No bearer or Permit material is included.
type GuardPlanStepReceipt struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	RunAttemptID  string `json:"run_attempt_id"`
	TurnID        string `json:"turn_id"`
	DecisionID    string `json:"decision_id"`
	PlanHash      string `json:"plan_hash"`
	StepID        string `json:"step_id"`
	RecordSHA256  string `json:"record_sha256"`
	BreakerEpoch  int64  `json:"breaker_epoch"`
	BreakerVersion int64 `json:"breaker_version"`
	Status        string `json:"status"`
}

// matchGuardPlanStep checks all untrusted selectors against one immutable
// proposal. Even a correctly hashed stale plan is denied by the separate
// live authority checks before the result is returned to Guard.
func matchGuardPlanStep(record Record, request GuardPlanStepRequest) error {
	if request.SchemaVersion != GuardPlanStepSchema ||
		!nameRe.MatchString(request.RunID) || !nameRe.MatchString(request.AgentID) ||
		!nameRe.MatchString(request.AgentReleaseID) || !nameRe.MatchString(request.SessionID) ||
		!decisionIDRe.MatchString(request.DecisionID) ||
		!validOpaque(request.PlanID) || !digestRe.MatchString(request.PlanHash) ||
		!validOpaque(request.StepID) || !nameRe.MatchString(request.CapabilityID) ||
		!semverRe.MatchString(request.CapabilityVersion) || !nameRe.MatchString(request.ResourceRef) ||
		request.BreakerEpoch < 1 || request.BreakerVersion < 1 ||
		!bytes.Equal(request.Arguments, []byte("{}")) {
		return ErrAuthorityRejected
	}
	if record.Status != StatusProposed || record.RunID != request.RunID ||
		record.AgentID != request.AgentID || record.SessionID != request.SessionID ||
		record.DecisionID != request.DecisionID || record.Plan.PlanID != request.PlanID ||
		record.Plan.PlanHash != request.PlanHash || record.Plan.PlanHash != planHash(record.Plan) {
		return ErrAuthorityRejected
	}
	for _, step := range record.Plan.Steps {
		if step.StepID != request.StepID {
			continue
		}
		if !step.ReadOnly || step.Capability.EffectClass != "read_only" ||
			step.Capability.Idempotency != "safe" || !step.Capability.TenantScoped ||
			step.Capability.ID != request.CapabilityID ||
			step.Capability.Version != request.CapabilityVersion ||
			step.TargetRef != request.ResourceRef ||
			step.InputSchemaRef != step.Capability.InputSchemaRef ||
			step.OutputSchemaRef != step.Capability.OutputSchemaRef ||
			len(step.EvidenceRefs) == 0 {
			return ErrAuthorityRejected
		}
		return nil
	}
	return ErrAuthorityRejected
}

// VerifyGuardPlanStep re-reads the original proposal and independently
// revalidates current Runtime, ACP and per-source evidence. It does not
// accept a submitted plan body as authority. No record is created.
func (a *LiveAuthority) VerifyGuardPlanStep(
	ctx context.Context, store Store, tenant string, request GuardPlanStepRequest,
) (GuardPlanStepReceipt, error) {
	var empty GuardPlanStepReceipt
	if a == nil || store == nil || tenant == "" || request.SchemaVersion != GuardPlanStepSchema {
		return empty, ErrAuthorityUnavailable
	}
	record, err := store.GetByDecisionID(ctx, tenant, request.AgentID, request.SessionID, request.DecisionID)
	switch {
	case errors.Is(err, ErrNotFound):
		return empty, ErrAuthorityRejected
	case err != nil:
		return empty, ErrAuthorityUnavailable
	}
	if record.TenantID != tenant || matchGuardPlanStep(record, request) != nil {
		return empty, ErrAuthorityRejected
	}
	fresh, err := a.VerifyCommittedTurn(ctx, store, request.RunID, record.InvocationID)
	if err != nil {
		return empty, err
	}
	s := fresh.Authority
	if s.TenantID != tenant || s.RunID != request.RunID || s.AgentID != request.AgentID ||
		s.AgentReleaseID != request.AgentReleaseID || s.SessionID != request.SessionID ||
		s.AttemptID == "" || s.InvocationID == "" ||
		s.BreakerState != "CLOSED" || s.Status != "RUNNING" ||
		s.BreakerEpoch != request.BreakerEpoch || s.BreakerVersion != request.BreakerVersion ||
		fresh.DecisionID != record.DecisionID || fresh.RecordSHA256 != digest(record) ||
		fresh.PlanHash != record.Plan.PlanHash {
		return empty, ErrAuthorityRejected
	}
	return GuardPlanStepReceipt{
		SchemaVersion: GuardPlanStepSchema, RunID: s.RunID,
		RunAttemptID: s.AttemptID, TurnID: s.InvocationID,
		DecisionID: record.DecisionID, PlanHash: record.Plan.PlanHash,
		StepID: request.StepID, RecordSHA256: fresh.RecordSHA256,
		BreakerEpoch: s.BreakerEpoch, BreakerVersion: s.BreakerVersion,
		Status: "VERIFIED",
	}, nil
}
