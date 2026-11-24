package decision

import (
	"context"
	"time"
)

// ContinuationReceipt is a point-in-time, authenticated observation for the
// Runtime's local CAS. It is not a Permit, execution receipt, distributed
// revocation fence, or transferable grant. Never accept one from an Agent.
type ContinuationReceipt struct {
	SchemaVersion string                   `json:"schema_version"`
	Authority     RuntimeDecisionAuthority `json:"authority"`
	DecisionID    string                   `json:"decision_id"`
	RecordSHA256  string                   `json:"record_sha256"`
	PlanHash      string                   `json:"plan_hash"`
}

// VerifyCommittedTurn does not plan, allocate an invocation or write an
// outbox event. Evidence references come only from the immutable ledger;
// the caller selects the exact Run/Invocation. Recheck all live authorities
// and reconstruct the deterministic proposal before returning its digest.
func (a *LiveAuthority) VerifyCommittedTurn(ctx context.Context, store Store, runID, invocation string) (ContinuationReceipt, error) {
	var empty ContinuationReceipt
	if a == nil || store == nil {
		return empty, ErrAuthorityUnavailable
	}
	before, err := a.currentRuntime(ctx, runID, invocation)
	if err != nil {
		return empty, err
	}
	stored, err := store.GetByInvocation(ctx, before.TenantID, invocation)
	if err != nil {
		return empty, err
	}
	if stored.RunID != runID || stored.InvocationID != invocation || stored.TenantID != before.TenantID {
		return empty, ErrAuthorityRejected
	}
	principal, req, err := a.build(ctx, runID, invocation, stored.Evidence)
	if err != nil {
		return empty, err
	}
	if err := verifyCommittedProposal(principal, req, stored); err != nil {
		return empty, err
	}
	after, err := a.currentRuntime(ctx, runID, invocation)
	if err != nil {
		return empty, err
	}
	// build's final observation precedes this additional network read.
	// Never issue a continuation receipt for inputs stale at this point.
	if before != after || !a.inputsFreshAt(req, a.currentTime()) {
		return empty, ErrAuthorityRejected
	}
	return ContinuationReceipt{
		SchemaVersion: "decision.continuation.v1",
		Authority:     after,
		DecisionID:    stored.DecisionID,
		RecordSHA256:  digest(stored),
		PlanHash:      stored.Plan.PlanHash,
	}, nil
}

// A valid self-reported plan hash is insufficient. Compare the entire
// stored result against the freshly reconstructed rule-only output.
func verifyCommittedProposal(p Principal, req Request, got Record) error {
	if p.Validate() != nil || req.Validate() != nil || req.Replan != nil ||
		got.Status != StatusProposed || got.CreatedAt.IsZero() || got.CreatedAt.After(time.Now().UTC()) {
		return ErrAuthorityRejected
	}
	expected, err := recordFromVerifiedRequest(p, req, SREReadOnlyStrategy{}, got.CreatedAt)
	if err != nil || expected.Status != StatusProposed || digest(expected) != digest(got) {
		return ErrAuthorityRejected
	}
	return nil
}
