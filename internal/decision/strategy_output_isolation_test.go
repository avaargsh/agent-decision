package decision

import (
	"testing"
	"time"
)

func TestMaterializedDecisionOwnsStrategyEvidenceBindings(t *testing.T) {
	req := validRequest()
	var retained StrategyResult
	strategy := strategyFunc(func(r Request, id string) StrategyResult {
		retained = SREReadOnlyStrategy{}.Plan(r, id)
		return retained
	})
	record, err := recordFromVerifiedRequest(testPrincipal(), req, strategy, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	want := record.Plan.Steps[0].EvidenceRefs[0]
	originalHash := record.Plan.PlanHash

	// A strategy may retain its result buffers. A later invocation or
	// cleanup must not rewrite an already materialized decision.
	retained.Steps[0].EvidenceRefs[0].Ref = "unattested-evidence"
	if got := record.Plan.Steps[0].EvidenceRefs[0]; got != want {
		t.Fatalf("strategy retained mutable evidence binding: got %v, want %v", got, want)
	}
	if planHash(record.Plan) != originalHash {
		t.Fatal("materialized plan no longer matches its committed hash")
	}

	// The isolation must hold in both directions.
	record.Plan.Steps[1].EvidenceRefs[0].Ref = "record-local"
	if got := retained.Steps[1].EvidenceRefs[0].Ref; got == "record-local" {
		t.Fatal("record mutation reached strategy-owned result")
	}
}
