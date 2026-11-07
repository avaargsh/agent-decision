package decision

import "testing"

// An immutable DecisionRecord must not share nested step evidence slices with
// a caller-visible replay; otherwise a caller can mutate another observation.
func TestCloneDeepCopiesPlanStepEvidenceBindings(t *testing.T) {
	original := Record{
		Plan: PlanCandidate{Steps: []PlanStep{{
			StepID: "investigate",
			EvidenceRefs: []EvidenceBinding{{SourceID: "metrics-source", Ref: "sample-v1"}},
		}}},
	}

	copied := clone(original)
	copied.Plan.Steps[0].EvidenceRefs[0].Ref = "tampered"

	if got := original.Plan.Steps[0].EvidenceRefs[0].Ref; got != "sample-v1" {
		t.Fatalf("caller-mutated replay changed source evidence binding: %s", got)
	}
}
