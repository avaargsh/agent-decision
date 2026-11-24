package decision

import (
	"errors"
	"reflect"
	"testing"
)

func TestDeploymentHypothesisEvaluation(t *testing.T) {
	req := validRequest()
	// These are synthetic typed observations, not assertions inferred from
	// EvidenceType or a real verified incident trajectory.
	p := testPrincipal()
	now := req.Evidence[0].CollectedAt
	observation := func(index int, fact hypothesisFact) hypothesisObservation {
		e := req.Evidence[index]
		return hypothesisObservation{Evidence: e, Fact: fact}
	}
	symptom := observation(0, symptomIncreased)
	change := observation(2, deploymentPrecedesSymptom)
	noChange := observation(2, noDeploymentInWindow)
	negative := observation(0, symptomNotIncreased)
	for _, tc := range []struct {
		name string
		observations []hypothesisObservation
		want hypothesisStatus
		support, contradict, missing int
	}{
		{"untested", nil, hypothesisUntested, 0, 0, 2},
		{"missing_change", []hypothesisObservation{symptom}, hypothesisInsufficient, 1, 0, 1},
		{"supported", []hypothesisObservation{symptom, change}, hypothesisSupported, 2, 0, 0},
		{"contradicted", []hypothesisObservation{symptom, noChange}, hypothesisContradicted, 1, 1, 0},
		{"no_symptom", []hypothesisObservation{negative, change}, hypothesisContradicted, 1, 1, 0},
		{"unrelated_only", []hypothesisObservation{observation(1, unrelatedObservation)}, hypothesisUntested, 0, 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evaluateDeploymentHypothesis(p, req, tc.observations, now)
			if err != nil || got.Status != tc.want || len(got.Supporting) != tc.support || len(got.Contradicting) != tc.contradict || len(got.Missing) != tc.missing {
				t.Fatalf("result=%+v err=%v; want status=%s support=%d contradiction=%d missing=%d", got, err, tc.want, tc.support, tc.contradict, tc.missing)
			}
			if got.ID != "deployment-correlation-v1" || len(got.Assumptions) == 0 {
				t.Fatal("missing hypothesis identity or assumptions")
			}
		})
	}
	// Independent evidence sources can disagree about the same fact.
	conflicting := req.Evidence[2]
	conflicting.Ref = "change-conflict"
	conflicting.AttestationRef = "att-change-conflict"
	req.Evidence = append(req.Evidence, conflicting)
	conflict := hypothesisObservation{Evidence: conflicting, Fact: noDeploymentInWindow}
	first, err := evaluateDeploymentHypothesis(p, req, []hypothesisObservation{symptom, change, conflict}, now)
	if err != nil || first.Status != hypothesisConflicting {
		t.Fatalf("expected conflict, got %+v %v", first, err)
	}
	second, err := evaluateDeploymentHypothesis(p, req, []hypothesisObservation{conflict, change, symptom}, now)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("permutation changed result: %+v %+v %v", first, second, err)
	}
}

func TestDeploymentHypothesisRejectsUnboundObservation(t *testing.T) {
	for _, tc := range []struct {
		name string
		mutate func(*hypothesisObservation)
	}{
		{"unknown_ref", func(o *hypothesisObservation) { o.Evidence.Ref = "unknown" }},
		{"wrong_digest", func(o *hypothesisObservation) { o.Evidence.SHA256 = validRequest().Evidence[2].SHA256 }},
		{"wrong_tenant", func(o *hypothesisObservation) { o.Evidence.TenantID = "tenant-b" }},
		{"wrong_run", func(o *hypothesisObservation) { o.Evidence.RunID = "run-99" }},
		{"wrong_service", func(o *hypothesisObservation) { o.Evidence.Service = "other-api" }},
		{"wrong_kind", func(o *hypothesisObservation) { o.Fact = deploymentPrecedesSymptom }},
		{"unknown_fact", func(o *hypothesisObservation) { o.Fact = hypothesisFact("unknown") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			o := hypothesisObservation{Evidence: req.Evidence[0], Fact: symptomIncreased}
			tc.mutate(&o)
			got, err := evaluateDeploymentHypothesis(testPrincipal(), req, []hypothesisObservation{o}, req.Evidence[0].CollectedAt)
			if !errors.Is(err, ErrInvalidRequest) || !reflect.DeepEqual(got, hypothesisResult{}) {
				t.Fatalf("unbound observation accepted: %+v %v", got, err)
			}
		})
	}
}
