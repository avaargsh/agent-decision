package decision

import (
	"errors"
	"reflect"
	"testing"
	"time"
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
	// Distinct evidence references can disagree about the same fact.
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

func TestDeploymentHypothesisRejectsInvalidEvaluationContext(t *testing.T) {
	for _, tc := range []struct {
		name string
		mutate func(*Principal, *Request, *[]hypothesisObservation, *time.Time)
	}{
		{"duplicate_observation", func(_ *Principal, _ *Request, o *[]hypothesisObservation, _ *time.Time) {
			*o = append(*o, (*o)[0])
		}},
		{"contradictory_same_reference", func(_ *Principal, _ *Request, o *[]hypothesisObservation, _ *time.Time) {
			other := (*o)[0]
			other.Fact = symptomNotIncreased
			*o = append(*o, other)
		}},
		{"future_collection", func(_ *Principal, _ *Request, _ *[]hypothesisObservation, now *time.Time) {
			*now = now.Add(-time.Nanosecond)
		}},
		{"zero_clock", func(_ *Principal, _ *Request, _ *[]hypothesisObservation, now *time.Time) {
			*now = time.Time{}
		}},
		{"snapshot_expired_at_boundary", func(_ *Principal, r *Request, _ *[]hypothesisObservation, now *time.Time) {
			r.ContextSnapshot.ExpiresAt = *now
		}},
		{"evidence_expired_at_boundary", func(_ *Principal, r *Request, o *[]hypothesisObservation, now *time.Time) {
			r.Evidence[0].ExpiresAt = *now
			r.Evidence[0].CollectedAt = now.Add(-time.Second)
			(*o)[0].Evidence = r.Evidence[0]
		}},
		{"unreferenced_revoked_evidence", func(_ *Principal, r *Request, _ *[]hypothesisObservation, _ *time.Time) {
			r.Evidence[1].RevocationState = "revoked"
		}},
		{"wrong_principal_tenant", func(p *Principal, _ *Request, _ *[]hypothesisObservation, _ *time.Time) {
			p.TenantID = "tenant-b"
		}},
		{"wrong_principal_session", func(p *Principal, _ *Request, _ *[]hypothesisObservation, _ *time.Time) {
			p.SessionID = "session-99"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, req := testPrincipal(), validRequest()
			now := req.Evidence[0].CollectedAt
			observations := []hypothesisObservation{{Evidence: req.Evidence[0], Fact: symptomIncreased}}
			tc.mutate(&p, &req, &observations, &now)
			got, err := evaluateDeploymentHypothesis(p, req, observations, now)
			if !errors.Is(err, ErrInvalidRequest) || !reflect.DeepEqual(got, hypothesisResult{}) {
				t.Fatalf("invalid context accepted: %+v %v", got, err)
			}
		})
	}
}

func TestDeploymentHypothesisResultOwnsEvidence(t *testing.T) {
	req := validRequest()
	now := req.Evidence[0].CollectedAt
	observations := []hypothesisObservation{
		{Evidence: req.Evidence[0], Fact: symptomIncreased},
		{Evidence: req.Evidence[2], Fact: deploymentPrecedesSymptom},
	}
	got, err := evaluateDeploymentHypothesis(testPrincipal(), req, observations, now)
	if err != nil || got.Status != hypothesisSupported || len(got.Supporting) != 2 {
		t.Fatalf("unexpected evaluation: %+v %v", got, err)
	}
	// The sorted result contains a value copy of the change evidence.
	original := observations[1]
	if got.Supporting[0] != original {
		t.Fatalf("expected exact change evidence, got %+v", got.Supporting[0])
	}
	observations[1].Evidence.Ref = "mutated-observation"
	req.Evidence[2].Ref = "mutated-request"
	if got.Supporting[0] != original {
		t.Fatal("input mutation changed result")
	}
	got.Supporting[0].Evidence.Ref = "mutated-result"
	if observations[1].Evidence.Ref != "mutated-observation" || req.Evidence[2].Ref != "mutated-request" {
		t.Fatal("result mutation changed inputs")
	}
}
