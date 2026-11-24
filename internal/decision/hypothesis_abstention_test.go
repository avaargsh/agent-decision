package decision

import (
	"reflect"
	"testing"
)

func TestDeploymentHypothesisAbstentionReasonTaxonomy(t *testing.T) {
	req := validRequest()
	now := req.Evidence[0].CollectedAt
	observe := func(index int, fact hypothesisFact) hypothesisObservation {
		return hypothesisObservation{Evidence: req.Evidence[index], Fact: fact}
	}

	symptom := observe(0, symptomIncreased)
	change := observe(2, deploymentPrecedesSymptom)
	noChange := observe(2, noDeploymentInWindow)
	unrelated := observe(1, unrelatedObservation)

	conflictingSymptom := req.Evidence[0]
	conflictingSymptom.Ref = "symptom-conflict"
	conflictingSymptom.AttestationRef = "att-symptom-conflict"
	conflictingChange := req.Evidence[2]
	conflictingChange.Ref = "change-conflict"
	conflictingChange.AttestationRef = "att-change-conflict"
	req.Evidence = append(req.Evidence, conflictingSymptom, conflictingChange)
	negativeSymptom := hypothesisObservation{Evidence: conflictingSymptom, Fact: symptomNotIncreased}
	negativeChange := hypothesisObservation{Evidence: conflictingChange, Fact: noDeploymentInWindow}

	cases := []struct {
		name         string
		observations []hypothesisObservation
		want         []hypothesisAbstentionReason
	}{
		{
			name: "no_observations",
			want: []hypothesisAbstentionReason{
				hypothesisAbstentionMissingSymptomObservation,
				hypothesisAbstentionMissingDeploymentObservation,
			},
		},
		{
			name: "missing_deployment",
			observations: []hypothesisObservation{symptom},
			want: []hypothesisAbstentionReason{
				hypothesisAbstentionMissingDeploymentObservation,
			},
		},
		{
			name: "unrelated_only",
			observations: []hypothesisObservation{unrelated},
			want: []hypothesisAbstentionReason{
				hypothesisAbstentionMissingSymptomObservation,
				hypothesisAbstentionMissingDeploymentObservation,
				hypothesisAbstentionNoRelevantEvidence,
			},
		},
		{
			name: "conflicting_symptom",
			observations: []hypothesisObservation{symptom, negativeSymptom},
			want: []hypothesisAbstentionReason{
				hypothesisAbstentionMissingDeploymentObservation,
				hypothesisAbstentionConflictingSymptomObservations,
			},
		},
		{
			name: "conflicting_deployment",
			observations: []hypothesisObservation{change, negativeChange},
			want: []hypothesisAbstentionReason{
				hypothesisAbstentionMissingSymptomObservation,
				hypothesisAbstentionConflictingDeploymentObservations,
			},
		},
		{
			name: "supported",
			observations: []hypothesisObservation{symptom, change},
			want: []hypothesisAbstentionReason{},
		},
		{
			name: "contradicted",
			observations: []hypothesisObservation{symptom, noChange},
			want: []hypothesisAbstentionReason{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evaluateDeploymentHypothesis(testPrincipal(), req, tc.observations, now)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.AbstentionReasons, tc.want) {
				t.Fatalf("abstention reasons = %v, want %v", got.AbstentionReasons, tc.want)
			}
		})
	}
}
