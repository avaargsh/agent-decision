package decision

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func evaluationReportCases(t *testing.T) []hypothesisEvaluationCase {
	t.Helper()
	fixture := newOfflineHypothesisFixture(t)

	unrelatedBase := requestFixtureEvidence(1)
	unrelatedBase.SourceID = "logs-alt"
	unrelatedBase.Source = "logs-alt"
	unrelatedBase.Ref = "logs-alt-sample"
	unrelatedBase.ResourceRef = "resource://payment-api/logs-alt"
	unrelated, unrelatedRef := makeOfflinePublication(t, unrelatedBase, "UNRELATED", fixture.from, fixture.to, fixture.now, 3)
	unrelatedRequest := fixture.request
	unrelatedRequest.Evidence = append(append([]EvidenceRef{}, fixture.request.Evidence...), unrelatedRef)

	conflictingBase := requestFixtureEvidence(0)
	conflictingBase.SourceID = "slo-adapter-secondary"
	conflictingBase.Source = "slo-adapter-secondary"
	conflictingBase.Ref = "slo-secondary-sample"
	conflictingBase.ResourceRef = "resource://payment-api/slo-secondary"
	conflicting, conflictingRef := makeOfflinePublication(t, conflictingBase, "SYMPTOM_NOT_INCREASED", fixture.from, fixture.to, fixture.now, 4)
	conflictingRequest := fixture.request
	conflictingRequest.Evidence = append(append([]EvidenceRef{}, fixture.request.Evidence...), conflictingRef)
	conflictingPublications := append(append([]signedHypothesisPublication{}, fixture.publications...), conflicting)

	unboundBase := requestFixtureEvidence(0)
	unboundBase.SourceID = "unbound-source"
	unboundBase.Source = "unbound-source"
	unboundBase.Ref = "unbound-sample"
	unboundBase.ResourceRef = "resource://payment-api/unbound"
	unbound, _ := makeOfflinePublication(t, unboundBase, "SYMPTOM_INCREASED", fixture.from, fixture.to, fixture.now, 5)

	wrongSigner := fixture.publications[0]
	wrongSigner.PublicKey = ed25519.NewKeyFromSeed(bytesOf(9, ed25519.SeedSize)).Public().(ed25519.PublicKey)

	return []hypothesisEvaluationCase{
		{
			ID: "01-supported", Split: hypothesisEvaluationGoldFixture,
			Principal: fixture.principal, Request: fixture.request, Publications: fixture.publications,
			From: fixture.from, To: fixture.to, Now: fixture.now,
			ExpectedStatus: hypothesisSupported, ExpectedBindingsBound: true,
		},
		{
			ID: "02-missing-change", Split: hypothesisEvaluationGoldFixture,
			Principal: fixture.principal, Request: fixture.request, Publications: fixture.publications[:1],
			From: fixture.from, To: fixture.to, Now: fixture.now,
			ExpectedStatus: hypothesisInsufficient, ExpectedBindingsBound: true,
		},
		{
			ID: "03-unrelated-only", Split: hypothesisEvaluationHoldoutFixture,
			Principal: fixture.principal, Request: unrelatedRequest, Publications: []signedHypothesisPublication{unrelated},
			From: fixture.from, To: fixture.to, Now: fixture.now,
			ExpectedStatus: hypothesisUntested, ExpectedBindingsBound: true,
		},
		{
			ID: "04-conflicting", Split: hypothesisEvaluationHoldoutFixture,
			Principal: fixture.principal, Request: conflictingRequest, Publications: conflictingPublications,
			From: fixture.from, To: fixture.to, Now: fixture.now,
			ExpectedStatus: hypothesisConflicting, ExpectedBindingsBound: true,
		},
		{
			ID: "05-no-observations", Split: hypothesisEvaluationHoldoutFixture,
			Principal: fixture.principal, Request: fixture.request,
			From: fixture.from, To: fixture.to, Now: fixture.now,
			ExpectedStatus: hypothesisUntested, ExpectedBindingsBound: false,
		},
		{
			ID: "06-unbound-reference", Split: hypothesisEvaluationHoldoutFixture,
			Principal: fixture.principal, Request: fixture.request, Publications: []signedHypothesisPublication{unbound},
			From: fixture.from, To: fixture.to, Now: fixture.now,
			ExpectedError: ErrInvalidRequest, ExpectedBindingsBound: false,
		},
		{
			ID: "07-wrong-signer", Split: hypothesisEvaluationHoldoutFixture,
			Principal: fixture.principal, Request: fixture.request, Publications: []signedHypothesisPublication{wrongSigner},
			From: fixture.from, To: fixture.to, Now: fixture.now,
			ExpectedError: ErrAuthorityRejected, ExpectedBindingsBound: true,
		},
	}
}

func TestHypothesisEvaluationReportIsDeterministicAndSeparatesMetrics(t *testing.T) {
	cases := evaluationReportCases(t)
	report, err := buildHypothesisEvaluationReport("sre-deployment-correlation-v1", cases)
	if err != nil {
		t.Fatal(err)
	}
	if report.DatasetKind != hypothesisEvaluationFixtureOnly || report.ScenarioCount != 7 ||
		report.PassedCount != 7 || report.FailedCount != 0 || report.AcceptedCount != 5 ||
		report.AbstentionCount != 4 || report.EvidenceBindingCaseCount != 6 ||
		report.EvidenceBindingCaseMatches != 6 || report.EvidenceBindingAccuracyBasisPoints != 10000 ||
		report.ScenarioPassRateBasisPoints != 10000 || report.AbstentionRateBasisPoints != 8000 {
		t.Fatalf("unexpected evaluation report: %+v", report)
	}
	if len(report.Cases) != len(cases) || report.Cases[0].ID != "01-supported" ||
		report.Cases[len(report.Cases)-1].ID != "07-wrong-signer" {
		t.Fatalf("report cases are not in stable ID order: %+v", report.Cases)
	}

	reversed := append([]hypothesisEvaluationCase{}, cases...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	reordered, err := buildHypothesisEvaluationReport("sre-deployment-correlation-v1", reversed)
	if err != nil || !reflect.DeepEqual(report, reordered) {
		t.Fatalf("dataset order changed report: first=%+v reordered=%+v err=%v", report, reordered, err)
	}
}

func TestHypothesisEvaluationReportDetectsIncorrectBindingExpectation(t *testing.T) {
	cases := evaluationReportCases(t)
	cases[5].ExpectedBindingsBound = true
	report, err := buildHypothesisEvaluationReport("sre-deployment-correlation-v1", cases)
	if err != nil {
		t.Fatal(err)
	}
	if report.PassedCount != 6 || report.FailedCount != 1 ||
		report.EvidenceBindingCaseMatches != 5 || report.EvidenceBindingAccuracyBasisPoints != 8333 {
		t.Fatalf("binding expectation mismatch was not reported: %+v", report)
	}
}


func TestHypothesisEvaluationReportMarksUnmeasuredBindingAndSerializesFalse(t *testing.T) {
	cases := evaluationReportCases(t)
	cases = cases[4:5]
	report, err := buildHypothesisEvaluationReport("empty-binding-fixture", cases)
	if err != nil {
		t.Fatal(err)
	}
	if report.EvidenceBindingAccuracyMeasured || report.EvidenceBindingCaseCount != 0 ||
		report.EvidenceBindingAccuracyBasisPoints != 0 {
		t.Fatalf("empty binding denominator must be explicitly unmeasured: %+v", report)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"evidence_binding_checked":false`) ||
		!strings.Contains(string(encoded), `"expected_bindings_bound":false`) ||
		!strings.Contains(string(encoded), `"actual_bindings_bound":false`) {
		t.Fatalf("report omitted explicit false binding state: %s", encoded)
	}
}

func TestHypothesisEvaluationReportRejectsInvalidDataset(t *testing.T) {
	valid := evaluationReportCases(t)
	for _, tc := range []struct {
		name string
		datasetID string
		cases []hypothesisEvaluationCase
	}{
		{"empty_dataset_id", "", valid},
		{"duplicate_case_id", "sre-deployment-correlation-v1", append(append([]hypothesisEvaluationCase{}, valid...), valid[0])},
		{"unknown_split", "sre-deployment-correlation-v1", func() []hypothesisEvaluationCase {
			out := append([]hypothesisEvaluationCase{}, valid...)
			out[0].Split = "UNCONTROLLED"
			return out
		}()},
		{"missing_expected_outcome", "sre-deployment-correlation-v1", func() []hypothesisEvaluationCase {
			out := append([]hypothesisEvaluationCase{}, valid...)
			out[0].ExpectedStatus = ""
			return out
		}()},
		{"binding_expectation_without_publication", "sre-deployment-correlation-v1", func() []hypothesisEvaluationCase {
			out := append([]hypothesisEvaluationCase{}, valid...)
			out[4].ExpectedBindingsBound = true
			return out
		}()},
		{"ambiguous_expected_outcome", "sre-deployment-correlation-v1", func() []hypothesisEvaluationCase {
			out := append([]hypothesisEvaluationCase{}, valid...)
			out[0].ExpectedError = errors.New("unexpected")
			return out
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildHypothesisEvaluationReport(tc.datasetID, tc.cases)
			if !errors.Is(err, ErrInvalidRequest) || !reflect.DeepEqual(got, hypothesisEvaluationReport{}) {
				t.Fatalf("invalid dataset accepted: report=%+v err=%v", got, err)
			}
		})
	}
}
