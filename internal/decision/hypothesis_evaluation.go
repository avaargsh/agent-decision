package decision

import (
	"errors"
	"sort"
	"time"
)

const (
	hypothesisEvaluationReportSchema = "sre.hypothesis-evaluation-report.v2"
	hypothesisEvaluationFixtureOnly = "SYNTHETIC_CONTRACT_FIXTURES_ONLY"
)

type hypothesisEvaluationSplit string

const (
	hypothesisEvaluationGoldFixture hypothesisEvaluationSplit = "GOLD_FIXTURE"
	hypothesisEvaluationHoldoutFixture hypothesisEvaluationSplit = "HOLDOUT_FIXTURE"
)

type hypothesisEvaluationCase struct {
	ID string
	Split hypothesisEvaluationSplit
	Principal Principal
	Request Request
	Publications []signedHypothesisPublication
	From, To, Now time.Time
	ExpectedStatus hypothesisStatus
	ExpectedError error
	ExpectedBindingsBound bool
	ExpectedAbstentionReasons []hypothesisAbstentionReason
}

type hypothesisEvaluationCaseResult struct {
	ID string `json:"id"`
	Split hypothesisEvaluationSplit `json:"split"`
	ExpectedStatus hypothesisStatus `json:"expected_status,omitempty"`
	ActualStatus string `json:"actual_status"`
	ExpectedErrorClass string `json:"expected_error_class,omitempty"`
	ActualErrorClass string `json:"actual_error_class,omitempty"`
	AbstentionReasons []hypothesisAbstentionReason `json:"abstention_reasons"`
	Passed bool `json:"passed"`
	EvidenceBindingChecked bool `json:"evidence_binding_checked"`
	ExpectedBindingsBound bool `json:"expected_bindings_bound"`
	ActualBindingsBound bool `json:"actual_bindings_bound"`
}

type hypothesisEvaluationStatusCount struct {
	Status string `json:"status"`
	Count int `json:"count"`
}

type hypothesisEvaluationSplitSummary struct {
	Split hypothesisEvaluationSplit `json:"split"`
	ScenarioCount int `json:"scenario_count"`
	PassedCount int `json:"passed_count"`
	FailedCount int `json:"failed_count"`
	AcceptedCount int `json:"accepted_count"`
	RejectedCount int `json:"rejected_count"`
	AbstentionCount int `json:"abstention_count"`
	AbstentionReasonCaseCount int `json:"abstention_reason_case_count"`
	AbstentionReasonCaseMatches int `json:"abstention_reason_case_matches"`
	AbstentionReasonAccuracyMeasured bool `json:"abstention_reason_accuracy_measured"`
	AbstentionReasonAccuracyBasisPoints int `json:"abstention_reason_accuracy_basis_points"`
}

type hypothesisEvaluationReport struct {
	SchemaVersion string `json:"schema_version"`
	DatasetID string `json:"dataset_id"`
	DatasetKind string `json:"dataset_kind"`
	ScenarioCount int `json:"scenario_count"`
	PassedCount int `json:"passed_count"`
	FailedCount int `json:"failed_count"`
	ScenarioPassRateBasisPoints int `json:"scenario_pass_rate_basis_points"`
	AcceptedCount int `json:"accepted_count"`
	RejectedCount int `json:"rejected_count"`
	AbstentionCount int `json:"abstention_count"`
	AbstentionRateMeasured bool `json:"abstention_rate_measured"`
	AbstentionRateBasisPoints int `json:"abstention_rate_basis_points"`
	EvidenceBindingCaseCount int `json:"evidence_binding_case_count"`
	EvidenceBindingCaseMatches int `json:"evidence_binding_case_matches"`
	EvidenceBindingAccuracyMeasured bool `json:"evidence_binding_accuracy_measured"`
	EvidenceBindingAccuracyBasisPoints int `json:"evidence_binding_accuracy_basis_points"`
	StatusCounts []hypothesisEvaluationStatusCount `json:"status_counts"`
	SplitSummaries []hypothesisEvaluationSplitSummary `json:"split_summaries"`
	Cases []hypothesisEvaluationCaseResult `json:"cases"`
}

// buildHypothesisEvaluationReport evaluates explicitly labelled offline
// fixtures. GOLD_FIXTURE and HOLDOUT_FIXTURE are fixture splits only: this
// report must never be represented as a human-reviewed incident benchmark.
func buildHypothesisEvaluationReport(datasetID string, cases []hypothesisEvaluationCase) (hypothesisEvaluationReport, error) {
	if !nameRe.MatchString(datasetID) || len(cases) == 0 || len(cases) > 256 {
		return hypothesisEvaluationReport{}, ErrInvalidRequest
	}
	seen := make(map[string]struct{}, len(cases))
	for _, item := range cases {
		if !nameRe.MatchString(item.ID) {
			return hypothesisEvaluationReport{}, ErrInvalidRequest
		}
		if _, exists := seen[item.ID]; exists {
			return hypothesisEvaluationReport{}, ErrInvalidRequest
		}
		seen[item.ID] = struct{}{}
		if item.Split != hypothesisEvaluationGoldFixture && item.Split != hypothesisEvaluationHoldoutFixture {
			return hypothesisEvaluationReport{}, ErrInvalidRequest
		}
		if !validHypothesisAbstentionReasons(item.ExpectedAbstentionReasons) ||
			(item.ExpectedError != nil && len(item.ExpectedAbstentionReasons) != 0) {
			return hypothesisEvaluationReport{}, ErrInvalidRequest
		}
		if len(item.Publications) == 0 && item.ExpectedBindingsBound {
			return hypothesisEvaluationReport{}, ErrInvalidRequest
		}
		if item.ExpectedError != nil {
			if item.ExpectedStatus != "" ||
				(!errors.Is(item.ExpectedError, ErrInvalidRequest) && !errors.Is(item.ExpectedError, ErrAuthorityRejected)) {
				return hypothesisEvaluationReport{}, ErrInvalidRequest
			}
		} else if !validHypothesisStatus(item.ExpectedStatus) {
			return hypothesisEvaluationReport{}, ErrInvalidRequest
		}
	}

	report := hypothesisEvaluationReport{
		SchemaVersion: hypothesisEvaluationReportSchema,
		DatasetID: datasetID,
		DatasetKind: hypothesisEvaluationFixtureOnly,
		ScenarioCount: len(cases),
		StatusCounts: []hypothesisEvaluationStatusCount{
			{Status: string(hypothesisSupported)},
			{Status: string(hypothesisContradicted)},
			{Status: string(hypothesisConflicting)},
			{Status: string(hypothesisInsufficient)},
			{Status: string(hypothesisUntested)},
			{Status: "REJECTED"},
		},
		SplitSummaries: []hypothesisEvaluationSplitSummary{
			{Split: hypothesisEvaluationGoldFixture},
			{Split: hypothesisEvaluationHoldoutFixture},
		},
		Cases: make([]hypothesisEvaluationCaseResult, 0, len(cases)),
	}
	statusIndex := make(map[string]int, len(report.StatusCounts))
	for i := range report.StatusCounts {
		statusIndex[report.StatusCounts[i].Status] = i
	}
	splitIndex := map[hypothesisEvaluationSplit]int{
		hypothesisEvaluationGoldFixture: 0,
		hypothesisEvaluationHoldoutFixture: 1,
	}

	for _, item := range cases {
		actual, evalErr := evaluateOfflineDeploymentHypothesis(
			item.Principal, item.Request, item.Publications, item.From, item.To, item.Now,
		)
		actualStatus := "REJECTED"
		actualReasons := []hypothesisAbstentionReason{}
		if evalErr == nil {
			actualStatus = string(actual.Status)
			actualReasons = append(actualReasons, actual.AbstentionReasons...)
			report.AcceptedCount++
		} else {
			report.RejectedCount++
		}

		passed := false
		if item.ExpectedError != nil {
			passed = errors.Is(evalErr, item.ExpectedError)
		} else {
			passed = evalErr == nil && actual.Status == item.ExpectedStatus &&
				sameHypothesisAbstentionReasons(actualReasons, item.ExpectedAbstentionReasons)
		}
		if evalErr == nil {
			report.AbstentionReasonCaseCount++
			if sameHypothesisAbstentionReasons(actualReasons, item.ExpectedAbstentionReasons) {
				report.AbstentionReasonCaseMatches++
			} else {
				passed = false
			}
		}

		bindingChecked := len(item.Publications) > 0
		actualBound := hypothesisPublicationsBoundToRequest(item.Request, item.Publications)
		if bindingChecked {
			report.EvidenceBindingCaseCount++
			if actualBound == item.ExpectedBindingsBound {
				report.EvidenceBindingCaseMatches++
			} else {
				passed = false
			}
		}
		if passed {
			report.PassedCount++
		} else {
			report.FailedCount++
		}

		report.StatusCounts[statusIndex[actualStatus]].Count++
		split := &report.SplitSummaries[splitIndex[item.Split]]
		split.ScenarioCount++
		if passed {
			split.PassedCount++
		} else {
			split.FailedCount++
		}
		if evalErr == nil {
			split.AcceptedCount++
			if isHypothesisAbstention(actual.Status) {
				report.AbstentionCount++
				split.AbstentionCount++
			}
		} else {
			split.RejectedCount++
		}

		report.Cases = append(report.Cases, hypothesisEvaluationCaseResult{
			ID: item.ID,
			Split: item.Split,
			ExpectedStatus: item.ExpectedStatus,
			ActualStatus: actualStatus,
			ExpectedErrorClass: hypothesisEvaluationErrorClass(item.ExpectedError),
			ActualErrorClass: hypothesisEvaluationErrorClass(evalErr),
			AbstentionReasons: actualReasons,
			Passed: passed,
			EvidenceBindingChecked: bindingChecked,
			ExpectedBindingsBound: item.ExpectedBindingsBound,
			ActualBindingsBound: actualBound,
		})
	}

	if report.ScenarioCount > 0 {
		report.ScenarioPassRateBasisPoints = report.PassedCount * 10000 / report.ScenarioCount
	}
	if report.AcceptedCount > 0 {
		report.AbstentionRateMeasured = true
		report.AbstentionRateBasisPoints = report.AbstentionCount * 10000 / report.AcceptedCount
	}
	if report.EvidenceBindingCaseCount > 0 {
		report.EvidenceBindingAccuracyMeasured = true
		report.EvidenceBindingAccuracyBasisPoints = report.EvidenceBindingCaseMatches * 10000 / report.EvidenceBindingCaseCount
	}
	if report.AbstentionReasonCaseCount > 0 {
		report.AbstentionReasonAccuracyMeasured = true
		report.AbstentionReasonAccuracyBasisPoints = report.AbstentionReasonCaseMatches * 10000 / report.AbstentionReasonCaseCount
	}
	sort.Slice(report.Cases, func(i, j int) bool { return report.Cases[i].ID < report.Cases[j].ID })
	return report, nil
}

func validHypothesisStatus(status hypothesisStatus) bool {
	switch status {
	case hypothesisSupported, hypothesisContradicted, hypothesisConflicting, hypothesisInsufficient, hypothesisUntested:
		return true
	default:
		return false
	}
}

func isHypothesisAbstention(status hypothesisStatus) bool {
	return status == hypothesisConflicting || status == hypothesisInsufficient || status == hypothesisUntested
}

func hypothesisEvaluationErrorClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest):
		return "INVALID_REQUEST"
	case errors.Is(err, ErrAuthorityRejected):
		return "AUTHORITY_REJECTED"
	case errors.Is(err, ErrAuthorityUnavailable):
		return "AUTHORITY_UNAVAILABLE"
	default:
		return "OTHER"
	}
}

func hypothesisPublicationsBoundToRequest(req Request, publications []signedHypothesisPublication) bool {
	if len(publications) == 0 {
		return false
	}
	byBinding := make(map[EvidenceBinding]EvidenceRef, len(req.Evidence))
	for _, evidence := range req.Evidence {
		key := EvidenceBinding{SourceID: evidence.SourceID, Ref: evidence.Ref}
		if _, exists := byBinding[key]; exists {
			return false
		}
		byBinding[key] = evidence
	}
	seen := make(map[EvidenceBinding]struct{}, len(publications))
	for _, publication := range publications {
		evidence := publication.Expected
		key := EvidenceBinding{SourceID: evidence.SourceID, Ref: evidence.Ref}
		bound, exists := byBinding[key]
		if !exists || bound != evidence {
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}
