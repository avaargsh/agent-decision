package decision

type hypothesisAbstentionReason string

const (
	hypothesisAbstentionMissingSymptomObservation hypothesisAbstentionReason = "MISSING_SYMPTOM_OBSERVATION"
	hypothesisAbstentionMissingDeploymentObservation hypothesisAbstentionReason = "MISSING_DEPLOYMENT_OBSERVATION"
	hypothesisAbstentionConflictingSymptomObservations hypothesisAbstentionReason = "CONFLICTING_SYMPTOM_OBSERVATIONS"
	hypothesisAbstentionConflictingDeploymentObservations hypothesisAbstentionReason = "CONFLICTING_DEPLOYMENT_OBSERVATIONS"
	hypothesisAbstentionNoRelevantEvidence hypothesisAbstentionReason = "NO_RELEVANT_EVIDENCE"
)

func hypothesisAbstentionReasonRank(reason hypothesisAbstentionReason) int {
	switch reason {
	case hypothesisAbstentionMissingSymptomObservation:
		return 0
	case hypothesisAbstentionMissingDeploymentObservation:
		return 1
	case hypothesisAbstentionConflictingSymptomObservations:
		return 2
	case hypothesisAbstentionConflictingDeploymentObservations:
		return 3
	case hypothesisAbstentionNoRelevantEvidence:
		return 4
	default:
		return -1
	}
}

func validHypothesisAbstentionReasons(reasons []hypothesisAbstentionReason) bool {
	lastRank := -1
	for _, reason := range reasons {
		rank := hypothesisAbstentionReasonRank(reason)
		if rank <= lastRank {
			return false
		}
		lastRank = rank
	}
	return true
}

func sameHypothesisAbstentionReasons(a, b []hypothesisAbstentionReason) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
