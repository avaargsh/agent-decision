package decision

import (
	"sort"
	"time"
)

type hypothesisFact string

const (
	symptomIncreased          hypothesisFact = "SYMPTOM_INCREASED"
	symptomNotIncreased       hypothesisFact = "SYMPTOM_NOT_INCREASED"
	deploymentPrecedesSymptom hypothesisFact = "DEPLOYMENT_PRECEDES_SYMPTOM"
	noDeploymentInWindow      hypothesisFact = "NO_DEPLOYMENT_IN_WINDOW"
	unrelatedObservation      hypothesisFact = "UNRELATED"
)

type hypothesisStatus string

const (
	hypothesisUntested     hypothesisStatus = "UNTESTED"
	hypothesisInsufficient hypothesisStatus = "INSUFFICIENT"
	hypothesisSupported    hypothesisStatus = "SUPPORTED"
	hypothesisContradicted hypothesisStatus = "CONTRADICTED"
	hypothesisConflicting  hypothesisStatus = "CONFLICTING"
)

type hypothesisObservation struct {
	Evidence EvidenceRef
	Fact     hypothesisFact
}

type hypothesisResult struct {
	ID               string
	Status           hypothesisStatus
	Assumptions      []string
	Supporting       []hypothesisObservation
	Contradicting    []hypothesisObservation
	Missing          []string
	AbstentionReasons []hypothesisAbstentionReason
}

// evaluateDeploymentHypothesis is an internal, offline evaluator. The caller
// must supply independently verified request evidence and trusted typed facts
// derived from the referenced content for the same symptom and time window.
// This function checks binding and scope, not signature or fact authenticity.
// It is deliberately not called by the live decision or authorization paths.
func evaluateDeploymentHypothesis(p Principal, req Request, observations []hypothesisObservation, now time.Time) (hypothesisResult, error) {
	if p.Validate() != nil || req.Validate() != nil ||
		p.AgentID != req.Identity.AgentID || p.SessionID != req.Identity.SessionID ||
		now.IsZero() || len(observations) > 32 {
		return hypothesisResult{}, ErrInvalidRequest
	}
	if _, err := requestFingerprint(p, req); err != nil {
		return hypothesisResult{}, ErrInvalidRequest
	}
	for _, snapshot := range []SnapshotRef{req.ContextSnapshot, req.CapabilitySnapshot} {
		if now.Before(snapshot.IssuedAt) || !now.Before(snapshot.ExpiresAt) {
			return hypothesisResult{}, ErrInvalidRequest
		}
	}
	byBinding := make(map[EvidenceBinding]EvidenceRef, len(req.Evidence))
	for _, evidence := range req.Evidence {
		if evidence.TenantID != p.TenantID || now.Before(evidence.CollectedAt) ||
			!now.Before(evidence.ExpiresAt) {
			return hypothesisResult{}, ErrInvalidRequest
		}
		byBinding[EvidenceBinding{SourceID: evidence.SourceID, Ref: evidence.Ref}] = evidence
	}
	result := hypothesisResult{
		ID: "deployment-correlation-v1",
		Assumptions: []string{
			"Typed observations refer to the same service, symptom and investigation window.",
			"Deployment correlation is a hypothesis, not proof of causation.",
		},
		Supporting:    []hypothesisObservation{},
		Contradicting: []hypothesisObservation{},
		Missing:           []string{},
		AbstentionReasons: []hypothesisAbstentionReason{},
	}
	seen := make(map[EvidenceBinding]struct{}, len(observations))
	var symptomYes, symptomNo, changeYes, changeNo bool
	for _, observation := range observations {
		e := observation.Evidence
		key := EvidenceBinding{SourceID: e.SourceID, Ref: e.Ref}
		bound, exists := byBinding[key]
		// Exact envelope equality is intentionally stricter than a reference
		// or digest match alone. Return owned values from the request.
		if !exists || bound != e {
			return hypothesisResult{}, ErrInvalidRequest
		}
		if _, duplicate := seen[key]; duplicate {
			return hypothesisResult{}, ErrInvalidRequest
		}
		seen[key] = struct{}{}
		item := hypothesisObservation{Evidence: bound, Fact: observation.Fact}
		switch observation.Fact {
		case symptomIncreased, symptomNotIncreased:
			if e.EvidenceType != "metrics" && e.EvidenceType != "slo" {
				return hypothesisResult{}, ErrInvalidRequest
			}
			if observation.Fact == symptomIncreased {
				symptomYes = true
				result.Supporting = append(result.Supporting, item)
			} else {
				symptomNo = true
				result.Contradicting = append(result.Contradicting, item)
			}
		case deploymentPrecedesSymptom, noDeploymentInWindow:
			if e.EvidenceType != "change" {
				return hypothesisResult{}, ErrInvalidRequest
			}
			if observation.Fact == deploymentPrecedesSymptom {
				changeYes = true
				result.Supporting = append(result.Supporting, item)
			} else {
				changeNo = true
				result.Contradicting = append(result.Contradicting, item)
			}
		case unrelatedObservation:
			// Valid but irrelevant evidence does not increase coverage.
		default:
			return hypothesisResult{}, ErrInvalidRequest
		}
	}
	if !symptomYes && !symptomNo {
		result.Missing = append(result.Missing, "SYMPTOM_OBSERVATION")
		result.AbstentionReasons = append(result.AbstentionReasons, hypothesisAbstentionMissingSymptomObservation)
	}
	if !changeYes && !changeNo {
		result.Missing = append(result.Missing, "DEPLOYMENT_OBSERVATION")
		result.AbstentionReasons = append(result.AbstentionReasons, hypothesisAbstentionMissingDeploymentObservation)
	}
	if symptomYes && symptomNo {
		result.AbstentionReasons = append(result.AbstentionReasons, hypothesisAbstentionConflictingSymptomObservations)
	}
	if changeYes && changeNo {
		result.AbstentionReasons = append(result.AbstentionReasons, hypothesisAbstentionConflictingDeploymentObservations)
	}
	if len(observations) > 0 && len(result.Supporting)+len(result.Contradicting) == 0 {
		result.AbstentionReasons = append(result.AbstentionReasons, hypothesisAbstentionNoRelevantEvidence)
	}
	switch {
	case (symptomYes && symptomNo) || (changeYes && changeNo):
		result.Status = hypothesisConflicting
	case symptomNo || changeNo:
		result.Status = hypothesisContradicted
	case symptomYes && changeYes:
		result.Status = hypothesisSupported
	case symptomYes || changeYes:
		result.Status = hypothesisInsufficient
	default:
		result.Status = hypothesisUntested
	}
	sortHypothesisObservations(result.Supporting)
	sortHypothesisObservations(result.Contradicting)
	return result, nil
}

func sortHypothesisObservations(observations []hypothesisObservation) {
	sort.Slice(observations, func(i, j int) bool {
		a, b := observations[i].Evidence, observations[j].Evidence
		if a.SourceID != b.SourceID {
			return a.SourceID < b.SourceID
		}
		return a.Ref < b.Ref
	})
}
