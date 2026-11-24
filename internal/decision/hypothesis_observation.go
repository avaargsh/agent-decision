package decision

import (
	"crypto/ed25519"
	"time"
)

const hypothesisObservationSchema = "sre.hypothesis-observation.v1"
const maxHypothesisObservationBytes = 4096

type hypothesisObservationContent struct {
	SchemaVersion string         `json:"schema_version"`
	Signal        string         `json:"signal"`
	ObservedFrom  time.Time      `json:"observed_from"`
	ObservedTo    time.Time      `json:"observed_to"`
	Fact          hypothesisFact `json:"fact"`
}

// decodeVerifiedHypothesisObservation converts an independently signed typed
// assertion into offline evaluator input. The caller must supply the pinned
// source, expected signal and common investigation window from trusted context.
// A signature binds the assertion to its source, not its truth or causality.
// This does not fetch live revocation state or participate in live decisions.
func decodeVerifiedHypothesisObservation(wire []byte, key ed25519.PublicKey, scope EvidenceSourceScope, expected EvidenceRef, signal string, from, to, now time.Time) (hypothesisObservation, error) {
	if (signal != "latency" && signal != "errors" && signal != "saturation") ||
		from.IsZero() || !to.After(from) ||
		!expected.ObservedFrom.Equal(from) || !expected.ObservedTo.Equal(to) {
		return hypothesisObservation{}, ErrAuthorityRejected
	}
	content, err := verifyEvidencePublicationContent(wire, key, scope, expected, now)
	if err != nil {
		return hypothesisObservation{}, err
	}
	var typed hypothesisObservationContent
	if !decodeACP(content, maxHypothesisObservationBytes, &typed, true) ||
		typed.SchemaVersion != hypothesisObservationSchema ||
		typed.Signal != signal || !typed.ObservedFrom.Equal(from) || !typed.ObservedTo.Equal(to) {
		return hypothesisObservation{}, ErrAuthorityRejected
	}
	switch typed.Fact {
	case symptomIncreased, symptomNotIncreased:
		if expected.EvidenceType != "metrics" && expected.EvidenceType != "slo" {
			return hypothesisObservation{}, ErrAuthorityRejected
		}
	case deploymentPrecedesSymptom, noDeploymentInWindow:
		if expected.EvidenceType != "change" {
			return hypothesisObservation{}, ErrAuthorityRejected
		}
	case unrelatedObservation:
	default:
		return hypothesisObservation{}, ErrAuthorityRejected
	}
	return hypothesisObservation{Evidence: expected, Fact: typed.Fact}, nil
}
