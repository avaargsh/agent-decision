package decision

import (
	"crypto/ed25519"
	"time"
)

// signedHypothesisPublication is an offline evaluation input. Scope and key
// must be pinned by the source owner; Expected must come from the already
// verified DecisionRequest, never from the signed payload alone.
type signedHypothesisPublication struct {
	Wire      []byte
	PublicKey ed25519.PublicKey
	Scope     EvidenceSourceScope
	Expected  EvidenceRef
}

// evaluateOfflineDeploymentHypothesis composes signed typed-observation
// verification with the deterministic deployment-correlation evaluator.
// It is intentionally not wired into live decisions: offline signatures do
// not prove current registry revocation state. A production caller must fetch
// a fresh source-owned publication/revocation result before using any output.
// Supporting temporal correlation is not proof of causality.
func evaluateOfflineDeploymentHypothesis(
	principal Principal,
	req Request,
	publications []signedHypothesisPublication,
	from, to, now time.Time,
) (hypothesisResult, error) {
	if principal.Validate() != nil || req.Validate() != nil ||
		now.IsZero() || from.IsZero() || !to.After(from) || len(publications) > 32 {
		return hypothesisResult{}, ErrInvalidRequest
	}

	observations := make([]hypothesisObservation, 0, len(publications))
	for _, publication := range publications {
		observation, err := decodeVerifiedHypothesisObservation(
			publication.Wire,
			publication.PublicKey,
			publication.Scope,
			publication.Expected,
			req.Input.Signal,
			from,
			to,
			now,
		)
		if err != nil {
			return hypothesisResult{}, err
		}
		observations = append(observations, observation)
	}

	return evaluateDeploymentHypothesis(principal, req, observations, now)
}
