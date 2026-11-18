package decision

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"
)

const EvidencePublicationSchema = "sre.evidence-publication.v1"
const maxEvidenceContent = 256 * 1024
const maxEvidenceWire = 512 * 1024

// EvidenceSourceScope is provisioned by the independent source owner and
// verifier, not by an Agent, Decision caller or ACP publication. One exact
// source/version/kind/resource and Run scope; no wildcard authority.
type EvidenceSourceScope struct {
	TenantID      string
	AgentID       string
	RunID         string
	Service       string
	ResourceRef   string
	SourceID      string
	Source        string
	SourceVersion string
	EvidenceType  string
	SchemaVersion string
	MaxAge        time.Duration
	MaxLifetime   time.Duration
}

// EvidenceObservation is trusted collector metadata. It does not contain a
// claimed content digest, attestation, signature, or trust level.
type EvidenceObservation struct {
	Ref          string
	ObservedFrom time.Time
	ObservedTo   time.Time
	ObservedAt   time.Time
	CollectedAt  time.Time
	ExpiresAt    time.Time
}

type evidencePublication struct {
	SchemaVersion string      `json:"schema_version"`
	Reference     EvidenceRef `json:"reference"`
	Content       []byte      `json:"content"`
}

type signedEvidence struct {
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func evidenceScopeMatches(scope EvidenceSourceScope, e EvidenceRef, now time.Time) bool {
	req := Request{Identity: Identity{AgentID: scope.AgentID, RunID: scope.RunID}, Input: Input{Service: scope.Service}}
	return !now.IsZero() && scope.MaxAge > 0 && scope.MaxAge <= 24*time.Hour &&
		scope.MaxLifetime > 0 && scope.MaxLifetime <= 24*time.Hour &&
		nameRe.MatchString(scope.TenantID) && nameRe.MatchString(scope.AgentID) &&
		acpUUID.MatchString(scope.RunID) && nameRe.MatchString(scope.Service) &&
		validEvidence(e, req) && e.TenantID == scope.TenantID && e.AgentID == scope.AgentID &&
		e.RunID == scope.RunID && e.Service == scope.Service && e.ResourceRef == scope.ResourceRef &&
		e.SourceID == scope.SourceID && e.Source == scope.Source && e.SourceVersion == scope.SourceVersion &&
		e.EvidenceType == scope.EvidenceType && e.SchemaVersion == scope.SchemaVersion &&
		!e.ObservedFrom.Before(now.Add(-scope.MaxAge)) &&
		!e.CollectedAt.After(now) && now.Before(e.ExpiresAt) &&
		e.ExpiresAt.Sub(e.CollectedAt) <= scope.MaxLifetime
}

func evidenceAttestation(keyID, source, ref string) string {
	return "evidence:v1:" + keyID + ":" + acpHash([]byte(source+"\x00"+ref))
}

// PublishEvidence belongs to the independent source process. The caller
// supplies actual collector-owned observations; this function never queries
// or invents telemetry and never issues a Permit. Source key custody is a
// deployment requirement. The returned proof must enter the source's live
// append-only publication/revocation registry before use by Decision.
func PublishEvidence(scope EvidenceSourceScope, observation EvidenceObservation, content []byte, key ed25519.PrivateKey, now time.Time) (EvidenceRef, []byte, error) {
	fail := func() (EvidenceRef, []byte, error) {
		return EvidenceRef{}, nil, fmt.Errorf("%w: invalid source observation", ErrAuthorityRejected)
	}
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key.Seed())) ||
		len(content) == 0 || len(content) > maxEvidenceContent {
		return fail()
	}
	keyID := acpHash(key.Public().(ed25519.PublicKey))
	ref := EvidenceRef{
		Ref: observation.Ref, EvidenceType: scope.EvidenceType, SchemaVersion: scope.SchemaVersion,
		TenantID: scope.TenantID, AgentID: scope.AgentID, RunID: scope.RunID, Service: scope.Service,
		ResourceRef: scope.ResourceRef, SourceID: scope.SourceID, Source: scope.Source, SourceVersion: scope.SourceVersion,
		SHA256: acpHash(content), AttestationRef: evidenceAttestation(keyID, scope.SourceID, observation.Ref),
		TrustLevel: "attested", ObservedFrom: observation.ObservedFrom.UTC(), ObservedTo: observation.ObservedTo.UTC(),
		ObservedAt: observation.ObservedAt.UTC(), CollectedAt: observation.CollectedAt.UTC(), ExpiresAt: observation.ExpiresAt.UTC(),
		RevocationState: "active",
	}
	if !evidenceScopeMatches(scope, ref, now) {
		return fail()
	}
	payload, err := json.Marshal(evidencePublication{SchemaVersion: EvidencePublicationSchema, Reference: ref, Content: bytes.Clone(content)})
	if err != nil {
		return fail()
	}
	wire, err := json.Marshal(signedEvidence{KeyID: keyID, Payload: payload, Signature: ed25519.Sign(key, payload)})
	if err != nil || len(wire) > maxEvidenceWire {
		return fail()
	}
	return ref, wire, nil
}

// VerifyEvidencePublication independently checks the full signed observation,
// source pin, exact reference, immutable bytes and bounded timestamps. It
// cannot determine revocation from old signed bytes; the caller must obtain a
// fresh current proof from the independent source registry on every new turn.
func VerifyEvidencePublication(wire []byte, key ed25519.PublicKey, scope EvidenceSourceScope, expected EvidenceRef, now time.Time) error {
	fail := func() error { return fmt.Errorf("%w: invalid source evidence publication", ErrAuthorityRejected) }
	if len(key) != ed25519.PublicKeySize || !evidenceScopeMatches(scope, expected, now) {
		return fail()
	}
	var signed signedEvidence
	if !decodeACP(bytes.TrimSpace(wire), maxEvidenceWire, &signed, true) || signed.KeyID != acpHash(key) ||
		len(signed.Signature) != ed25519.SignatureSize || !ed25519.Verify(key, signed.Payload, signed.Signature) {
		return fail()
	}
	var proof evidencePublication
	if !decodeACP(signed.Payload, maxEvidenceWire, &proof, true) ||
		proof.SchemaVersion != EvidencePublicationSchema || len(proof.Content) == 0 ||
		len(proof.Content) > maxEvidenceContent || proof.Reference.SHA256 != acpHash(proof.Content) ||
		proof.Reference.AttestationRef != evidenceAttestation(signed.KeyID, scope.SourceID, expected.Ref) ||
		!evidenceScopeMatches(scope, proof.Reference, now) {
		return fail()
	}
	// Scope + every metadata field must match, including exact observation
	// interval, source, resource, attestation and expiration. JSON compare
	// avoids time.Time internal location differences.
	want, err := json.Marshal(expected)
	if err != nil {
		return fail()
	}
	got, err := json.Marshal(proof.Reference)
	if err != nil || !bytes.Equal(want, got) {
		return fail()
	}
	return nil
}
