package decision

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// The private content extractor must apply the same verification as the
// publication verifier. This is not a revocation lookup or a live fact source.
func TestVerifiedEvidencePublicationContent(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := EvidenceSourceScope{
		TenantID: "tenant-a", AgentID: "agent-1", RunID: "11111111-1111-4111-8111-111111111111",
		Service: "payments", ResourceRef: "service:payments", SourceID: "metrics-collector-1",
		Source: "metrics-collector", SourceVersion: "1.0.0", EvidenceType: "metrics", SchemaVersion: "1.0.0",
		MaxAge: 15 * time.Minute, MaxLifetime: 10 * time.Minute,
	}
	obs := EvidenceObservation{
		Ref: "sample-1", ObservedFrom: now.Add(-time.Minute), ObservedTo: now,
		ObservedAt: now, CollectedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	content := []byte("http_requests_total 7\n")
	ref, wire, err := PublishEvidence(scope, obs, content, key, now)
	if err != nil {
		t.Fatal(err)
	}
	originalWire := bytes.Clone(wire)
	got, err := verifyEvidencePublicationContent(wire, pub, scope, ref, now)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("verified content=%q err=%v", got, err)
	}
	got[0] ^= 0xff
	again, err := verifyEvidencePublicationContent(wire, pub, scope, ref, now)
	if err != nil || !bytes.Equal(again, content) || !bytes.Equal(wire, originalWire) {
		t.Fatal("returned content aliases input or later result")
	}

	wrongKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongRef := ref
	wrongRef.RunID = "22222222-2222-4222-8222-222222222222"
	var signed signedEvidence
	if err := json.Unmarshal(wire, &signed); err != nil {
		t.Fatal(err)
	}
	var proof evidencePublication
	if err := json.Unmarshal(signed.Payload, &proof); err != nil {
		t.Fatal(err)
	}
	proof.Content = []byte("http_requests_total 999\n")
	signed.Payload, err = json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature = ed25519.Sign(key, signed.Payload)
	forged, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		wire []byte
		key ed25519.PublicKey
		ref EvidenceRef
		now time.Time
	}{
		{"wrong_signer", wire, wrongKey, ref, now},
		{"cross_run", wire, pub, wrongRef, now},
		{"expired", wire, pub, ref, obs.ExpiresAt},
		{"signed_content_digest_mismatch", forged, pub, ref, now},
		{"malformed", []byte("{}"), pub, ref, now},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := verifyEvidencePublicationContent(tc.wire, tc.key, scope, tc.ref, tc.now)
			if got != nil || !errors.Is(err, ErrAuthorityRejected) {
				t.Fatalf("invalid proof released content: %q %v", got, err)
			}
			if err := VerifyEvidencePublication(tc.wire, tc.key, scope, tc.ref, tc.now); !errors.Is(err, ErrAuthorityRejected) {
				t.Fatalf("public verification disagrees: %v", err)
			}
		})
	}
}
