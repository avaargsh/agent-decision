package decision

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func TestIndependentEvidencePublicationBindsActualBytesAndSource(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
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
	observation := EvidenceObservation{
		Ref: "sample-1", ObservedFrom: now.Add(-time.Minute), ObservedTo: now,
		ObservedAt: now, CollectedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	content := []byte("http_requests_total{service=\"payments\",status=\"500\"} 7\n")
	ref, wire, err := PublishEvidence(scope, observation, content, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePublication(wire, pub, scope, ref, now); err != nil {
		t.Fatal(err)
	}
	again, replay, err := PublishEvidence(scope, observation, content, key, now.Add(time.Second))
	if err != nil || again != ref || !bytes.Equal(wire, replay) {
		t.Fatal("same observation did not yield stable signed artifact")
	}
	changed := ref
	changed.SourceVersion = "2.0.0"
	if err := VerifyEvidencePublication(wire, pub, scope, changed, now); err == nil {
		t.Fatal("caller-selected source version accepted")
	}
	changed = ref
	changed.RunID = "22222222-2222-4222-8222-222222222222"
	if err := VerifyEvidencePublication(wire, pub, scope, changed, now); err == nil {
		t.Fatal("cross-Run replay accepted")
	}
	var envelope signedEvidence
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	var proof evidencePublication
	if err := json.Unmarshal(envelope.Payload, &proof); err != nil {
		t.Fatal(err)
	}
	// Even a valid signature cannot attest bytes with the wrong digest.
	proof.Content = []byte("forged metrics")
	envelope.Payload, _ = json.Marshal(proof)
	envelope.Signature = ed25519.Sign(key, envelope.Payload)
	forged, _ := json.Marshal(envelope)
	if err := VerifyEvidencePublication(forged, pub, scope, ref, now); err == nil {
		t.Fatal("signed but content-substituted proof accepted")
	}
	wrongKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePublication(wire, wrongKey, scope, ref, now); err == nil {
		t.Fatal("untrusted evidence signer accepted")
	}
	if err := VerifyEvidencePublication(wire, pub, scope, ref, observation.ExpiresAt); err == nil {
		t.Fatal("expired evidence accepted")
	}
}
