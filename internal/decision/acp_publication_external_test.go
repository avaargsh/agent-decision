package decision

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// This test driver is invoked by the ACP real issuer / real PostgreSQL /
// mTLS service integration. It never signs the artifact itself. The public
// key and expected binding are provisioned by the isolated harness, not
// decoded from the untrusted publication.
func TestExternalACPSignedPublication(t *testing.T) {
	if os.Getenv("DECISION_EXTERNAL_ACP_PUBLICATION") != "1" {
		t.Skip("external real ACP service acceptance only")
	}
	read := func(name string) []byte {
		t.Helper()
		path := os.Getenv(name)
		if path == "" {
			t.Fatalf("external verifier requires %s", name)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	wire := read("DECISION_PUBLICATION_FILE")
	key := ed25519.PublicKey(read("DECISION_ACP_PINNED_KEY_FILE"))
	var expected ACPRunBinding
	if err := json.Unmarshal(read("DECISION_EXPECTED_BINDING_FILE"), &expected); err != nil {
		t.Fatal(err)
	}
	got, err := VerifyACPPublication(wire, key, expected, time.Now().UTC())
	if err != nil || got.Input.Objective != "sre_incident_triage" || got.Input.Service != "payments" ||
		len(got.Capabilities) != 3 || got.ContextSnapshot.SHA256 == "" ||
		got.CapabilitySnapshot.SHA256 != expected.ConfigDigest[len("sha256:"):] {
		t.Fatalf("actual ACP publication rejected: %+v %v", got, err)
	}
	changed := expected
	changed.RunID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := VerifyACPPublication(wire, key, changed, time.Now()); err == nil {
		t.Fatal("signed publication replayed for another Run")
	}
	var signed signedACP
	if err := json.Unmarshal(wire, &signed); err != nil {
		t.Fatal(err)
	}
	signed.Payload = bytes.Replace(signed.Payload, []byte("payments"), []byte("changed-service"), 1)
	tampered, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyACPPublication(tampered, key, expected, time.Now()); err == nil {
		t.Fatal("tampered ACP publication was accepted")
	}
	other := append(ed25519.PublicKey(nil), key...)
	other[0] ^= 1
	if _, err := VerifyACPPublication(wire, other, expected, time.Now()); err == nil {
		t.Fatal("untrusted public key accepted")
	}
	if _, err := VerifyACPPublication(wire, key, expected, got.ContextSnapshot.ExpiresAt); err == nil {
		t.Fatal("expired signed publication accepted")
	}
	// Even with the real signature, the digest pinned in the Runtime binding
	// must not be substituted with another release.
	changed = expected
	sum := sha256.Sum256([]byte("other release"))
	changed.ConfigDigest = "sha256:" + hex.EncodeToString(sum[:])
	if _, err := VerifyACPPublication(wire, key, changed, time.Now()); err == nil {
		t.Fatal("different Runtime config digest accepted")
	}
	t.Logf("independent Decision process verified actual ACP signed publication for Run %s", expected.RunID)
}
