package decision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

type freshnessTransport func(*http.Request) (*http.Response, error)

func (f freshnessTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// The transport returns real signed, byte-bound publications but uses a
// deterministic clock instead of relying on wall-clock sleeps or remote TLS.
func TestLiveAuthorityRejectsInputsStaleAtFinalObservation(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		snapshotTTL, evidenceTTL time.Duration
		maxAge, delay            time.Duration
		wantReject               bool
	}{
		{"fresh", 10 * time.Minute, 10 * time.Minute, 5 * time.Minute, time.Minute, false},
		{"snapshot expiry", time.Minute, 10 * time.Minute, 5 * time.Minute, time.Minute, true},
		{"evidence expiry", 10 * time.Minute, time.Minute, 5 * time.Minute, time.Minute, true},
		{"evidence max age", 10 * time.Minute, 10 * time.Minute, 2 * time.Minute, time.Minute + time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
			now := start
			marshal := func(v any) []byte {
				t.Helper()
				b, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			acpKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
			sourceKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
			acpPub := acpKey.Public().(ed25519.PublicKey)
			input := Input{Objective: "sre_incident_triage", Service: "payments", Signal: "errors"}
			runtime := RuntimeDecisionAuthority{
				SchemaVersion: "runtime.decision-authority.v1",
				TenantID: "tenant-a", RunID: "11111111-1111-4111-8111-111111111111",
				RunIntentID: "22222222-2222-4222-8222-222222222222",
				ExecutionID: "33333333-3333-4333-8333-333333333333",
				AttemptID: "44444444-4444-4444-8444-444444444444",
				TurnID: "55555555-5555-4555-8555-555555555555",
				InvocationID: "55555555-5555-4555-8555-555555555555",
				AgentID: "agent-1", AgentReleaseID: "release-1", ProjectID: "project-1",
				SessionID: "session-1", SubjectID: "runtime", ActorID: "runtime",
				PolicyRevision: "policy-1", RequestDigest: "sha256:" + acpHash([]byte("request")),
				InputDigest: "sha256:" + acpHash(marshal(input)),
				Status: "RUNNING", Phase: "WAITING_AUTHORITY", BreakerState: "CLOSED",
				BreakerEpoch: 1, BreakerVersion: 1,
			}
			runtime.WorkflowID = "agent-run/v1/" + runtime.RunID
			release := acpRelease{
				SchemaVersion: "acp.release-publication.v1", TenantID: runtime.TenantID,
				ProjectID: runtime.ProjectID, AgentID: runtime.AgentID, AgentReleaseID: runtime.AgentReleaseID,
				PolicyRevision: runtime.PolicyRevision, CatalogVersion: "1.0.0",
				IssuedAt: start.Add(-time.Minute), ExpiresAt: start.Add(tc.snapshotTTL),
				Services: []string{input.Service}, Capabilities: []acpReleaseContract{},
			}
			releaseBytes := marshal(release)
			runtime.ConfigDigest = "sha256:" + acpHash(releaseBytes)
			binding := acpWireBinding{
				SchemaVersion: "acp.run-authority.v1", TenantID: runtime.TenantID,
				RunIntentID: runtime.RunIntentID, RunID: runtime.RunID, RequestDigest: runtime.RequestDigest,
				ProjectID: runtime.ProjectID, AgentID: runtime.AgentID, AgentReleaseID: runtime.AgentReleaseID,
				SessionID: runtime.SessionID, PrincipalID: "principal-1", SubjectID: runtime.SubjectID,
				ActorID: runtime.ActorID, PolicyRevision: runtime.PolicyRevision, ConfigDigest: runtime.ConfigDigest,
			}
			contextValue := acpContext{Authority: binding, Objective: input.Objective, Service: input.Service, Signal: input.Signal}
			contextBytes := marshal(contextValue)
			keyID := acpHash(acpPub)
			snapshot := func(kind, version string, content []byte) SnapshotRef {
				hash := acpHash(content)
				return SnapshotRef{
					ID: kind + "-" + hash, Version: version, SHA256: hash, Source: "agent-control-panel",
					AttestationRef: "acp:publication:" + keyID + ":" + runtime.RunID, TrustLevel: "attested",
					IssuedAt: release.IssuedAt, ExpiresAt: release.ExpiresAt,
				}
			}
			payload := marshal(acpPublication{
				SchemaVersion: "acp.decision-publication.v1", Authority: binding, Context: contextValue,
				ContextSnapshot: snapshot("ctx", "acp-context-v1", contextBytes),
				CapabilitySnapshot: snapshot("cap", release.CatalogVersion, releaseBytes),
				Capabilities: []CapabilityRef{}, ContextContent: contextBytes, CapabilityContent: releaseBytes,
			})
			acpWire := marshal(signedACP{KeyID: keyID, Payload: payload, Signature: ed25519.Sign(acpKey, payload)})
			scope := EvidenceSourceScope{
				TenantID: runtime.TenantID, AgentID: runtime.AgentID, RunID: runtime.RunID,
				Service: input.Service, ResourceRef: "service:payments", SourceID: "metrics-1",
				Source: "metrics", SourceVersion: "1.0.0", EvidenceType: "metrics", SchemaVersion: "1.0.0",
				MaxAge: tc.maxAge, MaxLifetime: 10 * time.Minute,
			}
			ref, proof, err := PublishEvidence(scope, EvidenceObservation{
				Ref: "sample-1", ObservedFrom: start.Add(-time.Minute), ObservedTo: start,
				ObservedAt: start, CollectedAt: start, ExpiresAt: start.Add(tc.evidenceTTL),
			}, []byte("errors=3"), sourceKey, start)
			if err != nil {
				t.Fatal(err)
			}
			client := func(wire []byte, before func()) *authorityClient {
				return &authorityClient{origin: "https://fixture.invalid", client: &http.Client{
					Transport: freshnessTransport(func(_ *http.Request) (*http.Response, error) {
						if before != nil {
							before()
						}
						header := make(http.Header)
						header.Set("Cache-Control", "no-store")
						header.Set("Content-Type", "application/json")
						return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(bytes.NewReader(wire))}, nil
					}),
				}}
			}
			calls := 0
			a := &LiveAuthority{
				tenant: runtime.TenantID, acpKey: acpPub, now: func() time.Time { return now },
				runtime: client(marshal(runtime), func() {
					calls++
					if calls == 2 {
						now = start.Add(tc.delay)
					}
				}),
				acp: client(acpWire, nil),
				sources: map[string]pinnedEvidenceSource{scope.SourceID: {
					client: client(proof, nil), scope: scope, key: sourceKey.Public().(ed25519.PublicKey),
				}},
			}
			_, _, err = a.ResolveTurn(context.Background(), runtime.RunID, runtime.InvocationID, []EvidenceRef{ref})
			if calls != 2 {
				t.Fatalf("fixture never reached final Runtime read: calls=%d err=%v", calls, err)
			}
			if tc.wantReject {
				if !errors.Is(err, ErrAuthorityRejected) {
					t.Fatalf("stale input accepted after final Runtime read: %v", err)
				}
			} else if err != nil {
				t.Fatalf("fresh input rejected: %v", err)
			}
		})
	}
}
