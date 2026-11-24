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
	testFinalFreshness(t, false, false)
}

func TestContinuationRejectsInputsStaleAtFinalObservation(t *testing.T) {
	testFinalFreshness(t, true, false)
}

// Guard receives only an exact read-only plan-step receipt; stale evidence
// must never produce VERIFIED, even when all immutable selectors match.
func TestGuardPlanRejectsInputsStaleAtFinalObservation(t *testing.T) {
	testFinalFreshness(t, true, true)
}

func testFinalFreshness(t *testing.T, continuation, guard bool) {
	t.Helper()
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
		{"intermediate runtime drift", 10 * time.Minute, 10 * time.Minute, 5 * time.Minute, 0, true},
	} {
		drift := tc.name == "intermediate runtime drift"
		if drift && !continuation {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			start := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)
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
			caps := []CapabilityRef{}
			for _, id := range []string{"sre.changes.read", "sre.logs.read", "sre.metrics.read"} {
				contract := acpReleaseContract{
					ID: id, Version: "1.0.0", InputSchema: json.RawMessage(`{}`),
					OutputSchema: json.RawMessage(`{}`), EffectClass: "read_only",
					Idempotency: "safe", TenantScoped: true,
				}
				release.Capabilities = append(release.Capabilities, contract)
				caps = append(caps, CapabilityRef{
					ID: id, Version: contract.Version, ContractSHA256: acpHash(marshal(contract)),
					InputSchemaRef: "sha256:" + acpHash(contract.InputSchema),
					OutputSchemaRef: "sha256:" + acpHash(contract.OutputSchema),
					EffectClass: "read_only", Idempotency: "safe", TenantScoped: true,
				})
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
				Capabilities: caps, ContextContent: contextBytes, CapabilityContent: releaseBytes,
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
			refs := []EvidenceRef{ref}
			sources := map[string]pinnedEvidenceSource{scope.SourceID: {
				client: client(proof, nil), scope: scope, key: sourceKey.Public().(ed25519.PublicKey),
			}}
			for _, kind := range []string{"logs", "change"} {
				s := scope
				s.SourceID = kind + "-1"
				s.Source = kind
				s.EvidenceType = kind
				e, wire, err := PublishEvidence(s, EvidenceObservation{
					Ref: "sample-" + kind, ObservedFrom: start.Add(-time.Minute), ObservedTo: start,
					ObservedAt: start, CollectedAt: start, ExpiresAt: start.Add(tc.evidenceTTL),
				}, []byte(kind), sourceKey, start)
				if err != nil {
					t.Fatal(err)
				}
				refs = append(refs, e)
				sources[s.SourceID] = pinnedEvidenceSource{client: client(wire, nil), scope: s, key: sourceKey.Public().(ed25519.PublicKey)}
			}
			calls := 0
			delayAt := 2
			if continuation {
				delayAt = 0 // First build an unexpired committed record.
			}
			a := &LiveAuthority{
				tenant: runtime.TenantID, acpKey: acpPub, now: func() time.Time { return now },
				runtime: client(marshal(runtime), func() {
					calls++
					if calls == delayAt {
						now = start.Add(tc.delay)
					}
				}),
				acp: client(acpWire, nil),
				sources: sources,
			}
			ctx := context.Background()
			expectedCalls := 2
			if continuation {
				p, req, buildErr := a.ResolveTurn(ctx, runtime.RunID, runtime.InvocationID, refs)
				if buildErr != nil {
					t.Fatal(buildErr)
				}
				record, buildErr := recordFromVerifiedRequest(p, req, SREReadOnlyStrategy{}, start)
				if buildErr != nil || record.Status != StatusProposed {
					t.Fatalf("fixture requires proposed record: %v %s", buildErr, record.Status)
				}
				store := NewMemoryStore()
				if _, created, saveErr := store.SaveOrGet(ctx, record); saveErr != nil || !created {
					t.Fatalf("fixture store: %v", saveErr)
				}
				calls = 0
				delayAt = 4 // before, build's two reads, after.
				expectedCalls = 4
				if drift {
					// Simulate inconsistent authenticated Runtime observations:
					// outer reads see version 1, both inner reads version 2.
					// The committed proposal does not encode breaker version.
					inner := runtime
					inner.BreakerVersion++
					transport := a.runtime.client.Transport
					a.runtime.client.Transport = freshnessTransport(func(r *http.Request) (*http.Response, error) {
						res, err := transport.RoundTrip(r)
						if err == nil && (calls == 2 || calls == 3) {
							_ = res.Body.Close()
							res.Body = io.NopCloser(bytes.NewReader(marshal(inner)))
						}
						return res, err
					})
				}
				if guard {
					step := record.Plan.Steps[0]
					request := GuardPlanStepRequest{
						SchemaVersion: GuardPlanStepSchema,
						RunID: runtime.RunID, AgentID: runtime.AgentID,
						AgentReleaseID: runtime.AgentReleaseID, SessionID: runtime.SessionID,
						DecisionID: record.DecisionID, PlanID: record.Plan.PlanID,
						PlanHash: record.Plan.PlanHash, StepID: step.StepID,
						CapabilityID: step.Capability.ID, CapabilityVersion: step.Capability.Version,
						ResourceRef: step.TargetRef, Arguments: json.RawMessage(`{}`),
						BreakerEpoch: runtime.BreakerEpoch, BreakerVersion: runtime.BreakerVersion,
					}
					var receipt GuardPlanStepReceipt
					receipt, err = a.VerifyGuardPlanStep(ctx, store, p.TenantID, request)
					if tc.wantReject && receipt != (GuardPlanStepReceipt{}) {
						t.Fatal("rejected Guard step returned a receipt")
					}
					if !tc.wantReject && err == nil &&
						(receipt.Status != "VERIFIED" || receipt.DecisionID != record.DecisionID ||
							receipt.StepID != step.StepID || receipt.PlanHash != record.Plan.PlanHash ||
							receipt.RecordSHA256 != digest(record) ||
							receipt.BreakerEpoch != runtime.BreakerEpoch ||
							receipt.BreakerVersion != runtime.BreakerVersion) {
						t.Fatal("fresh Guard receipt did not bind the exact committed plan step")
					}
				} else {
					var receipt ContinuationReceipt
					receipt, err = a.VerifyCommittedTurn(ctx, store, runtime.RunID, runtime.InvocationID)
					if tc.wantReject && receipt != (ContinuationReceipt{}) {
						t.Fatal("rejected continuation returned a receipt")
					}
					if !tc.wantReject && err == nil && receipt.DecisionID != record.DecisionID {
						t.Fatal("fresh continuation did not bind stored decision")
					}
				}
				got, lookupErr := store.GetByInvocation(ctx, p.TenantID, req.InvocationID)
				if lookupErr != nil || digest(got) != digest(record) {
					t.Fatal("continuation modified ledger")
				}
			} else {
				_, _, err = a.ResolveTurn(ctx, runtime.RunID, runtime.InvocationID, refs)
			}
			if (!drift && calls != expectedCalls) || (drift && (calls < 2 || calls > expectedCalls)) {
				t.Fatalf("unexpected Runtime observation count: calls=%d err=%v", calls, err)
			}
			if tc.wantReject {
				if !errors.Is(err, ErrAuthorityRejected) {
					t.Fatalf("inconsistent or stale authority inputs accepted: %v", err)
				}
			} else if err != nil {
				t.Fatalf("fresh input rejected: %v", err)
			}
		})
	}
}
