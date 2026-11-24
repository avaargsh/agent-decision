package decision

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

type offlineHypothesisFixture struct {
	principal Principal
	request Request
	publications []signedHypothesisPublication
	from, to, now time.Time
}

func newOfflineHypothesisFixture(t *testing.T) offlineHypothesisFixture {
	t.Helper()
	principal := testPrincipal()
	request := validRequest()
	now := request.Evidence[0].CollectedAt
	from, to := now.Add(-time.Minute), now
	runID := "11111111-1111-4111-8111-111111111111"
	request.Identity.RunID = runID

	symptom, symptomRef := makeOfflinePublication(t, requestFixtureEvidence(0), "SYMPTOM_INCREASED", from, to, now, 1)
	change, changeRef := makeOfflinePublication(t, requestFixtureEvidence(2), "DEPLOYMENT_PRECEDES_SYMPTOM", from, to, now, 2)
	request.Evidence = []EvidenceRef{symptomRef, changeRef}
	return offlineHypothesisFixture{
		principal: principal, request: request,
		publications: []signedHypothesisPublication{symptom, change},
		from: from, to: to, now: now,
	}
}

func requestFixtureEvidence(index int) EvidenceRef {
	return validRequest().Evidence[index]
}

func bytesOf(value byte, size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = value
	}
	return out
}

func makeOfflinePublication(t *testing.T, base EvidenceRef, fact string, from, to, now time.Time, seed byte) (signedHypothesisPublication, EvidenceRef) {
	t.Helper()
	base.RunID = "11111111-1111-4111-8111-111111111111"
	scope := EvidenceSourceScope{
		TenantID: base.TenantID, AgentID: base.AgentID, RunID: base.RunID,
		Service: base.Service, ResourceRef: base.ResourceRef, SourceID: base.SourceID,
		Source: base.Source, SourceVersion: base.SourceVersion, EvidenceType: base.EvidenceType,
		SchemaVersion: base.SchemaVersion, MaxAge: 15 * time.Minute, MaxLifetime: 10 * time.Minute,
	}
	key := ed25519.NewKeyFromSeed(bytesOf(seed, ed25519.SeedSize))
	raw, err := json.Marshal(struct {
		Schema string    `json:"schema_version"`
		Signal string    `json:"signal"`
		From   time.Time `json:"observed_from"`
		To     time.Time `json:"observed_to"`
		Fact   string    `json:"fact"`
	}{"sre.hypothesis-observation.v1", "latency", from, to, fact})
	if err != nil {
		t.Fatal(err)
	}
	meta := EvidenceObservation{
		Ref: base.Ref, ObservedFrom: from, ObservedTo: to, ObservedAt: to,
		CollectedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	ref, wire, err := PublishEvidence(scope, meta, raw, key, now)
	if err != nil {
		t.Fatal(err)
	}
	return signedHypothesisPublication{
		Wire: wire, PublicKey: key.Public().(ed25519.PublicKey), Scope: scope, Expected: ref,
	}, ref
}

func TestOfflineVerifiedDeploymentHypothesis(t *testing.T) {
	fixture := newOfflineHypothesisFixture(t)
	unrelatedBase := requestFixtureEvidence(1)
	unrelatedBase.SourceID = "logs-alt"
	unrelatedBase.Source = "logs-alt"
	unrelatedBase.Ref = "logs-alt-sample"
	unrelatedBase.ResourceRef = "resource://payment-api/logs-alt"
	unrelated, unrelatedRef := makeOfflinePublication(t, unrelatedBase, "UNRELATED", fixture.from, fixture.to, fixture.now, 3)
	unrelatedRequest := fixture.request
	unrelatedRequest.Evidence = append(append([]EvidenceRef{}, fixture.request.Evidence...), unrelatedRef)

	conflictingBase := requestFixtureEvidence(0)
	conflictingBase.SourceID = "slo-adapter-secondary"
	conflictingBase.Source = "slo-adapter-secondary"
	conflictingBase.Ref = "slo-secondary-sample"
	conflictingBase.ResourceRef = "resource://payment-api/slo-secondary"
	conflicting, conflictingRef := makeOfflinePublication(t, conflictingBase, "SYMPTOM_NOT_INCREASED", fixture.from, fixture.to, fixture.now, 4)
	conflictingRequest := fixture.request
	conflictingRequest.Evidence = append(append([]EvidenceRef{}, fixture.request.Evidence...), conflictingRef)
	conflictingPublications := append(append([]signedHypothesisPublication{}, fixture.publications...), conflicting)

	for _, tc := range []struct {
		name string
		request Request
		publications []signedHypothesisPublication
		want hypothesisStatus
		missing int
	}{
		{"supported", fixture.request, fixture.publications, hypothesisSupported, 0},
		{"missing_change", fixture.request, fixture.publications[:1], hypothesisInsufficient, 1},
		{"unrelated_only", unrelatedRequest, []signedHypothesisPublication{unrelated}, hypothesisUntested, 2},
		{"conflicting", conflictingRequest, conflictingPublications, hypothesisConflicting, 0},
		{"no_observations", fixture.request, nil, hypothesisUntested, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evaluateOfflineDeploymentHypothesis(fixture.principal, tc.request, tc.publications, fixture.from, fixture.to, fixture.now)
			if err != nil || got.Status != tc.want || len(got.Missing) != tc.missing {
				t.Fatalf("result=%+v err=%v; want status=%s missing=%d", got, err, tc.want, tc.missing)
			}
		})
	}

	first, err := evaluateOfflineDeploymentHypothesis(fixture.principal, fixture.request, fixture.publications, fixture.from, fixture.to, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []signedHypothesisPublication{fixture.publications[1], fixture.publications[0]}
	second, err := evaluateOfflineDeploymentHypothesis(fixture.principal, fixture.request, reversed, fixture.from, fixture.to, fixture.now)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("publication permutation changed result: first=%+v second=%+v err=%v", first, second, err)
	}
}

func TestOfflineVerifiedDeploymentHypothesisRejectsUnboundOrInvalidProof(t *testing.T) {
	fixture := newOfflineHypothesisFixture(t)
	extraBase := requestFixtureEvidence(0)
	extraBase.Ref = "unbound-sample"
	extraBase.SourceID = "unbound-source"
	extraBase.Source = "unbound-source"
	extraBase.ResourceRef = "resource://payment-api/unbound"
	extra, _ := makeOfflinePublication(t, extraBase, "SYMPTOM_INCREASED", fixture.from, fixture.to, fixture.now, 5)
	wrongScope := fixture.publications[0]
	wrongScope.Scope.TenantID = "tenant-b"
	wrongSigner := fixture.publications[0]
	wrongSigner.PublicKey = ed25519.NewKeyFromSeed(bytesOf(9, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	wrongWindowFrom := fixture.from.Add(-time.Second)
	for _, tc := range []struct {
		name string
		publications []signedHypothesisPublication
		from time.Time
		want error
	}{
		{"unknown_request_reference", []signedHypothesisPublication{extra}, fixture.from, ErrInvalidRequest},
		{"wrong_source_scope", []signedHypothesisPublication{wrongScope}, fixture.from, ErrAuthorityRejected},
		{"wrong_signer", []signedHypothesisPublication{wrongSigner}, fixture.from, ErrAuthorityRejected},
		{"wrong_investigation_window", fixture.publications[:1], wrongWindowFrom, ErrAuthorityRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evaluateOfflineDeploymentHypothesis(fixture.principal, fixture.request, tc.publications, tc.from, fixture.to, fixture.now)
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(got, hypothesisResult{}) {
				t.Fatalf("invalid publication accepted: result=%+v err=%v", got, err)
			}
		})
	}
}
