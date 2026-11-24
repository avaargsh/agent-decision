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
	request.Evidence = []EvidenceRef{}

	makePublication := func(base EvidenceRef, fact string, seed byte) (signedHypothesisPublication, EvidenceRef) {
		t.Helper()
		base.RunID = runID
		base.ObservedFrom, base.ObservedTo, base.ObservedAt = from, to, to
		base.CollectedAt, base.ExpiresAt = now, now.Add(5*time.Minute)
		base.RevocationState = "active"
		scope := EvidenceSourceScope{
			TenantID: base.TenantID, AgentID: base.AgentID, RunID: base.RunID,
			Service: base.Service, ResourceRef: base.ResourceRef, SourceID: base.SourceID,
			Source: base.Source, SourceVersion: base.SourceVersion, EvidenceType: base.EvidenceType,
			SchemaVersion: base.SchemaVersion, MaxAge: 15*time.Minute, MaxLifetime: 10*time.Minute,
		}
		key := ed25519.NewKeyFromSeed(bytesOf(seed, ed25519.SeedSize))
		raw, err := json.Marshal(struct {
			Schema string `json:"schema_version"`
			Signal string `json:"signal"`
			From time.Time `json:"observed_from"`
			To time.Time `json:"observed_to"`
			Fact string `json:"fact"`
		}{"sre.hypothesis-observation.v1", "latency", from, to, fact})
		if err != nil { t.Fatal(err) }
		meta := EvidenceObservation{
			Ref: base.Ref, ObservedFrom: from, ObservedTo: to, ObservedAt: to,
			CollectedAt: now, ExpiresAt: now.Add(5*time.Minute),
		}
		ref, wire, err := PublishEvidence(scope, meta, raw, key, now)
		if err != nil { t.Fatal(err) }
		return signedHypothesisPublication{Wire: wire, PublicKey: key.Public().(ed25519.PublicKey), Scope: scope, Expected: ref}, ref
	}

	symptom, symptomRef := makePublication(requestFixtureEvidence(0), "SYMPTOM_INCREASED", 1)
	change, changeRef := makePublication(requestFixtureEvidence(2), "DEPLOYMENT_PRECEDES_SYMPTOM", 2)
	request.Evidence = append(request.Evidence, symptomRef, changeRef)
	return offlineHypothesisFixture{
		principal: principal, request: request, publications: []signedHypothesisPublication{symptom, change},
		from: from, to: to, now: now,
	}
}

// requestFixtureEvidence obtains stable source identities from the ordinary
// read-only request fixture without mutating a test's request.
func requestFixtureEvidence(index int) EvidenceRef {
	return validRequest().Evidence[index]
}

func bytesOf(value byte, size int) []byte {
	out := make([]byte, size)
	for i := range out { out[i] = value }
	return out
}

func TestOfflineVerifiedDeploymentHypothesis(t *testing.T) {
	fixture := newOfflineHypothesisFixture(t)
	for _, tc := range []struct {
		name string
		publications []signedHypothesisPublication
		want hypothesisStatus
		missing int
	}{
		{"supported", fixture.publications, hypothesisSupported, 0},
		{"missing_change", fixture.publications[:1], hypothesisInsufficient, 1},
		{"unrelated_only", func() []signedHypothesisPublication {
			base := requestFixtureEvidence(1)
			base.SourceID, base.Source, base.Ref = "logs-alt", "logs-alt", "logs-alt-sample"
			base.ResourceRef = "resource://payment-api/logs-alt"
			publication, ref := makeOfflinePublication(t, base, "UNRELATED", fixture.from, fixture.to, fixture.now, 3)
			fixture.request.Evidence = append(fixture.request.Evidence, ref)
			return []signedHypothesisPublication{publication}
		}(), hypothesisUntested, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evaluateOfflineDeploymentHypothesis(fixture.principal, fixture.request, tc.publications, fixture.from, fixture.to, fixture.now)
			if err != nil || got.Status != tc.want || len(got.Missing) != tc.missing {
				t.Fatalf("result=%+v err=%v; want status=%s missing=%d", got, err, tc.want, tc.missing)
			}
		})
	}

	first, err := evaluateOfflineDeploymentHypothesis(fixture.principal, fixture.request, fixture.publications, fixture.from, fixture.to, fixture.now)
	if err != nil { t.Fatal(err) }
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
	extra, _ := makeOfflinePublication(t, extraBase, "SYMPTOM_INCREASED", fixture.from, fixture.to, fixture.now, 4)
	wrongScope := fixture.publications[0]
	wrongScope.Scope.TenantID = "tenant-b"
	wrongSigner := fixture.publications[0]
	wrongSigner.PublicKey = ed25519.NewKeyFromSeed(bytesOf(9, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	for _, tc := range []struct {
		name string
		publications []signedHypothesisPublication
		want error
	}{
		{"unknown_request_reference", []signedHypothesisPublication{extra}, ErrInvalidRequest},
		{"wrong_source_scope", []signedHypothesisPublication{wrongScope}, ErrAuthorityRejected},
		{"wrong_signer", []signedHypothesisPublication{wrongSigner}, ErrAuthorityRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evaluateOfflineDeploymentHypothesis(fixture.principal, fixture.request, tc.publications, fixture.from, fixture.to, fixture.now)
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(got, hypothesisResult{}) {
				t.Fatalf("invalid publication accepted: result=%+v err=%v", got, err)
			}
		})
	}
}

func makeOfflinePublication(t *testing.T, base EvidenceRef, fact string, from, to, now time.Time, seed byte) (signedHypothesisPublication, EvidenceRef) {
	t.Helper()
	runID := "11111111-1111-4111-8111-111111111111"
	base.RunID = runID
	base.ObservedFrom, base.ObservedTo, base.ObservedAt = from, to, to
	base.CollectedAt, base.ExpiresAt, base.RevocationState = now, now.Add(5*time.Minute), "active"
	scope := EvidenceSourceScope{
		TenantID: base.TenantID, AgentID: base.AgentID, RunID: base.RunID,
		Service: base.Service, ResourceRef: base.ResourceRef, SourceID: base.SourceID,
		Source: base.Source, SourceVersion: base.SourceVersion, EvidenceType: base.EvidenceType,
		SchemaVersion: base.SchemaVersion, MaxAge: 15*time.Minute, MaxLifetime: 10*time.Minute,
	}
	key := ed25519.NewKeyFromSeed(bytesOf(seed, ed25519.SeedSize))
	raw, err := json.Marshal(struct {
		Schema string `json:"schema_version"`
		Signal string `json:"signal"`
		From time.Time `json:"observed_from"`
		To time.Time `json:"observed_to"`
		Fact string `json:"fact"`
	}{"sre.hypothesis-observation.v1", "latency", from, to, fact})
	if err != nil { t.Fatal(err) }
	meta := EvidenceObservation{Ref: base.Ref, ObservedFrom: from, ObservedTo: to, ObservedAt: to, CollectedAt: now, ExpiresAt: now.Add(5*time.Minute)}
	ref, wire, err := PublishEvidence(scope, meta, raw, key, now)
	if err != nil { t.Fatal(err) }
	return signedHypothesisPublication{Wire: wire, PublicKey: key.Public().(ed25519.PublicKey), Scope: scope, Expected: ref}, ref
}
