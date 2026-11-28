package decision

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestVerifiedHypothesisObservation(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	from, to := now.Add(-time.Minute), now
	scope := EvidenceSourceScope{
		TenantID: "tenant-a", AgentID: "agent-1", RunID: "11111111-1111-4111-8111-111111111111",
		Service: "payment-api", ResourceRef: "service:payment-api", SourceID: "collector-1",
		Source: "collector", SourceVersion: "1.0.0", EvidenceType: "metrics", SchemaVersion: "1.0.0",
		MaxAge: 15 * time.Minute, MaxLifetime: 10 * time.Minute,
	}
	meta := EvidenceObservation{Ref: "sample-1", ObservedFrom: from, ObservedTo: to,
		ObservedAt: to, CollectedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	encode := func(signal, fact string, start, end time.Time) []byte {
		t.Helper()
		raw, err := json.Marshal(struct {
			Schema string    `json:"schema_version"`
			Signal string    `json:"signal"`
			From   time.Time `json:"observed_from"`
			To     time.Time `json:"observed_to"`
			Fact   string    `json:"fact"`
		}{"sre.hypothesis-observation.v1", signal, start, end, fact})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	valid := encode("latency", "SYMPTOM_INCREASED", from, to)
	for _, tc := range []struct {
		name, kind string
		content    []byte
		want       hypothesisFact
	}{
		{"metric", "metrics", valid, symptomIncreased},
		{"slo_negative", "slo", encode("latency", "SYMPTOM_NOT_INCREASED", from, to), symptomNotIncreased},
		{"change", "change", encode("latency", "DEPLOYMENT_PRECEDES_SYMPTOM", from, to), deploymentPrecedesSymptom},
		{"no_change", "change", encode("latency", "NO_DEPLOYMENT_IN_WINDOW", from, to), noDeploymentInWindow},
		{"unrelated", "logs", encode("latency", "UNRELATED", from, to), unrelatedObservation},
		{"wrong_kind", "change", valid, ""},
		{"wrong_signal", "metrics", encode("errors", "SYMPTOM_INCREASED", from, to), ""},
		{"wrong_window", "metrics", encode("latency", "SYMPTOM_INCREASED", from.Add(time.Second), to), ""},
		{"unknown_fact", "metrics", encode("latency", "ROOT_CAUSE_CONFIRMED", from, to), ""},
		{"unknown_schema", "metrics", []byte(`{"schema_version":"unknown"}`), ""},
		{"duplicate_key", "metrics", append(append([]byte{}, valid[:len(valid)-1]...), []byte(`,"fact":"SYMPTOM_INCREASED"}`)...), ""},
		{"unknown_field", "metrics", append(append([]byte{}, valid[:len(valid)-1]...), []byte(`,"extra":1}`)...), ""},
		{"trailing_json", "metrics", append(append([]byte{}, valid...), []byte("{}")...), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := scope
			s.EvidenceType = tc.kind
			ref, wire, err := PublishEvidence(s, meta, tc.content, key, now)
			if err != nil {
				t.Fatal(err)
			}
			got, err := decodeVerifiedHypothesisObservation(wire, pub, s, ref, "latency", from, to, now)
			if tc.want == "" {
				if !errors.Is(err, ErrAuthorityRejected) || got != (hypothesisObservation{}) {
					t.Fatalf("invalid fact accepted: %+v %v", got, err)
				}
				return
			}
			if err != nil || got != (hypothesisObservation{Evidence: ref, Fact: tc.want}) {
				t.Fatalf("observation=%+v err=%v", got, err)
			}
		})
	}
	ref, wire, err := PublishEvidence(scope, meta, valid, key, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name            string
		key             ed25519.PublicKey
		ref             EvidenceRef
		from, to, clock time.Time
	}{
		{"wrong_signer", ed25519.NewKeyFromSeed(append([]byte{1}, make([]byte, 31)...)).Public().(ed25519.PublicKey), ref, from, to, now},
		{"expired", pub, ref, from, to, meta.ExpiresAt},
		{"different_window", pub, ref, from.Add(-time.Second), to, now},
		{"zero_window", pub, ref, time.Time{}, to, now},
		{"empty_window", pub, ref, to, to, now},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeVerifiedHypothesisObservation(wire, tc.key, scope, tc.ref, "latency", tc.from, tc.to, tc.clock)
			if !errors.Is(err, ErrAuthorityRejected) || got != (hypothesisObservation{}) {
				t.Fatalf("invalid authority accepted: %+v %v", got, err)
			}
		})
	}
}
