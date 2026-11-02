package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-decision/internal/auth"
	"github.com/avaargsh/agent-decision/internal/decision"
)

type allowVerifier struct{}

func (allowVerifier) Verify(context.Context, auth.Principal, decision.Request) error { return nil }

func validBody() []byte {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	snapshot := func(id, source, marker string) decision.SnapshotRef {
		return decision.SnapshotRef{ID: id, Version: "v1", SHA256: strings.Repeat(marker, 64), Source: source,
			AttestationRef: "attestation:" + id, TrustLevel: "attested", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	}
	capability := func(id, marker string) decision.CapabilityRef {
		return decision.CapabilityRef{ID: id, Version: "1.0.0", ContractSHA256: strings.Repeat(marker, 64),
			InputSchemaRef: "schema:" + id + ":input", OutputSchemaRef: "schema:" + id + ":output",
			EffectClass: "read_only", Idempotency: "safe", TenantScoped: true}
	}
	request := decision.Request{
		SchemaVersion:      decision.RequestSchemaVersion,
		Identity:           decision.Identity{AgentID: "agent-a", SessionID: "session-a", RunID: "run-17"},
		IdempotencyKey:     "alert-17",
		Input:              decision.Input{Objective: "sre_incident_triage", Service: "payment-api", Signal: "latency"},
		Constraints:        decision.Constraints{DeadlineMS: 10000, MaxTokens: 2048, MaxCostMicros: 50000, MaxCandidates: 1},
		Versions:           decision.Versions{CapabilityCatalogVersion: "catalog-v1", StrategyVersion: decision.PolicyVersion, PromptVersion: "none", ModelProfile: "rule-only"},
		ContextSnapshot:    snapshot("context-v1", "context-store", "a"),
		CapabilitySnapshot: snapshot("capability-v1", "agent-control-panel", "b"),
		Capabilities:       []decision.CapabilityRef{capability("sre.metrics.read", "c"), capability("sre.logs.read", "d"), capability("sre.changes.read", "e")},
		Evidence: []decision.EvidenceRef{{Ref: "slo-17", Source: "slo-monitor", SourceVersion: "slo-v1", SHA256: strings.Repeat("f", 64),
			AttestationRef: "attestation:slo-17", TrustLevel: "attested", ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(10 * time.Minute)}},
	}
	body, _ := json.Marshal(request)
	return body
}

func authenticatedRequest(method, path string, body []byte, tenant string) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	principal := auth.Principal{TenantID: tenant, Subject: "subject-a", AgentID: "agent-a"}
	return request.WithContext(auth.WithPrincipal(context.Background(), principal))
}

func testHandler() http.Handler {
	return NewHandler(decision.NewService(decision.NewMemoryStore(), allowVerifier{}))
}

func TestHTTPCreateAndReplay(t *testing.T) {
	handler := testHandler()
	for index, expected := range []int{201, 200} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, authenticatedRequest(http.MethodPost, "/v1/decisions", validBody(), "tenant-a"))
		if recorder.Code != expected {
			t.Fatalf("pass %d: want %d got %d body=%s", index, expected, recorder.Code, recorder.Body.String())
		}
	}
}

func TestUnauthenticatedAndTenantSpoofingRejected(t *testing.T) {
	handler := testHandler()
	unauthenticated := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/decisions", bytes.NewReader(validBody()))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(unauthenticated, request)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", unauthenticated.Code)
	}

	spoofed := bytes.Replace(validBody(), []byte(`"idempotency_key"`), []byte(`"tenant_id":"victim","idempotency_key"`), 1)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, authenticatedRequest(http.MethodPost, "/v1/decisions", spoofed, "tenant-a"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("tenant_id from JSON must be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestAuthorityVerifierMissingFailsClosed(t *testing.T) {
	handler := NewHandler(decision.NewService(decision.NewMemoryStore(), nil))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, authenticatedRequest(http.MethodPost, "/v1/decisions", validBody(), "tenant-a"))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 fail-closed response, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestTenantScopedGet(t *testing.T) {
	handler := testHandler()
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, authenticatedRequest(http.MethodPost, "/v1/decisions", validBody(), "tenant-a"))
	if created.Code != http.StatusCreated {
		t.Fatalf("create failed: %d %s", created.Code, created.Body.String())
	}
	var record decision.Record
	if err := json.Unmarshal(created.Body.Bytes(), &record); err != nil {
		t.Fatal(err)
	}

	wrongTenant := httptest.NewRecorder()
	handler.ServeHTTP(wrongTenant, authenticatedRequest(http.MethodGet, "/v1/agents/agent-a/decisions/"+record.DecisionID, nil, "tenant-b"))
	if wrongTenant.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant GET must return 404, got %d", wrongTenant.Code)
	}
	owner := httptest.NewRecorder()
	handler.ServeHTTP(owner, authenticatedRequest(http.MethodGet, "/v1/agents/agent-a/decisions/"+record.DecisionID, nil, "tenant-a"))
	if owner.Code != http.StatusOK {
		t.Fatalf("owner GET failed: %d %s", owner.Code, owner.Body.String())
	}
	crossAgent := httptest.NewRecorder()
	handler.ServeHTTP(crossAgent, authenticatedRequest(http.MethodGet, "/v1/agents/agent-b/decisions/"+record.DecisionID, nil, "tenant-a"))
	if crossAgent.Code != http.StatusNotFound {
		t.Fatalf("cross-agent GET must return 404, got %d", crossAgent.Code)
	}
}

func TestStrictJSONRejectsDuplicatesUnknownAndTrailing(t *testing.T) {
	handler := testHandler()
	cases := [][]byte{
		[]byte(`{"idempotency_key":"a","idempotency_key":"b"}`),
		append(validBody(), []byte(`{}`)...),
		bytes.Replace(validBody(), []byte(`"signal"`), []byte(`"signal_typo"`), 1),
		[]byte(`{"identity":{"agent_id":"a","agent_id":"b"}}`),
	}
	for index, body := range cases {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, authenticatedRequest(http.MethodPost, "/v1/decisions", body, "tenant-a"))
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("case %d: expected 400, got %d", index, recorder.Code)
		}
	}
}

func TestConflictIs409(t *testing.T) {
	handler := testHandler()
	for index, body := range [][]byte{validBody(), bytes.Replace(validBody(), []byte(`"signal":"latency"`), []byte(`"signal":"errors"`), 1)} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, authenticatedRequest(http.MethodPost, "/v1/decisions", body, "tenant-a"))
		if index == 1 && recorder.Code != http.StatusConflict {
			t.Fatalf("expected 409 got %d: %s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestUnsupportedMediaTypeAndOversizedRequest(t *testing.T) {
	handler := testHandler()
	badType := httptest.NewRecorder()
	request := authenticatedRequest(http.MethodPost, "/v1/decisions", validBody(), "tenant-a")
	request.Header.Set("Content-Type", "text/plain")
	handler.ServeHTTP(badType, request)
	if badType.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 got %d", badType.Code)
	}

	oversized := httptest.NewRecorder()
	handler.ServeHTTP(oversized, authenticatedRequest(http.MethodPost, "/v1/decisions", []byte(strings.Repeat("x", maxBodyBytes+1)), "tenant-a"))
	if oversized.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 got %d", oversized.Code)
	}
}
