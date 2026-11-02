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

	"github.com/avaargsh/agent-decision/internal/decision"
)

type apiAuthority struct{}
func (apiAuthority) VerifyDecisionInputs(context.Context, decision.Principal, decision.Request) error { return nil }

func apiPrincipal() decision.Principal {
	return decision.Principal{TenantID:"tenant-a", SubjectID:"runtime-svc", AgentID:"agent-1", SessionID:"session-1", CallerID:"agent-runtime"}
}

func apiRequest() decision.Request {
	issued:=time.Date(2026,11,2,0,0,0,0,time.UTC)
	expires:=issued.Add(2*time.Hour)
	return decision.Request{
		SchemaVersion:decision.SchemaVersion,
		Identity:decision.Identity{AgentID:"agent-1",SessionID:"session-1",RunID:"run-17"},
		IdempotencyKey:"alert-17",
		Input:decision.Input{Objective:"sre_incident_triage",Service:"payment-api",Signal:"latency"},
		Constraints:decision.Constraints{DeadlineMS:30000,MaxTokens:2048,MaxCostMicros:50000,MaxCandidates:3},
		Versions:decision.VersionSet{CapabilityCatalogVersion:"catalog-12",StrategyVersion:decision.PolicyVersion,PromptVersion:"none",ModelProfile:"rule-only"},
		ContextSnapshot:decision.SnapshotRef{ID:"context-17",Version:"ctx-v1",SHA256:strings.Repeat("a",64),Source:"context-store",AttestationRef:"att-context-17",TrustLevel:"attested",IssuedAt:issued,ExpiresAt:expires},
		CapabilitySnapshot:decision.SnapshotRef{ID:"capabilities-12",Version:"catalog-12",SHA256:strings.Repeat("c",64),Source:"agent-control-plane",AttestationRef:"att-cap-12",TrustLevel:"attested",IssuedAt:issued,ExpiresAt:expires},
		Capabilities:[]decision.CapabilityRef{
			{ID:"sre.metrics.read",Version:"1.0.0",ContractSHA256:strings.Repeat("1",64),InputSchemaRef:"schema://metrics/input",OutputSchemaRef:"schema://metrics/output",EffectClass:"read_only",Idempotency:"safe",TenantScoped:true},
			{ID:"sre.logs.read",Version:"1.2.0",ContractSHA256:strings.Repeat("2",64),InputSchemaRef:"schema://logs/input",OutputSchemaRef:"schema://logs/output",EffectClass:"read_only",Idempotency:"safe",TenantScoped:true},
			{ID:"sre.changes.read",Version:"2.0.0",ContractSHA256:strings.Repeat("3",64),InputSchemaRef:"schema://changes/input",OutputSchemaRef:"schema://changes/output",EffectClass:"read_only",Idempotency:"safe",TenantScoped:true},
		},
		Evidence:[]decision.EvidenceRef{{Ref:"slo-sample-17",Source:"slo-adapter",SourceVersion:"v2",SHA256:strings.Repeat("b",64),AttestationRef:"att-slo-17",TrustLevel:"attested",ObservedAt:issued,ExpiresAt:expires}},
	}
}

func validBody() []byte {
	body,_:=json.Marshal(apiRequest())
	return body
}

func testHandler(resolver PrincipalResolver, verifier decision.AuthorityVerifier) http.Handler {
	return NewHandler(decision.NewService(decision.NewMemoryStore(),verifier),resolver)
}

func send(h http.Handler, body []byte, contentType string) *httptest.ResponseRecorder {
	w:=httptest.NewRecorder()
	r:=httptest.NewRequest(http.MethodPost,"/v1/decisions",bytes.NewReader(body))
	r.Header.Set("Content-Type",contentType)
	h.ServeHTTP(w,r)
	return w
}

func resolverFor(p decision.Principal) PrincipalResolver {
	return PrincipalResolverFunc(func(*http.Request)(decision.Principal,error){return p,nil})
}

func TestHTTPCreateAndReplay(t *testing.T) {
	h:=testHandler(resolverFor(apiPrincipal()),apiAuthority{})
	for i,want:=range []int{http.StatusCreated,http.StatusOK} {
		w:=send(h,validBody(),"application/json")
		if w.Code!=want { t.Fatalf("pass %d: want %d got %d body=%s",i,want,w.Code,w.Body.String()) }
	}
}

func TestHTTPRejectsTenantFromBodyAndStrictJSON(t *testing.T) {
	h:=testHandler(resolverFor(apiPrincipal()),apiAuthority{})
	body:=validBody()
	attackerTenant:=append([]byte(`{"tenant_id":"tenant-evil",`),body[1:]...)
	duplicate:=bytes.Replace(body,[]byte(`"idempotency_key":"alert-17"`),[]byte(`"idempotency_key":"alert-17","idempotency_key":"other"`),1)
	unknown:=bytes.Replace(body,[]byte(`"schema_version"`),[]byte(`"unexpected"`),1)
	trailing:=append(append([]byte{},body...),[]byte("{}")...)
	nestedDuplicate:=bytes.Replace(body,[]byte(`"agent_id":"agent-1"`),[]byte(`"agent_id":"agent-1","agent_id":"agent-2"`),1)
	for i,candidate:=range [][]byte{attackerTenant,duplicate,unknown,trailing,nestedDuplicate} {
		w:=send(h,candidate,"application/json")
		if w.Code!=http.StatusBadRequest { t.Errorf("case %d: expected 400 got %d",i,w.Code) }
	}
}

func TestHTTPConflictIs409(t *testing.T) {
	h:=testHandler(resolverFor(apiPrincipal()),apiAuthority{})
	first:=send(h,validBody(),"application/json")
	changed:=bytes.Replace(validBody(),[]byte(`"signal":"latency"`),[]byte(`"signal":"errors"`),1)
	second:=send(h,changed,"application/json")
	if first.Code!=http.StatusCreated || second.Code!=http.StatusConflict { t.Fatalf("got %d then %d",first.Code,second.Code) }
}

func TestHTTPFailsClosedWithoutIdentityOrAuthority(t *testing.T) {
	if w:=send(testHandler(nil,apiAuthority{}),validBody(),"application/json");w.Code!=http.StatusUnauthorized { t.Fatalf("no resolver: %d",w.Code) }
	if w:=send(testHandler(resolverFor(apiPrincipal()),nil),validBody(),"application/json");w.Code!=http.StatusServiceUnavailable { t.Fatalf("no verifier: %d",w.Code) }
	other:=apiPrincipal()
	other.AgentID="other-agent"
	if w:=send(testHandler(resolverFor(other),apiAuthority{}),validBody(),"application/json");w.Code!=http.StatusForbidden { t.Fatalf("identity mismatch: %d",w.Code) }
}

func TestHTTPRejectsWrongContentTypeAndOversizedBody(t *testing.T) {
	h:=testHandler(resolverFor(apiPrincipal()),apiAuthority{})
	if w:=send(h,validBody(),"text/plain");w.Code!=http.StatusUnsupportedMediaType { t.Fatalf("content type: %d",w.Code) }
	large:=strings.Repeat(" ",(1<<20)+1)
	if w:=send(h,[]byte(large),"application/json");w.Code!=http.StatusBadRequest { t.Fatalf("large body: %d",w.Code) }
}

func TestHealthDoesNotRequireAuthentication(t *testing.T) {
	h:=testHandler(nil,nil)
	w:=httptest.NewRecorder()
	h.ServeHTTP(w,httptest.NewRequest(http.MethodGet,"/healthz",nil))
	if w.Code!=http.StatusNoContent { t.Fatalf("health: %d",w.Code) }
}


func TestHTTPRequiresExplicitEvidenceCollections(t *testing.T) {
	h := testHandler(resolverFor(apiPrincipal()), apiAuthority{})
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(validBody(), &payload); err != nil {
		t.Fatal(err)
	}
	delete(payload, "evidence_refs")
	missing, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if w := send(h, missing, "application/json"); w.Code != http.StatusBadRequest {
		t.Fatalf("missing evidence_refs: got %d body=%s", w.Code, w.Body.String())
	}
	payload["evidence_refs"] = json.RawMessage("null")
	nullArray, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if w := send(h, nullArray, "application/json"); w.Code != http.StatusBadRequest {
		t.Fatalf("null evidence_refs: got %d body=%s", w.Code, w.Body.String())
	}
}
