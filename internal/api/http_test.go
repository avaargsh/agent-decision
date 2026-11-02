package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/avaargsh/agent-decision/internal/decision"
)

func validBody() []byte {
	req := decision.Request{TenantID: "tenant-a", IdempotencyKey: "alert-17", RunID: "run-17", Service: "payment-api", Signal: "latency", Snapshot: decision.SnapshotRef{ID: "snap-1", SHA256: strings.Repeat("a", 64)}, Capability: decision.SnapshotRef{ID: "capabilities-v1", SHA256: strings.Repeat("c", 64)}, Evidence: []decision.EvidenceRef{{Ref: "slo-1", SHA256: strings.Repeat("b", 64)}}}
	b, _ := json.Marshal(req)
	return b
}
func TestHTTPCreateAndReplay(t *testing.T) {
	h := NewHandler(decision.NewService(decision.NewMemoryStore()))
	for i, want := range []int{201, 200} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/decisions", bytes.NewReader(validBody())))
		if w.Code != want {
			t.Fatalf("pass %d: want %d got %d body=%s", i, want, w.Code, w.Body.String())
		}
	}
}
func TestStrictJSONRejectsDuplicatesAndUnknownAndTrailing(t *testing.T) {
	h := NewHandler(decision.NewService(decision.NewMemoryStore()))
	tests := [][]byte{[]byte(`{"tenant_id":"a","tenant_id":"b"}`), append(validBody(), []byte(`{}`)...), bytes.Replace(validBody(), []byte(`"signal"`), []byte(`"signal_typo"`), 1), []byte(`{"context_snapshot":{"id":"x","id":"y"}}`)}
	for i, b := range tests {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/decisions", bytes.NewReader(b)))
		if w.Code != 400 {
			t.Errorf("case %d: expected 400, got %d", i, w.Code)
		}
	}
}
func TestConflictIs409(t *testing.T) {
	h := NewHandler(decision.NewService(decision.NewMemoryStore()))
	for i, b := range [][]byte{validBody(), bytes.Replace(validBody(), []byte(`"latency"`), []byte(`"errors"`), 1)} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/decisions", bytes.NewReader(b)))
		if i == 1 && w.Code != 409 {
			t.Fatalf("expected 409 got %d: %s", w.Code, w.Body.String())
		}
	}
}
func TestOversizedRequestRejected(t *testing.T) {
	h := NewHandler(decision.NewService(decision.NewMemoryStore()))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/decisions", strings.NewReader(strings.Repeat("x", 1<<20+1))))
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}
