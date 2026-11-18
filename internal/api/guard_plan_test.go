package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/avaargsh/agent-decision/internal/decision"
)

func TestGuardPlanListenerRequiresIndependentExactWorkloadAndStore(t *testing.T) {
	if _, err := NewTrustedGuardPlanHandler(nil, nil, "spiffe://example.org/guard", "tenant-a"); err == nil {
		t.Fatal("unconfigured Guard authority started")
	}
	// The actual live sources must be supplied before positive verification;
	// without mTLS an HTTP request must never reach Decision persistence.
	h, err := NewTrustedGuardPlanHandler(decision.NewMemoryStore(), &decision.LiveAuthority{},
		"spiffe://example.org/ns/guard/sa/engageguard", "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, GuardPlanPath},
		{http.MethodGet, GuardPlanPath},
		{http.MethodPost, "/internal/v1/decision-turns:plan"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("X-Forwarded-Client-Cert", "spiffe://example.org/ns/guard/sa/engageguard")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("unverified Guard workload reached a plan: %d", w.Code)
		}
	}
}
