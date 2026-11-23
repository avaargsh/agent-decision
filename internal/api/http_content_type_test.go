package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A second Content-Type makes the incoming DecisionRequest representation
// ambiguous even when it repeats application/json. The request must be
// rejected before a DecisionRecord or outbox event can be persisted.
func TestDecisionPostRejectsDuplicateContentTypeBeforePersistence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []string
	}{
		{name: "identical", fields: []string{"application/json", "application/json"}},
		{name: "conflicting", fields: []string{"application/json", "text/plain"}},
		{name: "conflicting-reverse", fields: []string{"text/plain", "application/json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testHandler(resolverFor(apiPrincipal()), apiAuthority{})
			req := httptest.NewRequest(http.MethodPost, "/v1/decisions", bytes.NewReader(validBody()))
			for _, value := range tc.fields {
				req.Header.Add("Content-Type", value)
			}
			denied := httptest.NewRecorder()
			h.ServeHTTP(denied, req)
			if denied.Code != http.StatusUnsupportedMediaType {
				t.Fatalf("ambiguous Content-Type %q returned %d, want 415; body=%s",
					tc.fields, denied.Code, denied.Body.String())
			}
			// The same exact invocation must still be newly creatable;
			// rejected wire requests must not consume an idempotency key.
			valid := send(h, validBody(), "application/json")
			if valid.Code != http.StatusCreated {
				t.Fatalf("rejected wire request mutated Decision state: valid retry returned %d, body=%s",
					valid.Code, valid.Body.String())
			}
		})
	}
}
