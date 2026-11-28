package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Exercise the existing Runtime authority response boundary independently
// of the pending Guard receipt contract. The transport is an in-process
// fixture, not evidence of a real mTLS deployment or consumer integration.
func TestCurrentRuntimeRejectsInvalidAuthoritySelectors(t *testing.T) {
	const run = "11111111-1111-4111-8111-111111111111"
	const turn = "55555555-5555-4555-8555-555555555555"
	const other = "99999999-9999-4999-8999-999999999999"
	digest := "sha256:" + strings.Repeat("a", 64)
	baseline := RuntimeDecisionAuthority{
		SchemaVersion: "runtime.decision-authority.v1",
		TenantID:      "tenant-a",
		RunID:         run,
		RunIntentID:   "22222222-2222-4222-8222-222222222222",
		ExecutionID:   "33333333-3333-4333-8333-333333333333",
		AttemptID:     "44444444-4444-4444-8444-444444444444",
		TurnID:        turn, InvocationID: turn,
		WorkflowID: "agent-run/v1/" + run,
		AgentID:    "agent-1", AgentReleaseID: "release-1",
		ProjectID: "project-1", SessionID: "session-1",
		SubjectID: "runtime", ActorID: "runtime", PolicyRevision: "policy-1",
		RequestDigest: digest, ConfigDigest: digest, InputDigest: digest,
		Phase: "WAITING_AUTHORITY", Status: "RUNNING",
		BreakerState: "CLOSED", BreakerEpoch: 1, BreakerVersion: 1,
	}
	for _, tc := range []struct {
		name   string
		mutate func(*RuntimeDecisionAuthority)
	}{
		{"canonical response", nil},
		{"missing attempt", func(r *RuntimeDecisionAuthority) { r.AttemptID = "" }},
		{"malformed attempt", func(r *RuntimeDecisionAuthority) { r.AttemptID = "not-a-uuid" }},
		{"missing turn", func(r *RuntimeDecisionAuthority) { r.TurnID = "" }},
		{"wrong turn", func(r *RuntimeDecisionAuthority) { r.TurnID = other }},
		{"missing invocation", func(r *RuntimeDecisionAuthority) { r.InvocationID = "" }},
		{"wrong invocation", func(r *RuntimeDecisionAuthority) { r.InvocationID = other }},
		{"wrong run", func(r *RuntimeDecisionAuthority) { r.RunID = other; r.WorkflowID = "agent-run/v1/" + other }},
		{"wrong tenant", func(r *RuntimeDecisionAuthority) { r.TenantID = "tenant-b" }},
		{"missing session", func(r *RuntimeDecisionAuthority) { r.SessionID = "" }},
		{"wrong workflow", func(r *RuntimeDecisionAuthority) { r.WorkflowID = "agent-run/v1/" + other }},
		{"non-running", func(r *RuntimeDecisionAuthority) { r.Status = "CANCELLED" }},
		{"wrong phase", func(r *RuntimeDecisionAuthority) { r.Phase = "COMPLETED" }},
		{"open breaker", func(r *RuntimeDecisionAuthority) { r.BreakerState = "OPEN" }},
		{"zero breaker epoch", func(r *RuntimeDecisionAuthority) { r.BreakerEpoch = 0 }},
		{"zero breaker version", func(r *RuntimeDecisionAuthority) { r.BreakerVersion = 0 }},
		{"actor mismatch", func(r *RuntimeDecisionAuthority) { r.ActorID = "different-actor" }},
		{"malformed input digest", func(r *RuntimeDecisionAuthority) { r.InputDigest = "invalid" }},
		{"wrong schema version", func(r *RuntimeDecisionAuthority) { r.SchemaVersion = "runtime.decision-authority.v2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := baseline
			if tc.mutate != nil {
				tc.mutate(&response)
			}
			raw, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			a := &LiveAuthority{
				tenant: baseline.TenantID,
				runtime: &authorityClient{
					origin: "https://fixture.invalid",
					client: &http.Client{Transport: freshnessTransport(func(req *http.Request) (*http.Response, error) {
						if req.Method != http.MethodGet || req.URL.Path != "/internal/v1/decision-authority/"+run ||
							req.URL.Query().Get("invocation_id") != turn {
							t.Fatalf("unexpected authority selector: %s %s", req.Method, req.URL)
						}
						header := make(http.Header)
						header.Set("Cache-Control", "no-store")
						header.Set("Content-Type", "application/json")
						return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(bytes.NewReader(raw))}, nil
					})},
				},
			}
			got, err := a.currentRuntime(context.Background(), run, turn)
			if tc.mutate == nil {
				if err != nil || got != baseline {
					t.Fatalf("valid authority rejected: %+v %v", got, err)
				}
				return
			}
			if !errors.Is(err, ErrAuthorityRejected) || got != (RuntimeDecisionAuthority{}) {
				t.Fatalf("invalid response must fail closed with no authority: %+v %v", got, err)
			}
		})
	}
}
