package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
)

// GuardPlanPath is an isolated, Guard-only, read-only admission gate.
// Never mount this route on the agent-facing or Runtime-specific listener.
const GuardPlanPath = "/internal/v1/guard-plan-steps:verify"

// NewTrustedGuardPlanHandler only serves the exact mTLS Guard workload for
// one operator-pinned tenant. It revalidates immutable Decision records and
// all live Runtime/ACP/Evidence sources; it cannot issue an execution Permit.
func NewTrustedGuardPlanHandler(
	store decision.Store, authority *decision.LiveAuthority, expectedGuardPeer, tenant string, attest CatalogAttestor,
) (http.Handler, error) {
	peer, err := url.Parse(expectedGuardPeer)
	if store == nil || authority == nil || attest == nil || err != nil ||
		peer.Scheme != "spiffe" || peer.Host == "" || peer.Port() != "" ||
		peer.Path == "" || peer.Path == "/" || peer.User != nil ||
		peer.Opaque != "" || peer.RawPath != "" || peer.RawQuery != "" ||
		peer.ForceQuery || peer.Fragment != "" || peer.String() != expectedGuardPeer ||
		tenant == "" || len(tenant) > 255 {
		return nil, decision.ErrAuthorityUnavailable
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !verifiedRuntimePeer(r, expectedGuardPeer) {
			problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authenticated Guard required")
			return
		}
		if r.URL.Path != GuardPlanPath || r.URL.RawPath != "" ||
			r.URL.RawQuery != "" || r.URL.ForceQuery {
			problem(w, http.StatusNotFound, "NOT_FOUND", "unsupported Guard route")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			problem(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
			return
		}
		if r.Header.Get("Content-Type") != "application/json" || r.Body == nil {
			problem(w, http.StatusUnsupportedMediaType, "INVALID_CONTENT_TYPE", "canonical JSON required")
			return
		}
		defer r.Body.Close()
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		var request decision.GuardPlanStepRequest
		if err != nil || json.Unmarshal(raw, &request) != nil {
			problem(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid Guard plan step")
			return
		}
		canonical, err := json.Marshal(request)
		if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(raw)) {
			problem(w, http.StatusBadRequest, "INVALID_REQUEST", "noncanonical Guard request")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		// The Guard read path must not trust a stale or weakened Decision
		// PostgreSQL catalog. In particular a missing append-only trigger
		// must fail closed even when live source reads would succeed.
		if err := attest(ctx); err != nil {
			problem(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "immutable Decision catalog unavailable")
			return
		}
		receipt, err := authority.VerifyGuardPlanStep(ctx, store, tenant, request)
		switch {
		case errors.Is(err, decision.ErrAuthorityRejected), errors.Is(err, decision.ErrNotFound):
			problem(w, http.StatusForbidden, "PLAN_STEP_DENIED", "current Plan step denied")
		case err != nil:
			problem(w, http.StatusServiceUnavailable, "AUTHORITY_UNAVAILABLE", "authority unavailable")
		default:
			writeJSON(w, http.StatusOK, receipt)
		}
	}), nil
}
