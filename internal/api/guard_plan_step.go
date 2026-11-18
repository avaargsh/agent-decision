package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
)

const GuardPlanStepPath = "/internal/v1/guard-plan-steps:verify"

// NewTrustedGuardPlanHandler is a separate Guard-only mTLS authority listener.
// Do not mount it on the Runtime-facing Decision API or a generic forwarded
// ingress. Its response is reference-only verification, NEVER a Permit.
func NewTrustedGuardPlanHandler(store decision.Store, authority *decision.LiveAuthority, guardSPIFFE string, attest CatalogAttestor) (http.Handler, error) {
	if store == nil || authority == nil || attest == nil || !validTrustedWorkloadSPIFFE(guardSPIFFE) {
		return nil, decision.ErrAuthorityUnavailable
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !verifiedRuntimePeer(r, guardSPIFFE) {
			problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authenticated Guard required")
			return
		}
		if r.URL.Path != GuardPlanStepPath || r.Method != http.MethodPost {
			problem(w, http.StatusNotFound, "NOT_FOUND", "unsupported Guard verification route")
			return
		}
		if r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get("Content-Type") != "application/json" {
			problem(w, http.StatusBadRequest, "INVALID_REQUEST", "canonical reference-only JSON required")
			return
		}
		if r.Body == nil {
			problem(w, http.StatusBadRequest, "INVALID_REQUEST", "missing request")
			return
		}
		defer r.Body.Close()
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		var req decision.GuardPlanStepRequest
		if err != nil || len(raw) == 0 || json.Unmarshal(raw, &req) != nil || req.Validate() != nil {
			problem(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid Guard plan request")
			return
		}
		canonical, err := json.Marshal(req)
		if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(raw)) {
			problem(w, http.StatusBadRequest, "INVALID_REQUEST", "noncanonical or duplicate request fields")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		if err := attest(ctx); err != nil {
			problem(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "Decision catalog unavailable")
			return
		}
		receipt, err := authority.VerifyGuardPlanStep(ctx, store, req)
		switch {
		case errors.Is(err, decision.ErrAuthorityRejected), errors.Is(err, decision.ErrUnauthorized), errors.Is(err, decision.ErrNotFound):
			problem(w, http.StatusForbidden, "AUTHORITY_REJECTED", "current Plan/Step verification denied")
		case err != nil:
			problem(w, http.StatusServiceUnavailable, "AUTHORITY_UNAVAILABLE", "independent authority unavailable")
		default:
			writeJSON(w, http.StatusOK, receipt)
		}
	}), nil
}
