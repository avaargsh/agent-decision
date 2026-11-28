package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
)

const PlanTurnPath = "/internal/v1/decision-turns:plan"
const InspectTurnPrefix = "/internal/v1/decision-turns/"

type TurnRequest struct {
	RunID        string                 `json:"run_id"`
	InvocationID string                 `json:"invocation_id"`
	Evidence     []decision.EvidenceRef `json:"evidence_refs"`
}

type TurnInspection struct {
	Status string           `json:"status"`
	Record *decision.Record `json:"record,omitempty"`
}

func verifiedRuntimePeer(r *http.Request, expected string) bool {
	s := r.TLS
	if s == nil || !s.HandshakeComplete || s.Version != tls.VersionTLS13 ||
		len(s.PeerCertificates) == 0 || len(s.VerifiedChains) == 0 {
		return false
	}
	leaf := s.PeerCertificates[0]
	now := time.Now()
	if leaf == nil || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0] == nil ||
		leaf.URIs[0].String() != expected || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	clientAuth := false
	for _, u := range leaf.ExtKeyUsage {
		clientAuth = clientAuth || u == x509.ExtKeyUsageClientAuth
	}
	if !clientAuth {
		return false
	}
	for _, chain := range s.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && chain[0].Equal(leaf) {
			return true
		}
	}
	return false
}

// NewTrustedTurnHandler constructs the actual rule-only Decision Core with
// independently authenticated live authority. It is a separate internal
// listener; never mount it behind an Agent's forwarded identity. No generic
// caller-provided Principal, task, budget, capability or permit is accepted.
// A real TLS RequireAndVerifyClientCert listener must host this handler.
func NewTrustedTurnHandler(store decision.Store, authority *decision.LiveAuthority, expectedPeer string, attest CatalogAttestor) (http.Handler, error) {
	u, err := url.Parse(expectedPeer)
	if store == nil || authority == nil || attest == nil || err != nil || u.Scheme != "spiffe" ||
		u.Host == "" || u.Port() != "" || u.Path == "" || u.Path == "/" || u.User != nil ||
		u.Opaque != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.String() != expectedPeer {
		return nil, decision.ErrAuthorityUnavailable
	}
	core := decision.NewService(store, authority)
	fail := func(w http.ResponseWriter, err error) {
		switch {
		case errors.Is(err, decision.ErrConflict):
			problem(w, http.StatusConflict, "INVOCATION_ID_REUSED", "invocation belongs to another request")
		case errors.Is(err, decision.ErrAuthorityRejected), errors.Is(err, decision.ErrUnauthorized):
			problem(w, http.StatusForbidden, "AUTHORITY_REJECTED", "decision authority denied")
		case errors.Is(err, decision.ErrInvalidRequest):
			problem(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid decision turn")
		default:
			problem(w, http.StatusServiceUnavailable, "AUTHORITY_UNAVAILABLE", "decision authority or persistence unavailable")
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !verifiedRuntimePeer(r, expectedPeer) {
			problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authenticated Runtime required")
			return
		}
		if r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
			problem(w, http.StatusBadRequest, "INVALID_REQUEST", "unexpected URL selector")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		if r.URL.Path == PlanTurnPath && r.Method == http.MethodPost {
			if r.Header.Get("Content-Type") != "application/json" {
				problem(w, http.StatusUnsupportedMediaType, "INVALID_CONTENT_TYPE", "JSON required")
				return
			}
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128*1024))
			var requested TurnRequest
			if err != nil || json.Unmarshal(raw, &requested) != nil {
				problem(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid decision turn")
				return
			}
			canonical, err := json.Marshal(requested)
			if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(raw)) || requested.Evidence == nil || len(requested.Evidence) > 32 {
				problem(w, http.StatusBadRequest, "INVALID_REQUEST", "exact reference-only request required")
				return
			}
			if err := attest(ctx); err != nil {
				fail(w, decision.ErrStoreUnavailable)
				return
			}
			principal, req, err := authority.ResolveTurn(ctx, requested.RunID, requested.InvocationID, requested.Evidence)
			if err != nil {
				fail(w, err)
				return
			}
			record, created, err := core.Decide(ctx, principal, req)
			if err != nil {
				fail(w, err)
				return
			}
			status := http.StatusOK
			if created {
				status = http.StatusCreated
			}
			writeJSON(w, status, record)
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, InspectTurnPrefix) {
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, InspectTurnPrefix), "/")
			verify := len(parts) == 3 && parts[2] == "verify"
			if (!verify && len(parts) != 2) || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
				problem(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid inspection reference")
				return
			}
			if err := attest(ctx); err != nil {
				fail(w, decision.ErrStoreUnavailable)
				return
			}
			if verify {
				receipt, err := authority.VerifyCommittedTurn(ctx, store, parts[0], parts[1])
				if errors.Is(err, decision.ErrNotFound) {
					// No verifiable committed record now, not a final-absence barrier.
					problem(w, http.StatusNotFound, "NO_COMMITTED_DECISION", "no committed decision available for revalidation")
					return
				}
				if err != nil {
					fail(w, err)
					return
				}
				writeJSON(w, http.StatusOK, receipt)
				return
			}
			// Historical lookup is read-only, but still reauthenticates current
			// Runtime and ACP scope. Evidence may have expired since commit.
			principal, req, err := authority.ResolveTurn(ctx, parts[0], parts[1], []decision.EvidenceRef{})
			if err != nil {
				fail(w, err)
				return
			}
			got, err := store.GetByInvocation(ctx, principal.TenantID, req.InvocationID)
			if errors.Is(err, decision.ErrNotFound) {
				writeJSON(w, http.StatusOK, TurnInspection{Status: "ABSENT_UNCERTAIN"})
				return
			}
			if err != nil {
				fail(w, err)
				return
			}
			// No effect may be inferred from a historical FOUND record.
			if got.TenantID != principal.TenantID || got.SubjectID != principal.SubjectID ||
				got.AgentID != principal.AgentID || got.SessionID != principal.SessionID ||
				got.RunID != req.Identity.RunID || got.InvocationID != req.InvocationID ||
				got.ContextSnapshot != req.ContextSnapshot || got.CapabilitySnapshot != req.CapabilitySnapshot {
				fail(w, decision.ErrAuthorityRejected)
				return
			}
			writeJSON(w, http.StatusOK, TurnInspection{Status: "FOUND", Record: &got})
			return
		}
		problem(w, http.StatusNotFound, "NOT_FOUND", "unknown decision turn route")
	}), nil
}
