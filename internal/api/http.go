// Package api exposes a development-only HTTP contract. A trusted principal
// resolver and authoritative snapshot verifier are mandatory for decision calls.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/avaargsh/agent-decision/internal/decision"
)

const maxBodyBytes = 1 << 20

type PrincipalResolver interface {
	Resolve(*http.Request) (decision.Principal, error)
}

type PrincipalResolverFunc func(*http.Request) (decision.Principal, error)

func (f PrincipalResolverFunc) Resolve(r *http.Request) (decision.Principal, error) {
	return f(r)
}

func NewHandler(svc *decision.Service, resolver PrincipalResolver) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/decisions", func(w http.ResponseWriter, r *http.Request) {
		if resolver == nil {
			problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "trusted principal resolver is required")
			return
		}
		principal, err := resolver.Resolve(r)
		if err != nil {
			problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authenticated caller required")
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			problem(w, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			problem(w, http.StatusBadRequest, "INVALID_JSON", "invalid or oversized JSON body")
			return
		}
		if err := validateJSONObjects(body); err != nil {
			problem(w, http.StatusBadRequest, "INVALID_JSON", "duplicate keys or malformed JSON")
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var req decision.Request
		if err := decoder.Decode(&req); err != nil {
			problem(w, http.StatusBadRequest, "INVALID_JSON", "invalid or unknown request field")
			return
		}
		if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			problem(w, http.StatusBadRequest, "INVALID_JSON", "trailing JSON content")
			return
		}

		record, created, err := svc.Decide(r.Context(), principal, req)
		switch {
		case errors.Is(err, decision.ErrConflict):
			problem(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "idempotency key belongs to a different request")
			return
		case errors.Is(err, decision.ErrUnauthenticated):
			problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authenticated caller required")
			return
		case errors.Is(err, decision.ErrUnauthorized):
			problem(w, http.StatusForbidden, "IDENTITY_MISMATCH", "request identity does not match authenticated principal")
			return
		case errors.Is(err, decision.ErrAuthorityUnavailable):
			problem(w, http.StatusServiceUnavailable, "AUTHORITY_UNAVAILABLE", "authoritative snapshot verification is unavailable")
			return
		case errors.Is(err, decision.ErrAuthorityRejected):
			problem(w, http.StatusForbidden, "AUTHORITY_REJECTED", "authoritative snapshot verification rejected the request")
			return
		case errors.Is(err, decision.ErrStoreUnavailable):
			problem(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "decision persistence is unavailable")
			return
		case errors.Is(err, decision.ErrInvalidRequest):
			problem(w, http.StatusBadRequest, "INVALID_REQUEST", "decision request failed contract validation")
			return
		case err != nil:
			problem(w, http.StatusInternalServerError, "INTERNAL_ERROR", "decision request could not be processed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if created {
			w.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(w).Encode(record)
	})
	mux.HandleFunc("GET /v1/decisions/{decision_id}", func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resolvePrincipal(w, r, resolver)
		if !ok {
			return
		}
		record, err := svc.GetDecision(r.Context(), principal, r.PathValue("decision_id"))
		if err != nil {
			writeDecisionError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, record)
	})
	mux.HandleFunc("GET /v1/runs/{run_id}/decisions", func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resolvePrincipal(w, r, resolver)
		if !ok {
			return
		}
		limit := 0
		if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
			parsed, err := strconv.Atoi(rawLimit)
			if err != nil {
				problem(w, http.StatusBadRequest, "INVALID_REQUEST", "limit must be an integer")
				return
			}
			limit = parsed
		}
		page, err := svc.ListRunDecisions(r.Context(), principal, r.PathValue("run_id"), r.URL.Query().Get("cursor"), limit)
		if err != nil {
			writeDecisionError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, page)
	})
	return mux
}

// validateJSONObjects rejects duplicate keys at every depth.
func validateJSONObjects(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON object key")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON content")
	}
	return nil
}

func problem(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

func resolvePrincipal(w http.ResponseWriter, r *http.Request, resolver PrincipalResolver) (decision.Principal, bool) {
	if resolver == nil {
		problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "trusted principal resolver is required")
		return decision.Principal{}, false
	}
	principal, err := resolver.Resolve(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authenticated caller required")
		return decision.Principal{}, false
	}
	if err := principal.Validate(); err != nil {
		problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authenticated caller required")
		return decision.Principal{}, false
	}
	return principal, true
}

func writeDecisionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, decision.ErrUnauthenticated):
		problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authenticated caller required")
	case errors.Is(err, decision.ErrUnauthorized):
		problem(w, http.StatusForbidden, "IDENTITY_MISMATCH", "request identity does not match authenticated principal")
	case errors.Is(err, decision.ErrNotFound):
		problem(w, http.StatusNotFound, "NOT_FOUND", "decision record was not found")
	case errors.Is(err, decision.ErrInvalidCursor):
		problem(w, http.StatusBadRequest, "INVALID_CURSOR", "decision page cursor is invalid")
	case errors.Is(err, decision.ErrInvalidRequest):
		problem(w, http.StatusBadRequest, "INVALID_REQUEST", "decision query failed contract validation")
	case errors.Is(err, decision.ErrStoreUnavailable):
		problem(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "decision persistence is unavailable")
	default:
		problem(w, http.StatusInternalServerError, "INTERNAL_ERROR", "decision query could not be processed")
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
