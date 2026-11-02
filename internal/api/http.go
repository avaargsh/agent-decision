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
	mux.HandleFunc("GET /v1/decisions/{decisionID}", func(w http.ResponseWriter, r *http.Request) {
		if resolver == nil {
			problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "trusted principal resolver is required")
			return
		}
		principal, err := resolver.Resolve(r)
		if err != nil {
			problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authenticated caller required")
			return
		}
		record, err := svc.Get(r.Context(), principal, r.PathValue("decisionID"))
		if errors.Is(err, decision.ErrNotFound) {
			problem(w, http.StatusNotFound, "NOT_FOUND", "decision record not found")
			return
		}
		if errors.Is(err, decision.ErrUnauthenticated) {
			problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authenticated caller required")
			return
		}
		if err != nil {
			problem(w, http.StatusInternalServerError, "INTERNAL_ERROR", "decision record could not be loaded")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(record)
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
