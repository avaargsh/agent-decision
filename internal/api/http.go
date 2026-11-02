// Package api exposes the versioned Decision HTTP contract.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/avaargsh/agent-decision/internal/auth"
	"github.com/avaargsh/agent-decision/internal/decision"
)

const maxBodyBytes = 1 << 20

func NewHandler(service *decision.Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("POST /v1/decisions", func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok {
			problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authenticated tenant principal is required")
			return
		}
		mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mediaErr != nil || !strings.EqualFold(mediaType, "application/json") {
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
			problem(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var request decision.Request
		if err := decoder.Decode(&request); err != nil {
			problem(w, http.StatusBadRequest, "INVALID_JSON", "invalid or unknown request field")
			return
		}
		record, created, err := service.Decide(r.Context(), principal, request)
		switch {
		case errors.Is(err, decision.ErrConflict):
			problem(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "idempotency key already belongs to another request")
			return
		case errors.Is(err, decision.ErrNotAuthorized):
			problem(w, http.StatusForbidden, "NOT_AUTHORIZED", "principal is not authorized for this decision request")
			return
		case errors.Is(err, decision.ErrAuthorityUnavailable):
			problem(w, http.StatusServiceUnavailable, "AUTHORITY_UNAVAILABLE", "authoritative identity and evidence verification is not configured")
			return
		case errors.Is(err, decision.ErrAuthorityRejected):
			problem(w, http.StatusUnprocessableEntity, "AUTHORITY_REJECTED", "authoritative identity or evidence verification failed")
			return
		case errors.Is(err, decision.ErrInvalidRequest):
			problem(w, http.StatusBadRequest, "INVALID_REQUEST", "decision request does not satisfy the v1 contract")
			return
		case err != nil:
			problem(w, http.StatusInternalServerError, "INTERNAL_ERROR", "decision service could not persist the request")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if created {
			w.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(w).Encode(record)
	})
	mux.HandleFunc("GET /v1/agents/{agentID}/decisions/{decisionID}", func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok {
			problem(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authenticated tenant principal is required")
			return
		}
		record, err := service.Get(r.Context(), principal, r.PathValue("agentID"), r.PathValue("decisionID"))
		if errors.Is(err, decision.ErrNotFound) {
			problem(w, http.StatusNotFound, "NOT_FOUND", "decision record not found")
			return
		}
		if err != nil {
			problem(w, http.StatusInternalServerError, "INTERNAL_ERROR", "could not load decision record")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(record)
	})
	return mux
}

// validateJSONObjects rejects duplicate keys at every nesting depth.
func validateJSONObjects(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON key: %q", key)
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
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("unexpected trailing JSON content")
	}
	return nil
}

func problem(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}
