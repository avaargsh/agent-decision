// Package api exposes a development-only loopback HTTP surface.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/avaargsh/agent-decision/internal/decision"
)

const maxBodyBytes = 1 << 20

func NewHandler(svc *decision.Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("POST /v1/decisions", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		b, err := io.ReadAll(r.Body)
		if err != nil {
			problem(w, 400, "INVALID_JSON", "invalid or oversized JSON body")
			return
		}
		if err := validateJSONObjects(b); err != nil {
			problem(w, 400, "INVALID_JSON", err.Error())
			return
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		var req decision.Request
		if err := dec.Decode(&req); err != nil {
			problem(w, 400, "INVALID_JSON", "invalid or unknown request field")
			return
		}
		rec, created, err := svc.Decide(r.Context(), req)
		if errors.Is(err, decision.ErrConflict) {
			problem(w, 409, "IDEMPOTENCY_CONFLICT", "idempotency key already belongs to another request")
			return
		}
		if err != nil {
			problem(w, 400, "INVALID_REQUEST", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if created {
			w.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(w).Encode(rec)
	})
	return mux
}

// validateJSONObjects rejects duplicate keys at every depth, not just top-level.
func validateJSONObjects(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				name, ok := k.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if _, ok := seen[name]; ok {
					return fmt.Errorf("duplicate JSON key: %q", name)
				}
				seen[name] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("unexpected trailing JSON content")
	}
	return nil
}
func problem(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}
