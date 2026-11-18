package evidenceauthority

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
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
)

const ReadPath = "/internal/v1/evidence:read"

func exactPeer(r *http.Request, expected string) bool {
	state := r.TLS
	if state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 ||
		len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return false
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()
	if leaf == nil || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0] == nil ||
		leaf.URIs[0].String() != expected || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	usage := false
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			usage = true
		}
	}
	if !usage {
		return false
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && chain[0].Equal(leaf) {
			return true
		}
	}
	return false
}

// NewReadHandler serves the independent source's fresh read-only registry.
// A TLS 1.3 RequireAndVerifyClientCert listener and dedicated read-only
// PostgreSQL LOGIN must host it. No source signing key, publish or revoke
// endpoint is accepted. POST carries only the expected observation reference
// for exact verification; it never performs a mutation.
func NewReadHandler(registry *Registry, expectedPeer string) (http.Handler, error) {
	u, err := url.Parse(expectedPeer)
	if registry == nil || registry.db == nil || err != nil || u.Scheme != "spiffe" || u.Host == "" ||
		u.Port() != "" || u.Path == "" || u.Path == "/" || u.User != nil || u.Opaque != "" || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != expectedPeer {
		return nil, decision.ErrAuthorityUnavailable
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		deny := func(status int, code string) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
		}
		if !exactPeer(r, expectedPeer) {
			deny(http.StatusUnauthorized, "UNAUTHENTICATED")
			return
		}
		if r.URL.Path != ReadPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
			deny(http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if r.Method != http.MethodPost {
			deny(http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			deny(http.StatusUnsupportedMediaType, "INVALID_CONTENT_TYPE")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
		var expected decision.EvidenceRef
		if err != nil || json.Unmarshal(raw, &expected) != nil {
			deny(http.StatusBadRequest, "INVALID_REFERENCE")
			return
		}
		// This read endpoint requires the exact canonical Go EvidenceRef
		// representation: aliases, duplicate or extra fields are not valid.
		canonical, err := json.Marshal(expected)
		if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(raw)) {
			deny(http.StatusBadRequest, "INVALID_REFERENCE")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		proof, err := registry.ReadCurrent(ctx, expected, time.Now().UTC())
		switch {
		case errors.Is(err, decision.ErrAuthorityRejected):
			deny(http.StatusForbidden, "EVIDENCE_DENIED")
		case err != nil:
			deny(http.StatusServiceUnavailable, "EVIDENCE_UNAVAILABLE")
		default:
			_, _ = w.Write(proof)
		}
	}), nil
}
