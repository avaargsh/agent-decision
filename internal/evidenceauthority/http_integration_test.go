package evidenceauthority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
)

// Real mTLS listener backed by the independently authenticated read-only
// source registry and actual captured observation. No fake authority.
func liveEvidenceNetworkReader(t *testing.T, registry *Registry, ref decision.EvidenceRef, wantProof []byte) func(int) {
	t.Helper()
	const peerID = "spiffe://test.example/decision"
	const sourceID = "spiffe://test.example/evidence-source"
	now := time.Now().UTC()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(id string, serial int64, server bool) tls.Certificate {
		t.Helper()
		p, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		uri, err := url.Parse(id)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{uri},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if server {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, p, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: k}
	}
	handler, err := NewReadHandler(registry, peerID)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
		Certificates: []tls.Certificate{issue(sourceID, 2, true)},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := func(id string, serial int64) *http.Client {
		h := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{issue(id, serial, false)},
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 ||
					len(state.PeerCertificates[0].URIs) != 1 || state.PeerCertificates[0].URIs[0].String() != sourceID {
					return errors.New("wrong independent evidence source")
				}
				return nil
			},
		}}, Timeout: 5 * time.Second}
		t.Cleanup(h.CloseIdleConnections)
		return h
	}
	body, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	call := func(h *http.Client, request []byte, status int) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+ReadPath, bytes.NewReader(request))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-Client-Cert", peerID)
		res, err := h.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(res.Body, 512*1024+1))
		if err != nil || res.StatusCode != status || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("source read status=%d want=%d err=%v", res.StatusCode, status, err)
		}
		if status == http.StatusOK && !bytes.Equal(raw, wantProof) {
			t.Fatal("source network response did not preserve exact signed proof")
		}
	}
	trusted := client(peerID, 3)
	call(client("spiffe://test.example/agent", 4), body, http.StatusUnauthorized)
	foreign := ref
	foreign.RunID = "22222222-2222-4222-8222-222222222222"
	bad, err := json.Marshal(foreign)
	if err != nil {
		t.Fatal(err)
	}
	call(trusted, bad, http.StatusForbidden)
	malformed := append([]byte(`{"ref":"substituted",`), body[1:]...)
	call(trusted, malformed, http.StatusBadRequest)
	return func(want int) { t.Helper(); call(trusted, body, want) }
}
