package evidenceauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"time"
)

// issueRuntimeWorkerCertificate is a TEST-ONLY isolated CA helper.
// The Runtime process keeps the private key. Decision receives only a DER
// CSR and is forbidden from changing its URI or issuing server certificates.
func issueRuntimeWorkerCertificate(csrDER []byte, ca *x509.Certificate, signer ed25519.PrivateKey, now time.Time) ([]byte, error) {
	deny := errors.New("invalid isolated Runtime worker CSR")
	if ca == nil || !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 ||
		len(signer) != ed25519.PrivateKeySize || now.IsZero() {
		return nil, deny
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil || csr.PublicKeyAlgorithm != x509.Ed25519 ||
		len(csr.URIs) != 1 || len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 ||
		len(csr.EmailAddresses) != 0 || csr.Subject.CommonName != "" {
		return nil, deny
	}
	worker, err := url.Parse("spiffe://example.org/runtime-worker")
	if err != nil || csr.URIs[0] == nil || csr.URIs[0].String() != worker.String() {
		return nil, deny
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	leaf := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(30 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{worker},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, signer)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// fixtureMarker must only be produced by the other process after it actually
// commits or observes the required fact; an unbounded sleep is not evidence.
func fixtureMarker(ctx context.Context, filename string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		b, err := os.ReadFile(filename)
		if err == nil && len(b) > 0 {
			return nil
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
