package evidenceauthority

import (
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "math/big"
    "net/url"
    "testing"
    "time"
)

func TestIssueRuntimeWorkerCertificateBindsVerifiedCSR(t *testing.T) {
    now := time.Now().UTC()
    rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    template := &x509.Certificate{
        SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
        IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
    }
    rootDER, err := x509.CreateCertificate(rand.Reader, template, template, rootPub, rootKey)
    if err != nil { t.Fatal(err) }
    root, err := x509.ParseCertificate(rootDER)
    if err != nil { t.Fatal(err) }
    issueCSR := func(ids ...string) []byte {
        t.Helper()
        _, key, err := ed25519.GenerateKey(rand.Reader)
        if err != nil { t.Fatal(err) }
        uris := make([]*url.URL, 0, len(ids))
        for _, s := range ids {
            u, err := url.Parse(s)
            if err != nil { t.Fatal(err) }
            uris = append(uris, u)
        }
        csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: uris}, key)
        if err != nil { t.Fatal(err) }
        return csr
    }
    good := issueCSR("spiffe://example.org/runtime-worker")
    wire, err := issueRuntimeWorkerCertificate(good, root, rootKey, now)
    if err != nil { t.Fatal(err) }
    block, rest := pem.Decode(wire)
    if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
        t.Fatal("runtime certificate wire must contain only the worker public certificate")
    }
    leaf, err := x509.ParseCertificate(block.Bytes)
    if err != nil { t.Fatal(err) }
    roots := x509.NewCertPool()
    roots.AddCert(root)
    if _, err := leaf.Verify(x509.VerifyOptions{
        Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
    }); err != nil {
        t.Fatalf("runtime workload certificate was not verifiably issued: %v", err)
    }
    if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://example.org/runtime-worker" ||
        leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
        t.Fatal("issued worker leaf did not bind exact mTLS identity")
    }
    for _, ids := range [][]string{
        nil, {"spiffe://example.org/decision-api"}, {"spiffe://example.org/runtime-worker","spiffe://example.org/admin"},
        {"spiffe://example.org/runtime-worker?role=admin"}, {"spiffe://example.org/runtime-worker#admin"},
    } {
        if _, err := issueRuntimeWorkerCertificate(issueCSR(ids...), root, rootKey, now); err == nil {
            t.Fatalf("noncanonical or wrong worker CSR accepted: %v", ids)
        }
    }
    corrupted := append([]byte{}, good...)
    corrupted[len(corrupted)-1] ^= 0x40
    if _, err := issueRuntimeWorkerCertificate(corrupted, root, rootKey, now); err == nil {
        t.Fatal("modified CSR signature was accepted")
    }
}
