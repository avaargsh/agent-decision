package decision

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDecisionRejectsUnencodableRequestFingerprint(t *testing.T) {
	ctx := context.Background()
	p := testPrincipal()
	store := NewMemoryStore()
	svc := NewService(store, allowAuthority{})

	// Go time.Time supports years outside JSON's four-digit year range.
	// A serialization error must not become SHA256(empty) in the ledger.
	req := validRequest()
	req.ContextSnapshot.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, created, err := svc.Decide(ctx, p, req); created || !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unencodable request must be rejected: created=%t err=%v", created, err)
	}
	if _, err := store.GetByInvocation(ctx, p.TenantID, req.InvocationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unencodable request must not be persisted: %v", err)
	}

	// A valid request may still use this invocation; normal fingerprints
	// and exact replay remain compatible with previously stored decisions.
	valid := validRequest()
	record, created, err := svc.Decide(ctx, p, valid)
	if err != nil || !created {
		t.Fatalf("valid create: created=%t err=%v", created, err)
	}
	expected := digest(struct {
		Principal Principal
		Request   Request
	}{p, valid})
	if record.RequestSHA256 != expected {
		t.Fatal("valid request fingerprint changed")
	}
	if _, created, err := svc.Decide(ctx, p, req); created || !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unencodable retry must be rejected: created=%t err=%v", created, err)
	}
	replayed, created, err := svc.Decide(ctx, p, valid)
	if err != nil || created || replayed.DecisionID != record.DecisionID {
		t.Fatalf("valid replay: created=%t err=%v", created, err)
	}
}

func TestDecisionRejectsLossyUTF8Fingerprint(t *testing.T) {
	ctx := context.Background()
	p := testPrincipal()
	cases := []struct {
		name   string
		mutate func(*Request, string)
	}{
		{"snapshot ref", func(r *Request, s string) { r.ContextSnapshot.ID = s }},
		{"evidence ref", func(r *Request, s string) { r.Evidence[0].Ref = s }},
		{"capability schema", func(r *Request, s string) { r.Capabilities[0].InputSchemaRef = s }},
		{"version", func(r *Request, s string) {
			r.Versions.CapabilityCatalogVersion = s
			r.CapabilitySnapshot.Version = s
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMemoryStore()
			svc := NewService(store, allowAuthority{})
			for _, bad := range []string{"ref\xff", "ref\xfe"} {
				req := validRequest()
				tc.mutate(&req, bad)
				if _, created, err := svc.Decide(ctx, p, req); created || !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("invalid UTF-8 must not be hashed or persisted: created=%t err=%v", created, err)
				}
				if _, err := store.GetByInvocation(ctx, p.TenantID, req.InvocationID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("invalid request must leave no ledger entry: %v", err)
				}
			}
			req := validRequest()
			tc.mutate(&req, "ref\ufffd")
			record, created, err := svc.Decide(ctx, p, req)
			if err != nil || !created {
				t.Fatalf("valid Unicode must remain accepted: created=%t err=%v", created, err)
			}
			replay, created, err := svc.Decide(ctx, p, req)
			if err != nil || created || replay.RequestSHA256 != record.RequestSHA256 {
				t.Fatalf("valid Unicode replay: created=%t err=%v", created, err)
			}
			tc.mutate(&req, "ref\xff")
			if _, created, err := svc.Decide(ctx, p, req); created || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("invalid UTF-8 retry must be rejected before lookup: created=%t err=%v", created, err)
			}
		})
	}
}
