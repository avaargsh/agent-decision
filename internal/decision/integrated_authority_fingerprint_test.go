package decision

import (
	"context"
	"errors"
	"testing"
)

type lossyUTF8Authority struct{}

func (lossyUTF8Authority) VerifyDecisionInputs(_ context.Context, _ Principal, req Request) error {
	// encoding/json replaces malformed UTF-8 with U+FFFD.
	req.Evidence[0].Ref = "sample\xff"
	return nil
}

func TestIntegratedAuthorityRejectsLossyFingerprintMutation(t *testing.T) {
	ctx := context.Background()
	p := testPrincipal()
	req := validRequest()
	req.Evidence[0].Ref = "sample\ufffd"
	store := NewMemoryStore()
	svc := NewService(store, lossyUTF8Authority{})
	if _, created, err := svc.Decide(ctx, p, req); created || !errors.Is(err, ErrAuthorityRejected) {
		t.Fatalf("lossy verifier mutation must be rejected: created=%t err=%v", created, err)
	}
	if _, err := store.GetByInvocation(ctx, p.TenantID, req.InvocationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected verifier mutation persisted: %v", err)
	}
	if req.Evidence[0].Ref != "sample\ufffd" {
		t.Fatal("verifier mutated caller-owned evidence")
	}
	if _, created, err := NewService(store, allowAuthority{}).Decide(ctx, p, req); err != nil || !created {
		t.Fatalf("valid retry failed: created=%t err=%v", created, err)
	}
}
