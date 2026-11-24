package decision

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A verifier adapter must not be able to replace the request it verifies.
type mutatingAuthority struct{}

func (mutatingAuthority) VerifyDecisionInputs(_ context.Context, _ Principal, req Request) error {
	req.Evidence[0].SHA256 = strings.Repeat("f", 64)
	req.Capabilities[0].ContractSHA256 = strings.Repeat("f", 64)
	return nil
}

func TestAuthorityVerifierCannotMutateDecisionInputs(t *testing.T) {
	ctx := context.Background()
	principal := testPrincipal()
	req := validRequest()
	original := validRequest()
	store := NewMemoryStore()
	svc := NewService(store, mutatingAuthority{})

	if _, _, err := svc.Decide(ctx, principal, req); !errors.Is(err, ErrAuthorityRejected) {
		t.Fatalf("mutated authority input must be rejected: %v", err)
	}
	if digest(req) != digest(original) {
		t.Fatal("authority verifier modified caller-owned request")
	}
	if _, err := store.GetByInvocation(ctx, principal.TenantID, req.InvocationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected request must not be persisted: %v", err)
	}

	// An unchanged, independently verified request may retry the invocation.
	svc = NewService(store, allowAuthority{})
	record, created, err := svc.Decide(ctx, principal, original)
	if err != nil || !created {
		t.Fatalf("create: created=%t err=%v", created, err)
	}
	expectedFingerprint := digest(struct {
		Principal Principal
		Request   Request
	}{principal, original})
	if record.RequestSHA256 != expectedFingerprint {
		t.Fatal("record fingerprint does not bind original request")
	}
	if record.Evidence[0].SHA256 != original.Evidence[0].SHA256 ||
		record.Plan.Steps[0].Capability.ContractSHA256 != original.Capabilities[0].ContractSHA256 {
		t.Fatal("record contains authority-mutated evidence or capability")
	}
	replayed, created, err := svc.Decide(ctx, principal, original)
	if err != nil || created || replayed.DecisionID != record.DecisionID {
		t.Fatalf("exact retry must replay original record: created=%t err=%v", created, err)
	}
}
