package decision

import (
	"context"
	"errors"
	"testing"
)

func TestEvidenceBindingRejectsDelimiterAlias(t *testing.T) {
	req := validRequest()
	req.Evidence[0].SourceID = "source"
	req.Evidence[0].Ref = `metric\x00sample`
	strategy := strategyFunc(func(r Request, id string) StrategyResult {
		result := SREReadOnlyStrategy{}.Plan(r, id)
		result.Steps[0].EvidenceRefs[0] = EvidenceBinding{
			SourceID: `source\x00metric`,
			Ref:      "sample",
		}
		return result
	})
	ctx := context.Background()
	store := NewMemoryStore()
	svc := NewServiceWithStrategy(store, allowAuthority{}, strategy)
	if _, _, err := svc.Decide(ctx, testPrincipal(), req); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unattested evidence pair must be rejected: %v", err)
	}
	if _, err := store.GetByInvocation(ctx, testPrincipal().TenantID, req.InvocationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invalid evidence binding must not be persisted: %v", err)
	}
}

func TestDistinctEvidencePairsWithDelimiterRemainDistinct(t *testing.T) {
	req := validRequest()
	req.Evidence[0].SourceID = "source"
	req.Evidence[0].Ref = `metric\x00sample`
	req.Evidence[1].SourceID = `source\x00metric`
	req.Evidence[1].Ref = "sample"

	record, created, err := NewService(NewMemoryStore(), allowAuthority{}).Decide(
		context.Background(), testPrincipal(), req)
	if err != nil || !created || record.Status != StatusProposed {
		t.Fatalf("distinct valid evidence pairs must remain usable: created=%t err=%v", created, err)
	}
	for i, e := range req.Evidence {
		want := EvidenceBinding{SourceID: e.SourceID, Ref: e.Ref}
		got := record.Plan.Steps[i].EvidenceRefs
		if len(got) != 1 || got[0] != want {
			t.Fatalf("step %d: got %v, want %v", i, got, want)
		}
	}
}
