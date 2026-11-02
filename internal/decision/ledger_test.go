package decision

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestDecisionLedgerQueriesAreTenantAndSessionScoped(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	service := NewService(store, allowAuthority{})
	principal := testPrincipal()
	created := make([]Record, 0, 3)

	for i := 1; i <= 3; i++ {
		req := validRequest()
		req.IdempotencyKey = fmt.Sprintf("ledger-%d", i)
		service.now = func() time.Time {
			return time.Date(2026, 11, 2, 10, i, 0, 0, time.UTC)
		}
		record, inserted, err := service.Decide(ctx, principal, req)
		if err != nil || !inserted {
			t.Fatalf("create ledger record %d: inserted=%v err=%v", i, inserted, err)
		}
		created = append(created, record)
	}

	first, err := service.GetDecision(ctx, principal, created[0].DecisionID)
	if err != nil || first.DecisionID != created[0].DecisionID {
		t.Fatalf("get decision: record=%+v err=%v", first, err)
	}

	otherSession := principal
	otherSession.SessionID = "different-session"
	if _, err := service.GetDecision(ctx, otherSession, created[0].DecisionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-session read must be hidden, got %v", err)
	}
	otherTenant := principal
	otherTenant.TenantID = "tenant-b"
	if _, err := service.GetDecision(ctx, otherTenant, created[0].DecisionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read must be hidden, got %v", err)
	}

	page, err := service.ListRunDecisions(ctx, principal, "run-17", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("expected first page of 2 with cursor, got %+v", page)
	}
	if !page.Items[0].CreatedAt.After(page.Items[1].CreatedAt) {
		t.Fatalf("page must be ordered newest first: %+v", page.Items)
	}
	second, err := service.ListRunDecisions(ctx, principal, "run-17", page.NextCursor, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.NextCursor != "" {
		t.Fatalf("expected final page of 1 without cursor, got %+v", second)
	}
	if second.Items[0].DecisionID == page.Items[0].DecisionID || second.Items[0].DecisionID == page.Items[1].DecisionID {
		t.Fatalf("pagination repeated a decision: first=%+v second=%+v", page.Items, second.Items)
	}

	empty, err := service.ListRunDecisions(ctx, otherSession, "run-17", "", 20)
	if err != nil || len(empty.Items) != 0 {
		t.Fatalf("cross-session list must be empty: %+v err=%v", empty, err)
	}
}

func TestDecisionLedgerRejectsInvalidCursorAndLimit(t *testing.T) {
	service := NewService(NewMemoryStore(), allowAuthority{})
	principal := testPrincipal()

	if _, err := service.ListRunDecisions(context.Background(), principal, "run-17", "not-a-cursor", 10); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("expected invalid cursor, got %v", err)
	}
	if _, err := service.ListRunDecisions(context.Background(), principal, "run-17", "", -1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid limit, got %v", err)
	}
	if _, err := service.GetDecision(context.Background(), principal, "invalid-id"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid decision id, got %v", err)
	}
}
