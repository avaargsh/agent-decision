package decision

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	defaultLedgerPageSize = 20
	maxLedgerPageSize = 100
	maxCursorBytes = 2048
)

// DecisionCursor is an opaque continuation position for descending ledger order.
type DecisionCursor struct {
	CreatedAt time.Time `json:"created_at"`
	DecisionID string `json:"decision_id"`
}

// DecisionPage is a tenant- and session-scoped page of immutable decisions.
type DecisionPage struct {
	Items []Record `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

func (s *Service) GetDecision(ctx context.Context, principal Principal, decisionID string) (Record, error) {
	if err := principal.Validate(); err != nil {
		return Record{}, err
	}
	if !decisionIDRe.MatchString(decisionID) {
		return Record{}, fmt.Errorf("%w: invalid decision id", ErrInvalidRequest)
	}
	if s.store == nil {
		return Record{}, ErrStoreUnavailable
	}
	return s.store.GetByDecisionID(ctx, principal.TenantID, principal.AgentID, principal.SessionID, decisionID)
}

func (s *Service) ListRunDecisions(ctx context.Context, principal Principal, runID, cursor string, limit int) (DecisionPage, error) {
	if err := principal.Validate(); err != nil {
		return DecisionPage{}, err
	}
	if !nameRe.MatchString(runID) {
		return DecisionPage{}, fmt.Errorf("%w: invalid run id", ErrInvalidRequest)
	}
	if limit == 0 {
		limit = defaultLedgerPageSize
	}
	if limit < 1 || limit > maxLedgerPageSize {
		return DecisionPage{}, fmt.Errorf("%w: ledger page size must be between 1 and %d", ErrInvalidRequest, maxLedgerPageSize)
	}

	var before *DecisionCursor
	if cursor != "" {
		decoded, err := decodeDecisionCursor(cursor)
		if err != nil {
			return DecisionPage{}, err
		}
		before = &decoded
	}
	if s.store == nil {
		return DecisionPage{}, ErrStoreUnavailable
	}

	records, err := s.store.ListByRun(ctx, principal.TenantID, principal.AgentID, principal.SessionID, runID, before, limit+1)
	if err != nil {
		return DecisionPage{}, err
	}
	page := DecisionPage{Items: []Record{}}
	if len(records) > limit {
		page.Items = append(page.Items, records[:limit]...)
		page.NextCursor = encodeDecisionCursor(records[limit-1])
		return page, nil
	}
	page.Items = append(page.Items, records...)
	return page, nil
}

func encodeDecisionCursor(record Record) string {
	cursor := DecisionCursor{CreatedAt: record.CreatedAt.UTC(), DecisionID: record.DecisionID}
	payload, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeDecisionCursor(value string) (DecisionCursor, error) {
	if len(value) == 0 || len(value) > maxCursorBytes {
		return DecisionCursor{}, ErrInvalidCursor
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return DecisionCursor{}, ErrInvalidCursor
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var cursor DecisionCursor
	if err := decoder.Decode(&cursor); err != nil {
		return DecisionCursor{}, ErrInvalidCursor
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, context.Canceled) && err == nil {
		return DecisionCursor{}, ErrInvalidCursor
	}
	if cursor.CreatedAt.IsZero() || !decisionIDRe.MatchString(cursor.DecisionID) {
		return DecisionCursor{}, ErrInvalidCursor
	}
	return cursor, nil
}

func (s *MemoryStore) GetByDecisionID(ctx context.Context, tenantID, agentID, sessionID, decisionID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.byKey {
		if record.TenantID == tenantID && record.AgentID == agentID &&
			record.SessionID == sessionID && record.DecisionID == decisionID {
			return clone(record), nil
		}
	}
	return Record{}, ErrNotFound
}

func (s *MemoryStore) ListByRun(ctx context.Context, tenantID, agentID, sessionID, runID string, before *DecisionCursor, limit int) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	records := make([]Record, 0)
	for _, record := range s.byKey {
		if record.TenantID != tenantID || record.AgentID != agentID ||
			record.SessionID != sessionID || record.RunID != runID {
			continue
		}
		if before != nil {
			if record.CreatedAt.After(before.CreatedAt) ||
				(record.CreatedAt.Equal(before.CreatedAt) && record.DecisionID >= before.DecisionID) {
				continue
			}
		}
		records = append(records, clone(record))
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].DecisionID > records[j].DecisionID
		}
		return records[i].CreatedAt.After(records[j].CreatedAt)
	})
	if len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}
