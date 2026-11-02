// Package outbox implements at-least-once delivery over a transactional outbox.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var ErrLeaseLost = errors.New("outbox lease lost")

type Event struct {
	ID          string          `json:"event_id"`
	TenantID    string          `json:"tenant_id"`
	AggregateID string          `json:"aggregate_id"`
	Type        string          `json:"event_type"`
	Payload     json.RawMessage `json:"payload"`
	Attempts    int             `json:"attempts"`
}

type Store interface {
	Claim(context.Context, string, int, time.Duration) ([]Event, error)
	Ack(context.Context, string, string) error
	Retry(context.Context, string, string, time.Duration, string) error
}

type Publisher interface {
	Publish(context.Context, Event) error
}

// DispatchOnce publishes a claimed batch. A crash after Publish and before Ack
// intentionally causes redelivery; consumers must deduplicate by Event.ID.
func DispatchOnce(ctx context.Context, store Store, publisher Publisher, workerID string, limit int, lease, retryDelay time.Duration) (int, error) {
	if store == nil || publisher == nil || workerID == "" || limit < 1 || lease <= 0 || retryDelay < 0 {
		return 0, errors.New("invalid outbox dispatcher configuration")
	}
	events, err := store.Claim(ctx, workerID, limit, lease)
	if err != nil {
		return 0, err
	}
	published := 0
	var firstErr error
	for _, event := range events {
		if err := publisher.Publish(ctx, event); err != nil {
			if retryErr := store.Retry(ctx, event.ID, workerID, retryDelay, err.Error()); retryErr != nil && firstErr == nil {
				firstErr = retryErr
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := store.Ack(ctx, event.ID, workerID); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		published++
	}
	return published, firstErr
}
