// Package outbox provides at-least-once delivery for durable Decision events.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var ErrLeaseLost = errors.New("outbox lease lost")

// ReasonPublishFailed is the only durable retry diagnostic. Publisher error
// strings may contain credentials, endpoints or request data and are never persisted.
const ReasonPublishFailed = "publish_failed"

// Event is an immutable event envelope. Payload is the immutable DecisionRecord.
type Event struct {
	ID               string          `json:"event_id"`
	TenantID         string          `json:"tenant_id"`
	AggregateType    string          `json:"aggregate_type"`
	AggregateID      string          `json:"aggregate_id"`
	AggregateVersion int64           `json:"aggregate_version"`
	Type             string          `json:"event_type"`
	SchemaVersion    int             `json:"schema_version"`
	Payload          json.RawMessage `json:"payload"`
	Attempts         int             `json:"attempts"`
	CreatedAt        time.Time       `json:"created_at"`
}

// Each Ack/Retry carries the monotonic attempt (lease fencing token)
// returned by Claim, preventing a stale operation by the same worker ID.
type Store interface {
	Claim(context.Context, string, int, time.Duration) ([]Event, error)
	Ack(context.Context, string, string, int) error
	Retry(context.Context, string, string, int, time.Duration, string) error // reason code, never raw error text
}

type Publisher interface {
	Publish(context.Context, Event) error
}

// DispatchOnce publishes one claimed batch. A crash after Publish and before
// Ack intentionally causes redelivery; consumers must deduplicate by Event.ID.
func DispatchOnce(ctx context.Context, store Store, publisher Publisher, workerID string, limit int, lease, retryDelay time.Duration) (int, error) {
	if store == nil || publisher == nil || workerID == "" || limit < 1 ||
		lease <= 0 || retryDelay < 0 {
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
			if retryErr := store.Retry(ctx, event.ID, workerID, event.Attempts, retryDelay, ReasonPublishFailed); retryErr != nil && firstErr == nil {
				firstErr = retryErr
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := store.Ack(ctx, event.ID, workerID, event.Attempts); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		published++
	}
	return published, firstErr
}
