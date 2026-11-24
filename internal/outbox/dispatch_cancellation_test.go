package outbox

import (
	"context"
	"errors"
	"testing"
	"time"
)

type cancellationStore struct {
	events []Event
	claims int
	acks []string
	retries []string
}

func (s *cancellationStore) Claim(context.Context, string, int, time.Duration) ([]Event, error) {
	s.claims++
	return s.events, nil
}
func (s *cancellationStore) Ack(_ context.Context, id, _ string, _ int) error {
	s.acks = append(s.acks, id)
	return nil
}
func (s *cancellationStore) Retry(_ context.Context, id, _ string, _ int, _ time.Duration, _ string) error {
	s.retries = append(s.retries, id)
	return nil
}

type cancellationPublisher func(context.Context, Event) error

func (f cancellationPublisher) Publish(ctx context.Context, event Event) error {
	return f(ctx, event)
}

func TestDispatchOnceStopsBeforeNextPublishWhenCanceled(t *testing.T) {
	for _, tc := range []struct {
		name string
		cancelBefore bool
		failFirst bool
	}{
		{name: "already canceled", cancelBefore: true},
		{name: "cancel after publish"},
		{name: "cancel after failed publish", failFirst: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store := &cancellationStore{events: []Event{
				{ID: "first", Attempts: 1},
				{ID: "second", Attempts: 1},
			}}
			calls := 0
			publishErr := errors.New("publish failed")
			publisher := cancellationPublisher(func(_ context.Context, event Event) error {
				calls++
				if event.ID != "first" {
					t.Fatalf("published another event after cancellation: %s", event.ID)
				}
				cancel()
				if tc.failFirst {
					return publishErr
				}
				return nil
			})
			if tc.cancelBefore {
				cancel()
			}
			count, err := DispatchOnce(ctx, store, publisher, "worker", 2, time.Minute, time.Second)
			if tc.cancelBefore {
				if calls != 0 || store.claims != 0 || count != 0 || !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled before claim: calls=%d claims=%d count=%d err=%v", calls, store.claims, count, err)
				}
				return
			}
			if calls != 1 || store.claims != 1 {
				t.Fatalf("unexpected calls: publish=%d claim=%d", calls, store.claims)
			}
			if tc.failFirst {
				if count != 0 || !errors.Is(err, publishErr) || len(store.retries) != 1 || len(store.acks) != 0 {
					t.Fatalf("first failure not preserved: count=%d err=%v ack=%v retry=%v", count, err, store.acks, store.retries)
				}
			} else if count != 1 || !errors.Is(err, context.Canceled) || len(store.acks) != 1 || len(store.retries) != 0 {
				t.Fatalf("completed first event not preserved: count=%d err=%v ack=%v retry=%v", count, err, store.acks, store.retries)
			}
		})
	}
}
