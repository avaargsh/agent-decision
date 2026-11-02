package outbox

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeStore struct {
	events  []Event
	acked   []string
	retried []string
}

func (s *fakeStore) Claim(context.Context, string, int, time.Duration) ([]Event, error) {
	return s.events, nil
}
func (s *fakeStore) Ack(_ context.Context, id, _ string) error {
	s.acked = append(s.acked, id)
	return nil
}
func (s *fakeStore) Retry(_ context.Context, id, _ string, _ time.Duration, _ string) error {
	s.retried = append(s.retried, id)
	return nil
}

type fakePublisher struct{ fail bool }

func (p fakePublisher) Publish(context.Context, Event) error {
	if p.fail {
		return errors.New("temporary broker failure")
	}
	return nil
}

func TestDispatchAckAndRetry(t *testing.T) {
	store := &fakeStore{events: []Event{{ID: "evt-1"}, {ID: "evt-2"}}}
	count, err := DispatchOnce(context.Background(), store, fakePublisher{fail: true}, "worker-a", 10, time.Minute, time.Second)
	if count != 0 || err == nil || len(store.retried) != 2 || len(store.acked) != 0 {
		t.Fatalf("unexpected failed publish result: count=%d err=%v store=%+v", count, err, store)
	}
	store = &fakeStore{events: []Event{{ID: "evt-1"}}}
	count, err = DispatchOnce(context.Background(), store, fakePublisher{}, "worker-a", 10, time.Minute, time.Second)
	if count != 1 || err != nil || len(store.acked) != 1 {
		t.Fatalf("unexpected successful publish result: count=%d err=%v store=%+v", count, err, store)
	}
}
