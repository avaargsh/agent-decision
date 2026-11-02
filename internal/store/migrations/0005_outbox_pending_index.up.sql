CREATE INDEX outbox_events_pending_idx
    ON outbox_events (available_at, created_at)
    WHERE published_at IS NULL;
