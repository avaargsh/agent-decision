CREATE TABLE outbox_events (
    event_id       TEXT        PRIMARY KEY,
    tenant_id      TEXT        NOT NULL,
    aggregate_id   TEXT        NOT NULL,
    event_type     TEXT        NOT NULL,
    payload        JSONB       NOT NULL,
    attempts       INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    available_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner    TEXT,
    lease_until    TIMESTAMPTZ,
    published_at   TIMESTAMPTZ,
    last_error     TEXT,
    CONSTRAINT outbox_decision_fk FOREIGN KEY (tenant_id, aggregate_id)
        REFERENCES decision_records (tenant_id, decision_id),
    CONSTRAINT outbox_decision_event_uq UNIQUE (tenant_id, aggregate_id, event_type),
    CONSTRAINT outbox_lease_pair_ck CHECK ((lease_owner IS NULL) = (lease_until IS NULL))
);
