CREATE TABLE IF NOT EXISTS outbox_events (
    event_id          TEXT        PRIMARY KEY,
    tenant_id         TEXT        NOT NULL,
    aggregate_type    TEXT        NOT NULL CHECK (aggregate_type = 'decision_record'),
    aggregate_id      TEXT        NOT NULL,
    aggregate_version BIGINT      NOT NULL CHECK (aggregate_version > 0),
    event_type        TEXT        NOT NULL,
    schema_version    INTEGER     NOT NULL CHECK (schema_version > 0),
    payload           JSONB       NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    attempts          INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    available_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner       TEXT,
    lease_until       TIMESTAMPTZ,
    published_at      TIMESTAMPTZ,
    last_error        TEXT,
    CONSTRAINT outbox_decision_fk FOREIGN KEY (tenant_id, aggregate_id)
        REFERENCES decision_records (tenant_id, decision_id),
    CONSTRAINT outbox_decision_event_uq UNIQUE (tenant_id, aggregate_id, event_type),
    CONSTRAINT outbox_lease_pair_ck CHECK ((lease_owner IS NULL) = (lease_until IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_outbox_pending
    ON outbox_events (available_at, created_at, event_id)
    WHERE published_at IS NULL;

CREATE OR REPLACE FUNCTION reject_decision_outbox_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.event_id IS DISTINCT FROM OLD.event_id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.aggregate_type IS DISTINCT FROM OLD.aggregate_type
       OR NEW.aggregate_id IS DISTINCT FROM OLD.aggregate_id
       OR NEW.aggregate_version IS DISTINCT FROM OLD.aggregate_version
       OR NEW.event_type IS DISTINCT FROM OLD.event_type
       OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
       OR NEW.payload IS DISTINCT FROM OLD.payload
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'outbox event identity and payload are immutable';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS outbox_event_identity_immutable ON outbox_events;
CREATE TRIGGER outbox_event_identity_immutable
BEFORE UPDATE ON outbox_events
FOR EACH ROW EXECUTE FUNCTION reject_decision_outbox_identity_mutation();
