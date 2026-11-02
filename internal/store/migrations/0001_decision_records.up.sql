CREATE TABLE decision_records (
    tenant_id          TEXT        NOT NULL,
    decision_id        TEXT        NOT NULL,
    idempotency_key    TEXT        NOT NULL,
    schema_version     TEXT        NOT NULL CHECK (schema_version = 'decision.v1'),
    subject            TEXT        NOT NULL,
    agent_id           TEXT        NOT NULL,
    session_id         TEXT        NOT NULL,
    run_id             TEXT        NOT NULL,
    parent_decision_id TEXT,
    request_sha256     TEXT        NOT NULL CHECK (request_sha256 ~ '^[a-f0-9]{64}$'),
    policy_version     TEXT        NOT NULL,
    record_json        JSONB       NOT NULL CHECK (jsonb_typeof(record_json) = 'object'),
    created_at         TIMESTAMPTZ NOT NULL,
    CONSTRAINT decision_records_pk PRIMARY KEY (tenant_id, decision_id),
    CONSTRAINT decision_records_idempotency_uq UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT decision_records_tenant_ck CHECK (tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$'),
    CONSTRAINT decision_records_key_ck CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
);
