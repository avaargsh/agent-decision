CREATE TABLE IF NOT EXISTS decision_records (
    tenant_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    request_sha256 CHAR(64) NOT NULL,
    record JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, idempotency_key),
    UNIQUE (tenant_id, decision_id),
    CHECK (tenant_id <> ''),
    CHECK (idempotency_key <> ''),
    CHECK (decision_id <> ''),
    CHECK (request_sha256 ~ '^[a-f0-9]{64}$'),
    CHECK (jsonb_typeof(record) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_decision_records_tenant_created
    ON decision_records (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_decision_records_run
    ON decision_records (tenant_id, (record->>'run_id'));
