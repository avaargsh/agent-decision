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

CREATE OR REPLACE FUNCTION reject_decision_record_mutation() RETURNS trigger
LANGUAGE plpgsql AS $
BEGIN
    RAISE EXCEPTION 'decision_records are append-only';
END;
$;

DO $
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'decision_records_no_update'
          AND tgrelid = 'decision_records'::regclass
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER decision_records_no_update
        BEFORE UPDATE ON decision_records
        FOR EACH ROW EXECUTE FUNCTION reject_decision_record_mutation();
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'decision_records_no_delete'
          AND tgrelid = 'decision_records'::regclass
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER decision_records_no_delete
        BEFORE DELETE ON decision_records
        FOR EACH ROW EXECUTE FUNCTION reject_decision_record_mutation();
    END IF;
END;
$;

CREATE INDEX IF NOT EXISTS idx_decision_records_tenant_created
    ON decision_records (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_decision_records_ledger_scope
    ON decision_records (
        tenant_id,
        (record->>'agent_id'),
        (record->>'session_id'),
        (record->>'run_id'),
        created_at DESC,
        decision_id DESC
    );
