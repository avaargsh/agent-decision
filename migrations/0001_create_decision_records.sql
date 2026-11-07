CREATE TABLE IF NOT EXISTS decision_records (
    tenant_id TEXT NOT NULL,
    invocation_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    request_sha256 CHAR(64) NOT NULL,
    record JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, invocation_id),
    UNIQUE (tenant_id, decision_id),
    CHECK (tenant_id <> ''),
    CHECK (invocation_id <> ''),
    CHECK (decision_id <> ''),
    CHECK (request_sha256 ~ '^[a-f0-9]{64}$'),
    CHECK (jsonb_typeof(record) = 'object')
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'decision_records'::regclass
          AND conname = 'decision_records_json_identity_ck'
    ) THEN
        ALTER TABLE decision_records
        ADD CONSTRAINT decision_records_json_identity_ck CHECK (
            record->>'tenant_id' IS NOT DISTINCT FROM tenant_id
            AND record->>'invocation_id' IS NOT DISTINCT FROM invocation_id
            AND record->>'decision_id' IS NOT DISTINCT FROM decision_id
            AND record->>'request_sha256' IS NOT DISTINCT FROM request_sha256::text
        );
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION reject_decision_record_mutation() RETURNS trigger
LANGUAGE plpgsql AS '
BEGIN
    RAISE EXCEPTION ''decision_records are append-only'';
END;
';

DROP TRIGGER IF EXISTS decision_records_no_update ON decision_records;
CREATE TRIGGER decision_records_no_update
BEFORE UPDATE ON decision_records
FOR EACH ROW EXECUTE FUNCTION reject_decision_record_mutation();

DROP TRIGGER IF EXISTS decision_records_no_delete ON decision_records;
CREATE TRIGGER decision_records_no_delete
BEFORE DELETE ON decision_records
FOR EACH ROW EXECUTE FUNCTION reject_decision_record_mutation();

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
