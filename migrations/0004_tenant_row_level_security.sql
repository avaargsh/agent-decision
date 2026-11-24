-- Version 4: database-enforced tenant isolation for DecisionRecord and Outbox.
-- The login map is migrator-owned. Runtime logins receive SELECT only.
-- The authenticated PostgreSQL session_user, not the caller-controlled GUC,
-- determines the tenant. The transaction-local GUC is an additional equality
-- check against accidental or confused-deputy tenant binding.
CREATE TABLE decision_tenant_logins (
    login_role NAME PRIMARY KEY,
    tenant_id TEXT,
    login_kind TEXT NOT NULL CHECK (login_kind IN ('application', 'dispatcher')),
    CONSTRAINT decision_tenant_logins_identity_ck CHECK (
        login_role::text <> ''
        AND (
            (login_kind = 'application' AND tenant_id IS NOT NULL AND tenant_id <> '')
            OR (login_kind = 'dispatcher' AND tenant_id IS NULL)
        )
    ),
    CONSTRAINT decision_tenant_logins_tenant_uq UNIQUE NULLS NOT DISTINCT (tenant_id)
);

COMMENT ON TABLE decision_tenant_logins IS
    'Migrator-owned mapping from authenticated PostgreSQL LOGIN to one tenant or the global Outbox dispatcher. Runtime roles are read-only.';

ALTER TABLE decision_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY decision_records_tenant_select
ON decision_records
AS PERMISSIVE
FOR SELECT
TO PUBLIC
USING (
    tenant_id = NULLIF(pg_catalog.current_setting('decision.tenant_id', true), '')
    AND EXISTS (
        SELECT 1
        FROM decision_tenant_logins AS login
        WHERE login.login_role = SESSION_USER
          AND login.login_kind = 'application'
          AND login.tenant_id = decision_records.tenant_id
    )
);

CREATE POLICY decision_records_tenant_insert
ON decision_records
AS PERMISSIVE
FOR INSERT
TO PUBLIC
WITH CHECK (
    tenant_id = NULLIF(pg_catalog.current_setting('decision.tenant_id', true), '')
    AND EXISTS (
        SELECT 1
        FROM decision_tenant_logins AS login
        WHERE login.login_role = SESSION_USER
          AND login.login_kind = 'application'
          AND login.tenant_id = decision_records.tenant_id
    )
);

CREATE POLICY outbox_events_tenant_insert
ON outbox_events
AS PERMISSIVE
FOR INSERT
TO PUBLIC
WITH CHECK (
    tenant_id = NULLIF(pg_catalog.current_setting('decision.tenant_id', true), '')
    AND EXISTS (
        SELECT 1
        FROM decision_tenant_logins AS login
        WHERE login.login_role = SESSION_USER
          AND login.login_kind = 'application'
          AND login.tenant_id = outbox_events.tenant_id
    )
);

CREATE POLICY outbox_events_dispatcher_select
ON outbox_events
AS PERMISSIVE
FOR SELECT
TO PUBLIC
USING (
    EXISTS (
        SELECT 1
        FROM decision_tenant_logins AS login
        WHERE login.login_role = SESSION_USER
          AND login.login_kind = 'dispatcher'
          AND login.tenant_id IS NULL
    )
);

CREATE POLICY outbox_events_dispatcher_update
ON outbox_events
AS PERMISSIVE
FOR UPDATE
TO PUBLIC
USING (
    EXISTS (
        SELECT 1
        FROM decision_tenant_logins AS login
        WHERE login.login_role = SESSION_USER
          AND login.login_kind = 'dispatcher'
          AND login.tenant_id IS NULL
    )
)
WITH CHECK (
    EXISTS (
        SELECT 1
        FROM decision_tenant_logins AS login
        WHERE login.login_role = SESSION_USER
          AND login.login_kind = 'dispatcher'
          AND login.tenant_id IS NULL
    )
);
