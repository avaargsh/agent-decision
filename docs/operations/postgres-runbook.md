# PostgreSQL Operations Runbook — Agent Decision

**Status:** operational design baseline; deployment-specific credentials and restore evidence are not yet configured.  
**Applies to:** PostgreSQL 16 and migrations v0001 (DecisionRecord), v0002 (Outbox), and v0003 (TRUNCATE guards).

## 1. Role separation

Use a dedicated database and schema for Agent Decision. Keep migration ownership separate from the application login.

- `agent_decision_migrator`: schema owner; used only by the migration job. It may create/alter tables and indexes.
- `agent_decision_app`: runtime login; no schema ownership, DDL, role membership, or database-wide privileges.
- Human/automation backup role: read access required by the selected backup method; credentials live in the secrets manager and are not mounted into the API process.

Example bootstrap (run as the database administrator; replace database/schema and secret provisioning for the target environment):

```sql
CREATE ROLE agent_decision_migrator LOGIN;
CREATE ROLE agent_decision_app LOGIN;

CREATE DATABASE agent_decision OWNER agent_decision_migrator;

\connect agent_decision

REVOKE ALL ON DATABASE agent_decision FROM PUBLIC;
GRANT CONNECT ON DATABASE agent_decision TO agent_decision_app;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO agent_decision_app;

-- Apply migrations as agent_decision_migrator.
-- After migration 0001:
GRANT SELECT, INSERT ON TABLE public.decision_records TO agent_decision_app;
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON TABLE public.decision_records FROM agent_decision_app;

-- After migration 0002, the API role must atomically insert the Outbox
-- event alongside its immutable DecisionRecord.
GRANT SELECT, INSERT ON TABLE public.outbox_events TO agent_decision_app;
-- The dispatcher additionally requires SELECT and UPDATE of delivery metadata.
-- Use a separate least-privilege dispatcher login in production; the role
-- configuration and split-credential deployment are not yet implemented.
```

The runtime repository uses scoped SQL for tenant/idempotency lookup. The append-only trigger is defense in depth, not a replacement for least-privilege role grants. Database row-level security is **not yet wired**: a future production deployment must either add RLS with a transaction-bound tenant context or demonstrate equivalent isolation at a trusted data-access boundary. Do not grant broad read access to other schemas or tables.

## 2. Secret and connection handling

- Provision passwords or workload identity through the environment's secret manager; never commit credentials or place them in image layers.
- Require TLS for non-local database connections; validate the server certificate.
- Set connection pool limits, connection lifetime, statement/query deadlines and startup readiness checks according to deployment capacity.
- Rotate the application credential through the secret manager and restart/reload the API pool. Migration credentials must not be available to the API workload.
- Keep audit logs for role changes, schema migrations, backup jobs and restore operations. Do not log connection strings or record payloads.

## 3. Backup and retention

The v0.1 DecisionRecord ledger is append-only at both the SQL trigger and application-role privilege layers: UPDATE and DELETE are rejected by the table triggers, and the runtime role must not receive UPDATE, DELETE or TRUNCATE. No automatic deletion/retention job is defined.

Minimum deployment policy to establish before production:
- Nightly logical backup using a custom-format dump or a managed PostgreSQL backup service.
- For a production RPO below one day, configure managed base backups plus WAL archiving/PITR; document the target RPO/RTO with service owners.
- Encrypt backups at rest and in transit, restrict restore privileges, and apply a documented retention period approved by data owners.
- Retention must preserve immutable DecisionRecord attribution and idempotency history for the required audit window. Avoid deleting rows solely to reduce storage without a reviewed archival/retention contract.

Example logical backup and restore rehearsal:

```bash
pg_dump --format=custom --no-owner --dbname="$AGENT_DECISION_BACKUP_DSN" \
  --file="agent-decision-$(date -u +%Y%m%dT%H%M%SZ).dump"

# Restore into an isolated, empty rehearsal database as the restore operator.
createdb agent_decision_restore_rehearsal
pg_restore --dbname=agent_decision_restore_rehearsal --no-owner \
  --exit-on-error "agent-decision-YYYYMMDDTHHMMSSZ.dump"
```

Keep the DSN in the secret manager. The commands above are operational templates; they have not been executed against a deployment environment.

## 4. Restore verification

Perform a periodic isolated restore rehearsal and after material schema/backup changes.

1. Restore the backup/PITR point to an isolated database.
2. Confirm migration/schema version and indexes are present.
3. Run checks for row counts, required columns, JSONB object validity and duplicate tenant/invocation_ids.
4. Compare a deterministic sample of DecisionRecord JSON and request fingerprints with the backup evidence manifest.
5. Start a staging instance with the app role and run repository integration checks for same-key replay and changed-fingerprint conflict.
6. Record backup timestamp, restore point, duration, validation results and operator in an immutable evidence location.
7. Do not point production traffic at the restored database until owners approve the recovery.

## 5. Incident response and migration safety

- Database unavailable: API returns `503 STORE_UNAVAILABLE`; caller may retry the same tenant-scoped invocation_id and request fingerprint after recovery.
- Idempotency conflict: return `409 INVOCATION_ID_REUSED`; never overwrite the stored record.
- Schema migration: run as the migrator role, review SQL and lock impact, back up before destructive changes, and use forward-compatible expand/contract changes. v0001 currently creates the DecisionRecord table and indexes.
- A successful backup job is not a restore proof. Track restore rehearsal evidence independently.


## 6. Checksummed schema migration gate (PR #10)

The Go Outbox baseline's `decision.Migrate` serializes migrations under a PostgreSQL transaction-scoped advisory lock, hashes the exact embedded SQL bytes, and writes `schema_migrations(version, name, checksum, applied_at)`. Each explicit `decision.Migrate` invocation verifies the **entire applied prefix**, ordered and contiguous from version 1, against the binary's exact migration filename and SHA-256. Unrecognized future versions, missing earlier versions, changed names or mismatched digests stop before applying new DDL.

**Upgrading from unchecksummed draft history:** an existing `schema_migrations` table without `checksum` is inspected with a nullable compatibility column, but any pre-existing row without a stored checksum **fails closed**. The application does not silently backfill hashes from the currently deployed binary: that would attest to a file, not prove what the database actually executed.

Before accepting a historical migration, an authorized database migrator must:

1. Take and verify a restorable backup. Identify the previous release SHA and exact SQL bytes; compare the old deployment's migration history to database catalog objects, constraints, indexes and triggers.
2. Establish a written operator-approved migration evidence record with the expected version/name/content SHA-256. Compare it with the **new binary's** embedded migration bytes; if they differ, stop and plan an explicit versioned repair migration.
3. Only after the review, fill the legacy `checksum` field using the independently verified SHA-256 (and preserve the evidence outside the application). Re-run `Migrate` against an isolated restored database before production.
4. Never skip a missing migration, falsify version history or mark failed SQL as applied. Keep migration privileges separate from the runtime API role.

Repository CI tests new-schema re-entry, tampered name/digest, missing earlier version and correctly restored history with PostgreSQL 16. These tests are **not** a production upgrade rehearsal or proof of actual backups, RLS or approved migration custody.

## 7. Installed immutability trigger integrity gate (PR #13)

After applying/checking the approved migration history and while holding the migration transaction/advisory lock, `decision.Migrate` now examines PostgreSQL's live catalog for six critical protections:

- `decision_records_no_update` and `decision_records_no_delete`, both bound to `reject_decision_record_mutation()`;
- `outbox_event_identity_immutable`, bound to `reject_decision_outbox_identity_mutation()`;
- `outbox_events_no_delete`, bound to `reject_decision_outbox_delete()`;
- `decision_records_no_truncate`, a BEFORE TRUNCATE statement-level guard bound to `reject_decision_record_mutation()`;
- `outbox_events_no_truncate`, a BEFORE TRUNCATE statement-level guard bound to `reject_decision_outbox_delete()`.

Each trigger must exist on its intended table, be enabled for the normal origin role, use the expected row/BEFORE event type and reference the expected trigger function. The check also rejects conditional `WHEN` clauses, column-specific `UPDATE OF` triggers and any mismatch in the approved PL/pgSQL function source (`pg_proc.prosrc`, compared with the pinned Go-side definition). Missing, disabled or rewired triggers fail closed; the application does **not** automatically repair them. This complements historical SQL-byte checksums, which cannot independently attest the live PostgreSQL catalog.

**Scope limitation:** this check runs when `decision.Migrate` is explicitly invoked. The development server does not invoke it at startup. It compares the expected PL/pgSQL function source at migration-check time, but does not prove every index/constraint, monitor later DDL changes, provide RLS, verify all role grants, or prove actual backup/restore readiness. A privileged PostgreSQL owner can still alter catalog objects after the check; production role separation is required. Production startup should have an independently operated schema health gate; a periodic deployment attestation remains unimplemented.

**On a failure:** stop deployment/migration, preserve catalog/role metadata and prior migration evidence, investigate why the trigger was disabled or replaced, and restore the approved schema under a controlled, auditable migration/recovery process. Do not just re-enable an untrusted handler in production. Verify against an isolated restored database before reopening writes.

## 8. Critical CHECK semantics at migration time (integration PR #14)

Matching migration-history SHA-256, table names and constraint names are not sufficient to establish database integrity. An operator with DDL privileges can recreate a constraint under its original name with `CHECK (true)`; the `validated` catalog flag can still be true.

`decision.Migrate` checks the live PostgreSQL 16 deparsed predicate (`pg_get_expr`) against the reviewed expressions for five constraints: DecisionRecord relational/JSONB identity, request SHA-256 shape, Outbox lease-owner/expiry pairing, aggregate type, and sanitized retry-error code. It also executes four controlled, intentionally mismatched DecisionRecord inserts under transaction SAVEPOINT/ROLLBACK to independently assert that the identity constraint actually rejects each inconsistent field. A successful probe leaves no DecisionRecord or Outbox rows behind.

**Compatibility boundary:** expression strings here are reviewed for PostgreSQL 16. A future PostgreSQL deparser/version difference must fail closed and receive a specific upgrade review; it is not automatically equivalent. The probes are an additional regression guard, not proof of resistance to a privileged database owner modifying the schema after the check.

**TRUNCATE gate (v0003):** PostgreSQL `TRUNCATE` bypasses row-level DELETE triggers. The Draft integration now includes a checksummed v0003 migration that installs BEFORE TRUNCATE statement-level guards on DecisionRecord and Outbox; the migration catalog verifier requires both guards to remain enabled and bound to the reviewed handlers. PostgreSQL 16 integration tests attempt TRUNCATE inside rollback-only transactions and exercise missing-trigger recovery. This is code/CI evidence, not production restore or deployment acceptance. Least-privilege runtime roles must also exclude TRUNCATE, UPDATE/DELETE of immutable payload fields, schema ownership and migration privileges.
