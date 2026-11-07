# PostgreSQL Operations Runbook — Agent Decision

**Status:** operational design baseline; deployment-specific credentials and restore evidence are not yet configured.  
**Applies to:** PostgreSQL 16 and checksummed Decision migrations v0001–v0003.

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
-- After migrations 0001–0003; the application needs scoped reads,
-- immutable inserts and lease/ack updates only.
GRANT SELECT, INSERT ON TABLE public.decision_records TO agent_decision_app;
GRANT SELECT, INSERT ON TABLE public.outbox_events TO agent_decision_app;
GRANT UPDATE (lease_owner, lease_until, attempts, available_at,
              published_at, last_error_code)
  ON TABLE public.outbox_events TO agent_decision_app;
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON TABLE public.decision_records FROM agent_decision_app;
REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON TABLE public.outbox_events FROM agent_decision_app;

-- Production deployments must also review owner membership, inherited
-- grants, PUBLIC privileges and the trusted search_path; grants are templates.
```

The runtime repository uses scoped SQL for tenant/idempotency lookup. The append-only trigger is defense in depth, not a replacement for least-privilege role grants. Database row-level security is **not yet wired**: a future production deployment must either add RLS with a transaction-bound tenant context or demonstrate equivalent isolation at a trusted data-access boundary. Do not grant broad read access to other schemas or tables.

## 2. Secret and connection handling

- Provision passwords or workload identity through the environment's secret manager; never commit credentials or place them in image layers.
- Require TLS for non-local database connections; validate the server certificate.
- Set connection pool limits, connection lifetime, statement/query deadlines and startup readiness checks according to deployment capacity.
- Rotate the application credential through the secret manager and restart/reload the API pool. Migration credentials must not be available to the API workload.
- Keep audit logs for role changes, schema migrations, backup jobs and restore operations. Do not log connection strings or record payloads.

## 3. Backup and retention

The v0.1 DecisionRecord ledger and Outbox preserve append-only identity at both SQL trigger and role-privilege layers: v0001/v0002 reject row UPDATE/DELETE of protected data, and v0003 separately rejects statement-level TRUNCATE on both tables. The runtime role must not receive UPDATE/DELETE/TRUNCATE on DecisionRecord or DELETE/TRUNCATE on Outbox. No automatic deletion/retention job is defined.

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
- Schema migration: run as the migrator role, review SQL and lock impact, back up before destructive changes, and use forward-compatible expand/contract changes. v0001 creates DecisionRecord, v0002 creates Outbox, and additive v0003 installs statement-level TRUNCATE guards on both tables.
- A successful backup job is not a restore proof. Track restore rehearsal evidence independently.


## 6. Checksummed schema migration gate (PR #10)

The Go Outbox baseline's `decision.Migrate` serializes migrations under a PostgreSQL transaction-scoped advisory lock, hashes the exact embedded SQL bytes, and writes `schema_migrations(version, name, checksum, applied_at)`. Every startup/migration invocation verifies the **entire applied prefix**, ordered and contiguous from version 1, against the binary's exact migration filename and SHA-256. Unrecognized future versions, missing earlier versions, changed names or mismatched digests stop before applying new DDL.

**Upgrading from unchecksummed draft history:** an existing `schema_migrations` table without `checksum` is inspected with a nullable compatibility column, but any pre-existing row without a stored checksum **fails closed**. The application does not silently backfill hashes from the currently deployed binary: that would attest to a file, not prove what the database actually executed.

Before accepting a historical migration, an authorized database migrator must:

1. Take and verify a restorable backup. Identify the previous release SHA and exact SQL bytes; compare the old deployment's migration history to database catalog objects, constraints, indexes and triggers.
2. Establish a written operator-approved migration evidence record with the expected version/name/content SHA-256. Compare it with the **new binary's** embedded migration bytes; if they differ, stop and plan an explicit versioned repair migration.
3. Only after the review, fill the legacy `checksum` field using the independently verified SHA-256 (and preserve the evidence outside the application). Re-run `Migrate` against an isolated restored database before production.
4. Never skip a missing migration, falsify version history or mark failed SQL as applied. Keep migration privileges separate from the runtime API role.

Repository CI tests new-schema re-entry, tampered name/digest, missing earlier version and correctly restored history with PostgreSQL 16. These tests are **not** a production upgrade rehearsal or proof of actual backups, RLS or approved migration custody.

## 7. v0002 → v0003 append-only upgrade acceptance

Migration v0003 introduces `decision_records_no_truncate` and `outbox_events_no_truncate` as **BEFORE TRUNCATE FOR EACH STATEMENT** guards. PostgreSQL does not invoke row DELETE triggers for TRUNCATE, so v0001/v0002 alone were insufficient to prevent wholesale erasure by a schema/table owner. The immutable earlier SQL and checksums are unchanged.

Before any production rollout, apply this procedure to a fresh **isolated restored copy**:

1. Confirm the restored migration ledger has matching version/name/checksum for v0001 and v0002; reject unchecksummed, missing or unrecognized records. Record pre-upgrade Decision/Outbox row counts and a sample of immutable request hashes and pending event IDs.
2. Run `decision.Migrate` as the migrator role. Verify exactly three ordered migration records and that v0003 was applied once. Confirm both TRUNCATE guards with `pg_trigger`: `tgtype=34`, `tgenabled='O'`, and the expected rejecting PL/pgSQL function.
3. In an isolated disposable database transaction, attempt `TRUNCATE outbox_events` and `TRUNCATE decision_records, outbox_events`; each must return an error. Roll back the transaction and confirm rows are still present.
4. Confirm the same DecisionRecord/Outbox sample IDs and counts survived the upgrade and that running `Migrate` again is idempotent.
5. Test a deployment with **application** credentials: verify unauthorized DDL/DELETE/TRUNCATE fail, normal scoped Decision insert/replay and Outbox lease/ACK still work, and a real backup/PITR restore meets the target RPO/RTO. Record exact image/head, PostgreSQL version, migration hashes, grants and test receipts.

The repository's PostgreSQL 16 CI covers a simulated existing v0002 installation with committed data, upgrading to v0003, safe replay and TRUNCATE-denial cases. This does **not** prove a production cutover or resistance to a database owner/superuser who can disable triggers. Use strict role separation, restricted migration credentials and independent backup/retention evidence.
