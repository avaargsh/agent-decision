# PostgreSQL Operations Runbook — Agent Decision

**Status:** operational design baseline; deployment-specific credentials and restore evidence are not yet configured.  
**Applies to:** PostgreSQL 16 and checksummed Decision migrations v0001–v0003.

## 1. Role separation

Use a dedicated database and schema for Agent Decision. Keep migration ownership separate from the application login.

- `agent_decision_migrator`: schema owner; used only by the migration job, never mounted in API/dispatcher/attestor pods.
- `agent_decision_app`: Decision HTTP/API runtime; `SELECT/INSERT` DecisionRecord and `INSERT` Outbox only, **no Outbox lease/ACK UPDATE or SELECT**.
- `agent_decision_dispatcher`: claims and ACKs/retries Outbox events with `SELECT` plus narrowly scoped column `UPDATE`; **no DecisionRecord SELECT/INSERT or Outbox INSERT**.
- `agent_decision_attestor`: isolated read-only catalog verification; schema `USAGE` and `SELECT` on `schema_migrations`, never DDL or runtime DML.
- Human/automation backup role: only the backup access required by the selected backup method; secrets must not be mounted into API/dispatcher processes.

Example bootstrap (run as the database administrator; replace database/schema and secret provisioning for the target environment):

```sql
CREATE ROLE agent_decision_migrator LOGIN;
CREATE ROLE agent_decision_app LOGIN;
CREATE ROLE agent_decision_dispatcher LOGIN;
CREATE ROLE agent_decision_attestor LOGIN;

CREATE DATABASE agent_decision OWNER agent_decision_migrator;

\connect agent_decision

REVOKE ALL ON DATABASE agent_decision FROM PUBLIC;
GRANT CONNECT ON DATABASE agent_decision TO
  agent_decision_app, agent_decision_dispatcher, agent_decision_attestor;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO
  agent_decision_app, agent_decision_dispatcher, agent_decision_attestor;

-- Apply migrations 0001-0003 first as agent_decision_migrator.
-- API: immutable Decision + atomic Outbox INSERT only.
GRANT SELECT, INSERT ON TABLE public.decision_records TO agent_decision_app;
GRANT INSERT ON TABLE public.outbox_events TO agent_decision_app;

-- Dispatcher: bounded SKIP LOCKED Claim, fenced Ack/Retry; cannot forge events.
GRANT SELECT ON TABLE public.outbox_events TO agent_decision_dispatcher;
GRANT UPDATE (lease_owner, lease_until, attempts, available_at,
              published_at, last_error_code)
  ON TABLE public.outbox_events TO agent_decision_dispatcher;

-- Independent read-only deployment/startup attestor.
GRANT SELECT ON TABLE public.schema_migrations TO agent_decision_attestor;

-- Validate ALL effective privileges, including inherited/column grants,
-- with VerifyRuntimeDatabaseRole against actual API/dispatcher credentials.
-- These GRANTs assume new roles in a dedicated DB: check and revoke any
-- preexisting PUBLIC/role memberships before production.
-- No API/dispatcher role may own tables, use DDL/TRUNCATE/DELETE, bypass RLS,
-- be a member of the migrator or inherit schema/database CREATE privileges.
```

The Decision API uses scoped SQL for tenant/idempotency lookup, while a separate dispatcher owns Outbox Claim/Ack/Retry. The append-only trigger is defense in depth, not a replacement for least-privilege role grants. Database row-level security is **not yet wired**: a future production deployment must either add RLS with a transaction-bound tenant context or demonstrate equivalent isolation at a trusted data-access boundary. Do not grant broad read access to other schemas or tables.

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

## 8. Installed immutability trigger integrity gate (PR #13)

After applying/checking the approved migration history and while holding the migration transaction/advisory lock, `decision.Migrate` now examines PostgreSQL's live catalog for six critical protections:

- `decision_records_no_update` and `decision_records_no_delete`, both bound to `reject_decision_record_mutation()`;
- `outbox_event_identity_immutable`, bound to `reject_decision_outbox_identity_mutation()`;
- `outbox_events_no_delete`, bound to `reject_decision_outbox_delete()`;
- `decision_records_no_truncate`, a BEFORE TRUNCATE statement-level guard bound to `reject_decision_record_mutation()`;
- `outbox_events_no_truncate`, a BEFORE TRUNCATE statement-level guard bound to `reject_decision_outbox_delete()`.

Each trigger must exist on its intended table, be enabled for the normal origin role, use the expected row/BEFORE event type and reference the expected trigger function. The check also rejects conditional `WHEN` clauses, column-specific `UPDATE OF` triggers and any mismatch in the approved PL/pgSQL function source (`pg_proc.prosrc`, compared with the pinned Go-side definition). Missing, disabled or rewired triggers fail closed; the application does **not** automatically repair them. This complements historical SQL-byte checksums, which cannot independently attest the live PostgreSQL catalog.

**Scope limitation:** this check runs when `decision.Migrate` is explicitly invoked. The development server does not invoke it at startup. It compares the expected PL/pgSQL function source at migration-check time, but does not prove every index/constraint, monitor later DDL changes, provide RLS, verify all role grants, or prove actual backup/restore readiness. A privileged PostgreSQL owner can still alter catalog objects after the check; production role separation is required. Production startup should have an independently operated schema health gate; a periodic deployment attestation remains unimplemented.

**On a failure:** stop deployment/migration, preserve catalog/role metadata and prior migration evidence, investigate why the trigger was disabled or replaced, and restore the approved schema under a controlled, auditable migration/recovery process. Do not just re-enable an untrusted handler in production. Verify against an isolated restored database before reopening writes.

## 9. Critical CHECK semantics at migration time (integration PR #14)

Matching migration-history SHA-256, table names and constraint names are not sufficient to establish database integrity. An operator with DDL privileges can recreate a constraint under its original name with `CHECK (true)`; the `validated` catalog flag can still be true.

`decision.Migrate` checks the live PostgreSQL 16 deparsed predicate (`pg_get_expr`) against the reviewed expressions for five constraints: DecisionRecord relational/JSONB identity, request SHA-256 shape, Outbox lease-owner/expiry pairing, aggregate type, and sanitized retry-error code. It also executes four controlled, intentionally mismatched DecisionRecord inserts under transaction SAVEPOINT/ROLLBACK to independently assert that the identity constraint actually rejects each inconsistent field. A successful probe leaves no DecisionRecord or Outbox rows behind.

**Compatibility boundary:** expression strings here are reviewed for PostgreSQL 16. A future PostgreSQL deparser/version difference must fail closed and receive a specific upgrade review; it is not automatically equivalent. The probes are an additional regression guard, not proof of resistance to a privileged database owner modifying the schema after the check.

**TRUNCATE gate (v0003):** PostgreSQL `TRUNCATE` bypasses row-level DELETE triggers. The Draft integration now includes a checksummed v0003 migration that installs BEFORE TRUNCATE statement-level guards on DecisionRecord and Outbox; the migration catalog verifier requires both guards to remain enabled and bound to the reviewed handlers. PostgreSQL 16 integration tests attempt TRUNCATE inside rollback-only transactions and exercise missing-trigger recovery. This is code/CI evidence, not production restore or deployment acceptance. Least-privilege runtime roles must also exclude TRUNCATE, UPDATE/DELETE of immutable payload fields, schema ownership and migration privileges.


## 10. Trusted schema binding for migration (Issue #15; repository-level only)

`decision.Migrate(ctx, db)` always migrates the explicit trusted default PostgreSQL schema `public`, regardless of the connection's ambient `search_path`. For a deployment with a different dedicated schema, the migrator must call `decision.MigrateInSchema(ctx, db, configuredSchema)` using a reviewed deployment-controlled value. **Never derive this value from a tenant, request, HTTP header, EvidenceRef, environment content supplied by an untrusted caller, or an unchecked database setting.**

The migration transaction pins the effective `search_path` to `<approved_schema>, pg_catalog, pg_temp` before executing any migration SQL or live catalog verification. The explicit `pg_temp` last entry prevents temporary-table shadowing of protected objects; `pg_catalog` setup functions are schema-qualified. The target must already exist, be accessible to the migrator, have a lowercase ASCII schema name of at most 63 characters, and not use PostgreSQL's reserved internal schema prefix. This local setting is rolled back on failure and does not authorize changing the API or dispatcher connection's own `search_path`.

These guards **do not** make database owner/superuser DDL tamper-resistant, validate all role grants or RLS, or prove that every write-path process invokes a pre-write read-only schema attestation. A production-ready deployment must separately pin API/dispatcher schema identity; enforce least privilege, real tenant isolation and external audit; and require an independently operated **read-only** health gate before opening Decision write routes. Do not grant the API migrator privileges. The in-migration four-field behavioral probe performs rollback-only INSERT attempts as the privileged migrator and is **not** a read-only API startup probe.

PostgreSQL 16 repository regression tests cover ambient shadow-`search_path` misdirection and migration on explicitly named isolated schemas. This is CI evidence only; record migration identity, deployment role grants, schema OIDs, backup/restore and G02/G05 receipts separately.


## 11. Read-only catalog attestation and HTTP fail-closed boundary (Issue #15)

**Repository API, not production deployment evidence.** After a migration-capable job completes v0001–v0003, the separate `decision.VerifyInstalledCatalogInSchema(ctx, restrictedDB, configuredSchema)` validates the installed PostgreSQL 16 schema using a `ReadOnly: true` transaction. It never performs CREATE/ALTER/INSERT, never applies migrations, and does **not** call the migration-only four-field SAVEPOINT/INSERT behavior probe. The schema is explicitly pinned for that one transaction; the verifier checks the exact contiguous migration version/name/SHA-256 ledger, the tenant FK, six protection triggers, five critical CHECK predicate expressions, and expected PL/pgSQL function definitions/attributes. Missing objects or unreviewed catalog drift fail closed with `ErrCatalogDrift`.

The attestation role requires `USAGE` on the trusted schema and `SELECT` on its `schema_migrations` table, plus normal PostgreSQL system-catalog visibility. It must **not** own the schema or have CREATE/ALTER/TRIGGER privileges; no application or dispatcher should inherit the migrator role. In CI, a disposable non-owner `SET ROLE` test proves the verifier accepts a valid schema without CREATE permissions and fails for a disabled immutable trigger, a tampered migration name, and missing target schema. Those are test-role receipts, not audited production role grants or a cross-tenant RLS proof.

`api.NewCatalogGuardedHandler(service, resolver, attest)` implements `GET /readyz` and verifies the callback before **every** `POST /v1/decisions`; a nil or failing callback returns HTTP 503 / `STORE_UNAVAILABLE` without leaking catalog details. `GET /healthz` remains a separate liveness check. The concrete wiring must call `decision.VerifyInstalledCatalogInSchema` on the **same trusted schema/database** as the durable DecisionStore and use an application connection pool whose own `search_path` is safely pinned independently. The verifier's transaction-local `search_path` does not change the Store's other pool connections. A disabled trigger after a healthy request therefore blocks the next write **when this guarded handler is actually used**.

The repository's `cmd/agent-decision` remains a loopback-only in-memory **development** binary using the unguarded `NewHandler`, with no trusted PrincipalResolver/AuthorityVerifier. No production Postgres-backed entrypoint currently proves that the guarded handler is deployed. Real staging acceptance must verify the actual server composition, TLS/auth, restricted DB users, immutable log of fail-closed events, readiness/writes under post-start catalog drift, worker/dispatcher paths, RLS or equivalent tenant isolation, and a restored copy. Rechecking catalog on every write adds PostgreSQL round trips and still has a privileged-DDL time-of-check/time-of-use window; deployment policy and audit remain necessary. G02/G05 cross-service evidence is a separate gate.


### Deployment preflight CLI (not yet wired into a live deployment)

After an authorized migration job has succeeded, run the standalone read-only command with **separate restricted credentials**:

```bash
export DECISION_ATTEST_DATABASE_URL="<secret-manager-supplied PostgreSQL DSN>"
export DECISION_ATTEST_SCHEMA="public"  # or the approved dedicated schema
go run ./cmd/decision-catalog-attest
```

The command fails with a nonzero exit code if required configuration is absent, migration-history checksums are missing/tampered, or critical installed catalog protection has drifted. It emits a generic failure message instead of a DSN or tenant payload. PostgreSQL permissions should be scoped to `USAGE` on the approved schema and `SELECT` on its `schema_migrations`; test this with actual deployed credentials. The CI test of this CLI creates a disposable schema, verifies success, disables the Outbox TRUNCATE guard, and verifies that the command refuses the altered schema.

**Integration contract:** the deployer must treat a failed CLI check as a hard block *before* enabling the application Deployment; the application must also compose `NewCatalogGuardedHandler` with `VerifyInstalledCatalogInSchema` and a trusted schema-pinned DecisionStore pool. The repository supplies the building blocks and tests, **not** a deployed Kubernetes initContainer, real restricted secrets, authenticated ingress or independent production approval.


### Effective runtime database privilege gate (PR #14)

After executing the approved GRANTs above, call `decision.VerifyRuntimeDatabaseRole(ctx, db, schema, decision.RuntimeRoleApplication)` on the **actual API connection identity**, and `decision.VerifyRuntimeDatabaseRole(ctx, db, schema, decision.RuntimeRoleDispatcher)` on the **actual dispatcher identity**. This read-only gate checks the role's superuser/CREATEDB/CREATEROLE/replication/BYPASSRLS flags, schema/database CREATE, schema owner membership, and exact effective per-column SELECT/INSERT/UPDATE permissions plus DELETE/TRUNCATE/REFERENCES/TRIGGER bans. It rejects overprivileged sessions, including table-wide or inherited grants. The read-only `VerifyInstalledCatalogInSchema` uses separate attestor credentials, not either of these runtime credentials.

Repository PostgreSQL 16 tests use disposable NOLOGIN roles under `SET ROLE`; they are effective-privilege checks but do not prove separate production logins or workload identities. The API role's SELECT on all DecisionRecord rows still has a **cross-tenant exposure risk** without RLS or a trusted, independently verified tenant-isolation layer. The role check is not RLS, not a security audit of every object in the database, and not authorization to release.


### Standalone runtime-role preflight (CI capability; deployment not integrated)

Run the separate role-audit command twice with credentials belonging to the actual deployed non-owner **LOGIN** identity of each service. Do **not** supply the migrator or attestor connection string, and do not put credentials in shell history or CI artifacts.

```bash
DECISION_ROLE_DATABASE_URL="$DECISION_APP_DSN" \
  DECISION_ROLE_SCHEMA="$APPROVED_DECISION_SCHEMA" \
  DECISION_ROLE_KIND=application go run ./cmd/decision-role-audit

DECISION_ROLE_DATABASE_URL="$DECISION_DISPATCHER_DSN" \
  DECISION_ROLE_SCHEMA="$APPROVED_DECISION_SCHEMA" \
  DECISION_ROLE_KIND=dispatcher go run ./cmd/decision-role-audit
```

Each check must exit successfully before that workload starts. The command rejects absent/unknown role kind and overly privileged effective credentials, returns a nonzero exit status, and prints only a generic pass/fail result. The existing read-only `cmd/decision-catalog-attest` must run separately under the attestor identity after migrations. Tests also authenticate through three distinct disposable PostgreSQL 16 LOGIN passwords (rather than only `SET ROLE`) and exercise app SaveOrGet/replay, dispatcher Claim/Ack, attestor catalog reads, and unauthorized cross-role operations. These tests do **not** validate RLS, K8s workload identities, production credential custody, actual TLS or a real deployment.

Do not use a successful role audit to claim complete tenant isolation: the current application role has broad table-level `SELECT` on DecisionRecord and requires trusted caller authorization; PostgreSQL row-level enforcement or independently reviewed equivalent isolation remains a **P0 production blocker**. Role grants are also point-in-time, not an effective substitute for DDL audit, independent security review and actual restart/restore evidence.
