# PostgreSQL persistence and outbox operations

## Scope

The PostgreSQL store is the durable implementation of `decision.Store`. It persists immutable `DecisionRecord` rows and the matching `decision.recorded.v1` outbox event in one database transaction. It does not authorize, execute, or publish privileged actions.

## Build and run

The PostgreSQL driver is an optional build-tagged dependency. The default build remains standard-library-only and uses the in-memory development store when `DATABASE_URL` is absent. The development command intentionally has no principal resolver or authority verifier, so the decision endpoint fails closed even when PostgreSQL is configured.

```sh
go test -race ./...
go test -tags postgres -race ./...
DATABASE_URL='postgres://app:pass@localhost:5432/agent_decision?sslmode=disable' \
MIGRATOR_DATABASE_URL='postgres://migrator:pass@localhost:5432/agent_decision?sslmode=disable' \
go run -tags postgres ./cmd/agent-decision
```

`DATABASE_URL` selects the application PostgreSQL connection. `MIGRATOR_DATABASE_URL` is an optional separate migration-capable connection; when omitted, the command falls back to `DATABASE_URL` (development convenience, not the recommended production role split). Migrations run before the HTTP listener starts. The development listener remains bound to `127.0.0.1:8080`, but does not install an authenticated principal or an ACP authority verifier. Requests fail closed until trusted adapters are wired. Production must inject a verified principal from the trusted OIDC/mTLS gateway and must not expose the development listener directly.

## Transaction and idempotency semantics

- The unique key is `(tenant_id, idempotency_key)`; a different tenant may independently use the same client key.
- The request hash includes the authenticated tenant and normalized request struct. Same key + same logical request returns the original record; same key + different request returns `409 IDEMPOTENCY_CONFLICT`.
- The insert is a single `INSERT ... ON CONFLICT DO NOTHING RETURNING` followed by a tenant-scoped locked read on conflict. There is no check-then-insert race.
- The decision row and deterministic `decision.recorded.v1` outbox event commit in one transaction. Failure to insert the event rolls back the record.
- `decision_records` rejects UPDATE and DELETE through a database trigger. Use append-only retention/partition archival procedures rather than editing historical rows.
- Outbox event identity and payload are immutable; only lease, attempt, retry and published bookkeeping fields may change.
- Reads require authenticated tenant + active Agent identity + decision ID; cross-tenant and cross-agent lookups are indistinguishable from not found.

## Outbox delivery

Workers claim batches with `FOR UPDATE SKIP LOCKED`, a lease owner, lease expiry and incremented attempt count. Successful publication is followed by an owner-checked acknowledgement. Failed publication releases the lease and sets `available_at` for retry. A worker crash after publishing but before acknowledgement causes a later redelivery by design: delivery is **at least once**, not exactly once. Consumers must persist and deduplicate the stable `event_id` before applying event effects. Do not use an event payload as an authorization permit.

The current repository provides the storage and one-batch dispatcher interfaces. A concrete broker adapter, worker deployment, backpressure policy and alerting are separate integration work and are not claimed as production-complete here.

## Migration, backup and recovery

- Migrations 1–7 are embedded under `internal/store/migrations`; `Migrate` uses a PostgreSQL advisory transaction lock and rejects a schema newer than the binary. Run migrations with a dedicated migration-capable role before serving traffic.
- Runtime roles should receive `USAGE` on the schema, `SELECT, INSERT` on `decision_records`, `SELECT, INSERT` on `outbox_events`, and column-limited `UPDATE (attempts, available_at, lease_owner, lease_until, published_at, last_error)` on `outbox_events`. Do not grant UPDATE/DELETE on `decision_records` or UPDATE on outbox identity/payload columns to the application role; triggers are defense in depth, not a substitute for role separation.
- Back up the database with the organization's PostgreSQL base-backup/WAL policy. Verify restore by restoring to an isolated database, checking `schema_migrations`, record counts, tenant-scoped reads and pending outbox leases before reopening traffic.
- Retention and deletion must be defined with legal/compliance owners. Because records are append-only, deletion requires a separately reviewed archival/partition-retention procedure and must preserve required audit evidence.
- If a publisher outcome is ambiguous, do not mark an event published without broker evidence. Let the lease expire and redeliver with the same event ID; consumers must deduplicate.

## Acceptance evidence and limitations

The `postgres` build-tag integration suite covers restart/replay, 64 concurrent duplicate submissions, cross-tenant reads, exact-request conflict, record/outbox transaction rollback, append-only enforcement and outbox retry/ack lease ownership. These tests require a real PostgreSQL instance via `DATABASE_URL`; in-memory unit tests do not establish PostgreSQL behavior.

The principal is a typed context value populated only by trusted middleware. The development command intentionally installs no principal and no authority verifier. A production OIDC/mTLS resolver, ACP Run/Session authorization, content/signature verification of snapshots, broker adapter and operational restore drill remain explicit gates.
