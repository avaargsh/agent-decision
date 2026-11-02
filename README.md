# Agent Decision (Go)

Decision Plane for Open Agent Infrastructure. Go owns deterministic policy-first planning and immutable DecisionRecords. Python/TypeScript framework workers are optional, bounded and replaceable; they are never authorization authorities or side-effect executors.

## Authority boundaries

- **agent-control-panel** owns Tenant/Agent/Session/Run identity, AgentRelease and the versioned Capability Catalog. Decision consumes attested, version-pinned references; it cannot publish or revoke capabilities.
- **agent-decision** owns DecisionRequest validation, deterministic candidate planning and immutable DecisionRecord. It cannot issue permits, approve actions or execute tools.
- **Agent Runtime + Temporal** owns Run/Step/Attempt lifecycle, checkpoints, retries and the decision to request a bounded replan.
- **EngageGuard** owns ActionRequest normalization, ActionHash, risk/approval, action-bound Permit, Trusted Executor and UNKNOWN OperationJournal reconciliation.
- **compute-control-panel** owns Provider/Pool/Workload/Allocation and compute-provider operations, not Agent Run or Decision state.
- **Evaluation** owns offline replay, scoring and regression; it is not a live execution dependency.

## P0 Golden Path

`authenticated Runtime principal + ACP Run reference + attested ContextSnapshot + attested CapabilitySnapshot + SRE evidence -> DecisionRequest -> authority verification -> deterministic rule planner -> immutable PlanCandidate + DecisionRecord + transactional outbox -> Runtime validates and converts PlanStep to ActionRequest -> EngageGuard authorizes exact ActionHash -> Trusted Executor -> OperationJournal reconciliation -> OutcomeFeedback`

The Go implementation stops at DecisionRecord and typed PlanCandidate. It cannot execute or authorize anything. The HTTP body does not accept `tenant_id`; tenant and subject come from a trusted principal resolver. A mandatory `AuthorityVerifier` must independently verify Run ownership, snapshot/evidence digest, source version, expiry, attestation and revocation. Caller-supplied SHA-256 strings and `trust_level: attested` are not proof of authenticity.

The development command intentionally wires neither a principal resolver nor an ACP authority verifier. Requests therefore fail closed (`401` without a principal, `503` without the verifier). It binds only to **127.0.0.1:8080**. Never expose it as a production service.

The rule-only v1 planner proposes only version-pinned `sre.metrics.read`, `sre.logs.read` and `sre.changes.read` capabilities. Missing evidence or any required capability yields `ABSTAINED` with no partial plan. `read_only:true` is descriptive metadata, not authorization. Runtime owns replan admission and budgets; UNKNOWN and Guard-denied outcomes are not retryable failures.

## Local verification

```sh
go test -race ./...
go vet ./...
gofmt -w cmd internal
```

## PostgreSQL durability

The PostgreSQL store is implemented behind the optional `postgres` build tag, using pgx v5.7.2 via `database/sql`.

```sh
# PostgreSQL-backed local development (the decision endpoint still fails closed without trusted adapters)
DATABASE_URL='postgres://app:pass@localhost:5432/agent_decision?sslmode=disable' \
MIGRATOR_DATABASE_URL='postgres://migrator:pass@localhost:5432/agent_decision?sslmode=disable' \
go run -tags postgres ./cmd/agent-decision

# Real PostgreSQL integration tests
DATABASE_URL='postgres://user:pass@localhost:5432/agent_decision_test?sslmode=disable' \
  go test -tags postgres -race ./...
```

Durable semantics:

- Unique `(tenant_id, idempotency_key)` and atomic insert/replay; same key with a different normalized request or principal conflicts.
- Tenant identity is absent from JSON. Decision reads require both tenant and active Agent scope; cross-tenant or cross-agent records are hidden as `404`.
- DecisionRecord rows reject UPDATE and DELETE at the database trigger layer.
- DecisionRecord and deterministic `decision.recorded.v1` outbox intent commit in one PostgreSQL transaction.
- Outbox claims use `FOR UPDATE SKIP LOCKED`, owner-bound leases and stable event IDs. Delivery is at least once; consumers must deduplicate event IDs.
- Outbox payload and identity fields are immutable; lease and delivery bookkeeping fields remain mutable.

The outbox storage and dispatcher interface are implemented, but a concrete broker adapter, worker deployment, production principal resolver, ACP authority verifier, restore drill and cross-service E2E remain gates. Contracts: [DecisionRequest v1 JSON Schema](docs/contracts/decision-request.v1.schema.json) and [PlanCandidate v1 JSON Schema](docs/contracts/plan-candidate.v1.schema.json). See [PostgreSQL operations](docs/operations/POSTGRES.md), [architecture baseline](docs/architecture/BASELINE.md) and [review remediation](docs/architecture/REVIEW-REMEDIATION.md).

## Next milestones

1. **P0 persistence (Issue #4):** PostgreSQL immutable records, tenant-scoped idempotency, transactional outbox and real integration evidence (this branch).
2. **P0 provenance (Issue #5):** ACP-authoritative capability/Run binding, signed SRE evidence, five-stage Ed25519 receipt parity fixtures and TOCTOU validation.
3. **P0 integration (Issue #6):** Runtime/EngageGuard contracts, action-bound authorization, UNKNOWN reconciliation and E2E tests.
4. **P1 planner plugins:** isolated Python/TypeScript model decision workers behind the versioned contract; policy-first, model-assisted.
5. **P1 evaluation:** offline replay, regression suites, evidence provenance and decision-quality metrics.
