# Agent Decision

Go-first Decision Intelligence Core for Open Agent Infrastructure.

Agent Decision turns authenticated, evidence-backed context into deterministic and auditable decision records. The initial vertical is read-only SRE incident investigation planning.

## Responsibilities

- Validate versioned DecisionRequest contracts.
- Bind requests to a trusted tenant and caller principal.
- Verify externally owned context, evidence, and capability snapshots.
- Run a replaceable, versioned decision strategy.
- Persist an idempotent DecisionRecord and a bounded read-only PlanCandidate.
- Abstain explicitly when evidence or required capabilities are missing.

## Explicit non-goals

Agent Decision does not own Agent, Session, or Run lifecycle; workflow orchestration; approval state; capability authorization; credentials; execution permits; or tool execution. Agent Control Plane owns Tenant/Agent/Session/RunIntent identity and policy bindings; Agent Runtime creates and owns Run identity and durable execution semantics; EngageGuard owns action authorization and trusted execution; Agent Decision consumes a Runtime-issued Run ID and proposes only. The ACP/Runtime RunIntent-to-Run mapping remains a proposed cross-repository contract pending owner sign-off.

## Go implementation

- Core domain and strategy SPI: `internal/decision`
- PostgreSQL persistence: `internal/decision/postgres_store.go`
- HTTP transport: `internal/api`
- Decision Ledger query API: `GET /v1/decisions/{decision_id}` and `GET /v1/runs/{run_id}/decisions`
- Development entry point: `cmd/agent-decision`
- Database migration: `migrations/0001_create_decision_records.sql`
- Architecture contract: `docs/architecture.md`
- Cross-repository integration contract: `docs/architecture/integration-contract.md`
- Delivery roadmap: `docs/roadmap.md`
- OpenAPI 3.1 contract: `api/openapi.yaml`
- JSON Schema compatibility artifacts: `api/schemas/` (request, record, page, and problem)

The default `sre-readonly-v1` strategy emits a deterministic all-or-nothing plan using metrics, logs, and change-history read capabilities. Missing evidence or capabilities produces an explicit abstention. Strategy output is independently checked by the core for read-only safety invariants.

## Development

```bash
go test -race ./...
go vet ./...
go run ./cmd/agent-decision
```

PostgreSQL integration tests run when `DATABASE_URL` is set. The CI workflow provisions PostgreSQL 16 and exercises the migration, tenant-scoped idempotency, replay, conflict detection, and concurrent inserts.

Ledger reads require a trusted principal and are scoped to the principal's tenant, agent, and session. Run listings use bounded cursor pagination with descending `(created_at, decision_id)` ordering.

The development server binds to loopback and fails closed for decision requests until a trusted principal resolver and authoritative snapshot verifier are configured. The in-memory store is for tests and local development only. Production deployment must apply the migration and use a restricted database role; the durable store enforces atomic tenant-scoped idempotency.


## Kubernetes policy baseline

A starter OPA/Rego policy bundle checks rendered Deployment candidates for privileged execution, host namespace sharing, non-root execution, resource requests/limits and immutable image digests. Run it with the pinned Conftest image:

```bash
docker run --rm -v "$PWD:/project:ro" -w /project openpolicyagent/conftest:v0.71.1 test --policy ./policy/kubernetes testdata/kubernetes/hardened-deployment.yaml
```

CI also verifies that an unsafe init container is rejected even when the regular application container is compliant. The policy bundle is currently a standalone deterministic preflight artifact. It is not yet invoked by the Decision API, and it does not calculate probabilistic risk or expected loss.
