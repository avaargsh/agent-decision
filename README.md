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

Agent Decision does not own Agent, Session, or Run lifecycle; workflow orchestration; approval state; capability authorization; credentials; execution permits; or tool execution. Agent Control Plane governs, Agent Runtime orchestrates and executes through EngageGuard, and Agent Decision proposes.

## Go implementation

- Core domain and strategy SPI: `internal/decision`
- PostgreSQL persistence: `internal/decision/postgres_store.go`
- HTTP transport: `internal/api`
- Development entry point: `cmd/agent-decision`
- Database migration: `migrations/0001_create_decision_records.sql`
- Architecture contract: `docs/architecture.md`
- Delivery roadmap: `docs/roadmap.md`
- OpenAPI 3.1 contract: `api/openapi.yaml`
- JSON Schema compatibility artifacts: `api/schemas/`

The default `sre-readonly-v1` strategy emits a deterministic all-or-nothing plan using metrics, logs, and change-history read capabilities. Missing evidence or capabilities produces an explicit abstention. Strategy output is independently checked by the core for read-only safety invariants.

## Development

```bash
go test -race ./...
go vet ./...
go run ./cmd/agent-decision
```

PostgreSQL integration tests run when `DATABASE_URL` is set. The CI workflow provisions PostgreSQL 16 and exercises the migration, tenant-scoped idempotency, replay, conflict detection, and concurrent inserts.

The development server binds to loopback and fails closed for decision requests until a trusted principal resolver and authoritative snapshot verifier are configured. The in-memory store is for tests and local development only. Production deployment must apply the migration and use a restricted database role; the durable store enforces atomic tenant-scoped idempotency.
