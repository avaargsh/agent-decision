# Agent Decision

Go-first Decision Intelligence Core for Open Agent Infrastructure.

Agent Decision turns authenticated, evidence-backed context into deterministic and auditable decision records. The initial vertical is read-only SRE incident investigation planning.

## Quickstart

Prerequisites:

- Go 1.22 or newer, the version declared by `go 1.22` in `go.mod`.
- Docker is optional. The Kubernetes policy baseline later in this file runs Conftest with Docker.
- PostgreSQL 16 is optional. Integration tests use it when `DATABASE_URL` is set. `make test` does not start PostgreSQL, and those tests skip when `DATABASE_URL` is unset.

The root Makefile sets `GOTOOLCHAIN=local` and uses the Go toolchain already on `PATH`. When `go` is missing, or older than the `go` line in `go.mod`, `make build`, `make test`, and `make run` print an error and stop.

```bash
git clone https://github.com/avaargsh/agent-decision
cd agent-decision
make build
make test
make run
```

`make build` writes `bin/agent-decision`, `bin/decision-catalog-attest`, and `bin/decision-role-audit`. `make test` runs `go test -race -count=1 ./...`. `make run` runs `go run ./cmd/agent-decision --port 8080` and listens on `127.0.0.1`. Another port is `PORT=8081 make run`.

Leave `make run` in that terminal. In a second terminal:

```bash
curl http://127.0.0.1:8080/healthz
```

`GET /healthz` returns HTTP 204 and an empty body, so that `curl` command prints nothing and exits 0. The development server listens on `127.0.0.1` only. `POST /v1/decisions` is denied by design until a trusted principal resolver and an authoritative snapshot verifier are configured. This dev server starts with neither. A POST returns HTTP 401 `UNAUTHENTICATED` and `trusted principal resolver is required`. `GET /healthz` still answers.

`make clean` removes `bin/`.

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

`make test` runs `go test -race -count=1 ./...`. `make vet` runs `go vet ./...`. `make run` runs `go run ./cmd/agent-decision` and passes `--port` from `PORT` (default `8080`). `make lint` requires `gofmt -l .` to be empty and fails when `gofmt` itself exits with an error.

If port 8080 is occupied, run `go run ./cmd/agent-decision --port 8081`. Use
`--port 0` to select a free port and read the loopback address from the startup log.

PostgreSQL integration tests run when `DATABASE_URL` is set. The CI workflow provisions PostgreSQL 16 and exercises the migration, tenant-scoped idempotency, replay, conflict detection, and concurrent inserts.

Ledger reads require a trusted principal and are scoped to the principal's tenant, agent, and session. Run listings use bounded cursor pagination with descending `(created_at, decision_id)` ordering.

The development server binds to loopback and fails closed for decision requests until a trusted principal resolver and authoritative snapshot verifier are configured. The in-memory store is for tests and local development only. Production deployment must apply the migration and use a restricted database role; the durable store enforces atomic tenant-scoped idempotency.


## Kubernetes policy baseline

A starter OPA/Rego policy bundle checks rendered Deployment candidates for privileged execution, host namespace sharing, non-root execution, resource requests/limits and immutable image digests. Run it with the pinned Conftest image:

```bash
docker run --rm -v "$PWD:/project:ro" -w /project openpolicyagent/conftest:v0.71.1 test --policy ./policy/kubernetes testdata/kubernetes/hardened-deployment.yaml
```

CI also verifies that an unsafe init container is rejected even when the regular application container is compliant. The policy bundle is currently a standalone deterministic preflight artifact. It is not yet invoked by the Decision API, and it does not calculate probabilistic risk or expected loss.


## PostgreSQL catalog preflight (Draft integration)

The migrator owns `decision.MigrateInSchema(ctx, db, approvedSchema)`; the restricted application must **never** run migrations. Independently verify a deployed PostgreSQL 16 schema after migration and before enabling writes, using a read-only database role:

```bash
DECISION_ATTEST_DATABASE_URL="$READONLY_POSTGRES_DSN" DECISION_ATTEST_SCHEMA=public go run ./cmd/decision-catalog-attest
```

For a durable HTTP service, explicitly compose `api.NewCatalogGuardedHandler` using `decision.VerifyInstalledCatalogInSchema` on the same approved database/schema. `GET /readyz` and each `POST /v1/decisions` are denied while the catalog check fails; `GET /healthz` remains liveness-only. The existing `cmd/agent-decision` is an **in-memory development entrypoint**, not that production composition. See `docs/operations/postgres-runbook.md` for privilege bounds, schema-pinned application connections, limitations and still-open production/G02/G05 gates.

For the Runtime-owned internal Decision Turn endpoint, `decision.NewTenantPoolStore` constructs a bounded `decision.TenantPoolStore` from deployment-owned LOGIN pins and a pool-opener callback. It returns the `Store` plus `Close` lifecycle contract, reserves the dispatcher identity against tenant reuse, and verifies each tenant pool's database/LOGIN/Role OID and mapping. The opener still owns secret retrieval, dedicated credentials, TLS server/cluster verification, and schema-pinned settings on every physical connection; the constructor does not create the dispatcher pool, run migrations, or start an HTTP listener. Compose `api.NewTrustedTurnHandler` with this Store, `decision.LiveAuthority`, and an independent `decision.VerifyInstalledCatalogInSchema` attestor. This is a composition building block, not a production server; production deployment, dispatcher wiring, restore evidence and G02/G05 gates remain open.
