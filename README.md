# Agent Decision (Go)

Decision Plane for Open Agent Infrastructure. Go owns deterministic decisions, contracts, provenance, idempotency and governance boundaries; Python/TypeScript framework workers are **optional, replaceable decision plugins**, never an authority for approvals or tool side effects.

## Boundaries

- **agent-control-panel**: authoritative Agent/Release/Capability, Session/Run identity and desired state. Decision only consumes versioned references.
- **agent-decision**: side-effect-free candidate planning and immutable decision record. It does **not** issue an AuthorizationPermit, approve an action, or execute tools.
- **EngageGuard**: canonical ActionHash, risk/approval, action-bound permits, Trusted Executor and UNKNOWN operation reconciliation.
- **Agent Runtime + Temporal**: steps, task lifecycle, checkpoints, retries, replan requests and durable workflow state. No workflow engine in Decision.
- **compute-control-panel**: capacity, quota and compute reconciliation, not SRE plan selection.
- **Evaluation**: offline replay/scoring of decision records, separate from live decisions.

## P0: local, read-only SRE Golden Path

`ACP Run + ContextSnapshotRef + CapabilitySnapshotRef + SRE signal + EvidenceRefs -> DecisionRequest -> validate -> rule planner -> immutable DecisionRecord -> proposals -> Runtime -> EngageGuard (authorization required before *any* tool) -> executor/outcome`

The current code stops at **DecisionRecord**. It cannot execute or authorize anything. Evidence SHA-256 values are **caller-supplied references, not independently verified attestations**. Missing evidence yields `ABSTAINED` and zero proposed steps. Only `sre.*.read` capabilities are emitted by the initial rule planner; ACP and EngageGuard must still check authority at execution time.

### Development test

```sh
go test -race ./...
go vet ./...
go run ./cmd/agent-decision
```

Server binds **127.0.0.1:8080** and has no authentication. Do **not** expose to any external network or deploy as a production service. In-memory records are lost on restart and are not durable or tamper-evident.

```sh
curl -sS -X POST http://127.0.0.1:8080/v1/decisions \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id":"tenant-a", "idempotency_key":"incident-17", "run_id":"run-17",
    "service":"payment-api", "signal":"latency",
    "context_snapshot":{"id":"ctx-17","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    "capability_snapshot":{"id":"acp-cap-17","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
    "evidence_refs":[{"ref":"slo-17","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]
  }'
```

`POST /v1/decisions` returns `201` on creation, `200` on an identical idempotent replay, `409` on a conflicting reuse, `400` for invalid input. JSON rejects unknown fields, duplicate keys at any depth, trailing data and bodies > 1 MiB. `GET /healthz` returns `204`. This is a *development-only* API contract; production requests must obtain authenticated tenant identity from a trusted gateway, rather than trusting `tenant_id` in JSON.

## Next milestones

1. PostgreSQL-backed tenant-scoped immutable record + idempotency constraints, transactional outbox and authorization-safe APIs.
2. Read-through, signed or content-verified Context/Capability/Evidence snapshots; SLO provenance and TTL/TOCTOU validation.
3. Capability-contract integration with ACP, Agent Runtime and EngageGuard contract tests, without any local execution path.
4. Framework-independent Planner interface, optional isolated Python/TypeScript model decision adapter; policy-first, model-assisted.
5. Legacy `agent-decision-lab` read-only SRE five-stage receipt verifier migration only after parity fixtures and independent staging evidence.
6. Offline evaluation, replay without re-inference, regression sets and evidence/source-of-truth checks.

See [architecture baseline](docs/architecture/BASELINE.md).
