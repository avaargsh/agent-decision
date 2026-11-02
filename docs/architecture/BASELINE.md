# ADR-001 — Go Decision Plane boundary and migration baseline

Status: **Accepted for P0 development only** · 2026-11-02

## Context

The earlier SRE decision lab demonstrated read-only five-stage receipt verification, Ed25519, SLO observation provenance, health threshold recalculation, TOCTOU snapshot binding and strict JSON checks. Those results are evidence for migration, **not proof of parity** in this fresh Go repository. No legacy execution privileges are imported.

The initial repository charter described a Python-first framework plugin host. This ADR supersedes it: **Go is the Decision Plane service**, while Python and TypeScript remain bounded framework-worker implementations behind a versioned plugin adapter. Keep domain objects independent of LangGraph, a model provider, or Temporal SDK types.

## Authority (not shared)

| Concern | Authority | Decision Plane can do |
|---|---|---|
| Release, capability, tenant/Run identity | agent-control-panel | link immutable, versioned references |
| Candidate plans, decision record | agent-decision | propose; never execute |
| Run/Step/Checkpoint, retries, replanning | Agent Runtime / Temporal | answer one bounded decision request |
| Risk, approval, permit, ActionHash | EngageGuard | pass proposed action intent only |
| Trusted execution, UNKNOWN journal/reconciliation | EngageGuard Trusted Executor | consume outcome feedback; cannot retry side effects |
| Metrics/decision quality/replay | Evaluation | emit provenance, never re-infer during replay |
| Hardware resources | compute-control-panel | may consume capacity hints, not schedule compute |

## V1 contracts

- `DecisionRequest`: tenant, client-stable idempotency key, ACP Run reference, service/signal, `ContextSnapshotRef`, `CapabilitySnapshotRef`, evidence references.
- `DecisionRecord`: stable ID, input hash, policy version, input refs, status, reason, read-only proposals, creation time.
- Future adapter types (not yet implemented): `PlanCandidate`, `ActionRequest`, `AuthorizationPermit` (owned by Guard), `OutcomeFeedback`.
- State is immutable; retry with same tenant/key and same exact request returns the original record, different body conflicts. Cross-tenant keys never alias.
- This P0 planner returns `ABSTAINED` if no evidence references exist; does not claim submitted evidence is authentic.
- Existing in-memory mutex is only a concurrency demonstration. Replace with PostgreSQL uniqueness and transactional outbox **before production**.

## Threat model and strict exclusions

No execution, no approval shortcut, no credentials in prompts or proposal records, no workflow engine implementation, no self-managed scheduler. The local HTTP listener is loopback-only without authentication. In production, bind `tenant_id` to an authenticated principal, enforce tenant-scoped access, verify immutable snapshot provenance, impose body/time limits and prevent data-plane workers from directly calling Trusted Executor. `read_only:true` is descriptive metadata, **not** an authorization mechanism.

The future Planner adapter may call external model/framework workers only with bounded context, timeout, trace ID, no long-lived credentials and a typed output schema. Guard independently normalizes and hashes **individual actions**; a DecisionRecord or Plan hash is never a permit.

## P0 acceptance and migration gates

1. Rule planner and HTTP contract tests include missing-evidence abstention, immutable record replay, cross-tenant idempotency, concurrent duplicate requests, validation, duplicate-key rejection and limit enforcement.
2. Verify PostgreSQL restart/replay, key race and outbox atomicity before shipping. No production claim from in-memory test results.
3. ACP capability snapshot and SLO evidence source need independent attestation; failing closed if missing, expired or mismatched.
4. Migration from legacy SRE code is permitted only with traceable fixtures for five-stage Ed25519 receipts, revoked/rotated keys, raw SLO samples, observation windows, threshold recalculation and TOCTOU, plus independent reviewer sign-off.
5. E2E must demonstrate `Decision -> Runtime -> EngageGuard -> Trusted Executor -> OperationJournal -> OutcomeFeedback`, with UNKNOWN never retried blindly.

## ADRs to freeze next

- ADR-002: ACP Capability contract and tenant-scope authority
- ADR-003: Decision/Plan/Action split; action-bound authorization, not plan-bound
- ADR-004: Runtime replan semantics and `parent_decision_id`
- ADR-005: PostgreSQL immutable records, outbox and replay semantics
- ADR-006: Evidence/receipt signature, SLO provenance and key revocation
