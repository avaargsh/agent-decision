# Architecture Review Remediation — 2026-11-02

Review decision: **conditionally approved**. Complete all remaining P0 gates before freezing the v1.0 Architecture Baseline.

| Review finding | Remediation in this branch | Remaining gate |
|---|---|---|
| P0-1 Capability Registry ownership | ACP is the sole Capability Catalog publisher; Decision consumes a snapshot and version-pinned CapabilityRefs. | Signed ACP snapshot resolver and cross-repo contract conformance. |
| P0-2 Plan → Action contract | PlanCandidate/PlanStep is distinct from ActionRequest; Runtime owns conversion; EngageGuard owns ActionHash and Permit. | EngageGuard ActionRequest schema and Runtime-to-Guard conformance test. |
| P0-3 Replanning ownership | Runtime owns admission and maximum count; Decision accepts bounded child decisions only after RETRYABLE_FAILURE. | Runtime must persist and enforce the Run-level replan budget; UNKNOWN and Guard denial remain blocked. |
| P0-4 Multi-tenant identity | Tenant and active Agent are absent from the HTTP request body; principal scope is required for decision and read paths; a principal resolver and authority verifier are mandatory; service fails closed without them. | Real OIDC/mTLS resolver and ACP verifier are not wired. |
| P0-5 Complete idempotency/fingerprint | Fingerprint covers authenticated principal plus identity, objective, constraints, versions, snapshots, capability bindings, evidence and replan lineage. PostgreSQL uses unique tenant+key, append-only records, restart/replay and atomic outbox. | Real PostgreSQL CI execution, independent SQL review and restore drill. |

## Explicit safety boundary

Decision emits only PlanCandidate. Runtime turns one PlanStep into one ActionRequest. EngageGuard independently validates current capability and policy, normalizes exact arguments, calculates ActionHash, and issues an action-bound Permit only if authorized. Trusted Executor performs the operation; OperationJournal owns UNKNOWN and reconciliation. PlanHash is not an authorization artifact.

## Replan rule

Runtime admits replanning and enforces its per-Run budget. Decision cannot turn UNKNOWN, an ambiguous timeout, or Guard denial into a retryable failure. Replan records include parent Decision ID and sequence.

## Evidence classification

- **Implemented in code:** v1 request/plan contracts; strict JSON; fail-closed authority interface; deterministic read-only SRE plan; PostgreSQL immutable records; tenant-scoped atomic idempotency; transactional outbox; lease/ack/retry; local unit tests and PostgreSQL integration tests.
- **Not implemented:** real authentication, ACP source verification, signed evidence verification, broker adapter, deployed worker and real Runtime/Guard E2E.
- **Not production-ready:** current development command and default in-memory store; PostgreSQL integration must be green in GitHub CI and independently reviewed before merge.
