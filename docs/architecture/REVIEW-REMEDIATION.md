# Architecture Review Remediation — 2026-11-02

Review decision: **conditionally approved**. Complete the five P0 items before freezing the v1.0 Architecture Baseline.

| Review finding | Remediation in this branch | Remaining gate |
|---|---|---|
| P0-1 Capability Registry ownership | ACP is the sole Capability Catalog publisher; Decision consumes a snapshot and version-pinned CapabilityRefs. No endpoint or credential fields are present. | ACP signed snapshot resolver and cross-repo contract conformance. |
| P0-2 Plan → Action contract | PlanCandidate/PlanStep is distinct from ActionRequest; Runtime owns conversion; EngageGuard owns ActionHash and Permit. | EngageGuard ActionRequest schema and Runtime-to-Guard conformance test. |
| P0-3 Replanning ownership | Runtime owns admission and maximum count; Decision accepts bounded child decisions only after RETRYABLE_FAILURE. | Runtime must persist and enforce the Run-level replan budget; UNKNOWN and Guard denial remain blocked. |
| P0-4 Multi-tenant identity | Tenant is absent from the HTTP request body; a principal resolver and authority verifier are mandatory; principal identity is checked against Agent/Session. | Real OIDC/mTLS resolver and ACP verifier are not wired; current development command denies decision calls. |
| P0-5 Complete idempotency/fingerprint | Fingerprint covers authenticated principal plus identity, objective, constraints, versions, snapshots, capability bindings, evidence and replan lineage. Memory store enforces tenant+key atomic replay/conflict. | PostgreSQL uniqueness, immutable persistence, restart/replay and outbox tests remain mandatory before production. |

## Explicit safety boundary

Decision emits only PlanCandidate. Runtime turns one PlanStep into one ActionRequest. EngageGuard independently validates current capability and policy, normalizes exact arguments, calculates ActionHash, and issues an action-bound Permit only if authorized. Trusted Executor performs the operation; OperationJournal owns UNKNOWN and reconciliation. PlanHash is not an authorization artifact.

## Replan rule

Runtime admits replanning and enforces its per-Run budget. Decision cannot turn UNKNOWN, an ambiguous timeout, or Guard denial into a retryable failure. Replan records include parent Decision ID and sequence.

## Evidence classification

- **Implemented in code:** request/identity contract, capability pinning, rule-only SRE plan, strict HTTP parsing, fail-closed interfaces, tenant-scoped in-memory idempotency, immutable-copy tests and PlanHash.
- **Not implemented:** real authentication, ACP source verification, signed evidence verification, PostgreSQL, outbox and real Runtime/Guard E2E.
- **Not production-ready:** current development HTTP command and in-memory store.
