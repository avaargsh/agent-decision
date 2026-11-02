# ADR-001 — Go Decision Plane boundary and P0 baseline

Status: **P0 implementation in progress; v1.0 Architecture Baseline not yet frozen** · 2026-11-02

## Authority

| Concern | Authority | Decision Plane may |
|---|---|---|
| Tenant, Agent, Session, Run identity; AgentRelease; Capability Catalog | agent-control-panel | consume authenticated, attested, versioned references |
| Candidate plans and immutable DecisionRecord | agent-decision | propose; never authorize or execute |
| Run/Step/Attempt/Checkpoint, retries and replan admission | agent-runtime / Temporal | request one bounded decision turn |
| Action normalization, risk, approval, Permit, ActionHash | EngageGuard | independently authorize a concrete ActionRequest |
| Trusted execution and UNKNOWN journal/reconciliation | EngageGuard Trusted Executor | reconcile; never blind retry |
| Provider, Pool, Workload, Allocation | compute-control-panel | provide capacity hints only |
| Decision quality, replay and regression | Evaluation | consume records/outcomes offline |

## Frozen domain objects for P0

1. `DecisionRequest`: schema version, authenticated Agent/Session/Run identity, idempotency key, objective/input, resource constraints, strategy/prompt/model versions, attested ContextSnapshot and CapabilitySnapshot references, version-pinned CapabilityRefs, evidence references, optional bounded replan lineage.
2. `PlanCandidate`: stable PlanID, ordered PlanSteps, exact capability versions/schema refs, target refs, and PlanHash. It contains no executable credentials or arbitrary tool arguments.
3. `DecisionRecord`: immutable request fingerprint, identity, policy/version provenance, snapshots, evidence, status/reason codes, parent Decision lineage and PlanCandidate.
4. `ActionRequest`: created by Runtime from one PlanStep and resolved inputs; includes tenant/subject/agent/run/decision/plan/step/operation identity, exact capability reference, resource target, canonical arguments and trusted tool binding. Canonical contract and ActionHash are owned by EngageGuard.
5. `OutcomeFeedback`: Runtime supplies step result and evidence references; it cannot change prior DecisionRecords.

## P0 invariants

- ACP is the only publisher and lifecycle authority for Capability definitions and versions. Decision may select only references contained in an attested ACP CapabilitySnapshot.
- Runtime validates a PlanCandidate against the active Run and AgentRelease, then maps each PlanStep into an ActionRequest. EngageGuard independently revalidates current capability, policy and risk, computes ActionHash, and binds any Permit to that individual action.
- PlanHash, ActionHash and Permit are different objects. A PlanHash cannot authorize execution.
- Runtime owns replan admission, attempt count, deadline and lifecycle. Decision only creates a child DecisionRecord with `parent_decision_id` after a Runtime-authorized retryable failure. UNKNOWN and Guard-denied operations are not ordinary failures and cannot trigger replan.
- Tenant and active Agent identity are derived from authenticated OIDC/mTLS principal context, never from a request-body field. Decision reads are scoped by `(tenant_id, agent_id, decision_id)`. The authority adapter verifies tenant/agent/session/run ownership and snapshot/evidence provenance.
- Idempotency is scoped by tenant and client key. The fingerprint includes the complete normalized request and authenticated principal identity. Identical replay returns the original immutable record; any changed input or principal conflicts. A new decision requires a new key.
- Decision cannot issue AuthorizationPermit, approve a request, execute a tool, own workflow state, or schedule compute.

## P0 implementation status

Implemented in this branch: versioned DecisionRequest/PlanCandidate structures matching the checked-in JSON Schemas; strict JSON parsing; a deterministic read-only SRE planner; fail-closed `AuthorityVerifier` interface; tenant/subject-derived idempotency; PostgreSQL unique constraints, append-only DecisionRecord storage, transactional outbox, tenant-scoped reads, outbox leases/ack/retry and dispatcher semantics. The default command intentionally wires neither a principal resolver nor an ACP verifier, so requests fail closed.

Not yet production-complete: real OIDC/mTLS principal resolution; ACP Run/Session/capability snapshot verification; cryptographic SLO evidence verification; concrete broker adapter and worker deployment; real PostgreSQL CI execution and restore drill; Runtime/EngageGuard cross-service E2E.

## Replan contract

Runtime is the only component that decides whether a replan is admitted and enforces the per-Run maximum. Decision accepts a replan request only when it carries a parent Decision ID, a sequence within the Runtime-provided bound, and a prior disposition of `RETRYABLE_FAILURE`. UNKNOWN, timeout with uncertain side effect, Guard denial, cancellation and non-retryable failure must not be represented as retryable.

## Next ADRs

- ADR-002: ACP Capability Catalog contract and tenant-scoped authority.
- ADR-003: PlanStep → ActionRequest → ActionHash → Permit → Trusted Executor.
- ADR-004: Runtime replan admission, Attempt/Lease and fencing.
- ADR-005: PostgreSQL immutable DecisionRecords, idempotency and outbox.
- ADR-006: evidence attestation, SLO observation windows, key rotation/revocation and TOCTOU.
