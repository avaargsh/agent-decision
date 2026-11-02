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

`authenticated Runtime principal + ACP Run reference + attested ContextSnapshot + attested CapabilitySnapshot + SRE evidence -> DecisionRequest -> authority verification -> deterministic rule planner -> immutable PlanCandidate + DecisionRecord -> Runtime validates and converts PlanStep to ActionRequest -> EngageGuard authorizes exact ActionHash -> Trusted Executor -> OperationJournal reconciliation -> OutcomeFeedback`

The current Go implementation stops at the DecisionRecord. The development server has no authentication resolver or ACP verifier and therefore **fails closed** for all decision requests. This is intentional. Never expose it as a production service.

The HTTP body does not accept `tenant_id`; tenant, subject, agent and session identity are derived from a trusted principal resolver. A mandatory `AuthorityVerifier` must independently verify Run ownership and snapshot/evidence attestation, digest, source version, expiry and revocation. Caller-supplied SHA-256 strings are not proof of authenticity.

The rule-only v0.1 planner proposes only version-pinned `sre.metrics.read`, `sre.logs.read` and `sre.changes.read` capabilities. Missing evidence or any required capability yields `ABSTAINED` with no partial plan. `read_only:true` is descriptive metadata, not authorization.

## Local verification

```sh
go test -race ./...
go vet ./...
gofmt -w cmd internal
```

## Durability and production gates

- The in-memory mutex store is a test/development implementation, not durable. PostgreSQL uniqueness, immutable records, restart/replay, transactional outbox and key-race tests are required before production.
- An OIDC/mTLS-backed principal resolver and ACP/SLO authority verifier are required before any request can produce a plan.
- Runtime must enforce the Run's replan budget and only request a replan after an explicitly retryable failure. UNKNOWN and Guard-denied operations cannot be replanned as ordinary failures.
- Runtime must convert a PlanStep into an individual ActionRequest. EngageGuard independently re-resolves current capability and policy, computes ActionHash, and binds any Permit to that exact action. A PlanHash is never a Permit.
- No model planner, autonomous loop, approval shortcut, credentials in prompts, or local tool execution is included in P0.

See [architecture baseline](docs/architecture/BASELINE.md) and [review remediation](docs/architecture/REVIEW-REMEDIATION.md).
