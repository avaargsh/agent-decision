# Cross-repository Decision Integration Contract

**Status:** integration design baseline; upstream alignment review remains open  
**Applies to:** Agent Decision v0.1 and the Open Agent Infrastructure repositories

## 1. Authority map

| Concern | Authority | Agent Decision interaction |
|---|---|---|
| Tenant, Project, Agent, Session, RunIntent IDs, desired state and policy bindings | Agent Control Plane | Accept Agent/Session/RunIntent references; never mint Run IDs |
| Run, Task, RunAttempt and RunIntent-to-Run mapping | Agent Runtime / Temporal | Consume a Runtime-issued Run ID; return a proposal or abstention |
| Capability catalog, immutable capability contracts and policy bindings | Agent Control Plane | Consume version-pinned read-only capability references |
| Action normalization, authorization decision, approval, one-time permit, operation journal and trusted execution guard | EngageGuard | Never issue permits or claim an action is authorized |
| Provider resource identity and side effects | Sandbox / Compute providers | Consume no provider credentials or executor configuration |
| Decision strategy, evidence evaluation and immutable DecisionRecord | Agent Decision | Own this decision record only |

The cross-repository candidate in [agent-control-panel PR #4](https://github.com/avaargsh/agent-control-panel/pull/4), ADR-0001 and [agent-decision Issue #9](https://github.com/avaargsh/agent-decision/issues/9) proposes that ACP creates RunIntent while Runtime creates `run_id` and `workflow_id` after accepting that intent. PR #4 and ADR-0001 are explicitly **PROPOSED / NOT RATIFIED**; this document records the candidate boundary for integration work and does not claim owner sign-off. Until ratification, cross-repository integration remains a blocking gate.

### Run identity and lifecycle authority

Under the proposed v0.3 map, ACP owns `run_intent_id`; Runtime creates and owns `run_id`, `workflow_id`, Run state, Task and RunAttempt lifecycle, retry admission and recovery. Temporal owns workflow history and scheduling semantics, while Runtime owns the business mapping from accepted RunIntent to Run. Decision consumes a Runtime-issued `run_id`; it never creates or advances a Run.

This candidate must be ratified by ACP and Runtime owners. Decision's production AuthorityVerifier must verify Run existence, tenant/Agent/Session binding and allowed state against Runtime authority, while verifying Agent/Session/policy/capability snapshots against ACP and evidence provenance against the evidence authority. An optional replan context must be checked against Runtime-authoritative retry admission, retryable disposition and budget; syntactic fields in a DecisionRequest are not proof of replan permission.

Never conflate `run_intent_id`, `run_id`, `workflow_id`, `run_attempt_id`, Temporal Activity IDs or Decision IDs.

## 2. Protocol ownership and compatibility

Runtime creates a stable `invocation_id` for each logical Decision Turn and persists it before the first request. Agent Decision owns the immutable invocation result/DecisionRecord ledger and uses the unique key `(tenant_id, invocation_id)`. Temporal Activity retries must reuse the exact same `invocation_id` and normalized request digest. A changed digest for the same invocation is rejected with `409 INVOCATION_ID_REUSED`. This Core invocation contract is separate from the legacy Python/TypeScript DecisionTurn adapter protocol.


The Go Decision Core endpoint `POST /v1/decisions` publishes the Decision Core request/record contract (`decision.v1`, `PROPOSED | ABSTAINED`) and owns the immutable DecisionRecord ledger. The legacy Python/TypeScript framework adapter surface named `DecisionTurn` is a separate protocol with different context and response discriminators. These contracts are **not wire-compatible** and must not share a version identifier or be silently coerced.

A future framework adapter may provide bounded reasoning output to the Go Core under an independently versioned adapter contract. The Core must validate adapter output as untrusted strategy input; adapters do not write platform DecisionRecords, own Run identity, authorize capabilities, issue permits or execute actions. The retirement/migration policy for legacy adapter PRs remains open under Decision Issue #9.

## 2. Request identity and trust boundary

`DecisionRequest.identity` carries `agent_id`, `session_id` and `run_id`. Agent and Session identities are ACP-owned references; `run_id` is created and owned by Runtime after accepting an ACP RunIntent. These values are not caller authentication.

The trusted `PrincipalResolver` supplies tenant, subject, caller, Agent and Session identity out-of-band. For the v0.1 Runtime-only entry point, the caller is `agent-runtime`. The service binds the request Agent and Session to that Principal before planning.

The authoritative verifier must additionally establish that:

1. the Run exists and belongs to the supplied tenant, Agent and Session;
2. the Run is in a state in which a decision request is permitted by the upstream contract;
3. the Context and Capability snapshots are immutable, correctly attested, unexpired and not revoked;
4. each Evidence reference belongs to the expected tenant/scope, has a verified digest and attestation, and is not expired or revoked.

Decision does not create Sessions/Runs, advance lifecycle state, schedule retries or infer execution success. The Runtime remains the workflow owner.

## 3. Capability contract

A `CapabilityRef` is a version-pinned reference from the Control Plane capability catalog. Its contract digest, input/output schema references, effect class, idempotency classification and tenant scope are the only capability attributes Decision needs for planning.

The v0.1 planner accepts read-only, safe, tenant-scoped capabilities. Endpoint URLs, credential material, executor configuration, raw tool arguments and permits are intentionally excluded. A proposed `PlanStep` is not authority to invoke the capability; downstream policy and enforcement still apply.

The `CapabilitySnapshot` version must match `versions.capability_catalog_version`. The authoritative verifier, rather than the request parser alone, must prove that the snapshot and its referenced capability definitions are the canonical Control Plane publication.

## 4. Evidence contract and next-stage gap

The Decision-side Evidence Envelope v1 now carries evidence type/schema version, tenant/Agent/Run/service/resource scope, source identity/version, content digest/attestation, observation interval, observed and collected timestamps, expiry and revocation state. It contains no evidence payload. This is a syntactic and scope-binding baseline; the production AuthorityVerifier must independently verify tenant ownership, signatures, digests, source identity/version, expiry and revocation.

This is sufficient for identity/provenance verification, but it is not yet sufficient for a robust Evidence Quality or Hypothesis Engine. Before adding freshness scores or coverage rules, define and version the evidence envelope with at least:

- envelope evidence kind/modality and schema version (represented by the v1 envelope);
- tenant, Agent, Run and service/resource scope;
- observation interval or query window, not only a single timestamp;
- source identity and source-version semantics;
- immutable content digest and attestation/verifier identity;
- collection time, observed time, expiry and revocation state;
- optional correlation identifiers linking metrics, logs, traces, changes, SLOs and deployment events.

Freshness thresholds, evidence weights and conflict policies must be defined per evidence kind and operational objective. They must not be guessed globally. Evidence quality should be explainable from the actual source metadata and the policy version used.

## 5. EngageGuard boundary

The v0.1 plan contains only read-only investigation steps. Agent Decision never creates an EngageGuard permit and never reports a write action as authorized.

A future remediation proposal must remain a separate typed object. Runtime/Control Plane sends the normalized candidate to EngageGuard, where action hash binding, policy evaluation, risk checks, approval, one-time permit and trusted execution are enforced. Operation outcome and post-condition evidence return through the Runtime/Control Plane evidence path. Unknown side-effect outcomes must be reconciled before any retry or replanning.

## 6. End-to-end interaction

1. Control Plane creates Tenant/Agent/Session and RunIntent identities and publishes immutable context/capability snapshots.
2. Runtime accepts the RunIntent, creates the authoritative Run ID/workflow mapping, starts or resumes the durable workflow and obtains the authenticated Runtime principal.
3. Runtime calls Agent Decision with the Runtime-issued Run ID, canonical Agent/Session references, snapshot references, capability references and evidence references.
4. Agent Decision validates the request, binds Agent/Session to the Principal, and asks the authoritative verifier to verify Run ownership and snapshot/evidence authority.
5. Agent Decision persists a deterministic DecisionRecord or explicit abstention and returns it to Runtime.
6. Runtime interprets the proposal as workflow input. Any privileged or mutating action remains subject to Control Plane policy and EngageGuard authorization/execution.
7. Runtime and Control Plane attach execution receipts, observations and outcome evidence to the same canonical Run.

## 7. Open integration gates

- Ratify the proposed ACP RunIntent → Runtime Run identity mapping and confirm the Runtime authority API used by Decision's verifier.
- Freeze separate versioned contracts for the Go Decision Core and any Python/TypeScript DecisionTurn adapter; define optional adapter invocation and provenance.
- Implement the production AuthorityVerifier adapter against Control Plane identity/snapshot authority and the evidence store.
- Align the versioned Evidence Envelope v1 with producers and Control Plane before implementing freshness scoring, coverage or hypotheses.
- Add and verify PostgreSQL tenant row-level security, or document an independently reviewed equivalent isolation proof.
- Freeze a generated/client-consumable contract only after these upstream owners agree on the identity and reference semantics.
