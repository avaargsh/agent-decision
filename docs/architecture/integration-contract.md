# Cross-repository Decision Integration Contract

**Status:** integration design baseline; upstream alignment review remains open  
**Applies to:** Agent Decision v0.1 and the Open Agent Infrastructure repositories

## 1. Authority map

| Concern | Authority | Agent Decision interaction |
|---|---|---|
| Tenant, canonical Agent / Session / Run IDs, desired state and lifecycle coordination | Agent Control Plane | Accept IDs as references; never mint or mutate them |
| Run execution, workflow history, task/step semantics, retries, waits and checkpoints | Agent Runtime / Temporal | Receive an authenticated Runtime request; return a proposal or abstention |
| Capability catalog, immutable capability contracts and policy bindings | Agent Control Plane | Consume version-pinned read-only capability references |
| Action normalization, authorization decision, approval, one-time permit, operation journal and trusted execution guard | EngageGuard | Never issue permits or claim an action is authorized |
| Provider resource identity and side effects | Sandbox / Compute providers | Consume no provider credentials or executor configuration |
| Decision strategy, evidence evaluation and immutable DecisionRecord | Agent Decision | Own this decision record only |

The Agent Control Plane architecture baseline dated 2026-11-02 explicitly assigns canonical Agent, Session and Run identity to the Control Plane, while Runtime owns execution-plan semantics, workflow history and task/step scheduling. This is the contract Agent Decision follows.

### Run identity wording conflict

The current `avaargsh/agent-runtime` README says Runtime “owns Run identity”. The Control Plane baseline says it owns canonical Session/Run identity and Runtime owns execution semantics. Until the Runtime repository clarifies that wording, treat the Control Plane's Run ID as canonical and distinguish it from Temporal Workflow IDs, Activity IDs, attempt IDs and runtime-local execution identifiers. This mismatch is an upstream integration gate, not permission for Decision to create another Run ID.

## 2. Request identity and trust boundary

`DecisionRequest.identity` carries `agent_id`, `session_id` and `run_id`. These values are references to Control Plane-owned identities; they are not caller authentication.

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

The v1 `EvidenceRef` currently carries only a reference, source/version, content digest, attestation reference, trust label, observation time and expiry. It contains no evidence payload.

This is sufficient for identity/provenance verification, but it is not yet sufficient for a robust Evidence Quality or Hypothesis Engine. Before adding freshness scores or coverage rules, define and version the evidence envelope with at least:

- evidence kind/modality and schema version;
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

1. Control Plane creates canonical Agent, Session and Run identities and publishes immutable context/capability snapshots.
2. Runtime starts or resumes the durable workflow and obtains the authenticated Runtime principal.
3. Runtime calls Agent Decision with the canonical identity references, snapshot references, capability references and evidence references.
4. Agent Decision validates the request, binds Agent/Session to the Principal, and asks the authoritative verifier to verify Run ownership and snapshot/evidence authority.
5. Agent Decision persists a deterministic DecisionRecord or explicit abstention and returns it to Runtime.
6. Runtime interprets the proposal as workflow input. Any privileged or mutating action remains subject to Control Plane policy and EngageGuard authorization/execution.
7. Runtime and Control Plane attach execution receipts, observations and outcome evidence to the same canonical Run.

## 7. Open integration gates

- Resolve the Runtime README's “owns Run identity” wording against the Control Plane canonical identity contract.
- Implement the production AuthorityVerifier adapter against Control Plane identity/snapshot authority and the evidence store.
- Define the versioned evidence envelope before implementing freshness scoring, coverage or hypotheses.
- Add and verify PostgreSQL tenant row-level security, or document an independently reviewed equivalent isolation proof.
- Freeze a generated/client-consumable contract only after these upstream owners agree on the identity and reference semantics.
