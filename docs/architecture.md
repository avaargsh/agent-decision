# Agent Decision Architecture

**Status:** v0.1 baseline  
**Scope:** deterministic, read-only SRE decision planning  
**Implementation:** Go

## 1. Responsibility

Agent Decision is the decision-intelligence component of Open Agent Infrastructure. It accepts a caller-authenticated decision request, verifies externally owned context and capability snapshots, and produces an immutable, deterministic decision record containing a bounded read-only investigation plan or an explicit abstention.

It does not own:

- Agent, Session, or Run lifecycle;
- durable workflow orchestration or retries;
- identity issuance or tenant membership;
- capability publication or policy-binding authority;
- action authorization decisions, approvals, permits or trusted execution;
- tool credentials or privileged execution;
- incident lifecycle or SRE alert routing.

## 2. System boundary

```text
SRE domain workflow (agentic-aiops)
          |
          | DecisionRequest + immutable references
          v
Agent Decision
  - request validation
  - trusted principal binding
  - authoritative snapshot verification
  - deterministic read-only planning
  - idempotent DecisionRecord
          |
          | DecisionRecord / read-only PlanCandidate
          v
Agent Control Plane
  - canonical Agent / Session / Run identity
  - desired state, capability catalog and policy bindings
          |
          v
Agent Runtime
  - durable Run execution and workflow history
  - task/step scheduling, retry and checkpoint semantics
          |
          v
EngageGuard
  - action authorization, risk and approval
  - one-time permits, operation journal and trusted executor
          |
          v
Sandbox / Compute providers
```

Agent Decision may describe capability references but never receives capability endpoints, credentials, or executor configuration. A `PlanStep` is a proposal for read-only investigation, not an execution permit.

## 3. Request trust model

The HTTP transport obtains `Principal` from a trusted resolver (for example, an authenticated OIDC or mTLS gateway). Tenant identity is never accepted from the request body. The principal is bound to `agent_id` and `session_id` in the request. The current contract restricts the caller identity to `agent-runtime`.

The request carries references to immutable Context and Capability snapshots plus Evidence references. Their fields are untrusted claims until `AuthorityVerifier.VerifyDecisionInputs` independently verifies ownership, tenant/run binding, content digest, attestation, source version, expiry, and revocation against the authoritative owner.

Missing principal, missing verifier, failed verification, invalid request, or identity mismatch fails closed.

## 4. Deterministic v0.1 planner

The first strategy is `sre-readonly-v1` and supports `sre_incident_triage` for `latency`, `errors`, and `saturation` signals. It requires the following tenant-scoped, version-pinned, safe, read-only capabilities:

1. `sre.metrics.read` → `OBSERVE_METRICS`
2. `sre.logs.read` → `INSPECT_LOGS`
3. `sre.changes.read` → `CORRELATE_CHANGE`

The planner emits all three steps or no steps. Missing evidence yields `ABSTAINED / INSUFFICIENT_EVIDENCE`; a missing required capability yields `ABSTAINED / MISSING_REQUIRED_CAPABILITY`. It does not infer a root cause, rank remediation actions, or perform mutations in v0.1.

## 5. Identity, idempotency, and records

- Decision identity is deterministic for `(tenant_id, idempotency_key)`.
- The request fingerprint covers the authenticated principal and complete request.
- Replaying the same key and fingerprint returns the existing record.
- Reusing a key with a different fingerprint returns an idempotency conflict.
- `MemoryStore` is process-local and suitable only for tests and development. `PostgresStore` uses `INSERT ... ON CONFLICT DO NOTHING` followed by a read of the winning row; the database primary key `(tenant_id, idempotency_key)` is the cross-process idempotency authority. A changed fingerprint returns an idempotency conflict. The migration is `migrations/0001_create_decision_records.sql`. Production must use a restricted application database role and a separate migration owner; the application should not receive schema-alteration privileges.
- Decision records retain strategy/model/prompt/catalog versions, snapshot references, evidence references, reason codes, and a hash of the read-only plan.

## 6. Failure semantics

| Condition | Result |
|---|---|
| No trusted principal | 401 |
| Principal/request identity mismatch | 403 |
| Authority verifier unavailable | 503 |
| Snapshot verification rejected | 403 |
| Invalid or unknown JSON fields | 400 |
| Idempotency key reused with changed input | 409 |
| No evidence / required capability | Persisted `ABSTAINED` record |

`/healthz` is intentionally unauthenticated and returns 204. The development binary binds to loopback and fails closed for decision calls until authentication and authority verification are configured.

## 7. Persistence contract

`Store.SaveOrGet` is the persistence boundary. The PostgreSQL implementation stores the complete versioned DecisionRecord as JSONB and indexes tenant/time and tenant/run access paths. The relational columns hold the idempotency and identity keys required for atomic uniqueness. The JSON record is the immutable decision snapshot; updates are not part of the application API. Production database permissions and backup/retention policy must preserve this append-only usage model.

The PostgreSQL integration suite applies the real migration and verifies first insert, exact replay, changed-input conflict, tenant isolation, and concurrent same-key insertion. CI provisions PostgreSQL 16 and runs the suite with the Go race detector.

## 8. Upstream integration contract

The cross-repository ownership map, identity binding rules, evidence requirements and open integration gates are recorded in `docs/architecture/integration-contract.md`. In summary, the proposed (not yet ratified) v0.3 map assigns Agent/Session/RunIntent to Control Plane and Run/RunAttempt/RunIntent-to-Run mapping to Runtime. Decision consumes a Runtime-issued Run ID and verifies it through the Runtime authority adapter; it never creates or advances Runs. EngageGuard owns action authorization and trusted execution; Decision only returns proposals and abstentions. See the cross-repository integration contract for the open owner sign-off gate.

## 9. API compatibility artifacts

- `api/openapi.yaml` is the OpenAPI 3.1 description for `POST /v1/decisions`, `GET /v1/decisions/{decision_id}`, `GET /v1/runs/{run_id}/decisions`, and `GET /healthz`.
- `api/schemas/decision-request.schema.json` defines the strict `DecisionRequest` v1 shape.
- `api/schemas/decision-record.schema.json` defines the immutable `DecisionRecord` v1 shape.
- `api/schemas/decision-page.schema.json` defines the bounded cursor-paginated ledger page.
- `api/schemas/problem.schema.json` defines the public error envelope.
- The API remains development-only until trusted principal resolution and authoritative snapshot verification are wired to production adapters.

## 10. Next architecture increments

The following are deliberately outside the v0.1 implementation and require separate contracts and tests:

1. Decision context freshness and evidence quality policy (beyond signature/ownership validation).
2. Hypothesis and evidence correlation model.
3. Candidate remediation proposals and risk vectors (impact, blast radius, uncertainty, reversibility, current SLO/Error Budget state).
4. Confidence calibration backed by labeled incident trajectories; model confidence must not be treated as a probability without calibration.
5. Decision Ledger durability, append-only history, and replay.
6. Evaluation datasets, benchmark, calibration reports, and release gates.
7. Scenario-scoped autonomy levels and integration with Control Plane authorization.
8. Ledger export, retention and archival evidence for long-running audit requirements.

These increments must preserve the boundary: Decision proposes and explains; Control Plane owns Agent/Session/RunIntent identities and policy bindings; Runtime creates and owns Run identity and durable execution semantics; EngageGuard authorizes actions and trusted execution.


## 11. Production SRE decision loop

The production target is an evidence-backed, risk-aware decision loop. The current v0.1 implementation is only the deterministic, read-only proposal core; the following stages are architecture direction, not shipped capabilities.

### 11.1 Responsibility mapping

| Reference capability | Responsibility | Agent Decision integration boundary |
|---|---|---|
| Google AI Operator | Parallel investigation, hypothesis formation, mitigation proposal, post-action re-investigation | Decision supplies typed evidence, bounded hypotheses and candidate proposals; Runtime owns the durable agent loop |
| Google Actus / Actuation Agent | Discovery, concrete action planning, deterministic preflight checks, progressive authorization, long-running actuation, emergency stop | EngageGuard owns authorization/permit/trusted execution; Agent Runtime owns durable execution and recovery |
| Google IRM Analyzer | Reconstruct human incident trajectories, capture operational memory, curate Bronze/Silver/Gold evaluation data | Separate evidence/evaluation pipeline consumes Decision records and Runtime receipts; it does not become a runtime dependency of the decision core |
| Conftest + OPA/Rego | Deterministic policy-as-code checks over structured configuration, including rendered Kubernetes YAML | Preflight policy adapter validates candidate manifests and returns structured violations; it does not estimate probabilistic risk or execute changes |

Conftest is a policy-testing utility built on OPA/Rego for structured configuration. It supports Kubernetes YAML and other structured formats. A first versioned Deployment guardrail bundle now lives under `policy/kubernetes/` and is exercised by CI against compliant, unsafe-container and unsafe-init-container fixtures. The rules cover regular and init containers. It is currently a standalone preflight policy artifact; the Go Decision API does not yet invoke it. Probability calibration, expected-loss comparison, authorization, actuation and post-condition verification must be implemented by their respective components, not attributed to Conftest. The Google reference is [AI in SRE: How Google is Engineering the Future of Reliable Operations](https://sre.google/resources/practices-and-processes/ai-engineering-reliable-operations/). See also [Conftest documentation](https://github.com/open-policy-agent/conftest) and [Conftest policy testing](https://www.conftest.dev/).

### 11.2 Target decision pipeline

```text
Alert / SLO / change / topology / incident history
                    |
                    v
       Evidence collection + provenance
                    |
                    v
    Investigation / hypotheses / verification
                    |
                    v
  Candidate actions + explicit no-op alternative
                    |
          +---------+----------+
          |                    |
          v                    v
 Deterministic constraints   Calibrated risk model
 (OPA/Rego/Conftest)         P(outcome | evidence, action)
          |                    |
          +---------+----------+
                    v
       Expected-loss evaluation
                    |
                    v
     Proposal + explanation + confidence
                    |
                    v
 Control Plane policy / EngageGuard authorization
                    |
                    v
 Agent Runtime staged execution and recovery
                    |
                    v
 Post-condition checks / rollback / stop
                    |
                    v
 Runtime receipts + outcome evidence + human labels
                    |
                    v
 IRM-style trajectory store / eval / recalibration
```

### 11.3 Expected-loss and calibration contract

For a candidate action (a), compare its expected loss with the explicit no-op/continue-observing alternative:

[
EL(a \mid E)=\sum_{s \in S}P(s\mid E,a)\cdot Impact(s,a)
+ ExecutionCost(a)+ReversibilityPenalty(a)
]

An action is eligible for proposal only when its expected loss is lower than the no-op baseline by a policy-defined margin and its confidence, evidence freshness, blast radius and reversibility constraints are satisfied. A low model score alone never grants authority.

The probability term must come from a calibrated model measured against incident outcomes and human-verified labels. Record calibration version, training/evaluation window, cohort, sample count, reliability metrics and uncertainty bounds. Keep model confidence separate from probability until calibration evidence exists. Use stratified human review to promote programmatic labels into a trusted Gold set; avoid training and evaluating on leakage-correlated incident trajectories.

### 11.4 Progressive authorization and feedback

- L0/L1: monitor and investigate; Decision may emit read-only findings and verification plans.
- L2: propose or stage a bounded mitigation; human approval is mandatory before actuation.
- L3: allow autonomous actuation only for explicitly allow-listed scenarios with statistically supported precision, bounded blast radius, deterministic preflight checks and a working stop/rollback path.
- L4: multi-step autonomous resolution requires evidence of end-to-end recovery, not merely a successful API call.

Decision remains proposal-only at every level. Control Plane owns autonomy policy; EngageGuard verifies authorization and issues/consumes one-time permits; Runtime owns durable execution, retries, operation state and recovery. A post-action decision must consume a Runtime receipt and fresh post-condition evidence. Unknown execution outcomes, Guard denial and incomplete post-condition checks must not be converted into automatic retries.

### 11.5 Delivery sequence and exit criteria

1. **Evidence/hypothesis slice:** producer-backed envelope semantics, freshness/coverage policy, contradictory evidence representation, provenance verification and investigation outcome ingestion.
2. **Deterministic policy slice:** versioned OPA/Rego bundle, Kubernetes manifest fixtures, Conftest verification in CI, policy decision artifact and fail-closed behavior on evaluation errors.
3. **Risk slice:** candidate action contract, no-op baseline, calibrated probability model, uncertainty bounds and risk regression dataset.
4. **Expected-loss slice:** explicit loss taxonomy, unit/scale ownership, counterfactual evaluation and policy thresholds; reject uncalibrated probabilities.
5. **Governed actuation slice:** staged approvals and autonomy profiles through Control Plane/EngageGuard/Runtime; no direct executor in this repository.
6. **Feedback/evaluation slice:** execution receipts, post-condition evidence, human trajectory capture, Gold-label workflow, offline eval and release gates.

No probabilistic risk or expected-loss behavior is considered production-ready until the evaluation dataset, calibration report, reproducible thresholds and incident-level regression evidence are checked into the release artifacts.
