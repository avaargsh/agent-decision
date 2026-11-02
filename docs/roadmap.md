# Agent Decision Roadmap

## v0.1 — Deterministic Read-only SRE Decision Core

- [x] Versioned request and record types (`decision.v1`).
- [x] Trusted principal binding and tenant-scoped idempotency.
- [x] Mandatory authoritative snapshot verifier seam.
- [x] Strict JSON contract and fail-closed HTTP behavior.
- [x] Deterministic all-or-nothing read-only investigation plan.
- [x] Go module and repeatable CI workflow (`go test -race`, `go vet`).
- [x] Store contract and PostgreSQL implementation with atomic tenant-scoped idempotency.
- [x] PostgreSQL migration and integration tests for replay, conflict, tenant isolation, and concurrent inserts.
- [x] Tenant-, agent-, session-, and run-scoped Decision Ledger read API with bounded cursor pagination.
- [x] PostgreSQL role separation, backup/retention and restore runbook baseline documented (`docs/operations/postgres-runbook.md`).
- [ ] Configure deployment-specific roles/secrets, retention approval, and produce a successful isolated restore-rehearsal artifact.
- [x] OpenAPI 3.1 and JSON Schema compatibility artifacts published under `api/`; request/record schemas are checked against Go JSON contracts.
- [x] Document cross-repository identity, capability, evidence, and EngageGuard ownership boundaries.
- [ ] Resolve canonical Run ID wording with Agent Runtime and confirm the integration contract with upstream owners.

## v0.2 — Evidence-aware Investigation

- [x] Define a versioned, typed, tenant/Agent/Run/service-scoped Evidence Envelope v1 with observation windows, collection time, revocation state, and validation tests.
- [ ] Implement production AuthorityVerifier integration for tenant ownership, attestation, digest, expiry, and revocation.
- [ ] Evidence freshness, provenance, quality, and coverage policy (requires per-kind operational thresholds and source semantics).
- [ ] Hypothesis model with explicit supporting and contradicting evidence references.
- [ ] Investigation result ingestion and bounded follow-up decision steps.
- [ ] DecisionRecord schema evolution and replay compatibility tests.

## v0.3 — Risk-aware Candidate Planning

- [ ] Candidate action proposals separated from read-only investigation steps.
- [ ] Risk vector: impact, blast radius, probability, uncertainty, reversibility, and current SLO/Error Budget context.
- [ ] Abstention and escalation reasons for stale, conflicting, or insufficient evidence.
- [ ] Deterministic safety invariants; no authorization or execution in this repository.

## v0.4 — Evaluation and Calibration

- [ ] Human incident trajectories and curated Gold dataset.
- [ ] Decision quality, mitigation quality, execution outcome, and recovery outcome measured separately.
- [ ] Confidence calibration and risk regression suite.
- [ ] Evaluation artifact consumed by Control Plane release gates.

## v1.0 — Governed Autonomy Integration

- [ ] Scenario-scoped autonomy profiles.
- [ ] Control Plane policy and approval integration.
- [ ] Runtime execution receipt and post-condition evidence references.
- [ ] Production persistence, retention, tenant isolation, and disaster recovery verification.

## Release invariants

- A Decision never grants itself authority.
- A Decision never executes a tool or owns a Run.
- Missing or unverifiable authority fails closed.
- Evidence and capability references are versioned and content-addressed.
- Unknown execution outcomes are not automatically replannable.
- Every persisted decision is attributable to a trusted tenant and principal.


## Production SRE decision-loop gates

- [ ] Add a versioned OPA/Rego policy bundle for Kubernetes candidate manifests and run Conftest verification in CI. Conftest is a deterministic policy test gate, not the probabilistic risk model or actuation engine.
- [ ] Add candidate-action and explicit no-op contracts with impact, blast radius, reversibility, execution cost and uncertainty dimensions.
- [ ] Build incident outcome datasets with human-verified Gold labels before claiming calibrated probabilities.
- [ ] Publish calibration reports, uncertainty bounds, cohort/sample metadata and risk regression results as release artifacts.
- [ ] Implement expected-loss comparison against the no-op baseline with policy-owned thresholds and counterfactual evaluation.
- [ ] Integrate progressive authorization through Control Plane and EngageGuard; Runtime owns durable actuation, recovery, and post-condition receipts.
- [ ] Feed execution receipts, post-condition evidence and human-reviewed incident trajectories into continuous evaluation and recalibration.

These items are roadmap gates only. The current implementation remains a deterministic read-only planner and does not yet provide Kubernetes mutation proposals, probabilistic risk scores, expected-loss ranking, authorization, or execution.
