# Hypothesis Evaluation Report v2

## Status and scope

The current v0.2 evaluation harness is a deterministic, offline contract-fixture runner. It is **not** a human-reviewed incident benchmark and does not claim production accuracy, causality, probability calibration, or operational effectiveness.

The `GOLD_FIXTURE` and `HOLDOUT_FIXTURE` labels separate expected-answer fixtures for regression purposes only. They do not mean that incident trajectories have been collected, independently adjudicated, or approved as a real Gold/Holdout dataset. The report marks every output as `SYNTHETIC_CONTRACT_FIXTURES_ONLY` to prevent that ambiguity.

The current fixtures use typed categorical assertions such as `SYMPTOM_INCREASED` and `DEPLOYMENT_PRECEDES_SYMPTOM`. They contain no fabricated latency values, error rates, deployment timestamps, confidence scores, or measured incident outcomes. A signed assertion proves source attribution and byte integrity only; it does not prove the fact is true or causal.

## Report metrics

The internal report schema is `sre.hypothesis-evaluation-report.v2`.

- `scenario_count`, `passed_count`, and `failed_count` count labelled fixture cases. A case passes only when its expected status/error and its independently labelled exact-reference binding expectation both match.
- `scenario_pass_rate_basis_points` is `passed_count / scenario_count` scaled by 10,000 using integer arithmetic.
- `accepted_count` and `rejected_count` distinguish evaluations that returned a hypothesis result from fail-closed input/proof rejection.
- `abstention_count` counts accepted `CONFLICTING`, `INSUFFICIENT`, and `UNTESTED` results. `abstention_rate_basis_points` uses accepted cases as its denominator; `abstention_rate_measured` is false when there are no accepted cases.
- Each accepted case carries a deterministic `abstention_reasons` list. The taxonomy distinguishes missing symptom evidence, missing deployment evidence, conflicting symptom observations, conflicting deployment observations, and evidence that is present but irrelevant. Supported and contradicted results carry an explicit empty list.
- `abstention_reason_accuracy_basis_points` compares the exact ordered reason list with the fixture's expected reason labels across accepted cases. Its denominator is `abstention_reason_case_count`; rejected proof/input cases are excluded because no hypothesis result exists.
- `evidence_binding_case_count` counts cases containing at least one signed publication. `evidence_binding_accuracy_basis_points` measures whether the case-level expectation that **all** publication references are exactly bound to the request is correct. Its denominator is cases, not individual evidence references. It is deliberately separate from scenario pass rate and from signature verification.
- `status_counts` and `split_summaries` use fixed ordering. Case rows are sorted by stable case ID. Rates use integer basis points to keep output deterministic and avoid false precision.

The report contains no wall-clock generation timestamp and no floating-point confidence values, so the same labelled inputs produce byte-stable JSON after serialization.

## Fixture coverage

The current tests cover:

| Fixture | Expected result |
|---|---|
| Supporting symptom and preceding deployment | `SUPPORTED` |
| Missing deployment observation | `INSUFFICIENT` |
| Symptom with no deployment in the investigation window | `CONTRADICTED` |
| Unrelated evidence only | `UNTESTED` |
| Conflicting symptom observations | `CONFLICTING` |
| No observations | `UNTESTED` with missing symptom and deployment reasons |
| Unrelated evidence only | `UNTESTED` with `NO_RELEVANT_EVIDENCE` |
| Conflicting symptom or deployment observations | `CONFLICTING` with a dimension-specific conflict reason |
| Unknown request evidence reference | fail closed with `ErrInvalidRequest` |
| Wrong signer on a request-bound reference | fail closed with `ErrAuthorityRejected` |

Input order permutation must not change the report. An intentionally incorrect binding label must reduce binding accuracy and fail the affected scenario.

## Remaining gates before a real benchmark

1. Collect incident artifacts from an explicitly authorized environment with tenant/run/service scope and source-owner permission.
2. Have qualified SRE reviewers independently label incident symptom, change window, contradiction, missing evidence, and outcome; record adjudication provenance and disagreement.
3. Freeze separate development and holdout manifests with immutable content digests and no training/holdout leakage.
4. Bind source-owned typed fact schemas and freshness/revocation proof to the incident's common observation window.
5. Publish sample counts, cohort coverage, missingness, disagreement, abstention, evidence-binding results, and per-class errors. Do not publish a single headline accuracy without denominators.
6. Keep calibration, mitigation quality, execution outcome, recovery outcome, and production release gates separate from this read-only hypothesis report.

The reason taxonomy is explanatory metadata, not a causal conclusion, confidence score, or instruction to execute an action. It does not change the live decision path.

No live decision, authorization, permit, tool execution, ledger mutation, or production source-registry integration is added by this evaluation harness.
