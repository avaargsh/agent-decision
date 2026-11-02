# Legacy Decision Lab → Agent Decision migration ledger

**Status:** implementation in Draft PR #11.  
**Date:** 2026-11-02  
**New authority:** `avaargsh/agent-decision` (Go Decision Core).  
**Retired repository:** `musuntana/agent-decision-lab` (not an active release target).

The retired repository is not currently readable through the linked GitHub connection. This is a **behavioral migration** based on historical user-provided project work and confirmed new-repository source, not a byte-for-byte code import. Reviewers should not infer that old live-staging records, signer identities or approvals have been transferred.

## Reusable behavior and ownership

| Previous capability | New owner | Migration status / boundary |
| --- | --- | --- |
| Bounded deterministic SRE investigation plans and abstention when evidence is missing | Agent Decision Go Core | **Already implemented in Draft #8** as `SREReadOnlyStrategy`, with evidence-kind/capability matching, version-pinned read-only steps, and immutable `DecisionRecord`. Do not clone an old planner. |
| Tenant-scoped decision idempotency and immutable history | Agent Decision Go Core | **Draft #8** owns `(tenant_id, invocation_id)` DecisionRecord and PostgreSQL. **Draft #10** adds transactional Decision outbox and lease dispatcher on that schema. Do not port the old SQLite incident ledger wholesale. |
| Raw SLO samples SHA-256 pin, exact observation window, monotonic timestamps, error-ratio and sample-gap policy replay | Agent Decision evidence-quality helper | **Draft #11:** `ReplaySLOHealth` is a pure-Go, bounded, deterministic evaluator; its inputs are untrusted claims until an authority adapter authenticates source and policy. No API/side effects. |
| Signed 5-phase SRE receipts, approval, operation/attempt evidence and ACK-loss recovery | EngageGuard + Agent Runtime / Temporal | **Do not migrate ownership into Decision.** EngageGuard owns protected Action/Approval/Permit/OperationJournal; Runtime owns Run/Attempt and durable retry/reconciliation. Decision consumes independently authenticated evidence references. |
| ACP signed export, Agent/Session/Run linkage, release and capability catalog | Agent Control Panel and Runtime | ACP owns Agent, Session, RunIntent and publication; Runtime issues Run identity under proposed v0.3 map. The cross-repository authority map is **pending ratification** (Decision Issue #9, ACP PR #4). |
| Python/TypeScript Agent Framework reasoning and bounded tool proposals | Managed plugin adapters invoked through Runtime | Retain separately versioned `DecisionTurn` protocol. It is **not wire-compatible** with the Go `decision.v1` core API. Plugins do not persist the Go DecisionRecord, hold Permit, or perform protected effects. |
| IRM incident outcomes, reviewer labels, Bronze/Silver/Gold feedback and training | Offline evaluation / SRE domain ingestion | Future feature with source provenance and label governance. No production claims or automatic Gold classification. |
| GPU/provider allocation and scheduling | Compute Control Panel / Kubernetes / Kueue | Refer only to allocation/evidence identities, never move provider scheduler logic into Decision. |

## Go SLO replay contract in PR #11

`ReplaySLOHealth(SLOReplayInput)` accepts two observer-window metadata **claims** and two raw sample byte buffers, plus threshold policy raw bytes and an independently supplied expected SHA-256. Its purpose is to reject inconsistent *claimed* health and provide inspectable per-phase maxima.

The helper must fail closed when any of the following occurs:

- Missing/misordered phases, invalid or inconsistent source/query/window identifiers, duplicate JSON fields, unknown schema fields, unbounded payloads, malformed/nonfinite numbers, malformed digest or wrong SHA-256.
- Empty/insufficient samples, count mismatch, missing first/last boundary samples, timestamps outside window, non-monotonic sequence, excessive sample gap or error ratio above the threshold.
- Wrong metric/aggregation, policy source/query mismatch, too permissive/unbounded invalid threshold parameters.
- Caller mutation of input buffers between verification and arithmetic: the helper takes its own byte snapshots.

The report always sets `source_independently_authenticated=false`, `policy_independently_authenticated=false`, `external_execution_verified=false`, `staging_accepted=false`, and `authorized=false`. **Digest consistency is not source authentication.** Operator-pinned SHA-256 cannot establish independent custody when the same operator supplies both policy and digest.

This Go helper deliberately does **not**:

- validate Ed25519 receipts or custody/revocation (owned by an independently sourced AuthorityVerifier/evidence adapter);
- create or move Run/Task/Attempt, perform an agent loop, approve or execute actions;
- declare live Staging acceptance on synthetic fixtures;
- fetch actual telemetry or auto-promote an SRE incident.

## Cross-repository integration gates

1. **ACP + Runtime:** ratify RunIntent→Run ownership and stable invocation identity. Runtime must persist `invocation_id` before the call and reuse the exact value/digest on retry.
2. **Evidence authority:** provide independent adapter with trusted source keys, expiry/revocation lookup, source/query identity and policy registry. Map authenticated raw SLO samples to `EvidenceRef` only after authority verification.
3. **Agent Decision:** keep `ReplaySLOHealth` a pure consistency helper behind that adapter; add authority-provider contract tests before wiring to production `VerifyDecisionInputs`.
4. **EngageGuard:** consume only a versioned proposal from Runtime/ACP and revalidate any protected side effect with ActionHash/Approval/Permit; preserve UNKNOWN and reconciliation ownership.
5. **Outbox/Runtime:** merge #8 first, reconcile #10 (publisher/consumer Inbox and version handling), then integrate the decision event without duplicating Temporal retries.
6. **Acceptance:** test positive and negative cross-language contract vectors, separate key/policy trust roots, PostgreSQL durability, real execution receipts, restart/replay and authorization refusal. A synthetic Go test is an engineering regression, not operational attestation.

## Delivery policy

- Keep `main` intact until foundational #8 is reviewed and merged.
- Review PR #11 as an **independent evidence-quality increment stacked on #8**, parallel to #10; reconcile both after #8 lands.
- Do not merge legacy state machine, signed approval flow, operator-supplied credentials or provider-specific actions into the new Core.
- Any old implementation must pass a source/behavior parity check before being represented as migrated. Unavailable legacy source is explicitly **unverified**.
