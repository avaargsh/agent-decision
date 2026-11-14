# Evidence Envelope v1

**Status:** Decision-side contract baseline; producer and Control Plane alignment pending.

## Purpose

An evidence reference must be a typed, versioned, scoped reference to immutable evidence. The envelope metadata is untrusted until the authoritative verifier binds it to the trusted tenant, canonical Agent/Run identity, source attestation, content digest and revocation registry.

## Fields

- `ref`: immutable evidence object reference.
- `evidence_type`: one of `metrics`, `logs`, `traces`, `change`, `slo`.
- `schema_version`: semantic version for this envelope/evidence kind.
- `tenant_id`, `agent_id`, `run_id`: owner and canonical workflow scope.
- `service`, `resource_ref`: service and concrete resource scope.
- `source_id`, `source`, `source_version`: stable producer identity and provenance.
- `sha256`, `attestation_ref`, `trust_level`: immutable content and trust metadata.
- `observed_from`, `observed_to`: the covered observation interval.
- `observed_at`: evidence's source-observation timestamp.
- `collected_at`: when the evidence envelope was collected/assembled.
- `expires_at`: validity end; must be after collection time.
- `revocation_state`: only `active` is accepted by the v0.2 intake baseline.

## Validation invariants

1. Agent, Run and service scope match the DecisionRequest.
2. Observation interval is ordered; collection time is not before its end.
3. Envelope is versioned and uses a supported evidence kind.
4. Revoked or expired envelopes are rejected.
5. Tenant ID is only a claim in the payload. The AuthorityVerifier must compare it with the trusted Principal tenant and authoritative evidence owner.
6. The AuthorityVerifier independently verifies digest, attestation, source identity/version, expiry and revocation. Local syntactic validation alone never grants trust.

## Deliberate non-goals

The envelope does not yet assign freshness scores, evidence weights, confidence, root-cause conclusions or cross-source conflict resolution. Those policies need operationally grounded thresholds per evidence kind and SRE objective, with explainable evaluation artifacts.
