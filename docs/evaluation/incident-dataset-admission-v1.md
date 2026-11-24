# Real Incident Dataset Admission v1

## Status

This document defines the metadata and integrity contract for admitting authorized, human-adjudicated SRE incident trajectories into a future evaluation cohort. **No real incident records are included in this repository**, and this package does not claim that a Gold or Holdout benchmark has been collected.

The manifest schema is `sre.incident-dataset-manifest.v1`. Its Go implementation lives in `internal/evaluationdataset`.

## Admission contract

`ParseManifest(raw, now)`:

- Rejects empty or larger-than-1 MiB manifests.
- Rejects duplicate JSON keys, unknown fields, malformed JSON and trailing JSON values.
- Validates the schema version, dataset kind, authorization time window, de-identification references, case metadata and adjudication invariants.
- Returns the SHA-256 digest of the exact submitted manifest bytes.

Each manifest must identify:

- A dataset owner, source-owner grant reference, grant digest and bounded approval/expiry interval.
- A de-identification attestation reference, digest and completion time.
- An opaque incident reference, immutable evidence-bundle digest and observation window for each case.
- Exactly two distinct independent reviewers and their label digests.
- A final adjudicated label digest and adjudication timestamp.

If both reviewers agree, their label digests and the final label digest must match, and no third adjudicator may be present. If they disagree, the two independent label digests must differ and a distinct third adjudicator must be recorded.

## Integrity and split isolation

- `VerifyAuthorizationArtifacts` streams the grant and de-identification attestation bytes and checks their exact SHA-256 digests.
- `VerifyIndependentReviewArtifacts` streams both independent reviewer-label artifacts per case. `VerifyArtifacts` streams one evidence bundle and one final adjudicated-label artifact per case. Missing, extra, duplicate, oversized, nil or mismatched artifacts fail closed.
- Case IDs, incident references and evidence artifact digests must be unique across the entire manifest. A single incident or evidence bundle cannot appear in Development, Gold and Holdout under different case IDs.
- `ValidateSplitUse` allows training/tuning only from `DEVELOPMENT`; Gold and Holdout are evaluation-only. Every consumer must enforce this helper before exposing split artifacts.

The sample-count gate is deliberately separate from data admission:

| Split | Minimum for cohort-size readiness |
|---|---:|
| Development | 1 |
| Gold | 30 |
| Holdout | 20 |

A valid pilot manifest may be admitted below these counts, but `CohortSizeReady` remains false and reports deterministic blockers. Passing the count gate is not evidence of representativeness, label quality, model accuracy or production readiness.

## Trust boundary and remaining work

This package verifies metadata shape, timestamp bounds, cross-split isolation and exact artifact bytes. A digest proves byte integrity, **not** who issued a grant or whether a reviewer is qualified. The package does not cryptographically verify source-owner or reviewer signatures, query a live revocation registry, establish that the de-identification process was effective, or enforce holdout access control outside callers that use `ValidateSplitUse`.

Those checks remain dependent on the production AuthorityVerifier/source registry and independent reviewer identity governance tracked by Issue #5 and the v0.2 freshness/provenance roadmap gates. Real incident collection still requires explicit source-owner permission, secure storage outside Git, de-identification review, independent SRE adjudication, disagreement reporting and a frozen holdout custody process.

No raw incident artifacts, personal data, fabricated incident measurements, benchmark scores, public API, DecisionRecord schema, database migration, authorization or execution behavior are added by this change.
