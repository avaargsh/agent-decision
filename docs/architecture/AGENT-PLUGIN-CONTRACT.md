# Agent Plugin Protocol v0.1

Status: Proposed contract baseline. The schemas and fixtures under `protocol/v0.1/` are normative.

## Transport and execution

- HTTP JSON is the v0.1 transport. Do not add gRPC until measured streaming or throughput requirements justify it.
- One request is one bounded Decision Turn. The plugin returns a decision; it does not own Run, Task, Session, approval, Permit, or external operation lifecycle.
- The plugin returns exactly one of `final_response`, `action_proposals`, or `needs_input`.
- No plugin response can authorize an action, claim that an action was executed, or contain an executable credential.

## Request contract

The normative request schema is `protocol/v0.1/schemas/decision-turn-request.schema.json`.

- `invocation_id` is assigned by Runtime and remains unchanged across retries of the same logical invocation.
- `run_id`, `turn_id`, `session_id`, `agent_id`, `release_id`, and `bundle_digest` identify the immutable decision context.
- `user_input_ref` and `context_projection_ref` are immutable, content-addressed references. They include a digest, media type, and schema version. The plugin reads them through an authenticated, tenant-scoped, read-only context interface; it does not query Runtime storage directly.
- `allowed_capabilities` is an allow-list of capability ID, exact version, and argument-schema digest. It is a proposal boundary, not an authorization grant.
- `deadline` is an absolute UTC RFC 3339 timestamp. Runtime does not extend it when retrying an Activity.
- `trace_context` follows W3C Trace Context. It is diagnostic only and must not carry credentials or sensitive baggage.

Tenant and principal identity are derived from authenticated workload identity and trusted request context. They are not accepted as authoritative body fields. The plugin must not infer or elevate identity from prompt content.

## Response contract

The normative response schema is `protocol/v0.1/schemas/decision-turn-response.schema.json`.

| Result kind | Required content | Runtime behavior |
|---|---|---|
| `final_response` | text, evidence_refs; optional structured_output | Complete the Decision Turn |
| `action_proposals` | 1–16 ordered typed proposals | Validate the entire response, then submit proposals sequentially to EngageGuard |
| `needs_input` | prompt and non-empty missing_fields | Pause for user input; do not execute actions |

Each ActionProposal contains a unique-within-invocation `proposal_id`, capability ID/version, typed arguments, target resource reference, and rationale reference. Runtime validates the proposal against the exact capability descriptor and its argument schema digest. If any proposal is malformed or outside the request allow-list, reject the entire response before submitting any proposal.

After whole-response validation, proposals are processed in order. A Guard denial or UNKNOWN operation stops later proposals. Earlier completed operations are not rolled back; v0.1 does not promise atomic multi-action transactions.

The plugin must not return `tenant_id`, trusted `principal`, `permit_id`, Permit token, provider secret, executor credential, or an execution receipt as an authoritative field. Unknown response fields are rejected.

## Invocation idempotency

The request digest is SHA-256 over RFC 8785 JCS canonical JSON after removing only `trace_context`. All other request fields, including deadline and immutable context references, participate in the digest.

For the same authenticated tenant and `invocation_id`:

1. Same request digest and completed invocation: replay the stored response.
2. Same request digest and running invocation: return `409 INVOCATION_IN_PROGRESS` with optional `retry_after_ms`.
3. Different request digest: return `409 INVOCATION_ID_REUSED`.
4. A worker crash before a response is durably committed may cause inference to run again after its lease expires. This may duplicate model-provider cost, but cannot duplicate protected side effects because the plugin has no privileged executor access.

The HTTP worker remains stateless, but the service MUST persist invocation digest, lease/state, and the completed response before returning success. This invocation-result store is not canonical Run/Session state and is not a framework checkpoint.

The initial store is owned by Agent Decision (separate from Runtime PostgreSQL) and has a unique key on `(authenticated_tenant_id, invocation_id)`. Minimum record fields are `request_digest`, `state` (`RUNNING` / `COMPLETED`), `lease_token`, `lease_expires_at`, `response_json`, `created_at`, and `completed_at`. Claim/reclaim and completion are compare-and-set transactions. A worker may commit a response only while holding the current lease token. Completed response bytes are committed before HTTP success is returned, and retention must exceed the maximum Temporal retry/re-delivery horizon. A transient provider failure releases the lease for a bounded retry; an expired RUNNING lease may be reclaimed with a new fencing token.

## Error contract

The normative error schema is `protocol/v0.1/schemas/decision-turn-error.schema.json`. Do not expose a `retryable` boolean; Runtime owns retry policy.

| HTTP | Error codes | Runtime handling |
|---|---|---|
| 400 | INVALID_REQUEST | Do not retry |
| 401 / 403 | UNAUTHENTICATED / FORBIDDEN | Do not retry; security failure |
| 409 | INVOCATION_ID_REUSED | Do not retry; contract violation |
| 409 | INVOCATION_IN_PROGRESS | Bounded retry using retry_after_ms |
| 413 | PAYLOAD_TOO_LARGE | Do not retry |
| 422 | UNSUPPORTED_PROTOCOL_VERSION, UNSUPPORTED_CAPABILITY_VERSION, OUTPUT_VALIDATION_FAILED | Fail closed; do not retry |
| 429 | RATE_LIMITED | Bounded retry; honor retry_after_ms |
| 500 | INTERNAL_ERROR | Do not retry by default; alert and fail the invocation |
| 503 | DEPENDENCY_UNAVAILABLE | Bounded retry with backoff |
| 504 | DEADLINE_EXCEEDED | Stop retrying |

Cancellation is propagated from Runtime to the plugin. A cancelled request must stop model/tool orchestration as soon as possible. Cancellation does not imply that a model-provider request was never billed; the plugin has no protected side effects to reconcile.

## Limits and security

- v0.1 schema caps proposals at 16 and bounds IDs, references, text, trace state, and object sizes. Deployments additionally configure request/response byte limits, token budgets, wall-clock deadlines, concurrency, and per-tenant rate limits.
- Unknown protocol, capability, argument-schema, or context schema versions fail closed.
- The plugin receives only projected context and capability descriptors. No provider secrets, Permit tokens, direct executor credentials, or unmediated protected-tool access.
- ActionProposal is untrusted input. Runtime validates the protocol and maps the proposal into an ActionRequest; EngageGuard performs authoritative canonicalization, computes ActionHash, and applies fresh authorization against the final action and target.
- Framework metadata is bounded diagnostic data, never authoritative platform state.

## Compatibility

- JSON Schema Draft 2020-12 is canonical.
- v0.1 is frozen and closed-world: unknown fields are rejected. Any schema change, including an additive field, requires a new protocol version and updated shared fixtures.
- Python and TypeScript adapters must pass the exact same fixtures. Runtime Go validation must pass them as well before integration is accepted.
