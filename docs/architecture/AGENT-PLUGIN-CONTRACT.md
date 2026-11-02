# Agent Plugin Protocol v0.1

Transport: HTTP JSON initially; gRPC only after measured streaming or throughput needs. OpenAPI/JSON Schema is canonical.

Request: protocol_version, invocation_id, agent_id, bundle_digest, release_id, session_id, run_id, turn_id, context_projection, allowed_capabilities, deadline, trace_context.

Response union:
- FinalResponse { text, structured_output?, evidence_refs[] }
- ActionProposal { proposal_id, capability_id, capability_version, arguments, target_resource_ref, rationale_ref }
- NeedsInput { prompt, missing_fields[] }
- DecisionError { code, retryable, safe_message }

No response can contain an executable bearer credential or claim that an action was already authorized. Proposals are untrusted input and must be normalized and authorized by EngageGuard.

Limits: request/response bytes, wall-clock deadline, max output tokens, max proposals, concurrency and per-tenant rate. Plugin must propagate cancellation. Unknown schema or capability version fails closed.
