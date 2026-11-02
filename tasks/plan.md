# Agent Decision Implementation Plan

1. Freeze the language-neutral v0.1 protocol in `protocol/v0.1/` (JSON Schemas, manifest, and golden fixtures).
2. Implement Python HTTP plugin host with strict request/response validation and bounded execution.
3. Implement invocation ID + request-digest deduplication and completed-response replay; permit recomputation only after an expired worker lease and never expose privileged side effects.
4. Implement one bounded LangGraph adapter.
5. Add shared fixture conformance tests and a mock model; Python and TypeScript must consume the same fixtures.
6. Add token/latency/cost telemetry with bounded cardinality and no sensitive payloads.
7. Add TypeScript conformance harness after Python host passes.
8. Evaluate decision quality, prompt-injection resistance, cancellation, and proposal validity.

Exit gate: Go Runtime, Python host, and TypeScript adapter validate the same protocol fixtures; invocation ID reuse with a different digest is rejected; plugin cannot perform privileged side effects; invocation is bounded and cancellable.
