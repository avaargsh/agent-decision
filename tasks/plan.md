# Agent Decision Implementation Plan

1. Freeze language-neutral plugin contract and JSON Schema.
2. Implement Python HTTP plugin host and strict request/response validation.
3. Implement LangGraph adapter for a bounded one-turn invocation.
4. Add mock model and deterministic contract test vectors.
5. Add token/latency/cost telemetry with bounded cardinality.
6. Add TypeScript conformance harness and second adapter only after Python path passes.
7. Evaluate decision quality, prompt injection resistance and proposal validity.

Exit gate: Python and TypeScript clients conform to same schema; plugin cannot perform privileged tool side effects; invocation is bounded and cancellable.
