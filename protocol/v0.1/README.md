# Agent Decision Protocol v0.1

This directory is the canonical language-neutral wire contract for one bounded Decision Turn.

- JSON Schema Draft 2020-12 is normative.
- Unknown fields and unknown protocol versions are rejected.
- Runtime/host semantic validation must resolve exact capability versions, argument-schema digests, and context schema versions; schema-valid does not mean supported or authorized.
- The request digest uses RFC 8785 JCS over the request after removing only `trace_context`.
- `invocation_id` is stable across retries. A durable invocation-result store replays completed responses and rejects digest conflicts.
- The plugin has no protected side-effect credentials or direct executor access.

See `manifest.json` for schema paths, fixture inventory, and hard limits. The same fixtures are consumed by Go Runtime, Python host, and TypeScript adapter conformance suites.
