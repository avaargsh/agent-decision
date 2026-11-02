# Reference Decision Plugin Spike

This spike demonstrates a bounded and non-privileged decision contract. It is **not** a LangGraph model implementation and does not provide production authorization.

Run: `python -m decision_plugin.server`

Test: `python -m pytest -q`

POST `http://127.0.0.1:8081/api/v1/decision-turns`:

```json
{"protocol_version":"v0.1","invocation_id":"inv-1","tenant_id":"t-1","agent_id":"a-1","run_id":"r-1","turn_id":"turn-1","user_input":"hello"}
```

Expected response:

```json
{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final","text":"Accepted: hello"}
```

Do not expose this loopback-only development server externally. The upstream caller must provide authenticated workload identity, enforce deadlines and restrict network access before production use.
