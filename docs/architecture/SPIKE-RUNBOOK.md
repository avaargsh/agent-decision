# Reference Decision Plugin Spike

This is a bounded, non-privileged **smoke-test subset**. It is not full Agent Decision Protocol v0.1 conformance, a LangGraph model implementation, a durable invocation ledger or production authorization.

The canonical protocol schemas are maintained by [agent-control-panel](https://github.com/avaargsh/agent-control-panel/tree/feature/platform-foundation/contracts/agent-decision/v0.1). The production request/result must validate against those shared schemas. This spike intentionally supports only the minimal request fields below and a `final_response` result.

Run: `python -m decision_plugin.server`

Test: `python -m pytest -q`

POST `http://127.0.0.1:8081/api/v1/decision-turns`:

```json
{"protocol_version":"v0.1","invocation_id":"inv-1","tenant_id":"t-1","agent_id":"a-1","run_id":"r-1","turn_id":"turn-1","user_input":"hello"}
```

Expected smoke-test response:

```json
{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final_response","text":"Accepted: hello"}
```

The full protocol also requires Bundle/Release/Session identity, resolved bounded context projection, capability ID/version pairs, deadline and trace context; the full FinalResponse includes evidence references. Those fields are intentionally not implemented in this spike.

Do not expose this loopback-only development server externally. The upstream caller must provide authenticated workload identity, enforce deadlines and restrict network access before production use. Before production, add durable invocation idempotency: same invocation ID and request digest must replay the exact result; changed digest must conflict.
