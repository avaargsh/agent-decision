# Agent Decision

Managed Agent Framework plugin host for Open Agent Infrastructure.

## Product boundary

Owns framework-specific model reasoning, structured decision output, tool selection and decision evaluation. It does not own Run lifecycle, durable workflow history, approval state or privileged tool execution.

## Initial architecture

- Python-first plugin adapter; TypeScript adapter remains supported by the versioned plugin contract.
- Framework adapters are replaceable (initial candidate: LangGraph).
- Each invocation is bounded to one decision step and returns a final response or typed tool-call proposals.
- Tool proposals are executed by Agent Runtime through EngageGuard.
- Model access uses the platform gateway; plugin workers do not receive long-lived provider credentials.

The platform workflow and retries are owned by agent-runtime and Temporal.
