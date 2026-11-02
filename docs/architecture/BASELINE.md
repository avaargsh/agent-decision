# Agent Decision Baseline

Status: Proposed v0.1

## Authority

Owns framework-specific reasoning invocation, model decisions, plan/tool proposals, framework adapter configuration, invocation deduplication/result replay, and decision evaluation. Does not own platform Run/Task/Session lifecycle, Temporal Workflow history, approvals, Permit, Operation Journal, or privileged tool execution.

## Execution model

A plugin invocation is one bounded Decision Turn. Input and output follow the language-neutral protocol in `protocol/v0.1/`. Output is exactly one of FinalResponse, ActionProposal list, or NeedsInput. The host has no direct privileged credentials or unmediated access to protected tools.

## Framework strategy

Python-first with LangGraph as the initial adapter candidate. TypeScript is supported through the same protocol, not a second domain model. Add a second framework only to prove adapter portability or satisfy a concrete workload.

## Runtime and state

Start with stateless HTTP plugin workers. A small durable invocation-result store may enforce `(authenticated_tenant, invocation_id, request_digest)` deduplication and replay completed responses. It is not canonical Run/Session state and must not store framework checkpoints as platform truth. Framework-specific checkpointing is disabled or isolated in v0.1. Long-lived durable workflow state belongs to Temporal/Runtime.

## Evaluation

Persist model/provider/version, prompt/config digest, input/output schema versions, latency, token/cost metadata, and decision outcome. Avoid raw secrets and sensitive payloads in telemetry. Use deterministic fixtures for protocol tests and offline evaluation.

## Security

Plugin receives only projected context and allowed capability descriptors. It returns proposals; Runtime validates them and routes each to EngageGuard for fresh authorization. No tool execution inside plugin. Tenant/principal identity comes from trusted workload authentication, not model output or prompt text.
