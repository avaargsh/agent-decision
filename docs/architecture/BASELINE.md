# Agent Decision Baseline

Status: Proposed v0.1

## Authority
Owns framework-specific reasoning invocation, model decisions, plan/tool proposals, framework adapter configuration and decision evaluation. Does not own platform Run lifecycle, Temporal Workflow history, approvals, Permit or privileged tool execution.

## Execution model
A plugin invocation is one bounded decision turn. Input is a versioned DecisionTurn request. Output is a FinalResponse or typed ActionProposal list. The host has no direct privileged credentials or unmediated access to protected tools.

## Framework strategy
Python-first with LangGraph as the initial adapter candidate. TypeScript is supported through the same protocol, not a second domain model. Add a second framework only to prove adapter portability or satisfy a concrete workload.

## Runtime
Start with a stateless HTTP plugin worker. Framework-specific checkpointing is disabled or isolated from canonical platform Session/Run state in v0.1. Long-lived durable state belongs to Temporal/Runtime. Any model-side internal state must be bounded, versioned and non-authoritative.

## Evaluation
Persist model/provider/version, prompt/config digest, input/output schema versions, latency, token/cost metadata and decision outcome. Avoid raw secrets and sensitive payloads in telemetry. Use deterministic fixtures for contract tests and offline evaluation.

## Security
Plugin receives only projected context and allowed capability descriptors. It returns proposals; Runtime routes them to EngageGuard for fresh authorization. No tool execution inside plugin.
