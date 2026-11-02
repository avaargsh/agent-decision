# Protocol Fixture Rules

- `valid/`: must pass the referenced JSON Schema.
- `invalid/`: must fail schema validation.
- `semantic/`: JSON may pass structural schema validation but must be rejected by the host/Runtime semantic validator before any protected operation is submitted.
- `idempotency/`: compare the named request with the canonical valid request fixture; the same invocation_id with a different digest must return `INVOCATION_ID_REUSED`.

All language implementations must use the same fixtures. A schema-valid ActionProposal is never authorization. Runtime must validate the entire response before submitting any proposal to EngageGuard.
