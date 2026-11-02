#!/usr/bin/env python3
"""Validate Agent Decision v0.1 JSON Schemas and shared contract fixtures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "protocol" / "v0.1"
MANIFEST = json.loads((PROTOCOL / "manifest.json").read_text(encoding="utf-8"))
SCHEMAS = {
    name: json.loads((PROTOCOL / path).read_text(encoding="utf-8"))
    for name, path in MANIFEST["schemas"].items()
}
VALIDATOR = {
    name: Draft202012Validator(schema, format_checker=FormatChecker())
    for name, schema in SCHEMAS.items()
}


def load(relative_path: str):
    return json.loads((PROTOCOL / relative_path).read_text(encoding="utf-8"))


def assert_valid(name: str, instance, label: str) -> None:
    errors = sorted(VALIDATOR[name].iter_errors(instance), key=lambda item: list(item.path))
    if errors:
        details = "; ".join(error.message for error in errors)
        raise AssertionError(f"{label} should validate against {name}: {details}")


def assert_invalid(name: str, instance, label: str) -> None:
    errors = list(VALIDATOR[name].iter_errors(instance))
    if not errors:
        raise AssertionError(f"{label} unexpectedly validated against {name}")


def main() -> None:
    for schema in SCHEMAS.values():
        Draft202012Validator.check_schema(schema)

    valid_cases = {
        "decision-turn-request.json": "request",
        "final-response.json": "response",
        "action-proposals.json": "response",
        "needs-input.json": "response",
        "error-envelope.json": "error",
    }
    for filename, schema_name in valid_cases.items():
        instance = load(f"fixtures/valid/{filename}")
        assert_valid(schema_name, instance, filename)

    invalid_cases = {
        "unknown-protocol-version.request.json": "request",
        "unknown-field.request.json": "request",
        "mixed-result.response.json": "response",
        "non-utc-deadline.request.json": "request",
    }
    for filename, schema_name in invalid_cases.items():
        instance = load(f"fixtures/invalid/{filename}")
        assert_invalid(schema_name, instance, filename)

    # Semantic fixtures are structurally valid but must fail boundary checks.
    baseline_request = load("fixtures/valid/decision-turn-request.json")
    supported_capabilities = {
        (item["capability_id"], item["capability_version"])
        for item in baseline_request["allowed_capabilities"]
    }
    supported_context_schemas = {
        baseline_request["user_input_ref"]["schema_version"],
        baseline_request["context_projection_ref"]["schema_version"],
    }

    not_allowed = load("fixtures/semantic/capability-not-allowed.json")
    request = load("fixtures/" + not_allowed["request_fixture"].replace("../", "", 1))
    response = not_allowed["response"]
    assert_valid("request", request, "capability-not-allowed request")
    assert_valid("response", response, "capability-not-allowed response")
    proposal = response["result"]["proposals"][0]
    if (proposal["capability_id"], proposal["capability_version"]) in {
        (item["capability_id"], item["capability_version"])
        for item in request["allowed_capabilities"]
    }:
        raise AssertionError("capability-not-allowed fixture must be outside request allow-list")

    unknown_capability = load("fixtures/semantic/unsupported-capability-version.request.json")
    assert_valid("request", unknown_capability, "unsupported capability version request")
    capability = unknown_capability["allowed_capabilities"][0]
    if (capability["capability_id"], capability["capability_version"]) in supported_capabilities:
        raise AssertionError("unsupported capability version fixture must not be in supported registry")

    unknown_context = load("fixtures/semantic/unsupported-context-schema-version.request.json")
    assert_valid("request", unknown_context, "unsupported context schema version request")
    if unknown_context["context_projection_ref"]["schema_version"] in supported_context_schemas:
        raise AssertionError("unsupported context schema fixture must not be in supported schema registry")

    digest_vector = load("fixtures/idempotency/request-digest.json")
    digest_request = load("fixtures/" + digest_vector["request_fixture"].replace("../", "", 1))
    digest_input = {key: value for key, value in digest_request.items() if key not in digest_vector["excluded_fields"]}
    canonical_bytes = json.dumps(digest_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    actual_digest = "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()
    if actual_digest != digest_vector["expected_sha256"]:
        raise AssertionError(f"request digest vector mismatch: {actual_digest}")

    changed_request = load("fixtures/idempotency/invocation-id-reused-different-request.json")
    assert_valid("request", changed_request, "changed invocation request")
    if changed_request["invocation_id"] != baseline_request["invocation_id"]:
        raise AssertionError("idempotency fixture must reuse invocation_id")
    if changed_request == baseline_request:
        raise AssertionError("idempotency fixture must change the request payload")

    print(
        "Protocol v0.1 validation passed: "
        f"{len(valid_cases)} valid fixtures, {len(invalid_cases)} invalid fixtures, "
        "3 semantic rejection fixtures, 1 invocation-id conflict fixture."
    )


if __name__ == "__main__":
    main()
