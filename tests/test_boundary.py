"""Fail-closed Decision Turn boundary conformance tests."""

from __future__ import annotations

import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

import rfc8785

from agent_decision_protocol.boundary import (
    BoundaryError,
    request_digest,
    strict_json_loads,
    validate_request,
    validate_response,
)

ROOT = Path(__file__).resolve().parents[1] / "protocol" / "v0.1"


def fixture(path: str) -> dict:
    return json.loads((ROOT / "fixtures" / path).read_text(encoding="utf-8"))


ARGUMENTS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["relative_path"],
    "properties": {
        "relative_path": {"type": "string", "minLength": 1},
        "content": {"type": "string"},
    },
}

import hashlib
ARGUMENTS_DIGEST = "sha256:" + hashlib.sha256(rfc8785.dumps(ARGUMENTS_SCHEMA)).hexdigest()

REGISTRY = {
    ("workspace.write", "1.0.0"): {
        "arguments_schema_digest": ARGUMENTS_DIGEST,
        "arguments_schema": ARGUMENTS_SCHEMA,
    }
}
CONTEXT_VERSIONS = {
    "user_input_ref": {"user-input.v1"},
    "context_projection_ref": {"context-projection.v1"},
}


def wire(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def request() -> dict:
    data = fixture("valid/decision-turn-request.json")
    data["allowed_capabilities"][0]["arguments_schema_digest"] = ARGUMENTS_DIGEST
    return data


def accepted_request() -> dict:
    return validate_request(
        wire(request()),
        tenant_id="tenant-a",
        capability_registry=REGISTRY,
        context_versions=CONTEXT_VERSIONS,
        now=datetime(2026, 11, 2, tzinfo=timezone.utc),
    )


def assert_code(testcase: unittest.TestCase, code: str, callback) -> None:
    with testcase.assertRaises(BoundaryError) as caught:
        callback()
    testcase.assertEqual(caught.exception.code, code)


class StrictWireTests(unittest.TestCase):
    def test_duplicate_json_key_is_rejected(self) -> None:
        assert_code(self, "INVALID_JSON", lambda: strict_json_loads(b'{"a":1,"a":2}'))

    def test_nonfinite_json_is_rejected(self) -> None:
        assert_code(self, "INVALID_JSON", lambda: strict_json_loads(b'{"x":NaN}'))

    def test_bytes_limit_rejected_before_parse(self) -> None:
        assert_code(self, "PAYLOAD_TOO_LARGE", lambda: strict_json_loads(b" " * 2049, max_bytes=2048))

    def test_surrogate_unicode_is_rejected(self) -> None:
        assert_code(self, "INVALID_JSON", lambda: strict_json_loads(b'{"x":"\\ud800"}'))


class RequestBoundaryTests(unittest.TestCase):
    def test_valid_request_and_registry(self) -> None:
        self.assertEqual(accepted_request()["invocation_id"], "inv-001")

    def test_expired_deadline_rejected(self) -> None:
        assert_code(self, "DEADLINE_EXCEEDED", lambda: validate_request(
            wire(request()), tenant_id="tenant-a", capability_registry=REGISTRY,
            context_versions=CONTEXT_VERSIONS,
            now=datetime(2031, 1, 1, tzinfo=timezone.utc),
        ))

    def test_unknown_capability_version_rejected(self) -> None:
        bad = request()
        bad["allowed_capabilities"][0]["capability_version"] = "9.9.9"
        assert_code(self, "UNSUPPORTED_CAPABILITY_VERSION", lambda: validate_request(
            wire(bad), tenant_id="tenant-a", capability_registry=REGISTRY,
            context_versions=CONTEXT_VERSIONS,
            now=datetime(2026, 11, 2, tzinfo=timezone.utc),
        ))

    def test_unknown_context_schema_version_rejected(self) -> None:
        bad = request()
        bad["context_projection_ref"]["schema_version"] = "context-projection.v99"
        assert_code(self, "UNSUPPORTED_CONTEXT_SCHEMA_VERSION", lambda: validate_request(
            wire(bad), tenant_id="tenant-a", capability_registry=REGISTRY,
            context_versions=CONTEXT_VERSIONS,
            now=datetime(2026, 11, 2, tzinfo=timezone.utc),
        ))

    def test_cross_tenant_context_rejected(self) -> None:
        bad = request()
        bad["user_input_ref"]["ref"] = "context://tenant-b/input/001"
        assert_code(self, "INVALID_CONTEXT_REF", lambda: validate_request(
            wire(bad), tenant_id="tenant-a", capability_registry=REGISTRY,
            context_versions=CONTEXT_VERSIONS,
            now=datetime(2026, 11, 2, tzinfo=timezone.utc),
        ))

    def test_external_url_context_rejected(self) -> None:
        bad = request()
        bad["user_input_ref"]["ref"] = "https://example.com/secret"
        assert_code(self, "INVALID_CONTEXT_REF", lambda: validate_request(
            wire(bad), tenant_id="tenant-a", capability_registry=REGISTRY,
            context_versions=CONTEXT_VERSIONS,
            now=datetime(2026, 11, 2, tzinfo=timezone.utc),
        ))

    def test_mismatched_schema_digest_rejected(self) -> None:
        bad = request()
        bad["allowed_capabilities"][0]["arguments_schema_digest"] = "sha256:" + "f" * 64
        assert_code(self, "SCHEMA_DIGEST_MISMATCH", lambda: validate_request(
            wire(bad), tenant_id="tenant-a", capability_registry=REGISTRY,
            context_versions=CONTEXT_VERSIONS,
            now=datetime(2026, 11, 2, tzinfo=timezone.utc),
        ))

    def test_zero_trace_id_rejected(self) -> None:
        bad = request()
        bad["trace_context"]["traceparent"] = "00-" + "0"*32 + "-00f067aa0ba902b7-01"
        assert_code(self, "INVALID_TRACE_CONTEXT", lambda: validate_request(
            wire(bad), tenant_id="tenant-a", capability_registry=REGISTRY,
            context_versions=CONTEXT_VERSIONS,
            now=datetime(2026, 11, 2, tzinfo=timezone.utc),
        ))


class ResponseBoundaryTests(unittest.TestCase):
    def test_valid_action_proposal(self) -> None:
        actual = validate_response(
            wire(fixture("valid/action-proposals.json")),
            request=accepted_request(), capability_registry=REGISTRY,
        )
        self.assertEqual(actual["result"]["kind"], "action_proposals")

    def test_forbidden_capability_rejects_entire_response(self) -> None:
        bad = fixture("semantic/capability-not-allowed.json")["response"]
        assert_code(self, "CAPABILITY_NOT_ALLOWED", lambda: validate_response(
            wire(bad), request=accepted_request(), capability_registry=REGISTRY,
        ))

    def test_duplicate_proposal_ids_rejected(self) -> None:
        bad = fixture("valid/action-proposals.json")
        bad["result"]["proposals"].append(copy.deepcopy(bad["result"]["proposals"][0]))
        assert_code(self, "DUPLICATE_PROPOSAL_ID", lambda: validate_response(
            wire(bad), request=accepted_request(), capability_registry=REGISTRY,
        ))

    def test_malformed_arguments_reject_entire_response(self) -> None:
        bad = fixture("valid/action-proposals.json")
        bad["result"]["proposals"][0]["arguments"]["unknown_parameter"] = True
        assert_code(self, "INVALID_PROPOSAL_ARGUMENTS", lambda: validate_response(
            wire(bad), request=accepted_request(), capability_registry=REGISTRY,
        ))

    def test_wrong_invocation_id_rejected(self) -> None:
        bad = fixture("valid/final-response.json")
        bad["invocation_id"] = "inv-other"
        assert_code(self, "INVOCATION_ID_MISMATCH", lambda: validate_response(
            wire(bad), request=accepted_request(), capability_registry=REGISTRY,
        ))


class DigestTests(unittest.TestCase):
    def test_cross_language_digest_vector(self) -> None:
        vector = fixture("idempotency/request-digest.json")
        baseline = fixture("valid/decision-turn-request.json")
        self.assertEqual(request_digest(baseline), vector["expected_sha256"])

    def test_trace_context_not_part_of_digest(self) -> None:
        baseline = fixture("valid/decision-turn-request.json")
        changed = copy.deepcopy(baseline)
        changed["trace_context"]["traceparent"] = "00-" + "1"*32 + "-" + "2"*16 + "-01"
        self.assertEqual(request_digest(baseline), request_digest(changed))

    def test_changed_business_payload_changes_digest(self) -> None:
        baseline = fixture("valid/decision-turn-request.json")
        changed = fixture("idempotency/invocation-id-reused-different-request.json")
        self.assertNotEqual(request_digest(baseline), request_digest(changed))


if __name__ == "__main__":
    unittest.main()
