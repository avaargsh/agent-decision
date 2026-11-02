"""Strict, non-authorizing Decision Turn wire boundary for protocol v0.1.

This module validates untrusted model/plugin bytes. It never executes tools, obtains
Permits, or replaces trusted ContextRead and EngageGuard authorization.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker

_PROTOCOL_DIR = Path(__file__).resolve().parents[1] / "protocol" / "v0.1"
_SCHEMA_FILES = {
    "request": "decision-turn-request.schema.json",
    "response": "decision-turn-response.schema.json",
    "error": "decision-turn-error.schema.json",
}
_VALIDATORS = {
    kind: Draft202012Validator(
        json.loads((_PROTOCOL_DIR / "schemas" / filename).read_text(encoding="utf-8")),
        format_checker=FormatChecker(),
    )
    for kind, filename in _SCHEMA_FILES.items()
}
_MAX_WIRE_BYTES = 1024 * 1024


class BoundaryError(ValueError):
    """Protocol error. Its code, rather than its message, drives retry policy."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _pairs_no_duplicate(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise BoundaryError("INVALID_JSON", "duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise BoundaryError("INVALID_JSON", "non-finite JSON numeric value")


def _check_unicode(value: Any) -> None:
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
    elif isinstance(value, list):
        for item in value:
            _check_unicode(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_unicode(key)
            _check_unicode(item)


def strict_json_loads(payload: bytes | str, *, max_bytes: int = _MAX_WIRE_BYTES) -> Any:
    """Parse JSON without silently accepting duplicate keys, NaN or surrogate UTF-16."""
    if isinstance(payload, bytes):
        if len(payload) > max_bytes:
            raise BoundaryError("PAYLOAD_TOO_LARGE", "wire payload too large")
        try:
            body = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise BoundaryError("INVALID_JSON", "invalid UTF-8") from exc
    elif isinstance(payload, str):
        try:
            encoded = payload.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise BoundaryError("INVALID_JSON", "invalid unicode") from exc
        if len(encoded) > max_bytes:
            raise BoundaryError("PAYLOAD_TOO_LARGE", "wire payload too large")
        body = payload
    else:
        raise BoundaryError("INVALID_JSON", "expected JSON bytes or string")
    try:
        result = json.loads(
            body,
            object_pairs_hook=_pairs_no_duplicate,
            parse_constant=_reject_constant,
        )
        _check_unicode(result)
        return result
    except BoundaryError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise BoundaryError("INVALID_JSON", "invalid JSON document") from exc


def _schema_validate(kind: str, data: Any) -> None:
    failure = next(_VALIDATORS[kind].iter_errors(data), None)
    if failure is not None:
        raise BoundaryError("INVALID_REQUEST" if kind == "request" else "OUTPUT_VALIDATION_FAILED",
                            f"invalid {kind} wire schema")


def request_digest(request: Mapping[str, Any]) -> str:
    """RFC 8785 SHA-256 digest; trace_context alone is excluded."""
    content = {key: value for key, value in request.items() if key != "trace_context"}
    try:
        wire = rfc8785.dumps(content)
    except (ValueError, TypeError, UnicodeError, OverflowError) as exc:
        raise BoundaryError("INVALID_JSON", "request cannot be canonicalized") from exc
    return "sha256:" + hashlib.sha256(wire).hexdigest()


def _schema_digest(schema: Mapping[str, Any]) -> str:
    try:
        return "sha256:" + hashlib.sha256(rfc8785.dumps(schema)).hexdigest()
    except (ValueError, TypeError, UnicodeError, OverflowError) as exc:
        raise BoundaryError("SCHEMA_DIGEST_MISMATCH", "invalid registry schema") from exc


def _validate_context_reference(value: Mapping[str, Any], tenant_id: str) -> None:
    # The wire syntax does not confer access. ContextRead MUST also authenticate
    # the caller, verify tenant ownership, content hash, expiry and immutable version.
    url = urlsplit(value["ref"])
    if (url.scheme != "context" or url.netloc != tenant_id or not url.path.startswith("/")
            or url.path == "/" or url.username is not None or url.password is not None
            or url.port is not None or url.query or url.fragment):
        raise BoundaryError("INVALID_CONTEXT_REF", "context reference not tenant-scoped")
    if any(part in ("", ".", "..") for part in url.path[1:].split("/")):
        raise BoundaryError("INVALID_CONTEXT_REF", "noncanonical context path")
    if "%" in url.path or "\\" in url.path:
        raise BoundaryError("INVALID_CONTEXT_REF", "encoded or noncanonical context path")


def validate_request(
    payload: bytes | str,
    *,
    tenant_id: str,
    capability_registry: Mapping[tuple[str, str], Mapping[str, Any]],
    context_versions: Mapping[str, set[str]],
    now: datetime | None = None,
) -> dict[str, Any]:
    data = strict_json_loads(payload)
    _schema_validate("request", data)

    observed = datetime.now(timezone.utc) if now is None else now
    if observed.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    try:
        deadline = datetime.fromisoformat(data["deadline"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise BoundaryError("INVALID_REQUEST", "invalid deadline") from exc
    if deadline <= observed:
        raise BoundaryError("DEADLINE_EXCEEDED", "decision deadline expired")

    parent = data["trace_context"]["traceparent"]
    if int(parent[3:35], 16) == 0 or int(parent[36:52], 16) == 0:
        raise BoundaryError("INVALID_TRACE_CONTEXT", "zero trace or span ID")

    for kind in ("user_input_ref", "context_projection_ref"):
        ref = data[kind]
        _validate_context_reference(ref, tenant_id)
        if ref["schema_version"] not in context_versions.get(kind, set()):
            raise BoundaryError("UNSUPPORTED_CONTEXT_SCHEMA_VERSION", "unrecognized context schema")

    unique: set[tuple[str, str]] = set()
    for capability in data["allowed_capabilities"]:
        key = (capability["capability_id"], capability["capability_version"])
        if key in unique:
            raise BoundaryError("INVALID_REQUEST", "duplicate capability ID/version")
        unique.add(key)
        spec = capability_registry.get(key)
        if spec is None:
            raise BoundaryError("UNSUPPORTED_CAPABILITY_VERSION", "unknown capability")
        arguments_schema = spec["arguments_schema"]
        try:
            Draft202012Validator.check_schema(arguments_schema)
        except Exception as exc:
            raise BoundaryError("SCHEMA_DIGEST_MISMATCH", "invalid trusted capability schema") from exc
        digest = _schema_digest(arguments_schema)
        if (capability["arguments_schema_digest"] != digest
                or spec.get("arguments_schema_digest") != digest):
            raise BoundaryError("SCHEMA_DIGEST_MISMATCH", "capability schema hash mismatch")
    return data


def validate_response(
    payload: bytes | str,
    *,
    request: Mapping[str, Any],
    capability_registry: Mapping[tuple[str, str], Mapping[str, Any]],
) -> dict[str, Any]:
    data = strict_json_loads(payload)
    _schema_validate("response", data)
    if data["invocation_id"] != request["invocation_id"]:
        raise BoundaryError("INVOCATION_ID_MISMATCH", "response is from another invocation")

    result = data["result"]
    if result["kind"] == "action_proposals":
        allowed = {
            (c["capability_id"], c["capability_version"]): c["arguments_schema_digest"]
            for c in request["allowed_capabilities"]
        }
        observed_ids: set[str] = set()
        for proposal in result["proposals"]:
            if proposal["proposal_id"] in observed_ids:
                raise BoundaryError("DUPLICATE_PROPOSAL_ID", "duplicate proposal ID")
            observed_ids.add(proposal["proposal_id"])

            key = (proposal["capability_id"], proposal["capability_version"])
            if key not in allowed or key not in capability_registry:
                raise BoundaryError("CAPABILITY_NOT_ALLOWED", "proposal outside allow-list")
            spec = capability_registry[key]
            if allowed[key] != _schema_digest(spec["arguments_schema"]):
                raise BoundaryError("SCHEMA_DIGEST_MISMATCH", "capability schema hash mismatch")
            if next(Draft202012Validator(
                    spec["arguments_schema"], format_checker=FormatChecker()
            ).iter_errors(proposal["arguments"]), None):
                raise BoundaryError("INVALID_PROPOSAL_ARGUMENTS", "proposal arguments do not match schema")
    return data


def validate_error(payload: bytes | str) -> dict[str, Any]:
    data = strict_json_loads(payload)
    _schema_validate("error", data)
    return data
