#!/usr/bin/env python3
"""Bounded Python reference for S00/Q01. Standard library only.

This validates only the registered reference fixture shape and canonical subset
used by S00. It is not a claim that O-FC-01 is production-locked.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "message_id",
    "tenant_namespace",
    "producer_principal",
    "payload",
    "payload_digest",
}


class DuplicateKey(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKey(key)
        result[key] = value
    return result


def load_strict(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError("top-level object required")
    if set(value) != REQUIRED:
        raise ValueError(f"protected fields mismatch: {sorted(set(value) ^ REQUIRED)}")
    return value


def reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("floating point is outside the bounded canonical reference")
    if isinstance(value, dict):
        for item in value.values():
            reject_floats(item)
    elif isinstance(value, list):
        for item in value:
            reject_floats(item)


def canonical(value: Any) -> str:
    reject_floats(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_payload(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def validate(path: Path) -> dict[str, Any]:
    value = load_strict(path)
    if digest_payload(value["payload"]) != value["payload_digest"]:
        raise ValueError("payload digest mismatch")
    return value


def expect_invalid(path: Path) -> None:
    try:
        validate(path)
    except (ValueError, DuplicateKey, json.JSONDecodeError):
        return
    raise AssertionError(f"invalid fixture unexpectedly accepted: {path}")


def main() -> None:
    golden = validate(ROOT / "contracts/golden/q01-message.json")
    round_trip = json.loads(canonical(golden), object_pairs_hook=reject_duplicates)
    assert round_trip == golden

    expect_invalid(ROOT / "contracts/invalid/q01-changed-payload.json")
    expect_invalid(ROOT / "contracts/invalid/q01-unknown-critical.json")
    expect_invalid(ROOT / "contracts/invalid/q01-duplicate-message-id.json")

    assert canonical(golden["payload"]) == '{"a":"alpha","b":2,"flags":[true,false,null]}'
    print("Q01-PYTHON: PASS")


if __name__ == "__main__":
    main()
