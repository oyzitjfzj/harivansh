#!/usr/bin/env python3
"""Bounded S00 conformance for Foundation control/evidence records."""
from pathlib import Path

from verify_spec import SchemaRegistry, SchemaValidationError, load_json, pointer

ROOT = Path(__file__).resolve().parents[1]

CASES = {
    "InterruptEvent": (
        "contracts/golden/interrupt-event.json",
        "contracts/invalid/interrupt-event-missing-handling-state.json",
    ),
    "ObservationRecord": (
        "contracts/golden/observation-record.json",
        "contracts/invalid/observation-record-invalid-result.json",
    ),
    "MirrorVerdict": (
        "contracts/golden/mirror-verdict.json",
        "contracts/invalid/mirror-verdict-invalid-result.json",
    ),
    "DispatchAttempt": (
        "contracts/golden/dispatch-attempt.json",
        "contracts/invalid/dispatch-attempt-invalid-transport.json",
    ),
}


def expect_invalid(registry, fixture, schema, root):
    try:
        registry.validate(load_json(fixture), schema, root)
    except SchemaValidationError:
        return
    raise AssertionError(f"invalid fixture unexpectedly accepted: {fixture}")


def main():
    registry = SchemaRegistry()
    root = registry.by_filename["control-evidence.schema.json"]
    manifest = load_json(ROOT / "contracts/required-contracts.json")

    for name, (golden_rel, invalid_rel) in CASES.items():
        spec = manifest["contracts"].get(name)
        if spec != {"file": "control-evidence.schema.json", "pointer": f"/$defs/{name}"}:
            raise AssertionError(f"required contract missing or misbound: {name}")
        schema = pointer(root, f"/$defs/{name}")
        registry.validate(load_json(ROOT / golden_rel), schema, root)
        expect_invalid(registry, ROOT / invalid_rel, schema, root)

    if len(manifest["contracts"]) != 23:
        raise AssertionError(f"expected 23 required Foundation/WP05 contracts, got {len(manifest['contracts'])}")

    print("S00-CONTROL-EVIDENCE: PASS contracts=4 golden=4 invalid=4 required_contracts=23")


if __name__ == "__main__":
    main()
