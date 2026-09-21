#!/usr/bin/env python3
"""Dependency-free S00 specification and bounded schema-conformance checks.

Validates the JSON-Schema subset used by committed S00 reference contracts.
This is not a substitute for later production wire-format and independent-validator qualification.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "contracts/schemas"

class DuplicateKey(ValueError):
    pass

class SchemaValidationError(AssertionError):
    pass

def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise DuplicateKey(key)
        out[key] = value
    return out

def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)

def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

def ids(path: str, prefix: str, width: int) -> list[str]:
    return re.findall(rf"^\s*({re.escape(prefix)}-?\d{{{width}}}):", text(path), flags=re.MULTILINE)

def assert_sequence(actual: list[str], expected: list[str], label: str) -> None:
    if actual != expected or len(set(actual)) != len(actual):
        raise AssertionError(f"{label} IDs differ/duplicate: actual={actual!r} expected={expected!r}")

def pointer(value: Any, ptr: str) -> Any:
    if ptr == "":
        return value
    if not ptr.startswith("/"):
        raise AssertionError(f"unsupported JSON pointer {ptr!r}")
    current = value
    for token in ptr[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or token not in current:
            raise AssertionError(f"pointer {ptr!r} not found")
        current = current[token]
    return current

def json_type_matches(value: Any, expected: str) -> bool:
    if expected == "object": return isinstance(value, dict)
    if expected == "array": return isinstance(value, list)
    if expected == "string": return isinstance(value, str)
    if expected == "integer": return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number": return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean": return isinstance(value, bool)
    if expected == "null": return value is None
    raise SchemaValidationError(f"unsupported bounded schema type {expected!r}")

class SchemaRegistry:
    def __init__(self) -> None:
        self.by_id: dict[str, dict[str, Any]] = {}
        self.by_filename: dict[str, dict[str, Any]] = {}
        for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
            schema = load_json(path)
            if not isinstance(schema, dict):
                raise AssertionError(f"schema is not object: {path}")
            if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                raise AssertionError(f"unexpected schema dialect in {path}")
            schema_id = schema.get("$id")
            if not isinstance(schema_id, str) or not schema_id.startswith("urn:noerith:schema:"):
                raise AssertionError(f"invalid NOERITH schema id in {path}")
            if schema_id in self.by_id:
                raise AssertionError(f"duplicate schema id {schema_id}")
            self.by_id[schema_id] = schema
            self.by_filename[path.name] = schema

    def resolve(self, ref: str, current_root: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        if ref.startswith("#"):
            return current_root, pointer(current_root, ref[1:])
        base, sep, fragment = ref.partition("#")
        root = self.by_id.get(base)
        if root is None:
            raise SchemaValidationError(f"unresolved schema ref {ref!r}")
        return root, pointer(root, fragment if sep else "")

    def validate(self, value: Any, schema: dict[str, Any], current_root: dict[str, Any] | None = None, path: str = "$") -> None:
        root = current_root or schema
        if "$ref" in schema:
            resolved_root, resolved = self.resolve(schema["$ref"], root)
            self.validate(value, resolved, resolved_root, path)
            return
        if "anyOf" in schema:
            for candidate in schema["anyOf"]:
                try:
                    self.validate(value, candidate, root, path)
                    return
                except SchemaValidationError:
                    pass
            raise SchemaValidationError(f"{path}: no anyOf branch matched")
        if "enum" in schema and value not in schema["enum"]:
            raise SchemaValidationError(f"{path}: {value!r} not in enum")
        expected = schema.get("type")
        if expected is not None:
            types = [expected] if isinstance(expected, str) else expected
            if not any(json_type_matches(value, item) for item in types):
                raise SchemaValidationError(f"{path}: wrong type; expected {types!r}")
        if isinstance(value, str) and "minLength" in schema and len(value) < schema["minLength"]:
            raise SchemaValidationError(f"{path}: shorter than minLength")
        if isinstance(value, int) and not isinstance(value, bool) and "minimum" in schema and value < schema["minimum"]:
            raise SchemaValidationError(f"{path}: below minimum")
        if isinstance(value, dict):
            missing = [name for name in schema.get("required", []) if name not in value]
            if missing:
                raise SchemaValidationError(f"{path}: missing required fields {missing!r}")
            properties = schema.get("properties", {})
            if schema.get("additionalProperties") is False:
                unknown = sorted(set(value) - set(properties))
                if unknown:
                    raise SchemaValidationError(f"{path}: unknown fields {unknown!r}")
            for key, child in value.items():
                if key in properties:
                    self.validate(child, properties[key], root, f"{path}.{key}")
        if isinstance(value, list):
            if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
                raise SchemaValidationError(f"{path}: duplicate array items")
            item_schema = schema.get("items")
            if isinstance(item_schema, dict):
                for index, item in enumerate(value):
                    self.validate(item, item_schema, root, f"{path}[{index}]")

def expect_invalid(registry: SchemaRegistry, fixture: Path, schema: dict[str, Any], root: dict[str, Any]) -> None:
    try:
        registry.validate(load_json(fixture), schema, root)
    except SchemaValidationError:
        return
    raise AssertionError(f"invalid fixture unexpectedly accepted: {fixture}")

def main() -> None:
    registry_text = text("contracts/registry.yaml")
    for fragment in ["name: NOERITH", "systems: 7", "organs: 39", "contracts: 3", "regimes: 6", "rules: 19", "gates: 45", "foundation_invariants: 60"]:
        if fragment not in registry_text:
            raise AssertionError(f"registry missing {fragment!r}")
    assert_sequence(ids("contracts/rules.yaml", "R", 2), [f"R{i:02d}" for i in range(1, 20)], "rules")
    assert_sequence(ids("contracts/gates.yaml", "G", 2), [f"G{i:02d}" for i in range(1, 46)], "gates")
    assert_sequence(ids("contracts/foundation-invariants.yaml", "FC", 3), [f"FC-{i:03d}" for i in range(1, 61)], "foundation invariants")

    registry = SchemaRegistry()
    manifest = load_json(ROOT / "contracts/required-contracts.json")
    contracts = manifest.get("contracts")
    if not isinstance(contracts, dict) or not contracts:
        raise AssertionError("required-contracts manifest is empty")
    for name, spec in contracts.items():
        root = registry.by_filename.get(spec["file"])
        if root is None:
            raise AssertionError(f"required contract {name} references missing schema {spec['file']}")
        contract_schema = pointer(root, spec["pointer"])
        if not isinstance(contract_schema, dict) or contract_schema.get("type") != "object" or not contract_schema.get("required"):
            raise AssertionError(f"required contract {name} has no executable object/required shape")

    lookup = {
        "PolicyDecision.result": ("policy-authority.schema.json", "/$defs/PolicyDecision/properties/result/enum"),
        "AuthorityGrant.autonomy": ("policy-authority.schema.json", "/$defs/AuthorityGrant/properties/autonomy/enum"),
        "AdapterAssuranceProfile.returns_acceptance_receipt": ("effects.schema.json", "/$defs/AdapterAssuranceProfile/properties/returns_acceptance_receipt/enum"),
        "AdapterAssuranceProfile.status_query": ("effects.schema.json", "/$defs/AdapterAssuranceProfile/properties/status_query/enum"),
        "AdapterAssuranceProfile.callback_semantics": ("effects.schema.json", "/$defs/AdapterAssuranceProfile/properties/callback_semantics/enum"),
        "AdapterAssuranceProfile.cancel_before_acceptance": ("effects.schema.json", "/$defs/AdapterAssuranceProfile/properties/cancel_before_acceptance/enum"),
        "AdapterAssuranceProfile.cancel_after_acceptance": ("effects.schema.json", "/$defs/AdapterAssuranceProfile/properties/cancel_after_acceptance/enum"),
        "AdapterAssuranceProfile.compensation": ("effects.schema.json", "/$defs/AdapterAssuranceProfile/properties/compensation/enum"),
        "AdapterAssuranceProfile.transaction_boundary": ("effects.schema.json", "/$defs/AdapterAssuranceProfile/properties/transaction_boundary/enum")
    }
    expected_enums = manifest["required_enums"]
    if set(expected_enums) != set(lookup):
        raise AssertionError("required enum manifest/checker mapping differs")
    for label, expected_values in expected_enums.items():
        filename, ptr = lookup[label]
        actual = pointer(registry.by_filename[filename], ptr)
        if actual != expected_values:
            raise AssertionError(f"{label} enum differs")

    policy_root = registry.by_filename["policy-authority.schema.json"]
    policy_schema = pointer(policy_root, "/$defs/PolicyDecision")
    registry.validate(load_json(ROOT / "contracts/golden/policy-decision.json"), policy_schema, policy_root)
    expect_invalid(registry, ROOT / "contracts/invalid/policy-decision-missing-request-digest.json", policy_schema, policy_root)

    effects_root = registry.by_filename["effects.schema.json"]
    effect_schema = pointer(effects_root, "/$defs/EffectIntent")
    registry.validate(load_json(ROOT / "contracts/golden/effect-intent.json"), effect_schema, effects_root)
    expect_invalid(registry, ROOT / "contracts/invalid/effect-intent-incomplete-assurance.json", effect_schema, effects_root)

    decision_manifest = text("contracts/decision-manifest.yaml")
    for item in range(1, 12):
        if f"O-FC-{item:02d}:" not in decision_manifest:
            raise AssertionError(f"missing O-FC-{item:02d}")
    for item in range(1, 9):
        if f"D-IMPL-{item:03d}:" not in decision_manifest:
            raise AssertionError(f"missing D-IMPL-{item:03d}")
    print(f"S00-SPEC: PASS rules=19 gates=45 invariants=60 schemas={len(registry.by_filename)} required_contracts={len(contracts)} policy/effect_fixtures=4")

if __name__ == "__main__":
    main()
