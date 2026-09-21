#!/usr/bin/env python3
"""Fail if product crates bypass the canonical NOERITH effect domain.

The legacy noerith-storage::work module remains only as bounded regression/reference
infrastructure while S03 is repaired. New crates must route effect semantics through
noerith-effects instead of importing DurableWorkStore or other legacy work types.
"""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CRATES = ROOT / "crates"

FORBIDDEN = (
    re.compile(r"\bnoerith_storage\s*::\s*work\s*::"),
    re.compile(r"\buse\s+noerith_storage\s*::\s*\{[^}]*\bwork\s*::", re.DOTALL),
)

violations: list[str] = []
for path in sorted(CRATES.glob("*/**/*.rs")):
    relative = path.relative_to(ROOT)
    if relative.parts[1] == "noerith-storage":
        # The owning crate and its regression tests may exercise its legacy module.
        continue
    text = path.read_text(encoding="utf-8")
    for pattern in FORBIDDEN:
        if pattern.search(text):
            violations.append(str(relative))
            break

if violations:
    print("DEPENDENCY-BOUNDARY: FAIL")
    for item in violations:
        print(f"  direct legacy effect path: {item}")
    sys.exit(1)

print("DEPENDENCY-BOUNDARY: PASS canonical effect semantics route through noerith-effects")
