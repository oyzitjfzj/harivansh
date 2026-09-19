#!/usr/bin/env python3
"""Qualify an intentionally quarantined zero-dependency Rust crate.

The root workspace can keep a candidate crate out of normal workspace builds
while this verifier still compiles, lints, formats and tests the exact source in
a temporary standalone workspace. It deliberately fails if dependencies appear;
that transition requires an explicit integration decision rather than silently
changing the qualification boundary.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib


class VerificationError(RuntimeError):
    pass


def load_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise VerificationError(f"cannot read {path}: {exc}") from exc


def required_text(mapping: dict, key: str, source: Path) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise VerificationError(f"{source}: missing non-empty {key}")
    return value


def resolve_workspace_value(package: dict, workspace_package: dict, key: str, source: Path):
    value = package.get(key)
    if isinstance(value, dict) and value.get("workspace") is True:
        if key not in workspace_package:
            raise VerificationError(
                f"{source}: package.{key} inherits a workspace value that is absent"
            )
        return workspace_package[key]
    if value is None:
        raise VerificationError(f"{source}: package.{key} is absent")
    return value


def toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def run(command: list[str], *, env: dict[str, str]) -> None:
    print("+", " ".join(command), flush=True)
    completed = subprocess.run(command, env=env, check=False)
    if completed.returncode != 0:
        raise VerificationError(
            f"command failed with exit code {completed.returncode}: {' '.join(command)}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("crate", type=Path)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    crate_root = (repo_root / args.crate).resolve()
    try:
        crate_root.relative_to(repo_root)
    except ValueError as exc:
        raise VerificationError("crate path must stay inside repository") from exc

    root_manifest_path = repo_root / "Cargo.toml"
    crate_manifest_path = crate_root / "Cargo.toml"
    root_manifest = load_toml(root_manifest_path)
    crate_manifest = load_toml(crate_manifest_path)

    workspace_package = root_manifest.get("workspace", {}).get("package", {})
    package = crate_manifest.get("package")
    if not isinstance(package, dict):
        raise VerificationError(f"{crate_manifest_path}: [package] is required")

    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        values = crate_manifest.get(section, {})
        if values:
            raise VerificationError(
                f"{crate_manifest_path}: [{section}] is non-empty; "
                "extend the isolated qualification boundary explicitly before use"
            )

    name = required_text(package, "name", crate_manifest_path)
    version = resolve_workspace_value(package, workspace_package, "version", crate_manifest_path)
    edition = resolve_workspace_value(package, workspace_package, "edition", crate_manifest_path)
    rust_version = resolve_workspace_value(
        package, workspace_package, "rust-version", crate_manifest_path
    )
    publish = resolve_workspace_value(package, workspace_package, "publish", crate_manifest_path)

    if not isinstance(version, str) or not version.strip():
        raise VerificationError("resolved package version must be non-empty text")
    if not isinstance(edition, str) or not edition.strip():
        raise VerificationError("resolved package edition must be non-empty text")
    if not isinstance(rust_version, str) or not rust_version.strip():
        raise VerificationError("resolved package rust-version must be non-empty text")
    if not isinstance(publish, bool):
        raise VerificationError("resolved package publish must be boolean")

    with tempfile.TemporaryDirectory(prefix=f"noerith-{name}-") as temp_dir:
        temp_root = Path(temp_dir)
        copied_any = False
        for child in ("src", "tests", "benches", "examples"):
            source = crate_root / child
            if source.exists():
                shutil.copytree(source, temp_root / child)
                copied_any = True
        if not copied_any or not (temp_root / "src").exists():
            raise VerificationError(f"{crate_root}: src directory is required")

        standalone_manifest = "\n".join(
            [
                "[package]",
                f"name = {toml_string(name)}",
                f"version = {toml_string(version)}",
                f"edition = {toml_string(edition)}",
                f"rust-version = {toml_string(rust_version)}",
                f"publish = {'true' if publish else 'false'}",
                "",
                "[dependencies]",
                "",
            ]
        )
        (temp_root / "Cargo.toml").write_text(standalone_manifest, encoding="utf-8")

        env = os.environ.copy()
        env["CARGO_NET_OFFLINE"] = "true"
        manifest = str(temp_root / "Cargo.toml")
        run(["cargo", "metadata", "--manifest-path", manifest, "--format-version", "1"], env=env)
        run(["cargo", "fmt", "--manifest-path", manifest, "--", "--check"], env=env)
        run(
            [
                "cargo",
                "clippy",
                "--manifest-path",
                manifest,
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
            env=env,
        )
        run(["cargo", "test", "--manifest-path", manifest], env=env)

    print(f"isolated crate qualification passed: {args.crate}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as exc:
        print(f"verification error: {exc}", file=sys.stderr)
        raise SystemExit(1)
