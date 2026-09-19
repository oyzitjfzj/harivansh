#!/usr/bin/env python3
"""Qualify a quarantined Rust crate with an explicitly reviewed dependency profile.

This verifier is intentionally separate from `verify_isolated_std_crate.py`:
S04's zero-dependency boundary stays strict, while S05 may use only the exact
mature dependency contract that was independently selected for that crate.

A pass is isolated compile/lint/test evidence only. It is not workspace
integration, supply-chain attestation, or a NOERITH quality-gate pass.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib


EXPECTED_RUST_VERSION = "1.98.1"

# Profiles are code-reviewed qualification contracts, not caller-controlled
# allowlists. Extending this table requires its own dependency/architecture
# decision instead of weakening verification via command-line flags.
PROFILES: dict[str, dict] = {
    "noerith-capabilities": {
        "version": "0.1.0",
        "edition": "2024",
        "rust-version": EXPECTED_RUST_VERSION,
        "publish": False,
        "lib": {"path": "src/lib.rs"},
        "dependencies": {
            "sha2": {
                "version": "=0.11.0",
                "default-features": False,
            }
        },
    }
}


class VerificationError(RuntimeError):
    pass


def load_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise VerificationError(f"cannot read {path}: {exc}") from exc


def run(
    command: list[str],
    *,
    env: dict[str, str],
    capture: bool = False,
) -> str:
    print("+", " ".join(command), flush=True)
    completed = subprocess.run(
        command,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if completed.returncode != 0:
        detail = ""
        if capture:
            stderr = (completed.stderr or "").strip()
            stdout = (completed.stdout or "").strip()
            detail = f"\nstdout:\n{stdout}\nstderr:\n{stderr}"
        raise VerificationError(
            f"command failed with exit code {completed.returncode}: "
            f"{' '.join(command)}{detail}"
        )
    return (completed.stdout or "") if capture else ""


def require_exact(value, expected, source: Path, field: str) -> None:
    if value != expected:
        raise VerificationError(
            f"{source}: {field} must be exactly {expected!r}; found {value!r}"
        )


def ensure_no_symlinks(root: Path) -> None:
    if root.is_symlink():
        raise VerificationError(f"symlinked source root rejected: {root}")
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in [*dirs, *files]:
            candidate = current_path / name
            if candidate.is_symlink():
                raise VerificationError(f"symlink inside isolated source rejected: {candidate}")


def validate_manifest(crate_root: Path, manifest: dict) -> tuple[str, dict]:
    allowed_top_level = {"package", "lib", "dependencies"}
    unexpected = set(manifest) - allowed_top_level
    if unexpected:
        raise VerificationError(
            f"{crate_root / 'Cargo.toml'}: unsupported manifest sections/keys: "
            f"{sorted(unexpected)}"
        )

    package = manifest.get("package")
    if not isinstance(package, dict):
        raise VerificationError("[package] table is required")
    name = package.get("name")
    if not isinstance(name, str) or not name.strip():
        raise VerificationError("package.name must be non-empty text")
    profile = PROFILES.get(name)
    if profile is None:
        raise VerificationError(f"no reviewed isolated dependency profile for {name!r}")

    allowed_package_fields = {"name", "version", "edition", "rust-version", "publish"}
    extra_package_fields = set(package) - allowed_package_fields
    if extra_package_fields:
        raise VerificationError(
            f"unsupported package fields for isolated profile: {sorted(extra_package_fields)}"
        )
    for field in ("version", "edition", "rust-version", "publish"):
        require_exact(
            package.get(field),
            profile[field],
            crate_root / "Cargo.toml",
            f"package.{field}",
        )

    lib = manifest.get("lib")
    require_exact(lib, profile["lib"], crate_root / "Cargo.toml", "lib")

    dependencies = manifest.get("dependencies", {})
    require_exact(
        dependencies,
        profile["dependencies"],
        crate_root / "Cargo.toml",
        "dependencies",
    )

    if (crate_root / "build.rs").exists():
        raise VerificationError(f"{crate_root}: build.rs is not allowed in this profile")

    return name, profile


def exact_profile_manifest(name: str) -> dict:
    profile = PROFILES[name]
    return {
        "package": {
            "name": name,
            "version": profile["version"],
            "edition": profile["edition"],
            "rust-version": profile["rust-version"],
            "publish": profile["publish"],
        },
        "lib": copy.deepcopy(profile["lib"]),
        "dependencies": copy.deepcopy(profile["dependencies"]),
    }


def expect_manifest_rejected(
    crate_root: Path,
    base: dict,
    label: str,
    mutate,
) -> None:
    candidate = copy.deepcopy(base)
    mutate(candidate)
    try:
        validate_manifest(crate_root, candidate)
    except VerificationError:
        return
    raise VerificationError(f"verifier self-test failed: accepted forbidden {label}")


def run_contract_self_tests() -> None:
    """Prove the verifier itself rejects the dependency-surface attacks it names."""
    name = "noerith-capabilities"
    base = exact_profile_manifest(name)
    with tempfile.TemporaryDirectory(prefix="noerith-verifier-selftest-") as temp_dir:
        root = Path(temp_dir)
        (root / "src").mkdir()
        validate_manifest(root, copy.deepcopy(base))

        mutations = [
            (
                "wildcard dependency version",
                lambda m: m["dependencies"]["sha2"].__setitem__("version", "*"),
            ),
            (
                "dependency default features",
                lambda m: m["dependencies"]["sha2"].__setitem__(
                    "default-features", True
                ),
            ),
            (
                "extra dependency",
                lambda m: m["dependencies"].__setitem__(
                    "serde", {"version": "=1.0.229"}
                ),
            ),
            (
                "path dependency override",
                lambda m: m["dependencies"]["sha2"].__setitem__("path", "../sha2"),
            ),
            (
                "git dependency override",
                lambda m: m["dependencies"]["sha2"].__setitem__(
                    "git", "https://example.invalid/sha2"
                ),
            ),
            (
                "registry dependency override",
                lambda m: m["dependencies"]["sha2"].__setitem__(
                    "registry", "alternate"
                ),
            ),
            (
                "dev dependency section",
                lambda m: m.__setitem__("dev-dependencies", {"x": "=1.0.0"}),
            ),
            (
                "build dependency section",
                lambda m: m.__setitem__("build-dependencies", {"x": "=1.0.0"}),
            ),
            (
                "feature table",
                lambda m: m.__setitem__("features", {"bypass": []}),
            ),
            (
                "patch override",
                lambda m: m.__setitem__("patch", {"crates-io": {}}),
            ),
            (
                "replace override",
                lambda m: m.__setitem__("replace", {"sha2:0.11.0": {}}),
            ),
            (
                "workspace section",
                lambda m: m.__setitem__("workspace", {"members": []}),
            ),
            (
                "source override",
                lambda m: m.__setitem__("source", {"crates-io": {}}),
            ),
            (
                "package build script declaration",
                lambda m: m["package"].__setitem__("build", "build.rs"),
            ),
            (
                "changed Rust version",
                lambda m: m["package"].__setitem__("rust-version", "1.99.0"),
            ),
        ]
        for label, mutate in mutations:
            expect_manifest_rejected(root, base, label, mutate)

        build_script = root / "build.rs"
        build_script.write_text("fn main() {}\n", encoding="utf-8")
        try:
            validate_manifest(root, copy.deepcopy(base))
        except VerificationError:
            pass
        else:
            raise VerificationError(
                "verifier self-test failed: accepted physical build.rs"
            )
        build_script.unlink()

        symlink_target = root / "outside.rs"
        symlink_target.write_text("// target\n", encoding="utf-8")
        symlink = root / "src" / "escape.rs"
        try:
            symlink.symlink_to(symlink_target)
        except (OSError, NotImplementedError):
            # The production CI profile is Linux, but keep the verifier usable on
            # platforms where creating a symlink requires unavailable privilege.
            pass
        else:
            try:
                ensure_no_symlinks(root / "src")
            except VerificationError:
                pass
            else:
                raise VerificationError(
                    "verifier self-test failed: accepted source symlink"
                )

    print("isolated verifier contract self-tests passed", flush=True)


def standalone_manifest(name: str, profile: dict) -> str:
    dep = profile["dependencies"]["sha2"]
    return "\n".join(
        [
            "[package]",
            f'name = "{name}"',
            f'version = "{profile["version"]}"',
            f'edition = "{profile["edition"]}"',
            f'rust-version = "{profile["rust-version"]}"',
            "publish = false",
            "",
            "[lib]",
            f'path = "{profile["lib"]["path"]}"',
            "",
            "[dependencies.sha2]",
            f'version = "{dep["version"]}"',
            "default-features = false",
            "",
        ]
    )


def audit_metadata(metadata_json: str, package_name: str) -> None:
    try:
        metadata = json.loads(metadata_json)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"cargo metadata returned invalid JSON: {exc}") from exc

    packages = {package["id"]: package for package in metadata.get("packages", [])}
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict):
        raise VerificationError("cargo metadata missing resolve graph")
    root_id = resolve.get("root")
    root_package = packages.get(root_id)
    if not root_package or root_package.get("name") != package_name:
        raise VerificationError("cargo metadata root package does not match isolated candidate")

    root_node = next(
        (node for node in resolve.get("nodes", []) if node.get("id") == root_id),
        None,
    )
    if root_node is None:
        raise VerificationError("cargo metadata missing root resolve node")

    direct = []
    for dep in root_node.get("deps", []):
        package = packages.get(dep.get("pkg"))
        if package is None:
            raise VerificationError("cargo metadata dependency points to unknown package")
        direct.append((package.get("name"), package.get("version")))
    if sorted(direct) != [("sha2", "0.11.0")]:
        raise VerificationError(
            f"unexpected direct dependency resolution: {sorted(direct)!r}"
        )

    resolved = sorted(
        f"{package.get('name')}@{package.get('version')} [{package.get('source') or 'local'}]"
        for package in packages.values()
    )
    print("resolved isolated package set:", flush=True)
    for item in resolved:
        print(f"  {item}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("crate", type=Path)
    args = parser.parse_args()

    run_contract_self_tests()

    repo_root = Path(__file__).resolve().parents[1]
    crate_root = (repo_root / args.crate).resolve()
    try:
        crate_root.relative_to(repo_root)
    except ValueError as exc:
        raise VerificationError("crate path must stay inside repository") from exc
    if not crate_root.is_dir():
        raise VerificationError(f"crate directory does not exist: {crate_root}")

    manifest_path = crate_root / "Cargo.toml"
    manifest = load_toml(manifest_path)
    name, profile = validate_manifest(crate_root, manifest)

    rustc_version = run(["rustc", "--version"], env=os.environ.copy(), capture=True).strip()
    parts = rustc_version.split()
    if len(parts) < 2 or parts[0] != "rustc" or parts[1] != EXPECTED_RUST_VERSION:
        raise VerificationError(
            f"Rust toolchain must be exactly {EXPECTED_RUST_VERSION}; found {rustc_version!r}"
        )

    with tempfile.TemporaryDirectory(prefix=f"noerith-{name}-") as temp_dir:
        temp_root = Path(temp_dir)
        candidate_root = temp_root / "candidate"
        candidate_root.mkdir()

        copied_any = False
        for child in ("src", "tests", "benches", "examples"):
            source = crate_root / child
            if source.exists():
                ensure_no_symlinks(source)
                shutil.copytree(source, candidate_root / child)
                copied_any = True
        if not copied_any or not (candidate_root / "src").is_dir():
            raise VerificationError(f"{crate_root}: src directory is required")

        (candidate_root / "Cargo.toml").write_text(
            standalone_manifest(name, profile), encoding="utf-8"
        )

        cargo_home = temp_root / "cargo-home"
        cargo_home.mkdir()
        env = os.environ.copy()
        env["CARGO_HOME"] = str(cargo_home)
        manifest_arg = str(candidate_root / "Cargo.toml")

        # Resolution/fetch is the only network-eligible phase. The exact direct
        # dependency contract is checked above; Cargo.lock freezes its resolved
        # transitive closure for all executable verification commands below.
        run(["cargo", "generate-lockfile", "--manifest-path", manifest_arg], env=env)
        run(["cargo", "fetch", "--manifest-path", manifest_arg, "--locked"], env=env)

        offline_env = env.copy()
        offline_env["CARGO_NET_OFFLINE"] = "true"
        metadata_json = run(
            [
                "cargo",
                "metadata",
                "--manifest-path",
                manifest_arg,
                "--locked",
                "--offline",
                "--format-version",
                "1",
            ],
            env=offline_env,
            capture=True,
        )
        audit_metadata(metadata_json, name)
        run(
            ["cargo", "fmt", "--manifest-path", manifest_arg, "--", "--check"],
            env=offline_env,
        )
        run(
            [
                "cargo",
                "check",
                "--manifest-path",
                manifest_arg,
                "--all-targets",
                "--locked",
                "--offline",
            ],
            env=offline_env,
        )
        run(
            [
                "cargo",
                "clippy",
                "--manifest-path",
                manifest_arg,
                "--all-targets",
                "--locked",
                "--offline",
                "--",
                "-D",
                "warnings",
            ],
            env=offline_env,
        )
        run(
            [
                "cargo",
                "test",
                "--manifest-path",
                manifest_arg,
                "--locked",
                "--offline",
            ],
            env=offline_env,
        )

    print(f"isolated pinned-dependency qualification passed: {args.crate}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as exc:
        print(f"verification error: {exc}", file=sys.stderr)
        raise SystemExit(1)
