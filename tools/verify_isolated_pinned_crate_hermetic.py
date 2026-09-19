#!/usr/bin/env python3
"""Launch the S05 pinned-crate verifier behind a clean Cargo/Python boundary.

The underlying verifier owns the crate/dependency contract. This launcher owns
ambient-process isolation: it prevents repository/ancestor Cargo config and
inherited Cargo/Rust/Python override variables from silently changing what is
verified.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile


class HermeticLaunchError(RuntimeError):
    pass


# Environment variables in these families can change Cargo dependency sources,
# compiler/formatter choice or wrapping, flags, target selection, or Python
# import behavior. Network proxy/certificate variables are deliberately
# preserved so the verifier's fetch-only phase can use the runner's normal
# network path.
STRIP_PREFIXES = ("CARGO_",)
STRIP_EXACT = {
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS",
    "RUSTDOC",
    "RUSTDOCFLAGS",
    "RUSTC_BOOTSTRAP",
    "RUSTFMT",
    "PYTHONHOME",
    "PYTHONPATH",
}


def sanitized_environment(source: dict[str, str]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for key, value in source.items():
        if key in STRIP_EXACT or key.startswith(STRIP_PREFIXES):
            continue
        clean[key] = value
    return clean


def cargo_config_candidates(start: Path) -> list[Path]:
    """Return Cargo config files Cargo could discover from this cwd upward."""
    start = start.resolve()
    candidates: list[Path] = []
    for directory in (start, *start.parents):
        cargo_dir = directory / ".cargo"
        for name in ("config", "config.toml"):
            candidate = cargo_dir / name
            if candidate.exists():
                candidates.append(candidate)
    return candidates


def require_clean_cargo_ancestry(start: Path) -> None:
    configs = cargo_config_candidates(start)
    if configs:
        rendered = ", ".join(str(path) for path in configs)
        raise HermeticLaunchError(
            "cannot establish clean Cargo config ancestry; discovered: " + rendered
        )


def reject_symlink_path(path: Path, *, stop: Path) -> None:
    """Reject symlinks in the lexical path from stop through path."""
    stop = stop.resolve()
    lexical = path if path.is_absolute() else stop / path
    lexical = Path(os.path.abspath(lexical))
    try:
        relative = lexical.relative_to(stop)
    except ValueError as exc:
        raise HermeticLaunchError("candidate path must stay inside repository") from exc

    current = stop
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise HermeticLaunchError(f"symlinked candidate path rejected: {current}")


def self_test() -> None:
    sample = {
        "PATH": "/bin",
        "CARGO_HOME": "/evil/cargo",
        "CARGO_REGISTRIES_CRATES_IO_INDEX": "https://example.invalid/index",
        "HTTPS_PROXY": "http://proxy.example",
    }
    for key in STRIP_EXACT:
        sample[key] = f"/injected/{key.lower()}"
    clean = sanitized_environment(sample)
    expected = {"PATH": "/bin", "HTTPS_PROXY": "http://proxy.example"}
    if clean != expected:
        raise HermeticLaunchError(
            f"environment sanitizer self-test failed: {clean!r} != {expected!r}"
        )

    with tempfile.TemporaryDirectory(prefix="noerith-hermetic-selftest-") as temp_dir:
        root = Path(temp_dir)
        child = root / "a" / "b"
        child.mkdir(parents=True)
        if cargo_config_candidates(child):
            raise HermeticLaunchError("clean Cargo ancestry self-test unexpectedly found config")
        config_dir = root / ".cargo"
        config_dir.mkdir()
        config = config_dir / "config.toml"
        config.write_text("[net]\noffline = true\n", encoding="utf-8")
        detected = cargo_config_candidates(child)
        if config not in detected:
            raise HermeticLaunchError("Cargo config ancestry self-test failed to detect override")

        candidate = root / "candidate"
        candidate.mkdir()
        symlink = root / "candidate-link"
        try:
            symlink.symlink_to(candidate, target_is_directory=True)
        except (OSError, NotImplementedError):
            # Production CI is Linux, but keep the launcher usable where
            # creating symlinks requires an unavailable privilege.
            pass
        else:
            try:
                reject_symlink_path(symlink, stop=root)
            except HermeticLaunchError:
                pass
            else:
                raise HermeticLaunchError(
                    "candidate-path self-test failed to reject symlink"
                )

        try:
            reject_symlink_path(Path("../outside"), stop=root)
        except HermeticLaunchError:
            pass
        else:
            raise HermeticLaunchError(
                "candidate-path self-test failed to reject repository escape"
            )

    print("hermetic verifier launcher self-tests passed", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("crate", type=Path)
    parser.add_argument(
        "--self-test-only",
        action="store_true",
        help="run launcher boundary self-tests without invoking Cargo/Rust",
    )
    args = parser.parse_args()

    self_test()
    if args.self_test_only:
        return 0

    repo_root = Path(__file__).resolve().parents[1]
    verifier = repo_root / "tools" / "verify_isolated_pinned_crate.py"
    if not verifier.is_file() or verifier.is_symlink():
        raise HermeticLaunchError(f"canonical verifier missing or symlinked: {verifier}")

    reject_symlink_path(args.crate, stop=repo_root)
    candidate = repo_root / args.crate
    if not candidate.is_dir():
        raise HermeticLaunchError(f"candidate crate directory does not exist: {candidate}")
    manifest = candidate / "Cargo.toml"
    if not manifest.is_file() or manifest.is_symlink():
        raise HermeticLaunchError(f"candidate Cargo.toml missing or symlinked: {manifest}")

    clean_env = sanitized_environment(dict(os.environ))

    # Cargo searches .cargo/config(.toml) from the process cwd through every
    # ancestor. Running the underlying verifier from an unrelated clean temp
    # directory prevents repository-local Cargo config from redefining sources,
    # patches, compiler wrappers, targets, or aliases behind the verifier's back.
    with tempfile.TemporaryDirectory(prefix="noerith-hermetic-launch-") as temp_dir:
        clean_cwd = Path(temp_dir)
        require_clean_cargo_ancestry(clean_cwd)
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                str(verifier),
                str(args.crate),
            ],
            cwd=clean_cwd,
            env=clean_env,
            check=False,
        )
    if completed.returncode != 0:
        raise HermeticLaunchError(
            f"pinned-crate verifier failed with exit code {completed.returncode}"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HermeticLaunchError as exc:
        print(f"hermetic launch error: {exc}", file=sys.stderr)
        raise SystemExit(1)
