#!/usr/bin/env bash
set -euo pipefail

ROOT="${RUNNER_TEMP:-/tmp}/noerith-private-source"
TEMP="$(mktemp -d "${RUNNER_TEMP:-/tmp}/noerith-task4-targeted.XXXXXX")"
trap 'rm -rf "$TEMP"' EXIT

mkdir -p "$TEMP/src" "$TEMP/tests"
cp -R "$ROOT/crates/noerith-capabilities/src/." "$TEMP/src/"
cp "$ROOT/crates/noerith-capabilities/tests/linux_oci_environment_qualification.rs" "$TEMP/tests/"

cat > "$TEMP/Cargo.toml" <<'EOF'
[package]
name = "noerith-capabilities"
version = "0.1.0"
edition = "2024"
rust-version = "1.98.1"
publish = false

[lib]
path = "src/lib.rs"

[dependencies.sha2]
version = "=0.11.0"
default-features = false
EOF

cargo test --manifest-path "$TEMP/Cargo.toml" --test linux_oci_environment_qualification
