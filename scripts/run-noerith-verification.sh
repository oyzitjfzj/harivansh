#!/usr/bin/env bash
set -euo pipefail

ROOT="${RUNNER_TEMP:-/tmp}/noerith-private-source"
LOG_DIR="${RUNNER_TEMP:-/tmp}/noerith-private-verify-logs"
TARGET_SHA="${TARGET_SHA:-}"
DIAG_DIR="${NOERITH_ENCRYPTED_DIAGNOSTIC_DIR:-}"

bash scripts/validate-noerith-sha.sh "$TARGET_SHA"

if [[ ! -d "$ROOT/.git" ]]; then
  echo "NOERITH_VERIFY_RESULT=FAIL phase=source-missing" >&2
  exit 70
fi

actual="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
if [[ "$actual" != "$TARGET_SHA" ]]; then
  echo "NOERITH_VERIFY_RESULT=FAIL phase=identity-mismatch" >&2
  exit 71
fi

rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"
trap 'rm -rf "$LOG_DIR"' EXIT

run_gate() {
  local name="$1"
  shift
  local log="$LOG_DIR/${name}.log"
  echo "NOERITH_VERIFY_PHASE=$name"
  if ! "$@" >"$log" 2>&1; then
    if [[ -n "$DIAG_DIR" ]]; then
      mkdir -p "$DIAG_DIR"
      cp "$log" "$DIAG_DIR/current-head-${name}.log"
    fi
    echo "NOERITH_VERIFY_RESULT=FAIL phase=$name" >&2
    exit 72
  fi
}

cd "$ROOT"

run_gate python-compile python3 -m py_compile tools/verify_linux_oci_sandbox.py
run_gate python-qualification-selftest python3 tools/verify_linux_oci_sandbox.py --self-test-only
run_gate toolchain-install rustup toolchain install 1.98.1 --profile minimal --component rustfmt --component clippy --no-self-update
export RUSTUP_TOOLCHAIN=1.98.1
run_gate isolated-oci python3 tools/verify_isolated_std_crate.py crates/noerith-sandbox-oci

final_sha="$(git rev-parse HEAD 2>/dev/null || true)"
if [[ "$final_sha" != "$TARGET_SHA" ]]; then
  echo "NOERITH_VERIFY_RESULT=FAIL phase=post-verify-identity-mismatch" >&2
  exit 73
fi

echo "NOERITH_VERIFY_RESULT=PASS sha=$final_sha"
