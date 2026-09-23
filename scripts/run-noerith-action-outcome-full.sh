#!/usr/bin/env bash
set -euo pipefail

ROOT="${RUNNER_TEMP:-/tmp}/noerith-private-source"
TARGET_SHA="${TARGET_SHA:?TARGET_SHA required}"
LOG_DIR="${RUNNER_TEMP:-/tmp}/noerith-action-outcome-full-logs"

bash scripts/validate-noerith-sha.sh "$TARGET_SHA"

if [[ ! -d "$ROOT/.git" ]]; then
  echo "NOERITH_ACTION_OUTCOME_FULL=FAIL phase=source-missing" >&2
  exit 70
fi

actual="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
if [[ "$actual" != "$TARGET_SHA" ]]; then
  echo "NOERITH_ACTION_OUTCOME_FULL=FAIL phase=identity-mismatch" >&2
  exit 71
fi

rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"
trap 'rm -rf "$LOG_DIR"' EXIT

run_gate() {
  local name="$1"
  shift
  local log="$LOG_DIR/$name.log"
  echo "NOERITH_ACTION_OUTCOME_FULL_PHASE=$name"
  if ! "$@" >"$log" 2>&1; then
    echo "NOERITH_ACTION_OUTCOME_FULL=FAIL phase=$name" >&2
    exit 72
  fi
}

cd "$ROOT"
run_gate python-compile python3 -m py_compile   tools/grade_action_outcome_truth.py   tools/grade_software_test_outcomes.py   tools/run_software_test_outcome_protocol_calibration.py   tools/verify_grader_calibration.py   tools/verify_software_test_outcome_state_space.py
run_gate python-tools-suite python3 -m unittest discover -s tools/tests -p 'test_*.py' -v
run_gate action-grader-self-test python3 tools/grade_action_outcome_truth.py --self-test-only

echo "NOERITH_ACTION_OUTCOME_FULL_PHASE=s05-existing-gates"
(
  cd "$GITHUB_WORKSPACE"
  TARGET_SHA="$TARGET_SHA" RUNNER_TEMP="${RUNNER_TEMP:-/tmp}" bash scripts/run-noerith-verification.sh
)

final_sha="$(git rev-parse HEAD 2>/dev/null || true)"
if [[ "$final_sha" != "$TARGET_SHA" ]]; then
  echo "NOERITH_ACTION_OUTCOME_FULL=FAIL phase=post-verify-identity-mismatch" >&2
  exit 73
fi

echo "NOERITH_ACTION_OUTCOME_FULL=PASS sha=$final_sha"
