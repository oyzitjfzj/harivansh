#!/usr/bin/env bash
set -euo pipefail

ROOT="${RUNNER_TEMP:-/tmp}/noerith-private-source"
TARGET_SHA="${TARGET_SHA:?TARGET_SHA required}"
LOG_DIR="${RUNNER_TEMP:-/tmp}/noerith-action-outcome-green-logs"

bash scripts/validate-noerith-sha.sh "$TARGET_SHA"

if [[ ! -d "$ROOT/.git" ]]; then
  echo "NOERITH_ACTION_OUTCOME_GREEN=FAIL phase=source-missing" >&2
  exit 70
fi

actual="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
if [[ "$actual" != "$TARGET_SHA" ]]; then
  echo "NOERITH_ACTION_OUTCOME_GREEN=FAIL phase=identity-mismatch" >&2
  exit 71
fi

rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"
trap 'rm -rf "$LOG_DIR"' EXIT

run_gate() {
  local name="$1"
  shift
  local log="$LOG_DIR/$name.log"
  echo "NOERITH_ACTION_OUTCOME_PHASE=$name"
  if ! "$@" >"$log" 2>&1; then
    echo "NOERITH_ACTION_OUTCOME_GREEN=FAIL phase=$name" >&2
    exit 72
  fi
}

cd "$ROOT"
run_gate python-compile python3 -m py_compile   tools/grade_action_outcome_truth.py   tools/tests/test_grade_action_outcome_truth.py
run_gate focused-contract python3 -m unittest tools.tests.test_grade_action_outcome_truth -v
run_gate grader-self-test python3 tools/grade_action_outcome_truth.py --self-test-only

final_sha="$(git rev-parse HEAD 2>/dev/null || true)"
if [[ "$final_sha" != "$TARGET_SHA" ]]; then
  echo "NOERITH_ACTION_OUTCOME_GREEN=FAIL phase=post-verify-identity-mismatch" >&2
  exit 73
fi

echo "NOERITH_ACTION_OUTCOME_GREEN=PASS sha=$final_sha"
