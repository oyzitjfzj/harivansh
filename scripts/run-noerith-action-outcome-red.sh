#!/usr/bin/env bash
set -euo pipefail

ROOT="${RUNNER_TEMP:-/tmp}/noerith-private-source"
TARGET_SHA="${TARGET_SHA:?TARGET_SHA required}"
LOG="${RUNNER_TEMP:-/tmp}/noerith-action-outcome-red.log"

bash scripts/validate-noerith-sha.sh "$TARGET_SHA"

if [[ ! -d "$ROOT/.git" ]]; then
  echo "NOERITH_ACTION_OUTCOME_RED=UNEXPECTED phase=source-missing" >&2
  exit 70
fi

actual="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
if [[ "$actual" != "$TARGET_SHA" ]]; then
  echo "NOERITH_ACTION_OUTCOME_RED=UNEXPECTED phase=identity-mismatch" >&2
  exit 71
fi

cd "$ROOT"
if [[ -e tools/grade_action_outcome_truth.py ]]; then
  echo "NOERITH_ACTION_OUTCOME_RED=UNEXPECTED phase=implementation-already-present" >&2
  exit 72
fi

rm -f "$LOG"
trap 'rm -f "$LOG"' EXIT

set +e
python3 -m unittest   tools.tests.test_grade_action_outcome_truth.ActionOutcomeTruthGraderContractTests.test_exact_fresh_target_bound_outcome_passes   -v >"$LOG" 2>&1
status=$?
set -e

if [[ "$status" -eq 0 ]]; then
  echo "NOERITH_ACTION_OUTCOME_RED=UNEXPECTED phase=test-passed-before-implementation" >&2
  exit 73
fi

if ! grep -Fq "ModuleNotFoundError: No module named 'tools.grade_action_outcome_truth'" "$LOG"; then
  echo "NOERITH_ACTION_OUTCOME_RED=UNEXPECTED phase=wrong-failure" >&2
  exit 74
fi

echo "NOERITH_ACTION_OUTCOME_RED=PASS reason=missing-implementation-module sha=$actual"
