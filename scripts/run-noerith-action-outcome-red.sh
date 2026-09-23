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
test -f tools/grade_action_outcome_truth.py

rm -f "$LOG"
trap 'rm -f "$LOG"' EXIT

set +e
python3 -m unittest   tools.tests.test_grade_action_outcome_truth.ActionOutcomeTruthGraderContractTests.test_unknown_schema_fields_fail_closed_instead_of_disappearing_from_identity   -v >"$LOG" 2>&1
status=$?
set -e

if [[ "$status" -eq 0 ]]; then
  echo "NOERITH_ACTION_OUTCOME_RED=UNEXPECTED phase=test-passed-before-hardening" >&2
  exit 73
fi

if ! grep -Fq "GraderInputError not raised" "$LOG"; then
  echo "NOERITH_ACTION_OUTCOME_RED=UNEXPECTED phase=wrong-failure" >&2
  exit 74
fi

echo "NOERITH_ACTION_OUTCOME_RED=PASS reason=unknown-field-not-rejected sha=$actual"
