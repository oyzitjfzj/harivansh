#!/usr/bin/env bash
set -euo pipefail

bash -n scripts/run-noerith-action-outcome-full.sh
grep -Fq 'python3 -m unittest discover -s tools/tests' scripts/run-noerith-action-outcome-full.sh
grep -Fq 'python3 tools/grade_action_outcome_truth.py --self-test-only' scripts/run-noerith-action-outcome-full.sh
grep -Fq 'bash "$GITHUB_WORKSPACE/scripts/run-noerith-verification.sh"' scripts/run-noerith-action-outcome-full.sh

if grep -R -n -E 'set -x|cat .*\.log|tail .*\.log|tee .*\.log|actions/upload-artifact|gh .*upload' scripts/run-noerith-action-outcome-full.sh; then
  echo "NOERITH_ACTION_OUTCOME_FULL_PRIVACY_CONTRACT_FAILED" >&2
  exit 1
fi

echo "NOERITH_ACTION_OUTCOME_FULL_PRIVACY_CONTRACT=PASS"
