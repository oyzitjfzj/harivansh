#!/usr/bin/env bash
set -euo pipefail

bash -n scripts/validate-noerith-sha.sh
bash -n scripts/checkout-noerith-private.sh
bash -n scripts/run-noerith-action-outcome-green.sh

grep -Fq 'TARGET_SHA="${TARGET_SHA:?TARGET_SHA required}"' scripts/checkout-noerith-private.sh
grep -Fq 'TARGET_SHA="${TARGET_SHA:?TARGET_SHA required}"' scripts/run-noerith-action-outcome-green.sh
grep -Fq 'python3 -m unittest tools.tests.test_grade_action_outcome_truth -v' scripts/run-noerith-action-outcome-green.sh
grep -Fq 'python3 tools/grade_action_outcome_truth.py --self-test-only' scripts/run-noerith-action-outcome-green.sh

if grep -R -n -E 'set -x|cat .*\.log|tail .*\.log|tee .*\.log|actions/upload-artifact|gh .*upload' scripts/run-noerith-action-outcome-green.sh; then
  echo "NOERITH_ACTION_OUTCOME_GREEN_PRIVACY_CONTRACT_FAILED" >&2
  exit 1
fi

echo "NOERITH_ACTION_OUTCOME_GREEN_PRIVACY_CONTRACT=PASS"
