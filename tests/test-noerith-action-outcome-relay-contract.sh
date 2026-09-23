#!/usr/bin/env bash
set -euo pipefail

bash -n scripts/validate-noerith-sha.sh
bash -n scripts/checkout-noerith-private.sh
bash -n scripts/run-noerith-action-outcome-red.sh

grep -Fq 'PRIVATE_REPOSITORY="oyzitjfzj/NOERITH"' scripts/checkout-noerith-private.sh
grep -Fq 'fetch -q --no-tags --depth=1' scripts/checkout-noerith-private.sh
grep -Fq 'TARGET_SHA="${TARGET_SHA:?TARGET_SHA required}"' scripts/checkout-noerith-private.sh
grep -Fq 'TARGET_SHA="${TARGET_SHA:?TARGET_SHA required}"' scripts/run-noerith-action-outcome-red.sh
grep -Fq "ModuleNotFoundError: No module named 'tools.grade_action_outcome_truth'" scripts/run-noerith-action-outcome-red.sh

if grep -R -n -E 'set -x|cat .*\.log|tail .*\.log|tee .*\.log|actions/upload-artifact|gh .*upload' scripts/run-noerith-action-outcome-red.sh; then
  echo "NOERITH_ACTION_OUTCOME_RELAY_PRIVACY_CONTRACT_FAILED" >&2
  exit 1
fi

echo "NOERITH_ACTION_OUTCOME_RELAY_PRIVACY_CONTRACT=PASS"
