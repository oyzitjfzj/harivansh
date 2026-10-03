#!/usr/bin/env bash
set -euo pipefail

bash -n scripts/validate-noerith-sha.sh
bash -n scripts/checkout-noerith-private.sh
bash -n scripts/run-noerith-verification.sh

grep -Fq 'PRIVATE_REPOSITORY="oyzitjfzj/NOERITH"' scripts/checkout-noerith-private.sh
grep -Fq 'fetch -q --no-tags --depth=1' scripts/checkout-noerith-private.sh
grep -Fq 'rev-parse HEAD' scripts/checkout-noerith-private.sh
grep -Fq 'python3 tools/verify_linux_oci_sandbox.py --self-test-only' scripts/run-noerith-verification.sh
grep -Fq 'python3 tools/verify_isolated_std_crate.py crates/noerith-sandbox-oci' scripts/run-noerith-verification.sh
grep -Fq 'rustup toolchain install 1.98.1' scripts/run-noerith-verification.sh

workflow=".github/workflows/noerith-private-verify.yml"

grep -Fq 'persist-credentials: false' "$workflow"
grep -Fq 'PRIVATE_READ_TOKEN: ${{ secrets.PRIVATE_READ_TOKEN }}' "$workflow"
grep -Fq 'bash scripts/checkout-noerith-private.sh' "$workflow"
grep -Fq -- '--test validator --locked --message-format=json' "$workflow"
grep -Fq 'NOERITH_TASK5_ABSENT_INTERFACE_RED=' "$workflow"
grep -Fq 'rm -f "$LOG"' "$workflow"
grep -Fq 'rm -rf "$ROOT"' "$workflow"

# The Task-5 RED relay intentionally publishes only bounded status/error-code
# markers. It must not upload source, raw compiler logs, or a source archive.
if grep -Eq 'uses:[[:space:]]*actions/upload-artifact|path:.*noerith-private-source|path:.*q06-task5-red|cat[[:space:]].*\$LOG|tail[[:space:]].*\$LOG|tee[[:space:]].*\$LOG' "$workflow"; then
  echo "NOERITH_RELAY_PRIVACY_CONTRACT_FAILED=workflow-output-surface" >&2
  exit 1
fi

if grep -R -n -E 'set -x|cat .*\.log|tail .*\.log|tee .*\.log|actions/upload-artifact|gh .*upload' scripts >/dev/null; then
  echo "NOERITH_RELAY_PRIVACY_CONTRACT_FAILED=script-output-surface" >&2
  exit 1
fi

valid_sha=0123456789abcdef0123456789abcdef01234567
set +e
TARGET_SHA="$valid_sha" PRIVATE_READ_TOKEN='' RUNNER_TEMP="${RUNNER_TEMP:-/tmp}/noerith-missing-secret" \
  bash scripts/checkout-noerith-private.sh >/tmp/noerith-missing-secret.out 2>&1
status=$?
set -e

test "$status" -eq 65
grep -Fxq 'NOERITH_VERIFY_ACCESS_MISSING_CREDENTIAL' /tmp/noerith-missing-secret.out
if grep -Fq 'oyzitjfzj/NOERITH.git' /tmp/noerith-missing-secret.out; then
  echo "NOERITH_RELAY_PRIVACY_CONTRACT_FAILED=credential-error-leak" >&2
  exit 1
fi

rm -f /tmp/noerith-missing-secret.out
echo "NOERITH_RELAY_PRIVACY_CONTRACT_PASS"
