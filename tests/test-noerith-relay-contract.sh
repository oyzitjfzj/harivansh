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
grep -Fq 'TARGET_SHA="${TARGET_SHA:?TARGET_SHA required}"' scripts/checkout-noerith-private.sh
grep -Fq 'TARGET_SHA="${TARGET_SHA:?TARGET_SHA required}"' scripts/run-noerith-verification.sh

workflow=".github/workflows/noerith-private-verify.yml"
grep -Fq 'openssl cms -encrypt -binary -aes256' "$workflow"
grep -Fq 'certs/noerith-s05-evidence-recipient.pem' "$workflow"
grep -Fq 'uses: actions/upload-artifact@v4' "$workflow"
grep -Fq 'path: ${{ runner.temp }}/noerith-s05-evidence.cms' "$workflow"
grep -Fq 'retention-days: 1' "$workflow"
grep -Fq 'set +e' "$workflow"
if grep -E '^[[:space:]]*path:.*(noerith-s05-bundle|noerith-s05-evidence\.tar|qualification\.log|pull\.log)' "$workflow"; then
  echo "NOERITH_RELAY_PRIVACY_CONTRACT_FAILED" >&2
  exit 1
fi

if grep -R -n -E 'set -x|cat .*\.log|tail .*\.log|tee .*\.log|actions/upload-artifact|gh .*upload' scripts; then
  echo "NOERITH_RELAY_PRIVACY_CONTRACT_FAILED" >&2
  exit 1
fi

valid_sha=0123456789abcdef0123456789abcdef01234567
set +e
TARGET_SHA="$valid_sha" PRIVATE_READ_TOKEN='' RUNNER_TEMP="${RUNNER_TEMP:-/tmp}/noerith-missing-secret"   bash scripts/checkout-noerith-private.sh >/tmp/noerith-missing-secret.out 2>&1
status=$?
set -e

test "$status" -eq 65
grep -Fxq 'NOERITH_VERIFY_ACCESS_MISSING_CREDENTIAL' /tmp/noerith-missing-secret.out
if grep -Fq 'oyzitjfzj/NOERITH.git' /tmp/noerith-missing-secret.out; then
  echo "NOERITH_RELAY_PRIVACY_CONTRACT_FAILED" >&2
  exit 1
fi
