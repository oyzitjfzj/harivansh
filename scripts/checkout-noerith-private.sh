#!/usr/bin/env bash
set -euo pipefail

PRIVATE_REPOSITORY="oyzitjfzj/NOERITH"
TARGET_SHA="0607af3e88f4e13b691e9ebbdb389d4e51e32991"
PRIVATE_READ_TOKEN="${PRIVATE_READ_TOKEN:-}"
DEST="${RUNNER_TEMP:-/tmp}/noerith-private-source"
ACCESS_LOG="${RUNNER_TEMP:-/tmp}/noerith-private-access.log"

bash scripts/validate-noerith-sha.sh "$TARGET_SHA"

if [[ -z "$PRIVATE_READ_TOKEN" ]]; then
  echo "NOERITH_VERIFY_ACCESS_MISSING_CREDENTIAL" >&2
  exit 65
fi

cleanup() {
  unset PRIVATE_READ_TOKEN auth
}
trap cleanup EXIT

rm -rf "$DEST"
mkdir -p "$DEST"
: > "$ACCESS_LOG"
git -C "$DEST" init -q

auth="$(printf 'x-access-token:%s' "$PRIVATE_READ_TOKEN" | base64 | tr -d '\n')"

if ! GIT_TERMINAL_PROMPT=0 GCM_INTERACTIVE=never   git -C "$DEST"     -c "http.https://github.com/.extraheader=AUTHORIZATION: basic $auth"     fetch -q --no-tags --depth=1     "https://github.com/${PRIVATE_REPOSITORY}.git" "$TARGET_SHA"     >"$ACCESS_LOG" 2>&1; then
  echo "NOERITH_VERIFY_ACCESS_FAILED" >&2
  exit 67
fi

if ! git -C "$DEST" checkout -q --detach FETCH_HEAD >>"$ACCESS_LOG" 2>&1; then
  echo "NOERITH_VERIFY_CHECKOUT_FAILED" >&2
  exit 68
fi

actual="$(git -C "$DEST" rev-parse HEAD 2>>"$ACCESS_LOG")"
if [[ "$actual" != "$TARGET_SHA" ]]; then
  echo "NOERITH_VERIFY_IDENTITY_MISMATCH" >&2
  exit 66
fi

echo "NOERITH_VERIFY_ACCESS_OK"
echo "NOERITH_VERIFY_IDENTITY_OK"
