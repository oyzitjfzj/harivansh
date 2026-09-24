#!/usr/bin/env bash
set -euo pipefail

sha="${1:-}"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "NOERITH_VERIFY_INPUT_INVALID_SHA" >&2
  exit 64
fi
