#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if grep -R -nE --include='*.rs' 'current_route_(canonical_)?path[[:space:]]*\(' route/src; then
  echo "shared code must not dispatch on route identity" >&2
  exit 1
fi
if grep -R -lE --include='*.rs' 'secret_key|load_secret|"secrets"' route/files >/dev/null; then
  echo "route files must not access secret storage directly" >&2
  exit 1
fi
echo "route architecture check passed"
