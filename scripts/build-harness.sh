#!/usr/bin/env bash
# Build the guest-side differential/verifier-log harness -> harness/diffharness.
# Static by default so it runs unchanged inside the disposable VM; falls back to
# dynamic if the static toolchain is unavailable.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/harness/diffharness.c"
OUT="$REPO_ROOT/harness/diffharness"

if cc -O2 -static -o "$OUT" "$SRC" 2>/dev/null; then
  echo "[build-harness] static build -> $OUT"
else
  cc -O2 -o "$OUT" "$SRC"
  echo "[build-harness] dynamic build (static toolchain unavailable) -> $OUT"
fi
echo "[build-harness] run inside the VM (or as root): $OUT"
