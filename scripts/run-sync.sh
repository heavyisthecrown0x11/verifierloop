#!/usr/bin/env bash
# T1-1b first increment: build the harness, run the 32<->64 sync-fragile family
# (--gen-sync) in the VM, and measure it with the pipeline.
#
# Wanted result (fixed kernel, reusing the existing invariant B):
#   reg32_checked > 0     (B runs across the sync states -> a regression would fire)
#   finding_count = 0     (B silent -> the kernel is sync-consistent; working guard)
#   parser_unrecognized = 0
#
# Run outside auto mode (default permission mode) or a fresh session if the safety
# classifier blocks the build/VM steps mid-session.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LOG="$REPO_ROOT/.lab/harness-sync-out.log"

echo "[run-sync] building harness + running --gen-sync in the VM ..."
HARNESS_ARGS=--gen-sync TIMEOUT=150 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions (first + last few) ==="
grep -E "===PROG gensync|^RESULT" "$LOG" | head -8
echo "..."
grep -E "===PROG gensync|^RESULT" "$LOG" | tail -4

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 \
  | grep -E "MEASURE"
