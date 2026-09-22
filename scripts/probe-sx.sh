#!/usr/bin/env bash
# Calibration pair four (ae67b9fb8c4e) — the FIXED half, captured rather than derived.
#
# The buggy half is quoted from the commit message, which for once needs no reconstruction:
# that log is already in the format its kernel prints. The fixed half is this probe, run on
# the current tree, reproducing the commit's own disassembly at all three sign-extension
# widths:
#
#     r0 = bpf_get_prandom_u32(); r0 &= 1; r0 += <const>; r0 = (sN)r0
#
# Wanted: three accepts, and at insn 3 an untruncated 64-bit bound beside its 32-bit
# truncation — `umin=0xfffffffffffffffe,umin32=0xfffffffe`. The pipeline must report
# nothing; the buggy fixture must report tnum_bounds_inconsistent exactly once.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="${1:-$REPO_ROOT/.lab/harness-sx.log}"
HARNESS_ARGS=--probe-sx TIMEOUT="${TIMEOUT:-120}" scripts/run-harness-vm.sh "$LOG"
echo "[probe-sx] states at the sign-extending move:"
grep -E '^3: \(bf\) r0 = \(s[0-9]+\)r0' "$LOG" | sed 's/^/  /'
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 \
  | grep -E 'MEASURE (finding_count|parser|tnum)' | sed 's/^/  /' || true
