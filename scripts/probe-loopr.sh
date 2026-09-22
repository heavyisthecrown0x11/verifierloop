#!/usr/bin/env bash
# Cost probe for the loop-runtime leg (--probe-loopr): how long does ONE may_goto program
# actually spin? On x86-64 bpf_jit_supports_timed_may_goto() is true, so the budget is
# time-based (NSEC_PER_SEC/4) rather than the 8M-iteration BPF_MAX_LOOPS count. Measure
# it before committing to a family that would spend it once per run per input — OI-11 is
# the lesson that says do not guess about long in-kernel execution under KCOV+KASAN.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-probe-loopr.log"
HARNESS_ARGS=--probe-loopr TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"
echo
echo "=== measured budget and landing site per shape ==="
grep "^CHANNEL" "$LOG"
