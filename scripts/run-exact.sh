#!/usr/bin/env bash
# WHICH exact_level OUR SHAPES REACH (--gen-exact).
#
# regsafe takes an exact_level and behaves very differently per level (states.c):
#   EXACT        -> regs_exact(): memcmp + check_ids, the strictest comparison
#   NOT_EXACT    -> the precision short-circuit applies (!rold->precise matches anything)
#   RANGE_WITHIN -> range/tnum logic runs, precision short-circuit does NOT
# The main path picks `loop ? RANGE_WITHIN : NOT_EXACT` where loop = incomplete_read_marks
# (:1405) — NOT simply "there is a back-edge"; iterator paths pass RANGE_WITHIN
# (:1333/:1358/:1364); EXACT is used at :1372 for infinite-loop detection ONLY, and that
# prints "infinite loop detected at insn %d" — the one level confirmable from outside.
#
# Wanted:
#   inf.s6   -> reject WITH infinite_loop_detected=1 AND base_states >= 1. The state count
#               is the guard: a check_cfg rejection also says reject, but with ZERO states,
#               and then the EXACT path was never reached at all.
#   flat.s7 / flat.s6 -> 0050's precision gap, reproduced in-capture as the baseline.
#   loop.s7 / loop.s6 -> the same pair inside a may_goto loop. If a loop selected
#               RANGE_WITHIN the gap would CLOSE. Measured: it does not.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-exact-out.log"

echo "[run-exact] building harness + running --gen-exact in the VM ..."
HARNESS_ARGS=--gen-exact TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decision / EXACT marker / precision work / state count ==="
paste <(grep -oE 'genexact#[a-z]+\.s[0-9]+#[0-9]+' "$LOG") \
      <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+') \
      <(grep -E "^EXACT " "$LOG" | grep -oE 'infinite_loop_detected=[01] r7_backtracked=[0-9]+') \
      <(grep -E "^PRUNE " "$LOG" | grep -oE 'base_states=[0-9]+')

echo
echo "=== the EXACT path's own words ==="
grep -m1 "infinite loop detected" "$LOG" || echo "(NOT REACHED — check that the back-edge is CONDITIONAL)"

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
