#!/usr/bin/env bash
# TRYING TO REACH RANGE_WITHIN ON PURPOSE (--gen-rw) — and the limit it establishes.
#
# 0051 found that a may_goto loop does not select RANGE_WITHIN. This aims at a call site
# that passes it unconditionally (states.c:1333, the iterator's next-call instruction) by
# splitting BEFORE the loop, so the two states meet THERE and not at an ordinary body
# instruction — getting that wrong just re-measures the main NOT_EXACT path.
#
# Wanted: iter_active > 0 on the iter arms and 0 on the flat ones (or the comparison is
# between two straight-line programs wearing different names), and the iterator arms'
# active-state counts in a clean 2:1 ratio — the precise arm carries both register values
# through every iterator state, the imprecise one a single merged value.
#
# WHAT THIS CANNOT SHOW, and it is the leg's real result: the exact_level of an individual
# prune. Reading :1333 to the end, `goto hit` IS a prune path, so RANGE_WITHIN can merge
# there; the block is gated on sl->state.branches and completed states fall through to
# :1405 with `loop ? RANGE_WITHIN : NOT_EXACT`. Both can merge our pair and the log never
# names which fired. EXACT is the only level with an external marker ("infinite loop
# detected", 0051). Do not spend another leg predicting levels from context.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-rw-out.log"

echo "[run-rw] building harness + running --gen-rw in the VM ..."
HARNESS_ARGS=--gen-rw TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== ctx / decision / precision work / iterator states / total states ==="
paste <(grep -oE 'genrw#[a-z]+\.s[0-9]+#[0-9]+' "$LOG") \
      <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+') \
      <(grep -E "^RW " "$LOG" | grep -oE 'r7_backtracked=[0-9]+ iter_active=[0-9]+') \
      <(grep -E "^PRUNE " "$LOG" | grep -oE 'base_states=[0-9]+')

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
