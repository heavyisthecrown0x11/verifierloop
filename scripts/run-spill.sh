#!/usr/bin/env bash
# SPILLED LINKS and DELTA ARITHMETIC (--gen-spill).
#
# Two gaps left by 0046-0048, both in one line of sync_linked_regs (verifier.c:16847):
#   reg = e->is_reg ? &frame[e->frameno]->regs[e->regno]
#                   : &frame[e->frameno]->stack[e->spi].spilled_ptr;
# (1) a linked class spans STACK SLOTS, and stacksafe has its own check_ids calls;
# (2) the ADD_CONST branch does real arithmetic when two members carry different deltas:
#     __mark_reg_known(&fake_reg, (s64)reg->delta - (s64)known_reg->delta).
# Every id family before this kept its scalars in registers with a single delta.
#
# Wanted: for each shape the one-path variant REJECTS and the both-path variant ACCEPTS.
# And for the delta arm, acceptance is not enough — a too-wide but still-safe bound would
# accept too, so check the NUMBERS: with r6 narrowed to [0,7], the delta-12 member must
# read exactly umin=12 umax=19, and the kernel renders its id as `base+12`.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-spill-out.log"

echo "[run-spill] building harness + running --gen-spill in the VM ..."
HARNESS_ARGS=--gen-spill TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions (one must REJECT, both must ACCEPT, per shape) ==="
paste <(grep -oE 'genspill#[a-z0-9]+\.[a-z]+\.s[0-9]+#[0-9]+' "$LOG") \
      <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+')

echo
echo "=== the spilled slot: wide before the check, narrowed after, same id ==="
awk '/^===PROG genspill#spill.both.s0#/,/^---END---/' "$LOG" \
  | grep -oE "fp-16=scalar\(id=[0-9]+[^)]*\)" | sed 's/,var_off.*//' | sort -u

echo
echo "=== delta arithmetic: base [0,7] and the delta-12 member must be exactly [12,19] ==="
awk '/^===PROG genspill#delta.both.s9#/,/^---END---/' "$LOG" \
  | grep -E "if r6 > 0x7" | grep -oE "R[69]=scalar\(id=[0-9+]*[^)]*\)" | sed 's/,var_off.*//' | sort -u

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
