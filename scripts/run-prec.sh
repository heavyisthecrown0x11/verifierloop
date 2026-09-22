#!/usr/bin/env bash
# PRECISION AS THE PRUNING LEVER (--gen-prec).
#
# regsafe (states.c:551) holds the strongest pruning rule in the verifier:
#     if (!rold->precise && exact == NOT_EXACT) return true;
# An imprecise old scalar matches ANY current scalar, so precision is exactly what STOPS
# a prune. If a register whose value decides memory safety is not marked precise, two
# states differing only in it are equated and the unsafe one is pruned away.
# mark_chain_precision has to get that right; precise.c is on the kernel's danger list;
# and the backtracker logs its work (mark_precise: frame%d: regs=%s, backtrack.c:280).
#
# The first two arms differ in ONE operand of ONE instruction — which register the store
# adds — so anything that differs between them is precision and nothing else. Wanted:
# `regs=r7` chased in the s7 arm and NEVER in the s6 arm, and the s7 arm exploring MORE
# states. Note the RAW mark_precise line count is higher in the s6 arm (the backtracker
# works on other registers too) — the count is not the signal, WHICH register is.
#
# Store offset 40 makes the verdict a pure function of the constant: in bounds iff
# umax <= 23, so 23 accepts and 24 rejects — an exact one-byte boundary.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-prec-out.log"

echo "[run-prec] building harness + running --gen-prec in the VM ..."
HARNESS_ARGS=--gen-prec TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions / precision work / state counts ==="
paste <(grep -oE 'genprec#c[0-9_]+\.s[0-9]+#[0-9]+' "$LOG") \
      <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+') \
      <(grep -E "^PREC " "$LOG" | grep -oE 'mark_precise_lines=[0-9]+') \
      <(grep -E "^PRUNE " "$LOG" | grep -oE 'base_states=[0-9]+')

echo
echo "=== WHICH register the backtracker chases (this is the signal, not the count) ==="
for a in "genprec#c8_16.s7#" "genprec#c8_16.s6#"; do
  printf "%-22s " "$a"
  awk -v a="$a" '$0 ~ "^===PROG "a, /^---END---/' "$LOG" \
    | grep "mark_precise:" | grep -oE "regs=r[0-9,]*" | sort | uniq -c | tr '\n' ' '
  echo
done

echo
echo "=== the store pointer's claims (fixed offsets print as imm=, not off=) ==="
awk '/^===PROG genprec#c8_16.s7#/,/^---END---/' "$LOG" \
  | grep -oE "R2=map_value\([^)]*\)" | sort -u

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
