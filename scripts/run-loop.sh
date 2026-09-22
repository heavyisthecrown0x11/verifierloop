#!/usr/bin/env bash
# BACK-EDGE / LOOP-CONVERGENCE family (--gen-loop) — the first program shape with a loop.
#
# Every family before this one is a forward DAG. That is the root cause of six legs of
# zero findings (devlog 0042): the real bug list lives in state pruning, precision and
# convergence, and none of those is reachable without a back-edge.
#
# The ORACLE is 0042's, transferred UNCHANGED — same three loads (default /
# BPF_F_TEST_STATE_FREQ / BPF_F_TEST_REG_INVARIANTS), same directional predicate
# (flagged ACCEPT over default REJECT = pruning soundness bug; the reverse is classified
# as a resource artefact), same `freq_states > base_states` denominator. This leg is a
# pure INPUT increment, which is the point.
#
# MECHANISM: may_goto (OI-13). One raw instruction — BPF_JCOND = 0xe0, BPF_MAY_GOTO = 0,
# dst_reg and imm must be 0 — no BTF, no kfunc, no subprog. The jump target is the loop
# EXIT (confirmed against the kernel's own __cond_break macro) and the fall-through
# continues into the body. On the fall-through the verifier bumps may_goto_depth and
# calls widen_imprecise_scalars() against the previous entry at the same instruction
# (verifier.c:16923) — a deliberate convergence over-approximation sitting on top of
# precision marking and pruning.
#
# Wanted result (a sound kernel): the state reaching the store is the JOIN over 0, 1,
# 2, ... iterations, so with the store at +56 the program is acceptable iff that join
# keeps umax(r6) <= 7. Sharp pairs: incmask ([0,7], accept) vs maskinc ([1,8], reject) —
# same two operations, opposite order, one byte apart; and mask.m7 (accept) vs mask.m63
# (reject) — same body, and the only difference is that entering wide and breaking
# immediately leaves the wide range at the store.
#
# Run outside auto mode (default permission mode) or from a fresh session if a
# mid-session tool-access drop blocks the build/VM steps.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-loop-out.log"

echo "[run-loop] building harness + running --gen-loop in the VM ..."
HARNESS_ARGS=--gen-loop TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decision per arm (does the back-edge family even load?) ==="
paste <(grep -oE 'genloop#[a-z0-9]+\.m[0-9]+#[0-9]+' "$LOG") \
      <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+') \
      <(grep -E "^LOOP " "$LOG")

echo
echo "=== the differential (base vs freq vs inv) ==="
awk '/^===PROG /{name=$2}
     /^PRUNE /{b=f=i=bs=fs=""; for(j=1;j<=NF;j++){
        if($j ~ /^base_verdict=/){split($j,a,"="); b=a[2]}
        if($j ~ /^freq_verdict=/){split($j,a,"="); f=a[2]}
        if($j ~ /^inv_verdict=/){split($j,a,"="); i=a[2]}
        if($j ~ /^base_states=/){split($j,a,"="); bs=a[2]}
        if($j ~ /^freq_states=/){split($j,a,"="); fs=a[2]}}
        printf "%-26s base=%-6s freq=%-6s inv=%-6s  states %s->%s %s%s\n", name, b, f, i, bs, fs,
               (b==f && b==i) ? "agree" : "*** DIFFER ***",
               (fs+0 > bs+0) ? "" : "  *** FLAG NO EFFECT ***"}' "$LOG"

echo
echo "=== what the verifier proved about r6 at the store ==="
grep -E "^[0-9]+: R[0-9]+=" "$LOG" | grep "R7=map_value" | sort -u

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
