#!/usr/bin/env bash
# PRUNING-SOUNDNESS differential (--gen-prune) — a KERNEL-vs-KERNEL oracle.
#
# Every earlier leg compares the verifier against something WE compute: an invariant,
# a parsed bound, a runtime observation. This one compares the verifier against ITSELF,
# using a flag the kernel ships for exactly this purpose — so there is no bound parsing
# and no oracle of ours that can be wrong.
#
# BPF_F_TEST_STATE_FREQ (states.c: `force_new_state = env->test_state_freq || ...`)
# forces a checkpoint at EVERY instruction, where the default heuristic waits for >= 2
# jumps AND >= 8 instructions. It therefore makes pruning MORE aggressive, not less:
# regsafe()/states_equal() get far more candidate pairs to judge.
#
# THE PREDICATE IS DIRECTIONAL:
#   freq ACCEPT + base REJECT -> a path that produced the rejection was pruned away:
#                                a PRUNING SOUNDNESS bug. This is the finding.
#   freq REJECT + base ACCEPT -> classified, NOT counted: state-freq inflates the state
#                                count, so BPF_COMPLEXITY_LIMIT_INSNS ("BPF program is
#                                too large", -E2BIG) can reject a program the default
#                                run accepts. That is a resource artefact.
# A difference in state COUNT is not a finding either — it is the DENOMINATOR proving
# the flag engaged. Identical counts would make a zero finding count meaningless.
#
# Third channel, one flag bit: BPF_F_TEST_REG_INVARIANTS turns the kernel's own bounds
# sanity check (reg_bounds_sanity_check, verifier.c:2189 — literally our invariants
# A/B/C) into a hard -EFAULT. A program that loads clean by default but EFAULTs under
# the flag is a desync we could never observe from outside.
#
# Run outside auto mode (default permission mode) or from a fresh session if a
# mid-session tool-access drop blocks the build/VM steps.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-prune-out.log"

echo "[run-prune] building harness + running --gen-prune in the VM ..."
HARNESS_ARGS=--gen-prune TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== the differential, per program ==="
grep -E "^PRUNE " "$LOG" | sed -E 's/^PRUNE //' | while read -r line; do echo "$line"; done

echo
echo "=== decision agreement (base vs freq vs inv) ==="
awk '/^===PROG /{name=$2}
     /^PRUNE /{b=f=i=""; for(j=1;j<=NF;j++){
        if($j ~ /^base_verdict=/){split($j,a,"="); b=a[2]}
        if($j ~ /^freq_verdict=/){split($j,a,"="); f=a[2]}
        if($j ~ /^inv_verdict=/){split($j,a,"="); i=a[2]}}
        printf "%-28s base=%-6s freq=%-6s inv=%-6s %s\n", name, b, f, i,
               (b==f && b==i) ? "agree" : "*** DIFFER ***"}' "$LOG"

echo
echo "=== non-vacuity: did the flag actually change the state space? ==="
awk '/^===PROG /{name=$2}
     /^PRUNE /{bs=fs=""; for(j=1;j<=NF;j++){
        if($j ~ /^base_states=/){split($j,a,"="); bs=a[2]}
        if($j ~ /^freq_states=/){split($j,a,"="); fs=a[2]}}
        printf "%-28s base_states=%-5s freq_states=%-5s %s\n", name, bs, fs,
               (fs+0 > bs+0) ? "flag engaged" : "*** NO EFFECT ***"}' "$LOG"

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
