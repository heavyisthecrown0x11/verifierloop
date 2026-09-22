#!/usr/bin/env bash
# LOOP FIXPOINT vs RUNTIME (--gen-loopr) — 0041's location oracle, now on a back-edge.
#
# 0043 asked whether a loop program's VERDICT survives a change in checkpoint frequency.
# This asks the stronger question: the verifier proves a bound on the offset register by
# computing a FIXPOINT over an unbounded number of iterations; the runtime then picks one
# concrete count out of millions. The store must land inside the proven set whichever
# count it picks. It also closes 0043's hole — that family emits a STORE line but never
# executes, so store_locations_checked was 0 and the claim was never read.
#
# COST WAS MEASURED FIRST (scripts/probe-loopr.sh): x86-64 has
# bpf_jit_supports_timed_may_goto(), so the budget is TIME-based and every run spends the
# full NSEC_PER_SEC/4 — measured 250.3/250.5/251.4 ms. Six accepted shapes x eight inputs
# is ~12s of kernel-side spinning. Time-based is what makes it safe under KCOV+KASAN
# (OI-11): slowness lowers the iteration count inside the same 250ms, it does not extend
# the run.
#
# The sweep is this family's own: the shared RT_INPUTS collapses to only five distinct
# residues of `input & 7`, so LOOPR_INPUTS covers all eight instead.
#
# Run outside auto mode (default permission mode) or from a fresh session if a
# mid-session tool-access drop blocks the build/VM steps.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-loopr-out.log"

echo "[run-loopr] building harness + running --gen-loopr in the VM (~12s of spinning) ..."
HARNESS_ARGS=--gen-loopr TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions ==="
paste <(grep -oE 'genloopr#[a-z0-9]+#[0-9]+' "$LOG") \
      <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+')

echo
echo "=== what the verifier PROVED at the store ==="
grep -E "^[0-9]+: R[0-9]+=" "$LOG" | grep "R7=map_value" | sort -u

echo
echo "=== where the stores actually LANDED (base is +56, so r6 = off - 56) ==="
awk '/^===PROG /{name=$2} /^RUNTIME /{for(i=1;i<=NF;i++) if($i ~ /^store_off=/) printf "%s %s\n", name, $i}' "$LOG" \
  | sort -u | awk '{a[$1]=a[$1]" "$2} END {for (k in a) print k, a[k]}' | sort

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
