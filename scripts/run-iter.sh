#!/usr/bin/env bash
# OPEN-CODED ITERATOR family (--gen-iter) — the loop mechanism the kernel special-cases
# in its own pruning path. `bpf_is_state_visited` (states.c) skips its usual loop
# detection for iterators because `states_maybe_looping()` is "too simplistic ... about
# ID remapping". OI-13 named it the densest target; this is that leg.
#
# Machinery: kfunc calls need BPF_PSEUDO_KFUNC_CALL plus a load-time BTF id, so with no
# libbpf the harness reads /sys/kernel/btf/vmlinux and walks the type section itself.
# Run scripts/probe-iter.sh first if anything looks wrong — a WRONG BTF id is not a load
# error, it is a call to a different function, and the probe prints the resolved ids.
#
# Three oracles ride along, none of them new: 0042's three-load pruning differential,
# 0041's store-location check and 0037's write-safety check. Iterators take at most eight
# trips and have none of may_goto's 250ms budget (0044), so the runtime half is cheap.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-iter-out.log"

echo "[run-iter] building harness + running --gen-iter in the VM ..."
HARNESS_ARGS=--gen-iter TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions ==="
paste <(grep -oE 'geniter#[a-z0-9]+\.o[0-9]+#[0-9]+' "$LOG") \
      <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+')

echo
echo "=== iterator state machine (must show BOTH active and drained) ==="
grep -oE "state=(active|drained)" "$LOG" | sort | uniq -c

echo
echo "=== where the stores actually LANDED ==="
awk '/^===PROG /{name=$2} /^RUNTIME /{for(i=1;i<=NF;i++) if($i ~ /^store_off=/) printf "%s %s\n", name, $i}' "$LOG" \
  | sort -u | awk '{a[$1]=a[$1]" "$2} END {for (k in a) print k, a[k]}' | sort

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
