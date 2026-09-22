#!/usr/bin/env bash
# DYNPTR SLICES (--gen-dyn) — the first leg on a FRESH surface.
#
# What the verifier proves about a slice (verifier.c:13729):
#     regs[BPF_REG_0].mem_size = meta->arg_constant.value;   /* = buffer__szk */
# The static bound is THE CALLER'S CONSTANT — not the dynptr's extent, not size-offset.
# The real bound is enforced at runtime (helpers.c): bpf_dynptr_check_off_len, else NULL;
# and for a LOCAL dynptr the slice returns ptr->data + ptr->offset + offset, i.e. a
# pointer INTO the original memory — so the existing sentinel readback observes the whole
# two-part contract with no new oracle.
#
# PROGRAM TYPE MATTERS: bpf_dynptr_slice_rdwr requires a type that permits direct packet
# writes (verifier.c:13737) and applies that gate to EVERY dynptr type, including a LOCAL
# dynptr over a map value. socket_filter therefore rejects all of them; this family is
# SCHED_CLS. If every arm rejects with "the prog does not allow writes to packet data",
# that is the cause.
#
# Wanted: the static edge (k=7 accepts, k=8 rejects for szk=8); the two arms the verifier
# has NO basis for (szk=64 over a 32-byte dynptr, and off+szk past the extent) accepted
# statically and kept safe only by the runtime NULL — store_off=none WITH executed=0; and
# o24.z8.k7 landing at exactly 31, which is what confirms the slice hands back
# data + offset.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-dyn-out.log"

echo "[run-dyn] building harness + running --gen-dyn in the VM ..."
HARNESS_ARGS=--gen-dyn TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== resolved kfunc id ==="
grep "^CHANNEL" "$LOG" || echo "(BTF resolution failed)"

echo
echo "=== decision / runtime slice validity ==="
paste <(grep -oE 'gendyn#o[0-9]+\.z[0-9]+\.k[0-9]+#[0-9]+' "$LOG") \
      <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+') \
      <(grep -E "^DYN " "$LOG" | grep -oE 'runtime_slice_ok=[01]')

echo
echo "=== what the verifier proved about the slice (sz= is the CALLER'S constant) ==="
grep -oE "R0=mem\([^)]*\)" "$LOG" | sort -u

echo
echo "=== where the sentinels landed (none + executed=0 means the slice was NULL) ==="
awk '/^===PROG /{name=$2} /^RUNTIME /{off="";ex="";for(i=1;i<=NF;i++){if($i ~ /^store_off=/)off=$i; if($i ~ /^executed=/)ex=$i} printf "%s %s %s\n", name, off, ex}' "$LOG" \
  | sort -u | awk '{a[$1]=a[$1]" "$2"/"$3} END {for (k in a) print k, a[k]}' | sort

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
