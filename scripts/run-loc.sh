#!/usr/bin/env bash
# STORE-LOCATION DESYNC oracle (--gen-loc) — the strictly stronger memory-safety
# question, and the one the whole runtime-oracle era was built to reach.
#
# 0037/0038/0039 ask: did the store stay INSIDE the object? A verifier can pass that
# and still be wrong — if its abstract arithmetic for the offset is unsound, the store
# lands at an offset its OWN state says is impossible while still landing inside the
# object, so every earlier leg stays silent. That is the "consistent-but-wrong" class:
# the verifier's two views agree with each other and disagree only with reality, which
# no internal-consistency invariant can see by construction.
#
# This family asks instead: did the store land WHERE THE VERIFIER SAID it could? The
# verifier prints its own claim at the store instruction —
#   17: R7=map_value(ks=4,vs=64,smin=0,smax=umax=7,var_off=(0x0; 0x7))
#   17: (72) *(u8 *)(r7 +0) = -1
# — "in [0,7], and only at offsets whose bits fit (0x0; 0x7)". The runtime says where
# the sentinel actually landed. The diff stage (check_store_location) compares them.
#
# The axis is the ALU chain that shapes the offset: one program per abstract transfer
# function, because an unsound (too narrow) bound is what a wrong transfer function
# produces. The tnum arms are the sharpest: `r6 &= 3; r6 <<= 2` proves {0,4,8,12}, so
# an offset of 6 is INSIDE [0,12] and still impossible — an interval check alone would
# miss it, and the tnum half is what makes "where it SAID" mean the exact set.
#
# Wanted result (a sound kernel):
#   records=15 (accept=15 reject=0)   the decision is not the surface here
#   store_locations_checked = 180     15 programs x 12 sweep inputs, all evaluated
#   finding_count = 0                 every store landed inside its proven set
#   parser_unrecognized = 0
#
# A `store_location_desync` finding fires when an accepted program's store landed
# outside `ptr_off + insn_off + [umin, umax]`, or inside that interval but at an
# offset the pointer's var_off tnum excludes. Either way the verifier proved something
# the machine then contradicted.
#
# NOTE on store_locations_checked: it must be > 0 for a zero finding count to mean
# anything. If it is 0 while records=15, the diff stage found no usable pointer claim
# at the store (a parse gap, not a clean kernel) — investigate before reading the zero.
#
# Run outside auto mode (default permission mode) or from a fresh session if a
# mid-session tool-access drop blocks the build/VM steps.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-loc-out.log"

echo "[run-loc] building harness + running --gen-loc in the VM ..."
HARNESS_ARGS=--gen-loc TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions + declared store site ==="
paste <(grep -oE 'genloc#[a-z0-9]+#[0-9]+' "$LOG") \
      <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+') \
      <(grep -E "^STORE " "$LOG")

echo
echo "=== what the verifier PROVED at each store (its own claim) ==="
grep -E "^[0-9]+: R[0-9]+=" "$LOG" | grep "R7=map_value" | sort -u

echo
echo "=== where the stores actually LANDED (per program, distinct offsets) ==="
awk '/^===PROG /{name=$2} /^RUNTIME /{for(i=1;i<=NF;i++) if($i ~ /^store_off=/) print name, $i}' "$LOG" \
  | sort -u | awk '{a[$1]=a[$1]" "$2} END {for (k in a) print k, a[k]}' | sort

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
