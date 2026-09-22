#!/usr/bin/env bash
# COMPOSITION GENERATOR (--gen-comp) — random compositions of the pieces built across
# 0043-0053, with the oracles held fixed.
#
# WHY: every family before this produces shapes whose bug class can be NAMED, so "clean"
# has only meant "clean on the shapes I thought to write". Random composition starts to
# say something about shapes nobody named.
#
# THE HARD PART IS VALIDITY. A randomly concatenated program is almost always rejected and
# never reaches the runtime oracles — a denominator-zero trap one layer above the ones
# 0041-0050 kept finding. The generator therefore walks a typed CONTEXT: each piece
# declares what it REQUIRES of the live state and what it PROVIDES, and only pieces whose
# requirements hold are offered. dynptr is the piece that forces the context to be richer
# than register types: it consumes a STACK_DYNPTR slot pair tracked by id and yields a
# PTR_TO_MEM plus an OFFSET into the map value that the store's declared offset must be
# expressed in (0053's coordinate translation, generalised).
#
# THE NUMBER TO WATCH IS NOT THE ACCEPT RATE — a rejection is a legitimate verdict. It is
# the SPLIT of rejection reasons: every rejection should be BOUNDS-related ("Add or adjust
# a bounds check"), and STRUCTURAL rejections (uninitialised register, unreachable
# instruction, invalid instruction) should be ZERO. A structural rejection means the walk
# emitted garbage the oracle can never see.
#
# Seeds are fixed and printed per program, so the corpus is reproducible and any single
# program can be replayed on its own.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-comp-out.log"

echo "[run-comp] building harness + running --gen-comp in the VM ..."
HARNESS_ARGS=--gen-comp TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== validity: every rejection reason, as the verifier phrased it ==="
printf "programs : %s\n" "$(grep -c '^RESULT' "$LOG")"
printf "accepted : %s\n" "$(grep -c 'RESULT decision=accept' "$LOG")"
echo "-- reasons (all must be SEMANTIC: unbounded access / invalid access to map value /"
echo "   math between ... unbounded. Anything else — uninitialised register, unreachable"
echo "   instruction, unknown opcode — is STRUCTURAL and means the walk emitted garbage) --"
awk '/^===PROG /{r=0} /^RESULT decision=reject/{r=1} /---LOG---/{inlog=1; delete b; nb=0}
     inlog&&/^[a-zA-Z]/{b[nb++]=$0}
     /^---END---/{if(r){for(i=0;i<nb;i++) if(b[i] ~ /^(R[0-9]|invalid|math|Initialize|unreachable)/ || b[i] ~ /is not allowed|read_ok|unknown opcode/){print b[i]; break}} inlog=0}' "$LOG" \
  | sed 's/[0-9]\+/N/g' | sort | uniq -c | sort -rn

echo
echo "=== combination coverage — the metric that matters, since bugs live in the"
echo "    INTERACTION of features, not in single pieces ==="
python3 - "$LOG" <<'PY'
import re, sys, collections
log = open(sys.argv[1]).read()
rec = [[p for p in r.split(',') if p] for r in re.findall(r'recipe=([a-z0-9,]*)', log)]
pairs   = {(a,b)   for r in rec for a,b   in zip(r, r[1:])}
triples = {(a,b,c) for r in rec for a,b,c in zip(r, r[1:], r[2:])}
print(f"  distinct recipes : {len({tuple(r) for r in rec})} of {len(rec)} programs")
print(f"  adjacent pairs   : {len(pairs)} / 79 achievable")
print(f"  adjacent triples : {len(triples)} / 679 achievable  ({round(len(triples)/679*100)}%)")
print(f"  recipe lengths   : {dict(sorted(collections.Counter(len(r) for r in rec).items()))}")
print(f"  piece usage      : {dict(collections.Counter(p for r in rec for p in r).most_common())}")
PY

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
