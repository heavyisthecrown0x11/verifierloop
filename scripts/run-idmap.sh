#!/usr/bin/env bash
# SCALAR ID REMAPPING (--gen-idmap) — the thing states.c calls "too simplistic".
#
# check_ids() (states.c:319) builds a bijective old<->cur id mapping while comparing two
# states. The kernel's own regsafe comment gives the program that needs it: link two
# scalars with `r7 = r6` on ONE path, narrow r6, then use r7. Two states reach the use —
# one where r7 was narrowed through the shared id and one where it was not — and equating
# them would prune the unsafe state away.
#
# Every REJECT shape here is paired with an ACCEPT control that differs ONLY in whether
# the link exists on both paths. Without that pairing a rejection would prove the shape
# unsafe, not that linkage decides it. Wanted: one/both differ for every link form.
#
# Axis = how the link is formed, because each carries a different id: bare `r7 = r6`
# (plain shared id), `r7 = r6; r7 += 4` (BPF_ADD_CONST64, bit 31 — check_scalar_ids must
# map compound AND base id), and the alu32 form (BPF_ADD_CONST32, bit 30 — the kernel
# refuses to prune across differing flag types because alu32 zero-extends).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-idmap-out.log"

echo "[run-idmap] building harness + running --gen-idmap in the VM ..."
HARNESS_ARGS=--gen-idmap TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions (one vs both must DIFFER for every link form) ==="
paste <(grep -oE 'genidmap#[a-z0-9]+\.[a-z]+\.r[67]#[0-9]+' "$LOG") \
      <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+')

echo
echo "=== the shared id, and sync_linked_regs propagating the bound to r7 ==="
grep -E "r7 = r6|if r6 > 0x7" "$LOG" | grep "R6=scalar(id=" | sort -u | head

echo
echo "=== the differential (base vs freq vs inv) ==="
awk '/^===PROG /{name=$2}
     /^PRUNE /{b=f=i=""; for(j=1;j<=NF;j++){
        if($j ~ /^base_verdict=/){split($j,a,"="); b=a[2]}
        if($j ~ /^freq_verdict=/){split($j,a,"="); f=a[2]}
        if($j ~ /^inv_verdict=/){split($j,a,"="); i=a[2]}}
        printf "%-30s base=%-6s freq=%-6s inv=%-6s %s\n", name, b, f, i,
               (b==f && b==i) ? "agree" : "*** DIFFER ***"}' "$LOG"

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
