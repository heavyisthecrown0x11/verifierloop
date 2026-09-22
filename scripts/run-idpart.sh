#!/usr/bin/env bash
# ID-MAP BIJECTION / partition structure (--gen-idpart).
#
# 0046 asked whether a link is PRESENT. This asks whether the id mapping between two
# states is a BIJECTION — check_ids' consistency and injectivity clauses (states.c:319).
# Which clause fires is not controllable from the program (registers compare in order,
# first inconsistency wins), so the family varies the id STRUCTURE: the partition of
# registers into linked classes.
#
# Derived: accept iff BOTH paths put r9 in the class the narrowing check touches, because
# the state at the store is the join of the two.
#
# THE COMPLETENESS HALF is the `swap` arms and it is the half every earlier leg lacks:
# the same partition built in a different instruction order mints DIFFERENT id numbers
# (++env->id_gen is global), so accepting it proves the remapping actually maps rather
# than demanding equality. A check_ids that required identical ids would over-reject.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-idpart-out.log"

echo "[run-idpart] building harness + running --gen-idpart in the VM ..."
HARNESS_ARGS=--gen-idpart TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions (accept iff BOTH paths narrow r9) ==="
paste <(grep -oE 'genidpart#[a-z0-9]+-[a-z0-9]+#[0-9]+' "$LOG") \
      <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+') \
      <(grep -E "^IDPART " "$LOG" | grep -oE 'fall_narrows=[01] taken_narrows=[01]')

echo
echo "=== completeness: the swap arm must mint DIFFERENT id numbers on the two paths ==="
awk '/^===PROG genidpart#same-swap#/,/^---END---/' "$LOG" \
  | grep -E "r7 = r6|r9 = r6" | grep -oE "R6=scalar\(id=[0-9]+" | sort -u

echo
echo "=== how many proven states does the store instruction have? (union input) ==="
awk '/^===PROG /{name=$2} /^STORE /{for(i=1;i<=NF;i++) if($i ~ /^insn=/){split($i,a,"="); ins=a[2]}}
     $0 ~ "^"ins": R2=map_value" {print name, $0}' "$LOG" | sed 's/,var_off.*//' | sort -u

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
