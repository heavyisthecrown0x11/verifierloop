#!/usr/bin/env bash
# Calibration pair six (811c363645b3) — aimed at the RUNTIME channel, and the pair whose
# measurement contradicted the prediction.
#
# check_stack_write_fixed_off() tracked a 64-bit BPF_ST_MEM immediate through a (u32) cast,
# dropping the sign: -44 became 4294967252. The prediction was a clean retval divergence
# (verifier proves 1, runtime returns 0). It is NOT: the verifier resolved the branch
# statically, never walked the other side, and bpf_opt_hard_wire_dead_code_branches()
# (kernel/bpf/fixups.c) then removed that branch from the emitted program — so the runtime
# agrees with the wrong proof. The runtime oracle's reference is the program the verifier
# PRODUCED, not the one submitted.
#
# Setup (once):
#   git -C .lab/bpf-next worktree add ../bpf-buggy3 811c363645b3~1
#   SRC=$PWD/.lab/bpf-buggy3 OUT=$PWD/.lab/build/bzImage-buggy3 scripts/build-kernel.sh
#
# Wanted: the `neg` arm tracked as fp-40=-44 and returning 0 on the fixed kernel;
# fp-40_w=4294967252 and returning 1 on the buggy one. The `pos` control returns 1 on both.
# The pipeline must report ZERO findings on both, with runtime_checked non-zero — that
# silence is the result.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
BUGGY_KERNEL="${BUGGY_KERNEL:-$REPO_ROOT/.lab/build/bzImage-buggy3}"
for k in fixed buggy; do
  LOG="$REPO_ROOT/.lab/harness-spill-$k.log"
  echo "[spill] $k kernel ..."
  if [ "$k" = buggy ]; then
    [ -f "$BUGGY_KERNEL" ] || { echo "  no buggy kernel at $BUGGY_KERNEL — see the header" >&2; exit 1; }
    KERNEL="$BUGGY_KERNEL" HARNESS_ARGS=--probe-spill TIMEOUT="${TIMEOUT:-180}" \
      scripts/run-harness-vm.sh "$LOG" >/dev/null
  else
    HARNESS_ARGS=--probe-spill TIMEOUT="${TIMEOUT:-180}" scripts/run-harness-vm.sh "$LOG" >/dev/null
  fi
  paste -d' ' \
    <(grep -oE '^===PROG [^ ]+' "$LOG" | sed 's/===PROG //') \
    <(grep -oE '^RUNTIME .*retval=0x[0-9a-f]+' "$LOG" | grep -oE 'retval=0x[0-9a-f]+') | sed 's/^/  /'
  grep -oE 'fp-40[_w]*=[-0-9]+' "$LOG" | head -1 | sed 's/^/  tracked spill: /'
done
