#!/usr/bin/env bash
# Calibration pair five (af9e89d8dd39) — the pair whose answer is a BOUNDARY.
#
# sync_linked_regs() copied known_reg's id onto reg, ADD_CONST flag included, so the next
# `rX = reg` re-minted reg's id and broke the link. The resulting state is perfectly
# self-consistent and merely WIDER than the truth, so the bug is an over-rejection: no
# internal-consistency invariant can see it. The only channel that can is the VERDICT,
# across kernel versions.
#
# Setup (once):
#   git -C .lab/bpf-next worktree add ../bpf-buggy2 af9e89d8dd39~1
#   SRC=$PWD/.lab/bpf-buggy2 OUT=$PWD/.lab/build/bzImage-buggy2 scripts/build-kernel.sh
#
# Wanted: the TRIGGER arm rejects with "div by zero" on the buggy kernel and accepts on the
# fixed one, while the CONTROL arm — the same program minus the second link — accepts on
# both. A control that flips too would mean the flip is not about the broken link.
# The pipeline must report ZERO findings on both, and the denominators must be non-zero:
# that silence is the result, not a missing measurement.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
BUGGY_KERNEL="${BUGGY_KERNEL:-$REPO_ROOT/.lab/build/bzImage-buggy2}"

for k in fixed buggy; do
  LOG="$REPO_ROOT/.lab/harness-idlink-$k.log"
  echo "[idlink] $k kernel ..."
  if [ "$k" = buggy ]; then
    [ -f "$BUGGY_KERNEL" ] || { echo "  no buggy kernel at $BUGGY_KERNEL — see the header" >&2; exit 1; }
    KERNEL="$BUGGY_KERNEL" HARNESS_ARGS=--probe-idlink TIMEOUT="${TIMEOUT:-240}" \
      scripts/run-harness-vm.sh "$LOG" >/dev/null
  else
    HARNESS_ARGS=--probe-idlink TIMEOUT="${TIMEOUT:-240}" scripts/run-harness-vm.sh "$LOG" >/dev/null
  fi
  paste -d' ' \
    <(grep -oE '^===PROG [^ ]+' "$LOG" | sed 's/===PROG //') \
    <(grep -oE '^RESULT decision=[a-z]+' "$LOG" | cut -d= -f2) | sed 's/^/  /'
  echo "  r0 at the second link: $(grep -oE '5: \(bf\) r2 = r0 +; R0=scalar\(id=[0-9]+' "$LOG" | grep -oE 'id=[0-9]+' | head -1)"
done
