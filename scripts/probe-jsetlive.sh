#!/usr/bin/env bash
# CALIBRATION pair nine (3157f7e29996, "bpf: handle jset (if a & b ...) as a jump in CFG
# computation", 2025-06-13) — the LIVENESS GATE's own pair, and the first calibration of the
# cross-state channel 0088 built.
#
# `can_jump()` did not list BPF_JSET, so the CFG the liveness analysis walks was missing the
# taken edge of every `if a & b` jump. The commit says what that costs: "a jump to (5) would
# be missed and r2 won't be marked as alive at (3)". A register the verifier calls dead is
# never compared by func_states_equal — so a liveness that is too SMALL is a prune that never
# had to justify itself, which is exactly the direction check_liveness_gate reports.
#
# THREE ARMS: buggy = 3157f7e29996~1, fixed = 3157f7e29996 itself (byte-identical .config, so
# the two kernels differ in one case label and nothing else), tip = today's bpf-next. Tip is
# reported separately and is NOT a substitute for `fixed`: liveness moved to its own file and
# kept changing after this commit.
#
# Setup (once):
#   git -C .lab/bpf-next worktree add --detach $PWD/.lab/bpf-buggy5 3157f7e29996~1
#   git -C .lab/bpf-next worktree add --detach $PWD/.lab/bpf-fix5   3157f7e29996
#   SRC=$PWD/.lab/bpf-buggy5 OUT=$PWD/.lab/build/bzImage-buggy5 scripts/build-kernel.sh
#   SRC=$PWD/.lab/bpf-fix5   OUT=$PWD/.lab/build/bzImage-fix5    scripts/build-kernel.sh
#
# Wanted: on `buggy` the jset arm's table drops r2 at the jump and the oracle reports one
# liveness_gate_overreach; the jne control agrees everywhere; `fixed` and `tip` are silent —
# all four with the SAME denominator, so the zeros mean something.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
BUGGY_KERNEL="${BUGGY_KERNEL:-$REPO_ROOT/.lab/build/bzImage-buggy5}"
FIXED_KERNEL="${FIXED_KERNEL:-$REPO_ROOT/.lab/build/bzImage-fix5}"

for k in buggy fixed tip; do
  LOG="$REPO_ROOT/.lab/jsetlive-$k.log"
  case "$k" in
    buggy) KSEL="$BUGGY_KERNEL" ;;
    fixed) KSEL="$FIXED_KERNEL" ;;
    tip)   KSEL="" ;;
  esac
  if [ -n "$KSEL" ] && [ ! -f "$KSEL" ]; then
    echo "  no kernel at $KSEL — see the header" >&2; exit 1
  fi
  echo "[jsetlive] $k kernel ..."
  if [ -n "$KSEL" ]; then
    KERNEL="$KSEL" HARNESS_ARGS=--probe-jsetlive TIMEOUT="${TIMEOUT:-180}" \
      scripts/run-harness-vm.sh "$LOG" >/dev/null
  else
    HARNESS_ARGS=--probe-jsetlive TIMEOUT="${TIMEOUT:-180}" \
      scripts/run-harness-vm.sh "$LOG" >/dev/null
  fi
  # The one row that decides the pair: the kernel's live mask at the jump under test.
  # The liveness row for insn 4, and ONLY that: the disassembly listing also has
  # lines beginning with spaces and "4: ", and an SCC-numbered table shifts the
  # fields, so match the ten-column mask itself rather than a field position.
  paste -d' ' \
    <(grep -oE '^===PROG [^ ]+' "$LOG" | sed 's/===PROG //') \
    <(grep -E '^ +[0-9 ]*4: [0-9.]{10} ' "$LOG" \
       | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9.]{10}$/) {print $i; break}}') \
    | sed 's/^/  insn4 live: /'
  MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 \
    | grep -E "MEASURE (liveness_gate_checked|finding_count|parser)" | sed 's/^/  /'
done
