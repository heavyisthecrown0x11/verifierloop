#!/usr/bin/env bash
# CALIBRATION against a real verifier bug that must be RUN to be seen.
#
# Some bugs can be calibrated from the fix commit alone, when the inconsistent state is
# printed as ordinary register state — see tests/fixtures/calibration/cve-3844d153a41a-*
# and alu32-049c4e13714e-*, both of which run as plain `cargo test` with no VM at all.
# 92424801261d cannot: the corrupt registers (true_reg2, false_reg1/2) live inside
# reg_set_min_max and appear only in the kernel's own "REG INVARIANTS VIOLATION" message.
# The detection channel is the VERDICT — 0042's third load, where BPF_F_TEST_REG_INVARIANTS
# turns reg_bounds_sanity_check into a hard -EFAULT — so the kernel that had the bug has to
# be built and run.
#
# Setup (once):
#   git -C .lab/bpf-next worktree add ../bpf-buggy 92424801261d~1
#   SRC=$PWD/.lab/bpf-buggy OUT=$PWD/.lab/build/bzImage-buggy scripts/build-kernel.sh
# Both kernels use the SAME config; the comparison only means something if they differ in
# the fix and nothing else.
#
# Wanted: buggy -> base accepts, inv faults (errno 14), pipeline reports
# reg_invariants_violation once. fixed -> all three loads accept, pipeline silent.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
BUGGY_KERNEL="${BUGGY_KERNEL:-$REPO_ROOT/.lab/build/bzImage-buggy}"

for k in fixed buggy; do
  LOG="$REPO_ROOT/.lab/harness-fakereg-$k.log"
  echo "[calibration] $k kernel ..."
  if [ "$k" = buggy ]; then
    [ -f "$BUGGY_KERNEL" ] || { echo "  no buggy kernel at $BUGGY_KERNEL — see the header" >&2; exit 1; }
    KERNEL="$BUGGY_KERNEL" HARNESS_ARGS=--probe-fakereg TIMEOUT=180 \
      scripts/run-harness-vm.sh "$LOG" >/dev/null
  else
    HARNESS_ARGS=--probe-fakereg TIMEOUT=180 scripts/run-harness-vm.sh "$LOG" >/dev/null
  fi
  printf "  base=%s  inv=%s  kernel_reported_violation=%s\n" \
    "$(grep -oE 'base_verdict=[a-z]+' "$LOG" | cut -d= -f2)" \
    "$(grep -oE 'inv_verdict=[a-z]+ inv_errno=[0-9]+ inv_reason=[a-z_]+' "$LOG")" \
    "$(grep -oE 'reg_invariants_violation_in_log=[01]' "$LOG" | cut -d= -f2)"
  MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 \
    | grep -E "MEASURE (finding_count|parser)|MEASURE   finding" | sed 's/^/  /'
done
