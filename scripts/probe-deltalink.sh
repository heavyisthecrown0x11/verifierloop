#!/usr/bin/env bash
# CALIBRATION pair eight (3878ae04e9fc, "bpf: Fix incorrect delta propagation between
# linked registers", 2024-10-16) — the first pair aimed at the STORE-LOCATION channel.
#
# The bug leaves a self-consistent state, so no internal-consistency invariant can see it
# and the verdict is ACCEPT on both kernels. What is wrong is only the RELATION to reality:
# the verifier proves the store lands at map_value+8, the CPU puts it at map_value+0. The
# only oracle whose reference is the runtime landing site is check_store_location.
#
# THREE ARMS, because the pair must be airtight and the present must also be checked:
#   buggy = 3878ae04e9fc~1   fixed = 3878ae04e9fc   tip = today's bpf-next
# buggy vs fixed differ in the commit's four lines and NOTHING else (identical .config,
# verified byte for byte). `tip` is two further fixes to the same function downstream
# (7a433e519364, bc308be380c1), which is exactly why it cannot stand in for `fixed`.
#
# Setup (once):
#   git -C .lab/bpf-next worktree add --detach $PWD/.lab/bpf-buggy4 3878ae04e9fc~1
#   git -C .lab/bpf-next worktree add --detach $PWD/.lab/bpf-fix4   3878ae04e9fc
#   SRC=$PWD/.lab/bpf-buggy4 OUT=$PWD/.lab/build/bzImage-buggy4 scripts/build-kernel.sh
#   SRC=$PWD/.lab/bpf-fix4   OUT=$PWD/.lab/build/bzImage-fix4    scripts/build-kernel.sh
#
# Wanted: both arms ACCEPT on every kernel; the `wrap` arm's store lands at 0 while the
# buggy kernel proved 8 (one store_location_desync), and the `nowrap` control agrees
# everywhere.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
BUGGY_KERNEL="${BUGGY_KERNEL:-$REPO_ROOT/.lab/build/bzImage-buggy4}"
FIXED_KERNEL="${FIXED_KERNEL:-$REPO_ROOT/.lab/build/bzImage-fix4}"

for k in buggy fixed tip; do
  LOG="$REPO_ROOT/.lab/harness-deltalink-$k.log"
  case "$k" in
    buggy) KSEL="$BUGGY_KERNEL" ;;
    fixed) KSEL="$FIXED_KERNEL" ;;
    tip)   KSEL="" ;;                      # unset KERNEL = the default lab kernel
  esac
  if [ -n "$KSEL" ] && [ ! -f "$KSEL" ]; then
    echo "  no kernel at $KSEL — see the header" >&2; exit 1
  fi
  echo "[deltalink] $k kernel ..."
  if [ -n "$KSEL" ]; then
    KERNEL="$KSEL" HARNESS_ARGS=--probe-deltalink TIMEOUT="${TIMEOUT:-180}" \
      scripts/run-harness-vm.sh "$LOG" >/dev/null
  else
    HARNESS_ARGS=--probe-deltalink TIMEOUT="${TIMEOUT:-180}" \
      scripts/run-harness-vm.sh "$LOG" >/dev/null
  fi
  paste -d' ' \
    <(grep -oE '^===PROG [^ ]+' "$LOG" | sed 's/===PROG //') \
    <(grep -oE '^RESULT decision=[a-z]+' "$LOG") \
    <(grep -oE '^RUNTIME .*store_off=[0-9a-z]+' "$LOG" | grep -oE 'store_off=[0-9a-z]+') \
    | sed 's/^/  /'
  # What the verifier PROVED for the store's base register, straight out of the log.
  grep -oE 'R7(_w)?=map_value\([^)]*\)' "$LOG" | sort -u | sed 's/^/  proved: /'
done
