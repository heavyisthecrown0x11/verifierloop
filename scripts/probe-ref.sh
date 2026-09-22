#!/usr/bin/env bash
# Calibrate the reference interpreter (harness/bpfref.h) against the real kernel.
#
# bpfref.h exists so the intent oracle has a reference that never consults the kernel — but
# a second implementation is only worth having if it agrees with the first everywhere the
# first is right. This runs the sixteen places a naive interpreter goes wrong (32-bit
# zero-extension, JMP32's low-half compare, x/0 and x%0, S64_MIN sdiv -1, DW immediate
# sign-extension, MEMSX vs plain loads, MOVSX in each ALU class, LD_IMM64's two slots, the
# signed off field) through BOTH and requires every one to match.
#
# Every line must end verdict=agree. `not-run` means the program was rejected at load and
# the trap measured nothing — fix the program, do not read it as agreement. `DISAGREE` is
# the only interesting outcome, and the suspect order is: the trap program, then bpfref,
# then the kernel.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="${1:-$REPO_ROOT/.lab/harness-ref.log}"
HARNESS_ARGS=--probe-ref TIMEOUT="${TIMEOUT:-120}" scripts/run-harness-vm.sh "$LOG" >/dev/null
grep -oE 'name=[a-z0-9_]+ .*verdict=[A-Za-z-]+' "$LOG" |
  sed 's/name=//' | awk '{printf "  %-34s %s\n", $1, $NF}'
echo "  ---"
grep -oE 'verdict=[A-Za-z-]+' "$LOG" | sort | uniq -c | sed 's/^/  /'
# The AUTHORITY is the single counted summary line, not the per-trap greps. The serial
# console is shared with the kernel's printk, so a line can be split mid-word — it happened
# on this very probe (`verdict=agre`), and a split `DISAGREE` would slip past a grep. If the
# kernel manages to split even the summary, no summary is found and this fails loudly
# instead of passing on an absence.
SUM=$(grep -m1 '^REFCAL ' "$LOG" || true)
[ -n "$SUM" ] || { echo "  no REFCAL summary — the capture is damaged, not clean" >&2; exit 1; }
TOT=${SUM##*total=}; TOT=${TOT%% *}
AGR=${SUM##*agree=}
[ "$TOT" = "$AGR" ] && [ "$TOT" -ge 16 ] || {
  echo "  calibration FAILED: $SUM — triage: the trap program, then bpfref, then the kernel" >&2
  exit 1
}
echo "  reference interpreter calibrated ($SUM)"
