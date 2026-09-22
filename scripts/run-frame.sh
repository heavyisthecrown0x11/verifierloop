#!/usr/bin/env bash
# MULTI-FRAME STATES / subprograms (--gen-frame).
#
# Every earlier family lives in ONE frame. states_equal opens with
# `if (old->curframe != cur->curframe) return false` and then compares each frame, so the
# multi-frame half of state comparison was untouched — and calls.c is on the kernel's own
# danger list. A subprog call needs no BTF and no kfunc: BPF_CALL with
# src_reg = BPF_PSEUDO_CALL and imm = the pc-relative offset of the callee.
#
# The family answers by construction what crosses the boundary. Only r1-r5 are passed and
# the callee's r6-r9 start uninitialised, so if a link id survives into an argument then
# narrowing one argument narrows the other INSIDE a different frame. Wanted: one.a2
# rejects and both.a2 ACCEPTS — if ids stopped at the boundary both would reject and the
# rejection would say nothing about frames.
#
# WATCH THE DENOMINATOR. The store lives in the callee, so store_locations_checked = 0
# means the frame states were dropped by the parser, not that the kernel is clean. That is
# exactly how the `frameN:` prefix gap was found: it fails silently, leaving
# parser_unrecognized at 0.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-frame-out.log"

echo "[run-frame] building harness + running --gen-frame in the VM ..."
HARNESS_ARGS=--gen-frame TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions (one.a2 must reject, both.a2 must ACCEPT) ==="
paste <(grep -oE 'genframe#[a-z]+\.a[12]#[0-9]+' "$LOG") \
      <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+')

echo
echo "=== the caller-minted id, alive inside the callee frame ==="
grep -E "frame1:" "$LOG" | grep -E "if r6 > 0x7" | grep -oE "frame1: R6=scalar\(id=[0-9]+[^)]*\) R7=scalar\(id=[0-9]+[^)]*\)" | sort -u | head -3

echo
echo "=== pipeline measurement (store_locations_checked MUST be > 0) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
