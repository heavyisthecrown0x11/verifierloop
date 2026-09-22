#!/usr/bin/env bash
# Runtime memory-safety oracle for map-value STORES (--gen-rtw): build the harness,
# run the family in the VM (each accepted program is EXECUTED via BPF_PROG_TEST_RUN;
# the harness zeroes the target map, runs, reads it back, and locates the sentinel
# byte the program stored), and measure it with the pipeline.
#
# Wanted result (a sound kernel):
#   runtime_writes_checked > 0   (accepted stores were actually executed + located)
#   finding_count = 0            (every accepted store landed inside the map value)
#   parser_unrecognized = 0
#
# A `runtime_oob_write` finding (store_off=none) would mean the verifier accepted a
# program whose runtime store escaped the map value — an OOB write / soundness bug,
# caught by direct memory observation (no bound parsing).
#
# Run outside auto mode (default permission mode) or a fresh session if the safety
# classifier blocks the build/VM steps mid-session.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-rtw-out.log"

echo "[run-rtw] building harness + running --gen-rtw in the VM ..."
HARNESS_ARGS=--gen-rtw TIMEOUT=150 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions ==="
paste <(grep -oE 'genrtw#[a-z]+#[0-9]+' "$LOG") <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+')

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
