#!/usr/bin/env bash
# T2-2: multi-byte store-WIDTH memory-safety oracle (--gen-rtw2). Extends --gen-rtw
# from a single sentinel byte to N-byte stores, so the axis under test is the store
# WIDTH — the off-by-one a real verifier bug would hit lives in the in-bounds check
# `off + size <= value_size`. Build the harness, run the family in the VM (each
# accepted program is EXECUTED via BPF_PROG_TEST_RUN; the harness zeroes the target
# map before every run, stores N sentinel bytes, reads the map back, and reports both
# where the sentinel run started (store_off) and how long it was (store_len)), and
# measure it with the pipeline.
#
# Wanted result (a sound kernel):
#   runtime_writes_checked > 0   (accepted stores were actually executed + located)
#   finding_count = 0            (every accepted store landed ENTIRELY in the value)
#   parser_unrecognized = 0
#
# A `runtime_oob_write` finding fires when store_off=none (the whole store escaped)
# OR store_len < store_size (a truncated run — some bytes crossed the value end): a
# partial/total OOB write the verifier accepted, caught by direct memory observation.
#
# Run outside auto mode (default permission mode) or a fresh session if a mid-session
# tool-access drop blocks the build/VM steps.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-rtw2-out.log"

echo "[run-rtw2] building harness + running --gen-rtw2 in the VM ..."
HARNESS_ARGS=--gen-rtw2 TIMEOUT=150 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions ==="
paste <(grep -oE 'genrtw2#[a-z]+\.w[0-9]+#[0-9]+' "$LOG") <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+')

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
