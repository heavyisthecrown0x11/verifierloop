#!/usr/bin/env bash
# Runtime ground-truth oracle (--gen-rt): build the harness, run the family in the
# VM (each program is LOADED then EXECUTED via BPF_PROG_TEST_RUN over an input
# sweep), and measure it with the pipeline.
#
# Wanted result (a sound kernel):
#   runtime_checked > 0     (programs were actually executed and each retval was
#                            compared against the verifier's own proven r0 bound)
#   finding_count = 0       (no runtime return value escaped its bound)
#   parser_unrecognized = 0
#
# A `runtime_bound_violation` finding would mean the verifier accepted a program
# whose runtime behaviour escaped what it proved — a soundness bug caught WITHOUT
# trusting the verifier log to be internally consistent.
#
# Run outside auto mode (default permission mode) or a fresh session if the safety
# classifier blocks the build/VM steps mid-session.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LOG="$REPO_ROOT/.lab/harness-rt-out.log"

echo "[run-rt] building harness + running --gen-rt in the VM ..."
HARNESS_ARGS=--gen-rt TIMEOUT=150 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions (first + last few) ==="
grep -E "===PROG genrt|^RESULT" "$LOG" | head -6
echo "..."
grep -E "^RESULT" "$LOG" | tail -2

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
