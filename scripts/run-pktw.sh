#!/usr/bin/env bash
# T3 (packet-write) runtime memory-safety oracle (--gen-pktw): the PACKET analog of
# the map-value store oracle (--gen-rtw / --gen-rtw2). A store through a PTR_TO_PACKET
# whose bound the verifier does NOT know statically — the PROGRAM proves it with its
# own `data + M > data_end` compare and the verifier tracks the resulting `range`
# (find_good_pkt_pointers). The load-only packet families (--gen-pkt / --gen-pkt-cmp)
# can only see accept/reject and the verifier's OWN self-consistency; this one EXECUTES
# each accepted program via BPF_PROG_TEST_RUN with the packet sized to EXACTLY the
# proven headroom M (so data_end lands at byte M) and reads the packet back, so it
# catches a range that is internally consistent but WRONG — the blind spot every
# log-only leg shares.
#
# Build the harness, run the family in the VM, and measure it with the pipeline.
#
# Wanted result (a sound kernel):
#   runtime_writes_checked > 0   (accepted packet stores were executed + located)
#   finding_count = 0            (every accepted store landed ENTIRELY in the packet)
#   parser_unrecognized = 0
#
# A `runtime_oob_write` finding fires when store_off=none (the whole store escaped past
# data_end into skb tailroom, which test_run never copies back) OR store_len <
# store_size (a truncated run — the last byte(s) crossed data_end): a partial/total OOB
# packet write the verifier accepted, caught by direct memory observation. The reject
# programs (off = M-W+1) are the off-by-one control: a sound verifier rejects them, so
# they never execute and never count; a buggy one would accept, run, and truncate.
#
# The output format is byte-identical to --gen-rtw2, so the parser, the diff predicate
# (check_runtime_write_safety), and the metrics counters are reused UNCHANGED.
#
# Run outside auto mode (default permission mode) or a fresh session if a mid-session
# tool-access drop blocks the build/VM steps.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-pktw-out.log"

echo "[run-pktw] building harness + running --gen-pktw in the VM ..."
HARNESS_ARGS=--gen-pktw TIMEOUT=150 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions ==="
paste <(grep -oE 'genpktw#w[0-9]+\.o[0-9]+#[0-9]+' "$LOG") <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+')

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
