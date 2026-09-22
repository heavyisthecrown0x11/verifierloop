#!/usr/bin/env bash
# Packet-write OBSERVATION-CHANNEL probe (--probe-pktw): turns 0039's channel claim
# from an argument into a measurement.
#
# 0039's packet oracle reads an absent/truncated sentinel run as an OOB write, because
# bpf_prog_test_run_skb copies back only [0, skb->len) — a store past data_end lands in
# skb tailroom and never returns. That was read out of the kernel source, not observed:
# a sound verifier rejects every OOB store, so the channel's NEGATIVE half was never
# exercised. The next leg (store-location desync) asserts "the verifier proved X, the
# store landed at Y", so the channel must be shown to resolve bytes precisely first.
#
# The probe moves the WINDOW instead of the store: bpf_skb_change_tail() shrinks
# skb->len AFTER the store, leaving an already-written byte beyond the returned length —
# the geometry of an OOB store, with only ACCEPTED programs.
#
# Wanted result (a sound kernel):
#   probe#pktw.win32     out_size=32  store_off=31   tail_zero=1
#   probe#pktw.win40     out_size=40  store_off=31   tail_zero=1   (window tracks skb->len)
#   probe#pktw.trim.o19  out_size=20  store_off=19   tail_zero=1   (last returned byte: VISIBLE)
#   probe#pktw.trim.o20  out_size=20  store_off=none tail_zero=1   (first byte past it: ABSENT)
# The last two differ by ONE byte of store offset and nothing else: that is the
# byte-precise edge of the observation window.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-probe-pktw.log"

echo "[probe-pktw] building harness + running --probe-pktw in the VM ..."
HARNESS_ARGS=--probe-pktw TIMEOUT=120 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== channel geometry (the measurement) ==="
paste <(grep -oE 'probe#pktw[a-z0-9.]*' "$LOG") \
      <(grep -E "^RESULT" "$LOG" | grep -oE 'decision=[a-z]+') \
      <(grep -E "^CHANNEL" "$LOG")
