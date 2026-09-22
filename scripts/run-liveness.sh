#!/usr/bin/env bash
# THE LIVENESS GATE (devlog 0088) — the first cross-state check whose reference is neither
# the verifier nor a second kernel.
#
# `func_states_equal` compares only the registers the verifier believes are live where two
# states meet, so a register wrongly called dead is a prune that never had to justify
# itself. The pruning DECISION is not auditable from the log (the prune record carries
# neither state, and the log cannot express range_within's domain) — but the GATE is
# printed, and unlike the decision it is a property of the instruction stream alone.
#
# Each family emits a `LIVENESS status=ok n=<insns> mask=<hex>` claim from bpflive.h, an
# independent analysis over the EMITTED bytes; the kernel prints its own table at
# BPF_LOG_LEVEL2. The pipeline compares them cell by cell in the one direction that matters.
#
#   scripts/run-liveness.sh            # the two small families, ~2 min
#   FAMILIES="comp" scripts/run-liveness.sh   # the 896-program corpus, ~25 min
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
FAMILIES="${FAMILIES:-prune spill}"

for fam in $FAMILIES; do
  LOG="$REPO_ROOT/.lab/live-$fam.log"
  echo "[liveness] --gen-$fam ..."
  HARNESS_ARGS="--gen-$fam" TIMEOUT="${TIMEOUT:-1500}" \
    scripts/run-harness-vm.sh "$LOG" >/dev/null
  ok=$(grep -c 'LIVENESS status=ok' "$LOG" || true)
  un=$(grep -c 'LIVENESS status=unsupported' "$LOG" || true)
  # A program the model REFUSES contributes nothing rather than noise, so the refusal count
  # is part of the result: it is the honest scope of the claim, not a failure.
  printf "  modelled=%s refused=%s\n" "$ok" "$un"
  if [ "$un" -gt 0 ]; then
    echo "  refusals are named, never guessed at:"
    grep -o 'why=[a-z_ ]*' "$LOG" | sort | uniq -c | sed 's/^/    /'
  fi
  MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 \
    | grep -E "MEASURE (records|liveness_gate_checked|finding_count|parser)" | sed 's/^/  /'
done
