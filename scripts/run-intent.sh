#!/usr/bin/env bash
# The aimed closed-form family — the first corpus judged by an oracle that never consults
# the verifier.
#
# Each program's return value is computed by harness/bpfref.h, an independent implementation
# of the ISA, and compared against what the kernel's JIT actually returns. A disagreement
# means an ACCEPTED program did something its own instructions do not permit.
#
# The reference is calibrated FIRST and the run is abandoned if it is not: hunting with an
# uncalibrated instrument is worse than not hunting.
#
# Shapes are aimed at what history says breaks most often — link-then-diverge (a shared
# scalar id, a constant delta on one member, a narrowing branch, then a use of the other),
# 32-bit width and sign mis-tracking consumed by a signed compare, constant pinning (the
# precondition a dead-branch rewrite needs), and signed div/mod.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
scripts/probe-ref.sh >/dev/null || { echo "reference interpreter NOT calibrated — stopping" >&2; exit 1; }
echo "[intent] reference calibrated"
LOG="${1:-$REPO_ROOT/.lab/harness-intent.log}"
HARNESS_ARGS=--gen-intent TIMEOUT="${TIMEOUT:-1800}" scripts/run-harness-vm.sh "$LOG" >/dev/null
python3 - "$LOG" <<'PY'
import re, sys
from collections import Counter
txt = open(sys.argv[1]).read()
blocks = txt.split('===PROG ')[1:]
acc = [b for b in blocks if 'decision=accept' in b.split('---LOG---')[0]]
n = agree = dis = 0
bad = []
vals = Counter()
for b in acc:
    lab = b.split()[0]
    for m in re.finditer(r'RUNTIME input=(\S+) retval=0x([0-9a-f]+) intended_retval=(\d+) ref_status=ok', b):
        n += 1
        k, r = int(m.group(2), 16), int(m.group(3))
        vals[k] += 1
        if k == r:
            agree += 1
        else:
            dis += 1
            bad.append((lab, m.group(1), hex(k), r))
print(f"  programs {len(blocks)}  accepted {len(acc)}")
print(f"  compared {n}   agree {agree}   DISAGREE {dis}   distinct answers {len(vals)}")
for x in bad[:20]:
    print(f"    *** DISAGREE prog={x[0]} input={x[1]} kernel={x[2]} reference={x[3]}")
if dis:
    print("  TRIAGE ORDER: the generator's emitted bytes, then bpfref, then the kernel.")
    sys.exit(1)
PY
