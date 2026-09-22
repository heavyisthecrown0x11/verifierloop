#!/usr/bin/env bash
# The composition corpus run against TWO kernels, matched by seed.
#
# Not a hunting oracle — two kernel versions are allowed to disagree on a verdict, so a
# flip is evidence only when you already know which side is the bug (devlog 0068). It is a
# TEETH test: it answers "does the piece I added for a known bug actually discriminate on
# the kernel that had it, and does nothing else in the corpus?"
#
# Setup: the buggy kernel from scripts/probe-idlink.sh's header.
# Measured 0069: 896 programs matched, recipes identical on both kernels, 7 flips, all 7
# containing `relink`, none of the 598 without it.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
BUGGY_KERNEL="${BUGGY_KERNEL:-$REPO_ROOT/.lab/build/bzImage-buggy2}"
PIECE="${PIECE:-relink}"
A="$REPO_ROOT/.lab/harness-comp-fixed.log"
B="$REPO_ROOT/.lab/harness-comp-buggy.log"
HARNESS_ARGS=--gen-comp TIMEOUT="${TIMEOUT:-2400}" scripts/run-harness-vm.sh "$A" >/dev/null
KERNEL="$BUGGY_KERNEL" HARNESS_ARGS=--gen-comp TIMEOUT="${TIMEOUT:-2400}" \
  scripts/run-harness-vm.sh "$B" >/dev/null
PIECE="$PIECE" A="$A" B="$B" python3 - <<'PY'
import os, re
def load(p):
    d = {}
    for b in open(p).read().split('===PROG ')[1:]:
        h = b.split('---LOG---')[0]
        s = re.search(r'seed=(\w+)', h); r = re.search(r'recipe=(\S+)', h)
        v = re.search(r'decision=(\w+)', h)
        if s and r and v: d[s.group(1)] = (r.group(1), v.group(1))
    return d
a, b = load(os.environ['A']), load(os.environ['B'])
piece = os.environ['PIECE']
common = set(a) & set(b)
same = sum(1 for s in common if a[s][0] == b[s][0])
flip = [s for s in common if a[s][1] != b[s][1]]
wp = [s for s in flip if piece in a[s][0]]
print(f"  matched by seed {len(common)}, identical recipe {same}")
print(f"  flips {len(flip)}  with {piece}: {len(wp)}  without: {len(flip)-len(wp)}")
print(f"  seeds: {sorted(wp)}")
PY
