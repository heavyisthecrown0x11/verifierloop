#!/usr/bin/env bash
# Build REPLAY binaries from the syzkaller corpus.
#
# For each corpus program containing a BPF_PROG_LOAD, render it to C with
# `syz-prog2c`, compile it against harness/syzreplay/shim.c with
# `-Dsyscall=vl_syscall` so the shim can inject log_level=2 and capture the real
# verifier log in the harness native format. The programs stay syzkaller's; only
# log capture is added.
#
#   scripts/syz-replay-build.sh [OUTDIR]     # default: .lab/syzreplay
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
SYZ="$LAB/syzkaller"
OUTDIR="${1:-$LAB/syzreplay}"
CORPUS="${CORPUS:-$SYZ/workdir/corpus.db}"
LIMIT="${LIMIT:-0}"          # 0 = no limit

[ -x "$SYZ/bin/syz-db" ]      || { echo "[replay] no syz-db — run scripts/setup-syzkaller.sh" >&2; exit 1; }
[ -x "$SYZ/bin/syz-prog2c" ]  || { echo "[replay] no syz-prog2c" >&2; exit 1; }
[ -f "$CORPUS" ]              || { echo "[replay] no corpus at $CORPUS — run the fuzzer first" >&2; exit 1; }

rm -rf "$OUTDIR"; mkdir -p "$OUTDIR/progs" "$OUTDIR/bin"
"$SYZ/bin/syz-db" unpack "$CORPUS" "$OUTDIR/progs" >/dev/null 2>&1

total=0; built=0; skipped=0
for f in "$OUTDIR/progs"/*; do
  [ -f "$f" ] || continue
  grep -q 'PROG_LOAD' "$f" || continue
  total=$((total+1))
  [ "$LIMIT" -gt 0 ] && [ "$built" -ge "$LIMIT" ] && break
  id="$(basename "$f")"; id="${id:0:12}"
  c="$OUTDIR/progs/$id.c"
  if ! "$SYZ/bin/syz-prog2c" -prog "$f" > "$c" 2>/dev/null || [ ! -s "$c" ]; then
    skipped=$((skipped+1)); continue
  fi
  # -w: generated code is noisy; we are not reviewing syzkaller's codegen style.
  if cc -O1 -w -Dsyscall=vl_syscall -c "$c" -o "$OUTDIR/progs/$id.o" 2>/dev/null \
     && cc -O1 -w -DVL_PROG_LABEL="\"$id\"" -c "$REPO_ROOT/harness/syzreplay/shim.c" -o "$OUTDIR/progs/$id.shim.o" 2>/dev/null \
     && cc -static -o "$OUTDIR/bin/replay_$id" "$OUTDIR/progs/$id.o" "$OUTDIR/progs/$id.shim.o" 2>/dev/null; then
    built=$((built+1))
  else
    skipped=$((skipped+1))
  fi
done

echo "[replay] corpus programs with PROG_LOAD: $total | built: $built | skipped: $skipped"
echo "[replay] binaries -> $OUTDIR/bin"
