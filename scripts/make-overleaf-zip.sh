#!/usr/bin/env bash
# The zip to upload to Overleaf: SOURCE files, no build artifacts, no acmart.cls
# (Overleaf has its own copy; a second copy means a version conflict).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/paper"
OUT="$SRC/build"
ZIP="$OUT/verifierloop-paper-overleaf.zip"
command -v zip >/dev/null || { echo "[zip] zip not found: apt-get install zip" >&2; exit 1; }
mkdir -p "$OUT"; rm -f "$ZIP"
cd "$SRC"
# DON'T USE A FIXED LIST. When appendixA/B were added the zip silently came out incomplete and
# the build would break on Overleaf -- caught here. Glob + \input count verifies it.
zip -q -j "$ZIP" *.tex refs.bib
want=$(( $(grep -c '\\input{' main.tex) + 1 ))   # the inputted ones + main.tex
got=$(unzip -l "$ZIP" | grep -c '\.tex$')
[ "$got" -ge "$want" ] || { echo "[zip] MISSING: $got .tex present, at least $want expected" >&2; exit 1; }
echo "[zip] $(unzip -l "$ZIP" | awk 'END{print $2}') files -> $ZIP"
unzip -l "$ZIP" | sed -n '4,$p' | head -12
