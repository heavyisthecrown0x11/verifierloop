#!/usr/bin/env bash
# paper/ -> paper/build/main.pdf. The local equivalent of what Overleaf does:
# pdflatex, bibtex, pdflatex x2 (references and citations settle in two passes).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/paper"
OUT="$SRC/build"
command -v pdflatex >/dev/null || { echo "[paper] pdflatex not found" >&2; exit 1; }
kpsewhich acmart.cls >/dev/null || { echo "[paper] acmart.cls not found: texlive-publishers" >&2; exit 1; }
# This check is the payoff of an hour once lost: without fonts-extra acmart
# falls back to Computer Modern and microtype gives a FATAL error, not a missing-font warning.
kpsewhich libertine.sty >/dev/null || echo "[paper] WARNING: libertine not found -> microtype may give a fatal error (texlive-fonts-extra)" >&2
# GATE 1: a single active \maketitle. A str.replace("\\maketitle", ...) once caught the
# \maketitle in MY OWN comment line too; the result was two title blocks and an abstract-less
# first page, and none of the page-count/citation/overfull checks saw it.
mt=$(grep -c "^[^%]*\\\\maketitle" "$SRC/main.tex" || true)
[ "$mt" = "1" ] || { echo "[paper] ERROR: active \\maketitle count is $mt (must be 1)" >&2; exit 1; }

rm -rf "$OUT"; mkdir -p "$OUT"
cp "$SRC"/*.tex "$SRC"/*.bib "$OUT/"
cd "$OUT"
pdflatex -interaction=nonstopmode main.tex >/dev/null || true
bibtex main >/dev/null 2>&1 || true
pdflatex -interaction=nonstopmode main.tex >/dev/null || true
pdflatex -interaction=nonstopmode main.tex >/dev/null || true
[ -f main.pdf ] || { echo "[paper] PDF not produced; see $OUT/main.log" >&2; tail -20 main.log >&2; exit 1; }
# GATE 2: the FIRST page the reader sees. In the bug above page 1 was printed abstract-less
# and would go unnoticed for weeks -- I had looked at pages 2 and 3, not 1.
if command -v pdftotext >/dev/null 2>&1; then
  # NO PIPE: `... | grep -q` closes the pipe early on a match, pdftotext gets SIGPIPE
  # and because of `set -o pipefail` even a GOOD build got stuck at the gate.
  p1=$(pdftotext -f 1 -l 1 main.pdf - 2>/dev/null || true)
  case "$p1" in
    *ABSTRACT*) ;;
    *) echo "[paper] ERROR: no ABSTRACT on page 1 -- title block broken" >&2; exit 1 ;;
  esac
fi
# GATE 3: if a TikZ box is wider than the column LaTeX does NOT warn about an overfull hbox; the
# box silently overflows onto the neighboring column. fig-axes.tex measures it, here we surface it.
fw=$(grep -c "FIGWIDTH-ERROR" main.log 2>/dev/null || true); fw=${fw:-0}
[ "$fw" = "0" ] || { grep -m1 "FIGWIDTH-ERROR" main.log >&2; \
  echo "[paper] ERROR: figure wider than column -- narrow it or make it figure*" >&2; exit 1; }

echo "[paper] $(pdfinfo main.pdf 2>/dev/null | awk '/^Pages/{print $2}') pages -> $OUT/main.pdf"
# NOTE: in this environment `grep` is ugrep and `-c` prints nothing on a zero count -- we do the
# counting in the shell so that "0" and "grep stayed silent" don't look the same.
# Count ONLY CITATION/REFERENCE undefinedness. A plain "undefined" search produced false alarms:
# acmart+libertine leave two `Font shape ... undefined` warnings and LaTeX silently substitutes
# them -- nothing to do with the build.
u=$(grep -c "Warning: \(Citation\|Reference\) .* undefined" main.log 2>/dev/null || true); u=${u:-0}
echo "[paper] undefined citation/reference: $u"
[ "$u" = "0" ] || { echo "[paper] -> may need to run bibtex again" >&2; }
