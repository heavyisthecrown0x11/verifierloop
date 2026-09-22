#!/usr/bin/env bash
# Publish-time artifact preparation. Does NOT BREAK the main line: produces and verifies an
# `artifact-clean` branch with the session-URL trailer stripped. Runs again and again while main proceeds.
#
# WHY WE PRESERVE the history (NOT squash): paper §4.1 and the held-out pre-registrations
# say "the ordering is visible in the artifact's history" -- the commit order and time
# stamps are the proof of the pre-registration (that it was sealed BEFORE the result). Only the automatic
# citation/session trailer lines are dropped; the subject, body and real author stay as-is.
#
#   scripts/prepare-artifact.sh            # -> artifact-clean branch + report
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -z "$(git status --porcelain)" ] || { echo "[artifact] working tree dirty; commit/stash first" >&2; exit 1; }

SRC=main
git branch -f artifact-src "$SRC" >/dev/null
git checkout -q artifact-clean 2>/dev/null && git reset -q --hard "$SRC" || git checkout -q -b artifact-clean "$SRC"

# Drop the automatic citation/session trailers; don't touch anything else.
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f \
  --msg-filter 'grep -vE "^(Co-Authored-By: |[A-Za-z][A-Za-z-]*-Session:)" || true' -- artifact-clean >/dev/null 2>&1

echo "== VERIFICATION =="
n_src=$(git rev-list --count "$SRC")
n_cln=$(git rev-list --count artifact-clean)
echo "  commit count: main=$n_src  artifact-clean=$n_cln  (must be equal: order preserved)"
leak=$(git log artifact-clean --format=%B | grep -cE "^(Co-Authored-By: |[A-Za-z][A-Za-z-]*-Session:)" || true)
echo "  citation/session lines remaining in the cleaned branch: $leak  (must be 0)"
# is the tree content identical (only messages changed)
diff_tree=$(git diff --stat "$SRC" artifact-clean | tail -1)
echo "  tree diff (main vs artifact-clean): ${diff_tree:-NONE (identical content)}"
first_src=$(git log "$SRC"    --reverse --format=%ai | head -1)
first_cln=$(git log artifact-clean --reverse --format=%ai | head -1)
echo "  first commit timestamp preserved: $([ "$first_src" = "$first_cln" ] && echo YES || echo NO)"
git checkout -q "$SRC"
echo
echo "[artifact] ready: 'artifact-clean' branch. Publish (after acceptance):"
echo "    gh repo create <ad> --public --source=. --remote=origin"
echo "    git push origin artifact-clean:main"
