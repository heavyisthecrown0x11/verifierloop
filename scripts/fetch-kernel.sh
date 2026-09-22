#!/usr/bin/env bash
# Fetch bpf-next source as a BLOBLESS partial clone: full commit history (so
# git log / cross-version patch diffs — ground-truth source 4 — work later),
# with blobs fetched lazily so the initial download stays small.
#
# Idempotent: re-running fetches + fast-forwards the branch.
#
#   scripts/fetch-kernel.sh            # clone/update .lab/bpf-next @ master
#   BRANCH=for-next scripts/fetch-kernel.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
SRC="$LAB/bpf-next"
REMOTE="${REMOTE:-https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git}"
BRANCH="${BRANCH:-master}"

mkdir -p "$LAB"

if [ -d "$SRC/.git" ]; then
  echo "[fetch] existing clone at $SRC — updating $BRANCH"
  git -C "$SRC" fetch --filter=blob:none origin "$BRANCH"
  git -C "$SRC" checkout -q "$BRANCH"
  git -C "$SRC" reset --hard "origin/$BRANCH"
else
  echo "[fetch] blobless partial clone of $REMOTE ($BRANCH) -> $SRC"
  git clone --filter=blob:none --single-branch --branch "$BRANCH" "$REMOTE" "$SRC"
fi

REV="$(git -C "$SRC" rev-parse HEAD)"
DESC="$(git -C "$SRC" describe --tags --always 2>/dev/null || echo "$REV")"
printf '%s\n' "$REV" > "$LAB/kernel.rev"
echo "[fetch] HEAD = $REV ($DESC)"
du -sh "$SRC" 2>/dev/null | sed 's/^/[fetch] on-disk size: /'
echo "[fetch] recorded revision -> $LAB/kernel.rev"
