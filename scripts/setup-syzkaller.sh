#!/usr/bin/env bash
# Install a recent Go (if absent) and build syzkaller into .lab/syzkaller.
# syzkaller is the PRIMARY fuzzer; it runs its own QEMU VMs (TCG here, no KVM).
#
#   scripts/setup-syzkaller.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
GOROOT="${GOROOT:-/usr/local/go}"
export PATH="$GOROOT/bin:$PATH"
JOBS="${JOBS:-$(nproc)}"

# 1. Go toolchain (syzkaller needs a recent one; Ubuntu 22.04 apt Go is too old).
if ! command -v go >/dev/null 2>&1 || ! go version 2>/dev/null | grep -qE 'go1\.(2[2-9]|[3-9][0-9])'; then
  GOVER="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)"
  echo "[syz] installing $GOVER -> $GOROOT"
  ( cd /tmp && curl -fsSLO "https://go.dev/dl/${GOVER}.linux-amd64.tar.gz" \
      && rm -rf "$GOROOT" && tar -C "$(dirname "$GOROOT")" -xzf "${GOVER}.linux-amd64.tar.gz" )
fi
echo "[syz] $(go version)"

# 2. syzkaller source.
SYZ="$LAB/syzkaller"
if [ -d "$SYZ/.git" ]; then
  echo "[syz] updating $SYZ"
  git -C "$SYZ" pull --ff-only
else
  echo "[syz] cloning syzkaller -> $SYZ"
  git clone https://github.com/google/syzkaller "$SYZ"
fi

# 3. Build (host tools + linux/amd64 executor).
cd "$SYZ"
echo "[syz] building (-j$JOBS) ..."
make -j"$JOBS"

echo "[syz] host bins:"; ls bin/ 2>/dev/null | sed 's/^/    /'
echo "[syz] target bins:"; ls bin/linux_amd64/ 2>/dev/null | sed 's/^/    /'
echo "[syz] syzkaller ready at $SYZ"
