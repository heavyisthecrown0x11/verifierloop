#!/usr/bin/env bash
# Create a disposable Debian rootfs image for the fuzzing VM (debootstrap ->
# raw ext4). Serial autologin as root (for -nographic boots), sshd + a generated
# key (for syzkaller later), DHCP on the QEMU NIC, and an automated boot-verify
# script at /root/verify.sh.
#
# Uses `mkfs.ext4 -d` to populate the image WITHOUT loop-mounting (robust on WSL2).
#
#   scripts/create-rootfs.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
IMAGES="$LAB/images"
RELEASE="${RELEASE:-bookworm}"
MIRROR="${MIRROR:-http://deb.debian.org/debian}"
SIZE_MB="${SIZE_MB:-2048}"
CHROOT="$IMAGES/chroot"
IMG="$IMAGES/rootfs.img"
KEY="$IMAGES/vm-id_ed25519"

[ "$(id -u)" -eq 0 ] || { echo "[rootfs] must run as root (debootstrap)"; exit 1; }
command -v debootstrap >/dev/null 2>&1 || { echo "[rootfs] debootstrap required"; exit 1; }

mkdir -p "$IMAGES"

# 1. Minimal base system.
echo "[rootfs] debootstrap $RELEASE from $MIRROR ..."
rm -rf "$CHROOT"; mkdir -p "$CHROOT"
debootstrap --include=openssh-server,curl,ca-certificates,tar,xz-utils,kmod,iproute2,ifupdown,isc-dhcp-client,udev,libelf1 \
  "$RELEASE" "$CHROOT" "$MIRROR"

# 2. In-chroot configuration.
echo "[rootfs] configuring image ..."
# passwordless root
sed -i 's#^root:[^:]*:#root::#' "$CHROOT/etc/shadow"
echo "verifierloop-vm" > "$CHROOT/etc/hostname"
printf '127.0.0.1 localhost\n127.0.1.1 verifierloop-vm\n' > "$CHROOT/etc/hosts"

# serial autologin as root on ttyS0 (systemd getty override)
mkdir -p "$CHROOT/etc/systemd/system/serial-getty@ttyS0.service.d"
cat > "$CHROOT/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty -a root --keep-baud 115200,57600,38400,9600 ttyS0 $TERM
EOF

# DHCP via systemd-networkd with a WILDCARD match — name-agnostic. syzkaller's
# QEMU attaches an e1000 NIC at a PCI slot that renames to enp0s4 (not the enp0s3
# our own virtio launch produces), so per-interface ifupdown stanzas miss it and
# the VM never gets an IP -> ssh fails -> syzkaller can't connect. A wildcard
# networkd unit brings up DHCP on whatever the NIC is called. (See devlog 0009.)
cat > "$CHROOT/etc/network/interfaces" <<'EOF'
auto lo
iface lo inet loopback
EOF
mkdir -p "$CHROOT/etc/systemd/network"
cat > "$CHROOT/etc/systemd/network/10-eth.network" <<'EOF'
[Match]
Name=en* eth*
Type=ether
[Network]
DHCP=yes
EOF
# Enable networkd + sshd offline (host systemctl manipulates the chroot's symlinks).
systemctl --root="$CHROOT" enable systemd-networkd.service ssh.service 2>/dev/null || true

cat > "$CHROOT/etc/fstab" <<'EOF'
/dev/root / ext4 defaults 0 1
EOF

# sshd: root login with key
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' "$CHROOT/etc/ssh/sshd_config"
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' "$CHROOT/etc/ssh/sshd_config"
[ -f "$KEY" ] || ssh-keygen -t ed25519 -N "" -f "$KEY" -q
install -d -m700 "$CHROOT/root/.ssh"
install -m600 "$KEY.pub" "$CHROOT/root/.ssh/authorized_keys"

# automated boot-verify script (used by scripts/verify-vm.sh via init=)
cat > "$CHROOT/root/verify.sh" <<'EOF'
#!/bin/sh
# Minimal PID-1 verification: mount the pseudo-fs we need, print markers, poweroff.
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t debugfs none /sys/kernel/debug 2>/dev/null
echo "=== VERIFIERLOOP-VM-OK ==="
uname -a
echo "-- BTF --"
if [ -e /sys/kernel/btf/vmlinux ]; then echo "BTF present ($(wc -c </sys/kernel/btf/vmlinux) bytes)"; else echo "BTF MISSING"; fi
echo "-- bpffs --"
if mount -t bpf bpf /sys/fs/bpf 2>/dev/null; then echo "bpffs mounted"; else echo "bpffs mount FAILED"; fi
echo "-- kcov --"
if [ -e /sys/kernel/debug/kcov ]; then echo "kcov present"; else echo "kcov MISSING"; fi
echo "=== VERIFIERLOOP-VM-DONE ==="
sync
poweroff -f 2>/dev/null || { echo 1 > /proc/sys/kernel/sysrq 2>/dev/null; echo o > /proc/sysrq-trigger; }
sleep 5
EOF
chmod +x "$CHROOT/root/verify.sh"

# 3. Pack into a raw ext4 image WITHOUT mounting (mkfs.ext4 -d).
echo "[rootfs] building ${SIZE_MB}MB ext4 image ..."
rm -f "$IMG"
truncate -s "${SIZE_MB}M" "$IMG"
mkfs.ext4 -q -F -L verifierloop -d "$CHROOT" "$IMG"

rm -rf "$CHROOT"
echo "[rootfs] image   -> $IMG ($(du -h "$IMG" | cut -f1))"
echo "[rootfs] ssh key -> $KEY"
