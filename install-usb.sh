#!/usr/bin/env bash
# install-usb.sh — build + sign the UEFI box image and write it to a USB drive.
#
# Usage: bash install-usb.sh [DEVICE]
#   DEVICE defaults to /dev/sda.
#
# Run from the repo root as your normal user. The script calls sudo only for
# the partition and dd steps — the build runs as you (Docker + /tmp access).
# Requires: docker, sgdisk, cargo. (The build/sign CLI is the operator-host
set -euo pipefail

# Audit R1 F-10: NO default device. `/dev/sda` is the SYSTEM disk on many machines, and a rubber-stamped
# `yes` would wipe the OS. Require an explicit device argument.
if [[ $# -lt 1 ]]; then
    echo "usage: $0 /dev/sdX   (the USB stick — run \`lsblk\` first to identify it)" >&2
    echo "ERROR: refusing to guess the target device (no /dev/sda default — that is often the OS disk)" >&2
    exit 1
fi
DEVICE="$1"
ORCHARD="target/debug/orchard"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYS_DIR="$HOME/.config/recipes-deploy/keys"

# ── safety ────────────────────────────────────────────────────────────────────
if [[ ! -b "$DEVICE" ]]; then
    echo "ERROR: $DEVICE is not a block device" >&2
    exit 1
fi
# Echo the disk's identity (model + size + whether any partition is mounted) so the operator can SEE it is
# the USB stick and not a system disk before confirming (audit R1 F-10).
echo "Target device: $DEVICE"
lsblk -o NAME,SIZE,MODEL,TRAN,MOUNTPOINTS "$DEVICE"
if lsblk -nro MOUNTPOINTS "$DEVICE" | grep -q .; then
    echo "WARNING: $DEVICE has a MOUNTED partition — this looks like a system/in-use disk, not a USB stick." >&2
fi
read -r -p "Writing to $DEVICE will DESTROY all data. Continue? [yes/N] " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted."
    exit 1
fi

# ── build orchard CLI ─────────────────────────────────────────────────────────
echo
echo "==> Building orchard ..."
cargo build -p orchard

# ── prime sources (skip if already staged) ────────────────────────────────────
# bake re-verifies both tarballs at consumption + extracts a fresh per-build tree.
PINS="$SCRIPT_DIR/pins.toml"
KERNEL_VERSION="$(sed -n '/^\[kernel\]/,/^\[/{s/^version = "\(.*\)"/\1/p;}' "$PINS")"
SYSLINUX_VERSION="$(sed -n '/^\[syslinux\]/,/^\[/{s/^version = "\(.*\)"/\1/p;}' "$PINS")"

if [[ ! -f "/tmp/recipes-kbuild/linux-${KERNEL_VERSION}.tar.xz" \
   || ! -f "/tmp/recipes-syslinux/syslinux-${SYSLINUX_VERSION}.tar.xz" ]]; then
    echo
    echo "==> Priming kernel + syslinux source (fetch + verify + stage) ..."
    "$ORCHARD" prime
else
    echo "==> Kernel + syslinux source tarballs already staged, skipping prime."
fi

# ── build image ───────────────────────────────────────────────────────────────
echo
echo "==> Building box image (UEFI + secure-boot) ..."
BUILD_OUT="$("$ORCHARD" build --firmware uefi --secure-boot --domain box.local --allow-dirty --keys-dir "$KEYS_DIR" 2>&1 | tee /dev/stderr)"
IMG="$(echo "$BUILD_OUT" | grep -oP '(?<=wrote )/tmp/recipes-image-\S+\.img')"
if [[ -z "$IMG" ]]; then
    echo "ERROR: could not parse image path from build output" >&2
    exit 1
fi
echo "Image: $IMG"

# ── sign image ────────────────────────────────────────────────────────────────
echo
echo "==> Signing (sign-sb) ..."
"$ORCHARD" sign-sb --img "$IMG" --keys-dir "$KEYS_DIR"

# ── rootfs fit-check (audit R1 F-1) ───────────────────────────────────────────
# Mirror the installer's check_image_fits: the rootfs must fit slot A (partition 2 = 264192:+131072
# sectors = 64 MiB). Without this, a >64 MiB rootfs is silently TRUNCATED by the bounded
# `dd of=${DEVICE}2` below → a corrupt squashfs → verity fails → reboot loop, with no diagnostic.
LAYOUT="${IMG%.img}.layout.toml"
SLOT_A_BYTES=$((131072 * 512)) # = 64 MiB; matches the `2:264192:+131072` sgdisk arg + installer SLOT_SIZE_BYTES
ROOTFS_SIZE="$(sed -n 's/^rootfs_size = \([0-9]*\).*/\1/p' "$LAYOUT")"
if [[ -z "$ROOTFS_SIZE" ]]; then
    echo "ERROR: could not read rootfs_size from $LAYOUT (fit-check cannot run)" >&2
    exit 1
fi
if (( ROOTFS_SIZE > SLOT_A_BYTES )); then
    echo "ERROR: rootfs ($ROOTFS_SIZE bytes) exceeds slot-A capacity ($SLOT_A_BYTES bytes) — dd to" >&2
    echo "       ${DEVICE}2 would TRUNCATE it (corrupt squashfs → verity fail). Mirrors check_image_fits." >&2
    exit 1
fi
echo "rootfs fit-check OK: $ROOTFS_SIZE of $SLOT_A_BYTES slot-A bytes."

# ── partition USB (needs root) ────────────────────────────────────────────────
echo
echo "==> Partitioning $DEVICE (sudo required) ..."
sudo sgdisk --zap-all \
    -U "d91aff31-df15-4b91-9478-2ff7512c006e" \
    -n "1:2048:+262144"   -t "1:EF00" -u "1:e9abb6ab-76cf-4b2e-aa9a-f53e2ae152dd" \
    -n "2:264192:+131072" -t "2:8300" -u "2:04c92659-e47a-485b-b840-fe5561eaa0da" \
    -n "3:395264:+131072" -t "3:8300" -u "3:a5dff702-a9ff-41a1-9243-30e6136aba95" \
    -n "4:526336:0"       -t "4:8300" -u "4:95f6532c-6953-4b27-8f85-2ba29fb4b91e" \
    "$DEVICE"
sudo partprobe "$DEVICE"

# ── write components (needs root) ─────────────────────────────────────────────
echo
echo "==> Writing boot → ${DEVICE}1 ..."
sudo dd if="$IMG" of="${DEVICE}1" bs=4M count=32 conv=fsync status=progress

echo "==> Writing rootfs → ${DEVICE}2 ..."
sudo dd if="$IMG" of="${DEVICE}2" bs=512 skip=294912 conv=fsync status=progress

echo "==> Writing persist skeleton → ${DEVICE}4 ..."
sudo dd if="$IMG" of="${DEVICE}4" bs=4M skip=32 count=4 conv=fsync status=progress

sudo sync

echo
echo "Done. Boot the laptop from $DEVICE."
echo "Expected: rambutan SB banner → dm-verity → box-init PID-1 → s6 services up."
