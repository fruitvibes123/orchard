#!/bin/sh
#
# Runs in the PINNED Alpine container (same substrate as the kernel + musl builds). Builds the
# UNPATCHED `ldlinux.sys` core + the VBR (`ldlinux.bss`) that `syslinux-install` (the pure-Rust B1
# patcher) consumes. Reproduces the SAME bytes the pinned `syslinux=6.04_pre1-r19` apk's `extlinux`
# embeds — by building from the same upstream source + the same 4 Alpine patches the apk is built from.
#
# EMPIRICALLY VALIDATED (2026-06-03): byte-reproducible across builds IFF HEXDATE + DATE are pinned.
# syslinux's `core/Makefile` derives HEXDATE from `now.pl $(SRCS)` (the newest SOURCE-FILE mtime) and
# DATE from `gen-id.sh` (`git describe` if any .git is present, else the timestamp) — BOTH non-
# deterministic once `patch` stamps wall-clock mtimes / if a .git is in scope. Both are `ifndef`-
# overridable, so we pin them: HEXDATE = hex(SOURCE_DATE_EPOCH) (ties to the build's determinism
# anchor, same as the kernel/initramfs/squashfs), DATE = a fixed build string. `unset LDFLAGS` mirrors
# the APKBUILD. The bios CORE is unaffected by also building the installer/efi, so plain `make bios`
# suffices (it errors later on the irrelevant `dos` target, AFTER the core — tolerated + asserted).
#
# Inputs (env): SYSLINUX_SRC (a FRESH per-build extraction of the pinned + sha256-verified source,
# tarball), SYSLINUX_PATCHES (the dir holding the 4 committed Alpine patches), SOURCE_DATE_EPOCH
# (determinism), OUT (writable output dir — receives ldlinux.sys + ldlinux.bss).
set -eu

# makedepends — Alpine's exact `main/syslinux` APKBUILD set (+ build-base for gcc/make/binutils/ld).
apk add --no-cache build-base linux-headers nasm perl util-linux-dev gnu-efi-dev

# The source tree is a fresh per-build extraction (mounted RW): patches apply to a pristine tree, so
# the build stays idempotent + reproducible. The Rust extract already did `--strip-components=1`
# (the inner top-level dir is mounted directly).
cd "$SYSLINUX_SRC"

# Apply the 4 pinned Alpine patches, in APKBUILD source= order. `--no-backup-if-mismatch` keeps no
# .orig files (which could otherwise perturb a later `now.pl $(SRCS)` glob).
for p in 0008-Fix-build-with-GCC-14 0018-prevent-pow-optimization fix-sysmacros gcc-10; do
    patch -p1 --no-backup-if-mismatch < "$SYSLINUX_PATCHES/$p.patch"
done

unset LDFLAGS
HEXDATE="$(printf '0x%08x' "$SOURCE_DATE_EPOCH")"
DATE_STR="6.04-pre1-recipes"   # fixed build-id string (cosmetic version banner; pinned for determinism)

# `make bios` builds the bios bootloaders incl. bios/core/ldlinux.{sys,bss}; it then errors on the
# unrelated `dos` target — tolerated. We assert the core artifacts exist (fail-closed on a real failure).
make bios HEXDATE="$HEXDATE" DATE="$DATE_STR" \
    || echo ">> 'make bios' returned nonzero (expected: the post-core dos target); verifying core ..." >&2

test -f bios/core/ldlinux.sys || { echo "ERROR: bios/core/ldlinux.sys was not built" >&2; exit 1; }
test -f bios/core/ldlinux.bss || { echo "ERROR: bios/core/ldlinux.bss was not built" >&2; exit 1; }

cp bios/core/ldlinux.sys "$OUT/ldlinux.sys"
cp bios/core/ldlinux.bss "$OUT/ldlinux.bss"
chmod a+r "$OUT/ldlinux.sys" "$OUT/ldlinux.bss"
echo "SYSLINUX_TEMPLATE_OK: ldlinux.sys=$(wc -c <"$OUT/ldlinux.sys")B ldlinux.bss=$(wc -c <"$OUT/ldlinux.bss")B (HEXDATE=$HEXDATE DATE=$DATE_STR)"
