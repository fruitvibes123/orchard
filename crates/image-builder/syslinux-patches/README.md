# syslinux template patches

The four Alpine patches applied to the pinned syslinux 6.04-pre1 source before `make bios`. With them,
the `ldlinux.sys` core and `ldlinux.bss` VBR that `syslinux-install` (the pure-Rust B1 patcher, the
boot-fs installer) consumes are byte-faithful to the pinned `syslinux=6.04_pre1-r19` apk's
`extlinux`, the tool the box would otherwise use. `build-syslinux-template.sh` builds the template.
`orchard prime` stages the source (fetch + verify), and `crates/image-builder/src/sources.rs`
re-verifies it at consumption; the retired `fetch-syslinux-source.sh` is gone.

The patches are small, auditable text and an in-tree copy is the sovereign, reproducible choice, so
they are committed in-tree and not fetched at build time, the same as `kernel-hardening.config`. The
large source tarball stays fetched and sha256-pinned, like the kernel source.

## Provenance

Source: Alpine 3.23 aports `main/syslinux/` (APKBUILD `pkgver=6.04_pre1 pkgrel=19`, the exact pin in
the build container's `Containerfile`), captured 2026-06-03 from
`https://gitlab.alpinelinux.org/alpine/aports/-/raw/3.23-stable/main/syslinux/`. The build applies
them in the APKBUILD `source=` order:

| patch | sha256 | role |
|-------|--------|------|
| `0008-Fix-build-with-GCC-14.patch` | `505989a87e5bae60284210c7abea7bae624df73d9b97be42b568118e30d6c6fe` | build-compat (gcc 14+) |
| `0018-prevent-pow-optimization.patch` | `755cd7062fe8495f6f62053ce664451c12ae65dba9fb5c75062a495fbe040fb1` | stop gcc emitting a `pow()` call in the freestanding core |
| `fix-sysmacros.patch` | `cd45d694ac7f5726d2e5e5e470b53306b8616fad81b9ec470d65530413811610` | add `<sys/sysmacros.h>` (extlinux/main.c) |
| `gcc-10.patch` | `7e41e17e8cbc7287d6c3c9eb0a7b682cd8d3252030856b338050c21dff9bf05a` | build-compat (gcc 10+) |

## Effect on the build

Building the upstream source without these patches on the container's gcc 15.2 produces a different
`ldlinux.sys` (68121 B against the patched 58367 B), unfaithful to the pinned `extlinux` and not
proven bootable. None of them touch `libinstaller/syslxmod.c`, the patch area, or the sector map, so
the `syslinux-install` port stays authoritative. `fix-sysmacros` is the only one on the installer side
(`extlinux/main.c`), where it adds one `#include`.

## Source tarball anchor

The pinned `[syslinux].sha256` in `pins.toml` covers the exact upstream `syslinux-6.04-pre1.tar.xz`
that the Alpine 3.23 `main/syslinux` APKBUILD (`pkgver=6.04_pre1 pkgrel=19`) builds from. The
out-of-band anchor is that APKBUILD's committed sha512 `7927dd39…fc98` over the tarball (verified
2026-06-03). Syslinux is not a `market upgrade` leg and carries no PGP at bump, so its pin is a manual
review event: on a version bump, re-verify the new tarball's sha256 against the corresponding Alpine
APKBUILD before re-pinning. `orchard prime` fetches from
`www.kernel.org/.../Testing/6.04/syslinux-<ver>.tar.xz`, and the bake re-derives the pin at
consumption (`sources.rs`).

Re-pin the four patches and the source sha256 only on a deliberate syslinux-version bump.
