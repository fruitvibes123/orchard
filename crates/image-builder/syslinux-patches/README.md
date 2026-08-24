# syslinux template patches (B1 boot-fs installer)

These are the **4 Alpine patches** applied to the pinned syslinux 6.04-pre1 source before
`make bios`, so the `ldlinux.sys` core + `ldlinux.bss` VBR that `syslinux-install` (the pure-Rust B1
patcher) consumes are **byte-faithful to the pinned `syslinux=6.04_pre1-r19` apk's `extlinux`** — the
tool the box would otherwise use. Built by `build-syslinux-template.sh`; source staged (fetch + verify)
by `orchard prime` and **re-verified at consumption** by `crates/image-builder/src/sources.rs`
(the retired `fetch-syslinux-source.sh` is gone).

They are committed in-tree (not fetched at build time) because they are small, auditable text and the
sovereign, reproducible choice — mirroring how `kernel-hardening.config` is committed rather than
pulled. The large source tarball stays fetched-and-pinned (sha256), like the kernel source.

## Provenance

Source: Alpine 3.23 aports `main/syslinux/` (APKBUILD `pkgver=6.04_pre1 pkgrel=19` — the exact pin in
the build container's `Containerfile`). Captured 2026-06-03 from
`https://gitlab.alpinelinux.org/alpine/aports/-/raw/3.23-stable/main/syslinux/`. Applied in this order
(the APKBUILD `source=` order):

| patch | sha256 | role |
|-------|--------|------|
| `0008-Fix-build-with-GCC-14.patch` | `505989a87e5bae60284210c7abea7bae624df73d9b97be42b568118e30d6c6fe` | build-compat (gcc 14+) |
| `0018-prevent-pow-optimization.patch` | `755cd7062fe8495f6f62053ce664451c12ae65dba9fb5c75062a495fbe040fb1` | stop gcc emitting a `pow()` call in the freestanding core |
| `fix-sysmacros.patch` | `cd45d694ac7f5726d2e5e5e470b53306b8616fad81b9ec470d65530413811610` | add `<sys/sysmacros.h>` (extlinux/main.c) |
| `gcc-10.patch` | `7e41e17e8cbc7287d6c3c9eb0a7b682cd8d3252030856b338050c21dff9bf05a` | build-compat (gcc 10+) |

**Why they are load-bearing:** building the upstream source WITHOUT these patches (on the container's
gcc 15.2) produces a *different* `ldlinux.sys` (68121 B vs the patched 58367 B) — unfaithful to the
pinned `extlinux` and unproven-bootable. None touch `libinstaller/syslxmod.c`, the patch area, or the
sector map (so the `syslinux-install` port stays authoritative); `fix-sysmacros` is the only one
touching the installer side (`extlinux/main.c`), adding one `#include`.

## Source tarball anchor (re-homed from the retired `fetch-syslinux-source.sh` header)

The pinned `[syslinux].sha256` in `pins.toml` covers the exact upstream
`syslinux-6.04-pre1.tar.xz` the Alpine 3.23 `main/syslinux` APKBUILD (`pkgver=6.04_pre1 pkgrel=19`)
builds from. The out-of-band anchor is that APKBUILD's committed **sha512 `7927dd39…fc98`** over this
tarball (verified 2026-06-03). Syslinux is **not** a `market upgrade` leg and carries **no PGP at
bump** — its pin is a manual review event: on a version bump, re-verify the new tarball's sha256
against the corresponding Alpine APKBUILD before re-pinning. `orchard prime` fetches from
`www.kernel.org/.../Testing/6.04/syslinux-<ver>.tar.xz` and the bake re-derives the pin at
consumption (`sources.rs`).

Re-pin all four patches (and the source sha256) only on a deliberate syslinux-version bump.
