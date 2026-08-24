#!/bin/sh
# Reproducible kernel build for the box.
#
# Runs in the PINNED Alpine container (same substrate as the musl binary build). Assembles
# Alpine's linux-virt base config + the recipes hardening fragment, runs `make olddefconfig`,
# GATES on the image-builder asserting every required CONFIG survived, then builds bzImage with
# reproducible inputs.
#
# EMPIRICALLY VALIDATED on linux-virt 6.18.33 (2026-05-25): all the pinned CONFIGs survive
# olddefconfig (kernel-config-pins.toml; the exact count is owned by the pins_cover_the_spec_blocks
# test, so it is not duplicated here). R8 silent-drop risk closed; the hardened config (MODULES=n + IMA/EVM/verity
# built-in + lockdown-force + Alpine's hardening gcc-plugins) builds to a ~26 MB bzImage.
#
# Inputs (env): KSRC (a fresh per-build extraction of the pinned + sha256-verified tarball),
# BASE_CONFIG (Alpine config-<ver>-virt), HARDENING_FRAGMENT
# (kernel-hardening.config), CA_CERT (operator CA cert for CONFIG_SYSTEM_TRUSTED_KEYS — the CA that
# (R.4: the operator-secret-derived latent_entropy -frandom-seed; see KCFLAGS below).
set -eu

# makedepends — empirically discovered (mirrors Alpine's linux-virt makedepends). NB: objtool
# needs linux-headers (UAPI asm/types.h); the latent_entropy gcc-plugin (a hardening feature from
# Alpine's base config, KEPT) needs gmp-dev/mpc1-dev/mpfr-dev.
apk add --no-cache build-base bison flex perl bash openssl openssl-dev elfutils-dev bc \
    diffutils linux-headers gmp-dev mpc1-dev mpfr-dev zstd xz findutils

cd "$KSRC"
# Pristine tree (drop stale .o / vmlinux / .config) before configuring -- a dirty tree
# is a classic non-reproducibility (and miscompile) source per the kernel's own
# Documentation/kbuild/reproducible-builds.rst.
make mrproper
cp "$BASE_CONFIG" .config
# Merge the base hardening fragment. ONE plain kernel serves BOTH firmwares since the 2026-06-10 loader
# pivot: the kernel-stub-era UEFI EFI-stub fragment + the per-build CONFIG_INITRAMFS_SOURCE embed (D1)
# are GONE — the rambutan loader carries boot policy + serves the initrd via LoadFile2, so the kernel
bash scripts/kconfig/merge_config.sh -m .config "$HARDENING_FRAGMENT"
# C3 substrate fragment: ALWAYS merge the firmware-derived per-substrate fragment. vps-kvm's
# (kernel-hardening-vpskvm.config) DISABLES the USB host/storage stack the linux-virt base ships (a KVM
# guest never boots off USB media, so it's dead attack surface; the DISK transports SCSI/ATA/NVMe STAY
# so the box boots on any hypervisor's disk); bare-metal's (kernel-hardening-baremetal.config) ENABLES
# the USB stack for USB-media boot. kernel-config-pins-<substrate>.toml's assert then holds by construction.
bash scripts/kconfig/merge_config.sh -m .config "$SUBSTRATE_FRAGMENT"
make olddefconfig

# GATE (R8 silent-drop guard): every required CONFIG must survive olddefconfig. ENFORCED by the
# orchestrator — build() calls kernel::assert_kernel_config(.config, kernel-config-pins.toml) on the
# returned .config and aborts (no .img written) on any missing pin. NOTE (audit L-2): that assert
# runs POST-`make` (Rust-side) rather than pre-`make` here; the security property holds (a regression
# aborts before any output) at the cost of a wasted compile. Pre-`make` (the spec's intent) would
# require running the assertion inside this container before `make bzImage` — deferred.

# Operator CA cert -> CONFIG_SYSTEM_TRUSTED_KEYS embeds it into .builtin_trusted_keys; the CA vouches
# leaf here was the inverted-model lockout trap; the CA carries keyCertSign, the leaves do NOT).
mkdir -p certs && cp "$CA_CERT" certs/recipes-ca.pem

# Determinism (defense layer 8 + the pipeline's tamper-detection control: an independent rebuild ->
# identical hash makes build-host compromise detectable). Per the kernel's
# EXPORT SOURCE_DATE_EPOCH (neutralizes __DATE__/__TIME__ in any external code); prefix-map the
# absolute $KSRC source paths so the build location doesn't leak into the artifact.
export SOURCE_DATE_EPOCH
export KBUILD_BUILD_TIMESTAMP="@${SOURCE_DATE_EPOCH}"
export KBUILD_BUILD_USER=recipes
export KBUILD_BUILD_HOST=recipes-builder
# The operator-secret-derived -frandom-seed flips the latent_entropy gcc-plugin to its
# deterministic path (else it seeds from /dev/urandom PER BUILD → a non-reproducible kernel — the
# ~9% uncompressed delta the decompress-diff found, amplified ~99% by compression). Domain-separated
# HKDF from the operator master (recipes-host-key-derivation, kernel_frandom_seed_hex); secret, so
# reproducible-for-the-owner yet unpredictable without the key. set -u makes an unset FRANDOM_SEED fail.
export KCFLAGS="-fdebug-prefix-map=${KSRC}=/recipes-kernel -fmacro-prefix-map=${KSRC}=/recipes-kernel -frandom-seed=${FRANDOM_SEED}"
# (build_image.rs `build_twice_is_byte_identical`) is wired and GREEN, and the vmlinuz component
# hashes identically across builds — so the operator-secret -frandom-seed deterministically pins the
# latent_entropy plugin (was source-reasoned; now empirically confirmed).

make -j"$(nproc)" bzImage
ls -l arch/x86/boot/bzImage
