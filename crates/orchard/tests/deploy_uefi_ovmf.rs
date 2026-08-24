                                                                                            
//!
//! The UEFI analog of `deploy_prod_qemu` (the SeaBIOS gate). Deploy-feature-gated AND env-gated (heavy:
//! a full GPT install + an OVMF boot). SKIPPED unless the env is set; under `--ignored` (`make
                                                                               
//!
//! Env:
//!   - `RECIPES_UEFI_IMG` — a PRE-built `--firmware uefi` `.img` (its `.layout.toml` +
//!     `.vmlinuz` + `.initramfs` sidecars must sit beside it).
//!   - `RECIPES_UEFI_PRIVKEY` — the matching operator private key (the `--operator-pubkey` half).
//!   - `RECIPES_OVMF_CODE` — the SB-OFF OVMF_CODE firmware blob (readonly pflash unit 0).
//!   - `RECIPES_OVMF_VARS` — the OVMF_VARS template (copied writable per boot, pflash unit 1).
//!
//! Build such an image (`--firmware uefi` is a first-class build since the loader pivot un-defer):
//!   orchard build --domain box.test --firmware uefi \
//!     --operator-pubkey <key.pub> --out-dir <dir> --allow-dirty
//! then run:
//!   RECIPES_UEFI_IMG=<dir>/<img>.img RECIPES_UEFI_PRIVKEY=<key> \
//!   RECIPES_OVMF_CODE=/usr/share/edk2/x64/OVMF_CODE.4m.fd \
//!   RECIPES_OVMF_VARS=/usr/share/edk2/x64/OVMF_VARS.4m.fd \
//!     cargo test -p orchard --test deploy_uefi_ovmf -- --ignored --nocapture
//!
                                                                                            
//! mixed-endian serializer `build_gpt`, the ESP type GUID, the slot-A PARTUUID) + dd's the 3-file FAT
//! ESP / rootfs / persist-skeleton with `fb.firmware=uefi` → `commit()`'s GPT arm; OVMF then loads
//! `/EFI/BOOT/BOOTX64.EFI` (the rambutan SB loader) off the ESP with NO `-kernel`/`-append`, the loader
//! `LoadImage`s `\vmlinuz` + sets its LoadOptions to the baked cmdline (which resolves the slot-A
//! PARTUUID against the GPT) + serves the digest-verified `\initrd` via LoadFile2, dm-verity comes up,
//! and the box reaches a working runtime — dropbear accepts the OPERATOR pubkey, recipes serves, `/` is
                                                                                                        
//! `make boot-gate` (it is `#[ignore]`d, never a false green).
//!
//! GREEN 2026-06-10 (SB-OFF, the §9.1 keystone): the boot console showed `BdsDxe: starting … UEFI
//! Misc Device` → the kernel cmdline EXACTLY as the loader baked it (`fb.firmware=uefi
//! fb.root-hash=… fb.verity-hash-offset=… fb.rootfs-dev=PARTUUID=…`, no `initrd=` token) →
//! `Kernel is locked down` → dm-verity rootfs → box-init Services → operator-pubkey auth succeeded.

#[path = "deploy_uefi_ovmf/common.rs"]
mod common;
#[path = "deploy_uefi_ovmf/installer_usb.rs"]
mod installer_usb;
#[path = "deploy_uefi_ovmf/sb_chain.rs"]
mod sb_chain;
