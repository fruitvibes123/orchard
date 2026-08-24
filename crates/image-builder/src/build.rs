                                                                                  
//!
//! Wires Phase-1's components into the end-to-end build, emitting the **unsigned**
//! triple `recipes-image-<sha>.{img,layout.toml,sha256}` (the `.img` CMS `.sig` is
                                                                       
//!
//! The external-tool steps (musl binary build, evmctl IMA/EVM sign, abuild kernel
//! build, mksquashfs, veritysetup, initramfs cpio) sit behind the [`BuildTools`]
//! seam — mirroring the [`crate::PackageProvider`] / [`crate::Fetcher`] seams — so
//! the orchestration LOGIC (spec order, staging, the determinism-critical assembly
//! tail) is unit-tested with fakes. The production [`HostBuildTools`] impl shells
//! out via the pinned argv builders ([`crate::squashfs`] / [`crate::verity`] /
//! [`crate::ima_evm`]); its real-tool behaviour is integration-verified (operator
//! smoke + the Phase-3 QEMU boot test), like the other build-host tools.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use grape::PublicInputs;

use crate::firmware::{Firmware, Substrate};
use crate::image::{self, ImageOutputs};
use crate::kernel::{self, KernelConfigPins};
use crate::{boot_fs, ownership, PackageProvider, PinnedApks};

/// The OS-infra + reference-tenant base binaries ALWAYS staged at `/usr/bin`, independent of the tenant
/// manifest: the `recipes` app + `recipes-admin` (the reference tenant — staged-but-unused on a
/// non-recipes box, the accepted post-split de-hardcoding gap, see `toy-tenant.toml`), the four `fb-*`
/// box services, and the two os-update A/B v1 bins — `fb-update` (the engine the `orchard update`
/// ceremony ssh-execs) + `fb-mark-good` (the OS-invariant health-probe longrun `service_tree.rs`
/// renders, C-D). A dha box adds its own tenant bins ON TOP via [`staged_usr_bin_names`].
pub const OS_BINS: &[&str] = &[
    "recipes",
    "recipes-admin",
    "fb-acme",
    "fb-oneshots",
    "fb-backup",
    "fb-cert-check",
    "fb-update",
    "fb-mark-good",
];

/// The set of `/usr/bin` binary NAMES the box stages = [`OS_BINS`] ∪ the manifest-declared tenant bins
/// (each service's `Exec`/`PeriodicLoop` binary, each boot-hook binary, and the runtime-config client
/// program) whose parent dir is exactly `/usr/bin`. Deduped by the `BTreeSet` (a tenant bin already in
/// `OS_BINS` — e.g. the recipes service's `/usr/bin/recipes` — is not double-listed). `build_binaries`
                                                                                                          
/// tenant binary (the toy, whose `widget` is `/bin/busybox`) yields EXACTLY `OS_BINS`.
pub fn staged_usr_bin_names(manifest: &fb_manifest::ValidatedManifest) -> BTreeSet<String> {
    use fb_manifest::manifest::ServiceShape;
    let mut names: BTreeSet<String> = OS_BINS.iter().map(|s| (*s).to_string()).collect();
    let m = manifest.manifest();
    for svc in &m.services {
        let (ServiceShape::Exec { binary, .. } | ServiceShape::PeriodicLoop { binary, .. }) =
            &svc.shape;
        if let Some(name) = usr_bin_basename(binary) {
            names.insert(name);
        }
    }
    for hook in &m.boot_hooks {
        if let Some(name) = usr_bin_basename(&hook.binary) {
            names.insert(name);
        }
    }
    if let Some(rc) = &m.runtime_config {
        if let Some(name) = usr_bin_basename(&rc.client.program) {
            names.insert(name);
        }
    }
    names
}

/// The basename of a `/usr/bin/<name>` path, or `None` when the parent dir is not exactly `/usr/bin` —
/// a `/bin/busybox` or `/usr/sbin/ntpd` tenant binary is provided by the base rootfs apk closure, NOT a
/// fetched build artifact, so `build_binaries` does not stage it.
fn usr_bin_basename(path: &str) -> Option<String> {
    let p = Path::new(path);
    if p.parent() == Some(Path::new("/usr/bin")) {
        p.file_name()?.to_str().map(|s| s.to_string())
    } else {
        None
    }
}

/// Map a staged `/usr/bin` NAME to its `consume-pins` store KEY: `recipes` → `recipes-app` and
/// `creatine` → `creatine-serve` (the staged name is the manifest's execve basename; the key is the
/// owning repo's PUBLISH key — they differ where a repo publishes one specialized bin under a
/// product name). Every other name is its own key (a tenant bin absent from `consume-pins.toml`
/// then fails closed at `pins.artifact(key)?`). LOCKED by
/// `tests/consume_pins_fixture.rs::every_staged_dha_bin_resolves_to_a_pinned_key`: a
/// staged-name → key → pin chain break fails `make verify`, not the bake — the 2026-07-10 dha-bake
/// red (`Missing("creatine")`) happened because this map lacked the creatine arm and only a REAL
/// bake exercises it (the FakeTools staging path never consults pins).
pub fn bin_store_key(name: &str) -> &str {
    match name {
        "recipes" => "recipes-app",
        "creatine" => "creatine-serve",
        _ => name,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("apk acquisition failed: {0}")]
    Acquire(#[from] crate::AcquireError),
    #[error("kernel CONFIG assertion failed: {0}")]
    KernelConfig(#[from] kernel::ConfigAssertError),
    #[error("rescue-seed derivation failed: {0}")]
    RescueSeed(#[from] grape::DeriveError),
    #[error("config render/check failed: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("build tool `{tool}` failed: {reason}")]
    Tool { tool: &'static str, reason: String },
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("pin manifest: {0}")]
    Pin(#[from] crate::pin_manifest::PinManifestError),
    #[error("artifact store: {0}")]
    Store(#[from] crate::artifact_store::ArtifactStoreError),
    #[error(
        "verity-hash offset mismatch (H-1): the slot-A APPEND bakes {append} but the .img layout \
         records {layout} — the runtime dm-verity table would read the hash tree at the wrong block"
    )]
    VerityOffsetMismatch { append: u64, layout: u64 },
    #[error(
        "rootfs component is {size} bytes — exceeds the {slot}-byte A/B slot; without this build-side \
         guard it would only fail on the box at install. Shrink the rootfs (kernel/squashfs) or grow the slot"
    )]
    RootfsTooLarge { size: u64, slot: u64 },
    #[error(
        "persist-skeleton has an ext4 journal (superblock HAS_JOURNAL feature set) — it MUST be baked \
         `-O ^has_journal`: byte-reproducibility needs no journal, AND box-init's \
         prepare-persist gates the first-boot grow on journal-ABSENCE, so a journaled skeleton would \
         skip the grow and strand the box at the small skeleton size"
    )]
    PersistSkeletonHasJournal,
    #[error(
        "dha weights GGUF at {path} hashes to {got} but models.toml pins {want} — a tampered/wrong \
         weights file must never reach the squashfs+dm-verity bake (Component E integrity gate)"
    )]
    WeightsShaMismatch {
        path: String,
        want: String,
        got: String,
    },
    #[error(
        "weights GGUF at {path} is {got} bytes but the models.toml profile pins {want} — aborting \
         before the multi-GiB hash (the usual cause is the wrong model/projector file or a truncated \
         download; the sha256 gate below is the integrity check, this is the fast fail)"
    )]
    WeightsSizeMismatch { path: String, want: u64, got: u64 },
    #[error(
        "hotswap v4: the RuntimeRecord weights anchor requires a weights input (a runtime-weights \
         box without a model is a nonsense config — pass the GGUF, or use the BootCmdline anchor)"
    )]
    RuntimeAnchorWithoutWeights,
    #[error(
        "hotswap v4: the RuntimeRecord weights anchor requires a resource-domain ENGINE service in \
         the tenant manifest (the fb-weights setup prelude + the swap's stop/start target) — got none"
    )]
    RuntimeAnchorWithoutEngine,
    #[error(
        "hotswap v4: signing the baked weights record failed: {reason} — a v4 box never ships an \
         unverifiable record (mint the Purpose::Weights delegation via `orchard redelegate` if the \
         key set predates it)"
    )]
    WeightsRecordSigning { reason: String },
    #[error(
        "dha weights build requires a GPT firmware (SeabiosGpt or Uefi) — the weights volume is a 5th GPT \
         partition, and legacy MBR SeaBIOS has no 5th primary; build --firmware seabios-gpt (the \
         build-time twin of the install-time compute_partition_layout guard)"
    )]
    WeightsRequireGptFirmware,
    #[error(
"staged file {key:?} (mode {mode:#o}) is incoherent with its pin kind {kind:?} (V5): a \
         Binary must be executable, a Config must not be, and a Source drop is never a stageable rootfs file"
    )]
    StagedExecKindMismatch {
        key: String,
        kind: crate::pin_manifest::ArtifactKind,
        mode: u32,
    },
}

/// The custom kernel build's artifacts (build-pipeline step 5d/7).
pub struct KernelArtifacts {
    /// The `vmlinuz` bzImage bytes.
    pub vmlinuz: Vec<u8>,
    /// The produced `.config` (post-`olddefconfig`) — asserted against the pins.
    pub dot_config: String,
}

/// The dm-verity build's artifacts (build-pipeline step 9).
pub struct VerityArtifacts {
    /// The hash-tree bytes (appended after the padded squashfs).
    pub hash_tree: Vec<u8>,
    /// The verity root hash (hex) — goes onto the extlinux APPEND `fb.root-hash=` at deploy time.
    pub root_hash: String,
}

/// The boot partition filesystem size. MUST equal `initramfs_init::installer::BOOT_SIZE_BYTES` (the
/// installer slices the `.img`'s boot component to exactly this). Duplicated because the installer is
/// a separate panic=abort workspace; kept in lockstep by this cross-ref. 128 MiB (the spec's 50 MiB
/// was undersized vs the ~27 MiB kernel × 2 A/B kernels on /boot).
pub(crate) const BOOT_FS_SIZE_BYTES: u64 = 128 * 1024 * 1024;

/// The A/B rootfs slot size. MUST equal `initramfs_init::installer::SLOT_SIZE_BYTES` — the installer
/// `dd`s the rootfs component into a slot of exactly this size (`check_image_fits`). Duplicated (the
/// installer is a separate panic=abort workspace); the M-1 guard in `build()` uses it to fail a
/// too-large rootfs at BUILD instead of on the box at install.
pub(crate) const SLOT_SIZE_BYTES: u64 = 64 * 1024 * 1024;

/// The persist-skeleton size — a SMALL seed ext4 the box `resize2fs`-grows to fill the persist
/// partition on first boot (Task 7). It only carries the operator-pubkey skeleton; 16 MiB stays
/// comfortably above ext4's structural minimum while keeping the baked `.img` small.
pub(crate) const PERSIST_SKELETON_SIZE_BYTES: u64 = 16 * 1024 * 1024;

/// Fixed, build-time-PUBLIC ext4 identifiers for byte-reproducibility — NOT secret; they only make the
/// filesystem UUID + htree/csum seed deterministic run-to-run. Distinct per filesystem so the boot-fs
/// and persist images never share a UUID. (The box mounts persist by `LABEL=persist`, not this UUID.)
pub(crate) const BOOT_FS_UUID: &str = "b0070000-0000-4000-8000-000000000001";
pub(crate) const PERSIST_FS_UUID: &str = "9e751500-0000-4000-8000-000000000002";
pub(crate) const BAKE_HASH_SEED: &str = "5eed0000-0000-4000-8000-000000000003";
/// §9.5: the installer USB data partition's ext4 filesystem UUID — a fixed constant for determinism.
/// NOT load-bearing (the init resolves the data partition by its GPT PARTUUID `INSTALLER_DATA_PARTUUID`,
/// not the fs UUID); distinct from [`PERSIST_FS_UUID`] only so two baked filesystems never collide.
pub(crate) const INSTALLER_DATA_FS_UUID: &str = "b0a7da7a-0000-4000-8000-000000000004";

/// Fixed PAST epoch for restore-image bakes — applied on BOTH normalization legs (the in-container
/// `touch` sweep AND the `SOURCE_DATE_EPOCH` env), a constant so the mke2fs timestamp clamp always
                                                                                                   
                                                                                               
/// alternative is recorded in the spec).
pub(crate) const RESTORE_BAKE_EPOCH: u64 = 1_600_000_000;

/// The pinned sha256 of the container apk's `/usr/share/syslinux/ldlinux.c32` (syslinux=6.04_pre1-r19).
/// The core + VBR are built from the pinned SOURCE tarball; the c32 rides the pinned apk, so
/// `bake_boot_fs` asserts THIS sha before staging it (L-1) — a container rebuild that drifted the
/// syslinux apk fails the bake LOUD rather than pairing a drifted c32 with the source-pinned core.
/// Re-pin on a deliberate syslinux bump.
pub(crate) const LDLINUX_C32_SHA256: &str =
    "6bb315e3a4def84f4ae55cda933e4848fb28bb0745282cf8f86bb9283085590b";

/// The pinned sha256 of the container apk's `/usr/share/syslinux/mbr.bin` (syslinux=6.04_pre1-r19) —
/// the 440-byte MBR stage-1 the dd-only installer writes LAST (`SyscallInstallOps::write_mbr_bootcode`
/// reads it from the initramfs at `/usr/share/syslinux/mbr.bin`). `build_initramfs` stages it into the
/// initramfs cpio and asserts THIS sha first (same supply-chain discipline as the c32, L-1) — a drifted
/// syslinux apk fails the build LOUD rather than baking a mismatched stage-1. Re-pin on a syslinux bump.
pub(crate) const MBR_BIN_SHA256: &str =
    "4746f74bc9b9d3d579c41988a4a29bb7ac932ad1c70470ea779ea161eb799b64";

/// The pinned sha256 of the container apk's `/usr/share/syslinux/gptmbr.bin` (syslinux=6.04_pre1-r19) —
/// the 440-byte GPT-aware MBR stage-1 the dd-only installer writes LAST on the SeabiosGpt arm
/// (`SyscallInstallOps::write_gptmbr_bootcode` reads it from the initramfs at
/// `/usr/share/syslinux/gptmbr.bin`). `build_initramfs` stages it alongside `mbr.bin` and asserts THIS
/// sha first (same L-1 supply-chain discipline) — a drifted syslinux apk fails the build LOUD rather
/// than baking a mismatched stage-1. Re-pin on a syslinux bump.
pub(crate) const GPTMBR_BIN_SHA256: &str =
    "d2a9081727f91f4c38494e52cdeb86ebd9009fead17a739effbad4011c581d1f";

/// dha Component E: the weights RO dm-verity volume's MOUNT DIRECTORY, baked EMPTY into the rootfs
/// squashfs for a dha build (initramfs-init mounts the weights volume onto it before `switch_root`,
                                                                                                      
/// standalone `panic=abort` workspace (not a dependency here), so the constant is DUPLICATED (D3, the
/// same cross-crate convention-duplication as [`boot_fs::WEIGHTS_PARTUUID`]). A drift breaks the weights
/// mount on every dha boot (E3 fails closed on the absent dir → PID-1 reboot loop). Pinned to the literal
/// by `weights_mount_dir_is_the_canonical_literal`.
pub(crate) const WEIGHTS_MOUNT_DIR: &str = "/models";

/// The external-tool seam. Production = [`HostBuildTools`] (shell-outs); tests inject
/// fakes producing fixture bytes so the orchestration logic is exercised without a
/// container/network/root.
pub trait BuildTools {
    /// Stage the in-image `/usr/bin` binaries into `staging` from the pinned store: [`OS_BINS`] ∪ the
    /// manifest's tenant bins ([`staged_usr_bin_names`]) ∪ `extra_bins` (hotswap v4: `fb-weights` on a
    /// RuntimeRecord build — anchor-conditional so every other shape stays byte-identical). Each is
                                                                                                   
    /// pinned binary IS the artifact).
    fn build_binaries(
        &self,
        staging: &Path,
        manifest: &fb_manifest::ValidatedManifest,
        extra_bins: &[&str],
    ) -> Result<(), BuildError>;
                                                                                                            
    /// onto `staging` under `/opt/<dir>/…` with escape-proof semantics + the declared mode/owner. Returns
                                                                                                           
    fn stage_manifest_files(
        &self,
        staging: &Path,
        manifest: &fb_manifest::ValidatedManifest,
    ) -> Result<Vec<ownership::OwnerException>, BuildError>;
    /// Sign every regular file in `staging` with the in-tree DETERMINISTIC signer
    /// ([`crate::ima_evm_signer`], RFC-6979 ECDSA) and return a mksquashfs `-pf` pseudo-file that
    /// injects per-inode `m` ownership lines + the `security.ima`/`security.evm` xattrs. Pure
    /// host-Rust — no container, no CAP_SYS_ADMIN (the bytes go into the image via `pack_squashfs
    /// -pf`, not a live setxattr). `ima_cert` supplies the be32 keyid (its SubjectKeyIdentifier
    /// suffix). `owner_exceptions` are the manifest-declared non-`0:0` files (D7); every other inode
    /// defaults to `0:0` (D3), and an exception on a staging-absent path fails closed (R2-4).
    fn ima_evm_xattr_pseudo(
        &self,
        staging: &Path,
        ima_key: &Path,
        ima_cert: &Path,
        owner_exceptions: &[ownership::OwnerException],
    ) -> Result<String, BuildError>;
    /// Build the custom kernel; return the bzImage + the produced `.config`. `frandom_seed_hex` is
    /// the operator-secret-derived GCC `-frandom-seed` (R.4) that flips `latent_entropy` to its
    /// deterministic path so the kernel is reproducible-for-the-owner.
    fn build_kernel(
        &self,
        source_date_epoch: u64,
        frandom_seed_hex: &str,
    ) -> Result<KernelArtifacts, BuildError>;
    /// Pack `staging` into a deterministic squashfs (`-xattrs -all-root` + fixed mtime), injecting the
    /// IMA/EVM xattrs from `xattr_pseudo` (the `ima_evm_xattr_pseudo` mksquashfs `-pf` pseudo-file).
    fn pack_squashfs(
        &self,
        staging: &Path,
        source_date_epoch: u64,
        xattr_pseudo: &str,
    ) -> Result<Vec<u8>, BuildError>;
    /// Build the dm-verity hash tree over `squashfs` (fixed salt, `--no-superblock`); return the
    /// tree + root hash.
    fn build_verity(&self, squashfs: &[u8]) -> Result<VerityArtifacts, BuildError>;
    /// dha Component E (O4=(a) GPT): pack the operator's already-sha-verified weights GGUF(s) into a
    /// deterministic squashfs holding the canonical file [`crate::models::MODEL_GGUF_NAME`]
    /// (`model.gguf`) — plus [`crate::models::MMPROJ_GGUF_NAME`] (`mmproj.gguf`) when the resolved pin
                                                                                                         
    /// pseudo-file: the weights are DATA `creatine` `read(2)`s, not an `execve` target the Option-C policy
    /// appraises — dm-verity (built by [`Self::build_verity`] over this squashfs, mounted
    /// DEFAULT/opt-count-0 = EIO-on-corruption) is the integrity anchor. The caller wraps
    /// `(squashfs, verity)` into a [`crate::image::RootfsComponent`] exactly like the rootfs. Both paths
    /// are host GGUFs (multi-GiB — staged, never held in a `Vec`).
    ///
                                                                                                          
    /// profile and the `deploy-model` push path are unchanged).
    fn pack_weights_squashfs(
        &self,
        gguf_path: &Path,
        mmproj_path: Option<&Path>,
        source_date_epoch: u64,
    ) -> Result<Vec<u8>, BuildError>;
    /// Build the initramfs cpio (the compiled `/init` + the embedded installer siblings + the
    /// `/dev/console`+`/dev/null` nodes) — ONE initramfs for BOTH firmwares (SB-loader plan L5;
    /// the kernel-stub-era `build_initramfs_uefi` variant is gone).
    fn build_initramfs(&self, source_date_epoch: u64) -> Result<Vec<u8>, BuildError>;
    /// readelf the DT_NEEDED sonames of every ELF in the staging tree (no execution). Returns
    /// `(elf-relative-path, NEEDED sonames)` — feeds the link-completeness + no-PAM guards.
    fn collect_needed(&self, root: &Path) -> Result<Vec<(String, Vec<String>)>, BuildError>;
    /// Assemble the box's init/supervision layer into `staging`: write the servicedir tree
    /// ([`crate::service_tree`] — the longrun `run` scripts + the `.s6-svscan` handlers), build the
    /// `box-init` PID-1 (its own in-container cargo step), stage it at `/usr/bin/box-init` with
    /// `/sbin/init` a relative symlink to it, and `busybox --install -s` the runtime applet symlinks.
    /// NO `s6-rc-compile`/`s6-linux-init-maker` — both subsystems were dropped by the signed-exec
    /// redesign. MUST run BEFORE the IMA/EVM signer (step 8): box-init, `/sbin/init`, and every run
    /// script/handler are regular files the boot-time Option-C policy BPRM-appraises, so they must be
    /// in the signed set (the C-1 sign-window invariant). `domain` + `source_date_epoch` thread into
    /// the run scripts (set-hostname fallback / acme-renew `--min-epoch` clock floor).
    fn build_init_tree(
        &self,
        staging: &Path,
        domain: &str,
        source_date_epoch: u64,
        manifest: &fb_manifest::ValidatedManifest,
        weights: crate::service_tree::EngineWeightsSetup,
    ) -> Result<(), BuildError>;
    /// Bake the boot partition filesystem (O3 pre-baked installer). A fixed-size ext4 image
    /// (= [`BOOT_FS_SIZE_BYTES`]) populated mount-free via `mke2fs -d` with `/slot-a/{vmlinuz,
    /// initramfs, extlinux.conf, ldlinux.sys, ldlinux.c32}` (+ the `/extlinux.conf` symlink), then made
    /// bootable by the **B1** pure-Rust syslinux installer ([`syslinux_install`]): the source-built
    /// `ldlinux.sys` is `prepare_ldlinux_sys`-prepped before staging, and `install_into_bootfs` patches
    /// it + the VBR in place after `mke2fs -d`. NO `extlinux`, NO loop-mount, NO `CAP_SYS_ADMIN`
    /// (the I-3 invariant holds). `extlinux_conf` is the rendered APPEND
    /// ([`crate::boot_fs::render_boot_fs_extlinux`]). Byte-reproducible.
    ///
                                                                                               
    /// two-label layout: the loader home moves to `/syslinux/{ldlinux.sys,ldlinux.c32,extlinux.conf}`,
    /// the active kernel lands in `/slot-a/{vmlinuz,initramfs}`, and an EMPTY `/slot-b/` directory is
    /// created at genesis so `fb-update`'s staging has its target (R1-11; slot-b files are absent).
    /// `Seabios` (MBR) keeps today's single-label `/slot-a/*` shape (updates are refused there anyway).
    /// `Uefi` never reaches here (it bakes an ESP, [`Self::bake_esp`]).
    fn bake_boot_fs(
        &self,
        vmlinuz: &[u8],
        initramfs: &[u8],
        extlinux_conf: &str,
        firmware: Firmware,
        source_date_epoch: u64,
    ) -> Result<Vec<u8>, BuildError>;
    /// Bake the UEFI ESP — a deterministic FAT16 image (= [`BOOT_FS_SIZE_BYTES`], the boot partition
    /// size) holding the THREE boot files (SB-loader plan L6): `/EFI/BOOT/BOOTX64.EFI` = the SIGNED-set
    /// rambutan loader, `\vmlinuz` = the plain shared kernel (LoadImage'd + db-re-verified by the
    /// firmware under SB), `\initrd` = the shared initramfs (digest-gated + LoadFile2-served by the
    /// loader). Built mount-free via `mformat` and mtools (NO `mkfs.fat`/dosfstools, NO loop, NO
    /// `CAP_SYS_ADMIN` — the I-3 invariant holds); `SOURCE_DATE_EPOCH` + a fixed volume serial make it
    /// byte-reproducible. Fail-closed if the three files cannot fit the fixed partition size. The UEFI
    /// analog of [`Self::bake_boot_fs`] — no extlinux/`rootfs-dev` sentinel (the cmdline is baked into
    /// the signed loader; the rootfs is PARTUUID-selected against the GPT).
    fn bake_esp(
        &self,
        loader: &[u8],
        vmlinuz: &[u8],
        initrd: &[u8],
        source_date_epoch: u64,
    ) -> Result<Vec<u8>, BuildError>;
    /// Bake the persist-skeleton (O3). A SMALL fixed-size ext4 image (= [`PERSIST_SKELETON_SIZE_BYTES`]),
    /// labelled `persist` (M-1 — the box mounts by `LABEL=persist`), carrying the operator pubkey at
                                                                                                  
    /// skeleton dirs. The box `resize2fs`-grows it to the full persist partition on first boot. An empty
    /// `operator_pubkey` bakes an un-loginable skeleton (mirrors the recovery-pubkey placeholder).
    /// Byte-reproducible (root-owned inodes, fixed UUID/seed).
    fn bake_persist_skeleton(
        &self,
        operator_pubkey: &[u8],
        source_date_epoch: u64,
        weights_record: Option<&[u8]>,
    ) -> Result<Vec<u8>, BuildError>;
    /// §9.5 UEFI signed-USB installer: bake the installer USB's ext4 DATA partition (p2) — an ext4 image
    /// holding `box.img` + `box.layout.toml` at the fixed built-in paths the init reads (`/box.img`,
    /// `/box.layout.toml`). Populated mount-free via `mke2fs -d` (NO loop, NO `CAP_SYS_ADMIN` — the I-3
    /// invariant holds), sized to fit `box.img` + ext4 overhead/slack, with `SOURCE_DATE_EPOCH` + a fixed
    /// UUID/seed for determinism. The analog of [`Self::bake_persist_skeleton`] for the USB data
    /// partition; [`crate::installer_usb::assemble_usb_image`] lays the returned image at p2.
    fn bake_installer_data(
        &self,
        box_img: &[u8],
        box_layout_toml: &[u8],
        source_date_epoch: u64,
    ) -> Result<Vec<u8>, BuildError>;
    /// Compile the rambutan UEFI SB loader (`vendor/rambutan`, `--target x86_64-unknown-uefi`,
    /// in-container on the pinned toolchain) with its per-build POLICY baked as compile-time
    /// consts via `RECIPES_LOADER_*` env: the kernel cmdline (the §3.1 token string carrying the
    /// verity pair), the SHA-256 of the exact `\initrd` bytes the ESP will carry, and the
    /// `SB_REQUIRED` rung flag. Returns the loader PE (`BOOTX64.EFI`-to-be). NO post-link
                                                                                               
    /// own `/debug:none` link keeps the PE byte-reproducible (the rambutan Task-1.8 gate).
    fn build_efi_loader(
        &self,
        cmdline: &str,
        initrd_sha256_hex: &str,
        sb_required: bool,
        source_date_epoch: u64,
    ) -> Result<Vec<u8>, BuildError>;
}

/// dha Component E: the resolved weights build input — the operator-supplied GGUF path + its pinned
/// sha256 (from `models.toml`). The CLI boundary ([`crate::build::BuildConfig`] construction) resolves
/// the `RECIPES_DHA_WEIGHTS_GGUF` env + [`crate::models::Models`] pin; `build()` re-hashes the file
/// against `sha256` FAIL-CLOSED before any expensive work — the load-bearing integrity layer (a direct
/// lib caller bypasses the CLI, so the gate lives here too, the domain/net belt-and-suspenders class).
                                                                                                        
/// no cmdline tokens). The multi-GiB GGUF is referenced by PATH (staged by the tool), never held in a `Vec`.
#[derive(Debug, Clone)]
pub struct WeightsInput {
    /// The operator's on-disk GGUF (out-of-band, never committed). Staged as `model.gguf` at bake.
    pub gguf_path: PathBuf,
    /// 64 lowercase hex — the resolved profile's `[weights].sha256` pin. `build()` verifies the file
    /// matches.
    pub sha256: String,
    /// Exact pinned byte length — checked BEFORE the multi-GiB stream hash so a wrong file aborts fast.
    pub bytes: u64,
                                                                                                        
    /// model in the SAME verity volume; its sha is verified with the same fail-closed posture.
    pub mmproj: Option<WeightsFile>,
}

/// A secondary pinned GGUF staged into the weights volume (today: the `mmproj` projector).
#[derive(Debug, Clone)]
pub struct WeightsFile {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
}

/// Operator inputs + pinned build identifiers for one `deploy build`.
pub struct BuildConfig {
    /// The CLEAN 40-hex HEAD commit — feeds the rescue-seed IKM via `PublicInputs::new`, which
    /// requires exactly 40 hex chars. NEVER carries the `-dirty` taint (L-1: that taint belongs on
    /// [`Self::image_label`], not the seed input — a `<sha>-dirty` value is rejected by the IKM
    /// validator, which is what broke `--allow-dirty` before the split).
    pub git_sha: String,
    /// The artifact identity: `git_sha`, suffixed `-dirty` for an `--allow-dirty` build. Names the
    /// `.img` triple, so a dirty build can't masquerade as clean — while
    /// the rescue seed still derives from the clean commit (L-1).
    pub image_label: String,
    pub source_date_epoch: u64,
    pub alpine_version: String,
    pub domain: String,
    /// sha256(image-signing cert DER), hex — part of the rescue-seed IKM (F-mini-11).
                                                                                        
    /// from the actual image-signing cert / the pinned-cert-fingerprints.toml
    /// `[image_signing]` value (sans `sha256:`), NOT pass a hand-built string — a
    /// wrong-but-valid 64-hex value silently changes the rescue seed → TOFU break. The
    /// 64-hex check in `PublicInputs::new` catches malformed input, not a wrong value.
    pub image_signing_crt_sha256_hex: String,
    /// Operator-secret `rescue-seed-master.key` (32 bytes; build-time-only).
    pub master_key_path: PathBuf,
    /// The IMA/EVM signing leaf key (PKCS#8 PEM) — the in-tree RFC-6979 signer's private key.
    pub ima_key_path: PathBuf,
    /// The IMA/EVM leaf cert (`ima.crt`) — supplies the be32 keyid (its SubjectKeyIdentifier suffix).
    pub ima_cert_path: PathBuf,
    /// Output directory for the `.img` triple.
    pub out_dir: PathBuf,
    /// The operator recovery pubkey line baked into `/etc/ssh/recovery_authorized_keys` — the
    /// rescue dropbear's SOLE authorized key (in-rootfs, so it authenticates when `/persist` failed
    /// to mount; the normal operator key lives on the unavailable `/persist`). `None` ships the
    /// deploy-time placeholder, so a bare operator-agnostic `deploy build` still produces a bootable
    /// (un-loginable) rescue dropbear; `deploy build --recovery-pubkey` bakes the real key.
    pub recovery_authorized_keys: Option<String>,
    /// The operator's NORMAL-boot SSH pubkey line, baked into the persist-skeleton at
    /// `/etc/ssh/authorized_keys.d/root` (`bake_persist_skeleton`). `None` ⇒ an un-loginable skeleton
    /// (mirrors `recovery_authorized_keys`); the already-derived line is supplied by the CLI boundary
    /// (derive-not-cat). The runtime box authenticates the operator against the resized persist.
    pub operator_pubkey: Option<String>,
                                                                                                
    /// (Infomaniak is BIOS-only); UEFI builds the rambutan loader path (its production substrate is
    /// deferred until one is adopted). Threads into the boot-fs/ESP bake + the `.layout.toml`
    /// `firmware` field the installer reads back.
    pub firmware: Firmware,
    /// The operator's `fb.net=` VALUE baked into the boot-fs APPEND (network spec C1; e.g.
    /// `mode=static;ip=…;gw=…;dns=…`). `None` bakes no `fb.net=` token ⇒ box-init parses none ⇒
    /// rescue/link-only. Supplied by the CLI boundary (`deploy build --net`); `mode=dhcp` is the
    /// documented seam (build-A fail-closes it at bring-up).
    pub net: Option<String>,
                                                                                              
    /// loader — an SB-rung image then refuses to run with Secure Boot disabled (fail closed).
    /// `false` = the SB-off rungs (OVMF dryrun, rented UEFI): the same artifacts run unsigned.
                                                                                                
    /// until then build sites pass `false`.
    pub sb_required: bool,
    /// The validated service manifest the bake renders the tenant topology from (the operator
    /// `--manifest`, or the pinned reference tenant). The §5.3 fail-closed gate already ran
    /// (`config::load_manifest`) — the renderer only ever sees a `ValidatedManifest`. This is the
    /// de-hardcoding's completion: the topology is build-INPUT data, not a compiled-in const
                                                                                      
    pub manifest: fb_manifest::ValidatedManifest,
    /// dha Component E (O4=(a) GPT): the resolved + pinned weights GGUF, or `None` for a non-dha image.
    /// `Some` ⇒ `build()` verifies the GGUF sha256 fail-closed, bakes it into a squashfs+dm-verity 5th
    /// GPT partition, and anchors it per [`Self::weights_anchor`]. `None` ⇒ byte-identical to a plain
                                                                                                              
    pub weights: Option<WeightsInput>,
    /// Hotswap v4 (§7 decouple): HOW a weights build anchors the model's trust. `BootCmdline` = the
    /// dha boot-anchored shape (the `fb.weights-*` triple; byte-identical to pre-v4). `RuntimeRecord`
                                                                                                     
    /// the whole no-brick premise), a SIGNED weights record baked at `/persist/weights/current`, the
    /// engine run-script gains the `fb-weights setup` prelude, and the swap runbook files are baked.
    /// Ignored when [`Self::weights`] is `None` — except `RuntimeRecord`, which then fails the build
    /// (a runtime-weights box without a model is a nonsense config, refused not defaulted).
    pub weights_anchor: WeightsAnchor,
    /// os-update A/B v1 (§4i): the per-stream monotonic image serial the operator maintains
    /// (`--image-version`). Stamped firmware-unconditionally into both the rootfs
    /// `/etc/recipes/image-version` and the `.layout.toml`; the box's version-floor anti-rollback chain
    /// compares against it. A committed constant (NOT a build clock), so byte-reproducibility holds.
    pub image_version: u64,
    /// os-update A/B v1 (§4i): the operator's active `UpdateImage` delegation `monotonic_ctr`, read at
    /// the CLI boundary from `keys_dir` (fail-closed with the actionable `orchard redelegate` message if
    /// the delegation is absent — a legacy key set) and threaded here so image-builder stays free of the
    /// orchard key-loading code. Stamped firmware-unconditionally into both
    /// `/etc/recipes/min-delegation-ctr` and the `.layout.toml`; seeds the box's §4f `minctr-floor`
    /// (the delegation-revocation lever).
    pub min_delegation_ctr: u64,
    /// os-update A/B v1 (C-C): the operator's ed25519 artifact-root pubkey file (`generate-keys`'
    /// `artifact-root.pub`), COPIED verbatim onto the verity rootfs at `/etc/recipes/artifact-root.pub`
    /// — the box-side `fb-update apply` post-`switch_root` trust anchor (the twin of the C1 initramfs
    /// copy the restore path reads; both are the box's pinned update root, public + verity-protected).
    /// `None` (a keyless/unadopted build) ⇒ not staged ⇒ `fb-update apply` fails closed on the missing
    /// file (an unsigned dev box cannot apply pushed updates, the documented floor).
    pub artifact_root_pub: Option<PathBuf>,
}

/// Hotswap v4 (§7): how a weights build anchors the model's trust chain.
pub enum WeightsAnchor {
    /// The dha boot-anchored shape: the `fb.weights-*` cmdline triple, weights in the boot chain
    /// (initramfs fatal-mounts the volume pre-`switch_root`). The pre-v4 default — byte-identical.
    BootCmdline,
                                                                                               
    /// baked into the persist skeleton at `weights/current`; `EngineWeightsSetup::Runtime` rendered
    /// into the engine's run script; the `weights-engine`/`weights-health` runbook files baked.
    RuntimeRecord(WeightsRecordInputs),
}

/// The v4 runtime-record inputs, supplied at the CLI boundary (image-builder stays free of the
/// orchard key-loading code — the `min_delegation_ctr` threading pattern, taken one step further as
/// a callback because the manifest bytes to sign only exist mid-bake).
pub struct WeightsRecordInputs {
    /// Sign the canonical weights-manifest bytes → the 254-byte `Purpose::Weights` bundle + the
    /// delegation's `monotonic_ctr` (the baked initial floor). The CLI wires the operator
    /// artifact-key set here; tests wire a fixed fake. Errors abort the build (a v4 box REQUIRES a
    /// verifiable baked record — never bake unverifiable trust state).
    #[allow(clippy::type_complexity)]
    pub sign: Box<dyn Fn(&[u8]) -> Result<SignedWeightsManifest, String>>,
    /// The engine's local real-inference health probe, baked as `/etc/recipes/weights-health` (the
    /// swap sequencer's post-swap gate). From `models.toml`'s `[health]` (model-coupled config).
    pub health: WeightsHealth,
}

/// A signed weights manifest: the detached bundle + its delegation counter.
pub struct SignedWeightsManifest {
    /// The 254-byte dragonfruit `BundleFile` over `sha256(manifest_bytes)`.
    pub sig: [u8; 254],
    /// The `Purpose::Weights` delegation's `monotonic_ctr` — becomes the record's baked floor.
    pub delegation_ctr: u64,
}

/// The baked `/etc/recipes/weights-health` probe config (see fb-weights `boxops.rs` — the strict
/// 3-line grammar `port=`/`path=`/`body=` it parses back).
pub struct WeightsHealth {
    pub port: u16,
    pub path: String,
    pub body: String,
}

/// `deploy build`'s outputs: the unsigned triple + the verity root hash (the deploy
/// step bakes the root hash into the extlinux APPEND).
#[derive(Debug)]
pub struct BuildOutputs {
    pub outputs: ImageOutputs,
    pub root_hash: String,
    /// UEFI only (SB-loader plan Task 4.2): the UNSIGNED rambutan loader PE — `deploy build`
    /// writes it (+ the sign manifest) beside the `.img` as the `deploy sign-sb` inputs.
    /// `None` on SeaBIOS.
    pub loader_pe: Option<Vec<u8>>,
}

/// Orchestrate the build (steps 2-13, sign deferred). Fail-closed: any step's error
/// aborts; the staging tempdir is RAII-cleaned on every exit path.
                                                                                                   
/// The CANONICAL phase-banner sequence. `run_phase_banners_for_test` replays it, and `build()`'s
/// real (hand-authored) `phase_banner` call sites are asserted to MATCH it by the capture test
/// `build_real_emission_matches_build_phase_names` (which taps `build()`'s actual emissions via
                                                                                                    
/// this list to dispatch (the banners interleave with real bake calls); the capture test is what
/// binds them. `firmware` is accepted for future arms (unused today — both arms emit this order).
///
/// Order mirrors the REAL bake (the spec's intent) over the spec's literal list, which trailed
/// `sign` last: the in-tree IMA/EVM signer (`ima_evm_xattr_pseudo`, step 8) runs BEFORE the kernel
/// arm — its xattrs are packed INTO the squashfs, so it structurally cannot follow `image assemble`.
/// `sign` here is that early rootfs signing; the operator's off-box ed25519 ARTIFACT signing is a
/// separate post-build step surfaced by the `next:` epilogue (C4), not a build-phase banner.
pub fn build_phase_names(_firmware: Firmware, weights: bool) -> Vec<&'static str> {
    let mut v = vec![
        "preflight",
        "sign",
        "kernel compile",
        "config-assert",
        "squashfs",
        "verity",
        "initramfs",
        "rootfs assemble",
    ];
    if weights {
        v.push("weights");
    }
    v.extend(["boot-fs", "persist-skeleton", "image assemble"]);
    v
}

                                                                                                 
pub fn run_phase_banners_for_test(
    firmware: Firmware,
    weights: bool,
    mut sink: impl FnMut(&str, std::time::Duration),
) {
    for name in build_phase_names(firmware, weights) {
        sink(name, std::time::Duration::ZERO);
    }
}

                                                                                                      
                                                                                                
                                                                                                        
                                                                                                    
#[cfg(test)]
thread_local! {
    static BANNER_TAP: std::cell::RefCell<Option<Vec<String>>> =
        const { std::cell::RefCell::new(None) };
}

                                                                                                     
/// capture change): `=== {name} (+{elapsed-so-far}s) ===` — the CUMULATIVE wall-time since
                                                                                                     
/// delta state). The final total line is emitted once by [`build`] after the match, not a phase.
pub(crate) fn phase_banner(name: &str, build_start: std::time::Instant) {
    eprintln!("=== {name} (+{}s) ===", build_start.elapsed().as_secs());
    #[cfg(test)]
    BANNER_TAP.with(|t| {
        if let Some(v) = t.borrow_mut().as_mut() {
            v.push(name.to_string());
        }
    });
}

/// C3: the compile-time-embedded per-substrate kernel-config block, unioned with the shared pins in
/// [`build`]. `VpsKvm` forbids the four USB host/storage drivers (+ fail-closes the CONFIG_USB
/// prefix); `BareMetalUefi` asserts them present. Disk transports (SCSI/ATA/NVMe) stay on both. The
/// `.expect` is a crate-build-asset invariant — these `.toml` files ship with the crate and are
/// parse-tested (`tests/kernel_config_assert.rs::substrate_blocks_split_the_usb_configs`).
fn substrate_config_block(substrate: Substrate) -> KernelConfigPins {
    let toml = match substrate {
        Substrate::VpsKvm => include_str!("../kernel-config-pins-vpskvm.toml"),
        Substrate::BareMetalUefi => include_str!("../kernel-config-pins-baremetal.toml"),
    };
    KernelConfigPins::from_toml_str(toml)
        .expect("embedded substrate kernel-config block must parse (crate build asset)")
}

pub fn build<P: PackageProvider, T: BuildTools>(
    cfg: &BuildConfig,
    apk_pins: &PinnedApks,
    kernel_pins: &KernelConfigPins,
    provider: &P,
    tools: &T,
) -> Result<BuildOutputs, BuildError> {
                                                                                                            
                                                                                                             
                                                                                                               
    if let Some(w) = cfg.weights.as_ref() {
                                                                                                              
                                                                                                            
                                                                                
        if matches!(cfg.firmware, Firmware::Seabios) {
            return Err(BuildError::WeightsRequireGptFirmware);
        }
        verify_weights_sha256(w)?;
    }
                                                                                                    
                                                                                                    
                                                                     
    if matches!(cfg.weights_anchor, WeightsAnchor::RuntimeRecord(_)) {
        if cfg.weights.is_none() {
            return Err(BuildError::RuntimeAnchorWithoutWeights);
        }
        if cfg
            .manifest
            .manifest()
            .resource_domain
            .as_ref()
            .and_then(|rd| rd.engine.as_ref())
            .is_none()
        {
            return Err(BuildError::RuntimeAnchorWithoutEngine);
        }
    }
    let staging = tempfile::Builder::new()
        .prefix(".recipes-build-")
        .tempdir()
        .map_err(|source| BuildError::Io {
            path: "staging tempdir".into(),
            source,
        })?;
    let root = staging.path();

                                                                                                     
                                                                                                    
                                                                                                     
    let build_start = std::time::Instant::now();
    phase_banner("preflight", build_start);

                                                                   
    for pin in &apk_pins.packages {
        provider.acquire(pin, root)?;
    }

                                                                                               
                                                                                                        
                                                                   
    let extra_bins: &[&str] = match &cfg.weights_anchor {
        WeightsAnchor::RuntimeRecord(_) => &["fb-weights"],
        WeightsAnchor::BootCmdline => &[],
    };
    tools.build_binaries(root, &cfg.manifest, extra_bins)?;

                                                                              
    render_configs(
        root,
        &cfg.domain,
        cfg.recovery_authorized_keys.as_deref(),
        &cfg.manifest,
        cfg.image_version,
        cfg.min_delegation_ctr,
        cfg.artifact_root_pub.as_deref(),
    )?;

                                                                                           
                                                                                                         
                                                                                                       
                                                                                                           
                                                                                                         
                                                                                                    
    if cfg.weights.is_some() {
        let models_dir = root.join(WEIGHTS_MOUNT_DIR.trim_start_matches('/'));
        std::fs::create_dir_all(&models_dir).map_err(|source| BuildError::Io {
            path: models_dir.display().to_string(),
            source,
        })?;
    }
                                                                                                  
                                                                                                 
                                                                                               
                                                                                         
                                                                                       
    if let WeightsAnchor::RuntimeRecord(inputs) = &cfg.weights_anchor {
        let engine_service = cfg
            .manifest
            .manifest()
            .resource_domain
            .as_ref()
            .and_then(|rd| rd.engine.as_ref())
            .map(|e| e.service.clone())
            .ok_or(BuildError::RuntimeAnchorWithoutEngine)?;
        let etc = root.join("etc/recipes");
        std::fs::create_dir_all(&etc).map_err(|source| BuildError::Io {
            path: etc.display().to_string(),
            source,
        })?;
        let engine_path = etc.join("weights-engine");
        std::fs::write(&engine_path, format!("{engine_service}\n")).map_err(|source| {
            BuildError::Io {
                path: engine_path.display().to_string(),
                source,
            }
        })?;
        let health_path = etc.join("weights-health");
        let h = &inputs.health;
        std::fs::write(
            &health_path,
            format!("port={}\npath={}\nbody={}\n", h.port, h.path, h.body),
        )
        .map_err(|source| BuildError::Io {
            path: health_path.display().to_string(),
            source,
        })?;
    }

                                                                                      
                                                                                      
    run_hardening_checks(root, tools)?;

                                                                                                        
                                                                                                     
                                                                                                  
                                                                                                 
                                                                                                
                                                                                      
    let engine_weights = match &cfg.weights_anchor {
        WeightsAnchor::RuntimeRecord(_) => crate::service_tree::EngineWeightsSetup::Runtime,
        WeightsAnchor::BootCmdline => crate::service_tree::EngineWeightsSetup::None,
    };
    tools.build_init_tree(
        root,
        &cfg.domain,
        cfg.source_date_epoch,
        &cfg.manifest,
        engine_weights,
    )?;
                                                                                                         
                                                                                                         
                                                                                                    
    let init_manifest = collect_staging_paths(root)?;
                                                                                                         
                                                                                                       
    let tenant_runs: Vec<String> = cfg
        .manifest
        .manifest()
        .services
        .iter()
        .map(|s| format!("/etc/box-svc/{}/run", s.name))
        .collect();
    crate::config::check_required_init_components(
        init_manifest.iter().map(String::as_str),
        &tenant_runs,
    )?;
                                                                                                      
                                                                                                  
                                                                                                      
    crate::config::check_required_applets(init_manifest.iter().map(String::as_str))?;

                                                                                  
    let public_inputs = PublicInputs::new(
        cfg.git_sha.clone(),
        cfg.alpine_version.clone(),
        cfg.image_signing_crt_sha256_hex.clone(),
    )?;
    crate::rescue_seed::write_rescue_seed(root, &cfg.master_key_path, &public_inputs)?;

                                                                                                            
                                                                                                            
                                                                                                       
                                                                                                            
                                           
    let staged_exceptions = tools.stage_manifest_files(root, &cfg.manifest)?;

                                                                                                     
                                                                                                           
                                                                                                         
                                                                                                  
                                                                                                              
                                                                                                          
                                                                                                       
                                                                                                        
                                                                                                        
    run_hardening_checks(root, tools)?;

                                                                                                     
                                                                                                      
                                                                   
                                                                                                   
                                                                                                
                                                                                                    
                                                                                                       
                                                                                                       
                        
    let mut owner_exceptions = crate::config_render::render_dha_configs(root, &cfg.manifest)
        .map_err(|source| BuildError::Io {
            path: "etc/dha configs".into(),
            source,
        })?;
                                                                                                       
                                                                                                 
                                             
    owner_exceptions.extend(staged_exceptions);
    phase_banner("sign", build_start);
    let xattr_pseudo = tools.ima_evm_xattr_pseudo(
        root,
        &cfg.ima_key_path,
        &cfg.ima_cert_path,
        &owner_exceptions,
    )?;

                                                                                                
                                                                                                 
                                                                                                         
                                                                                                   
                                                                                          
                                                                                                   
                                                                                                     
                                                                                                   
                                                                                                   
                                                                                          
                                                                                                          
                                                                                                  
                                                                            
    let frandom_seed = grape::derive_kernel_frandom_seed_hex(&cfg.master_key_path, &cfg.git_sha)?;

                                                                                              
                                                                                                  
                                                                                                     
                                                                                              
                                                
    let substrate = Substrate::from_firmware(cfg.firmware);
    let kernel_pins = kernel_pins.union(&substrate_config_block(substrate));
    let (img, layout, vmlinuz, initramfs, root_hash, loader_pe) = match cfg.firmware {
                                                                                                  
                                                                                                        
                                                                                                          
                                                                                                          
                                                                                                           
        Firmware::Seabios | Firmware::SeabiosGpt => {
            phase_banner("kernel compile", build_start);
            let kernel = tools.build_kernel(cfg.source_date_epoch, &frandom_seed)?;
            phase_banner("config-assert", build_start);
            kernel::assert_kernel_config(&kernel.dot_config, &kernel_pins)?;
            phase_banner("squashfs", build_start);
            let squashfs = tools.pack_squashfs(root, cfg.source_date_epoch, &xattr_pseudo)?;
            assert_squashfs_block_aligned(squashfs.len())?;
            phase_banner("verity", build_start);
            let verity = tools.build_verity(&squashfs)?;
            phase_banner("initramfs", build_start);
            let initramfs = tools.build_initramfs(cfg.source_date_epoch)?;
            phase_banner("rootfs assemble", build_start);
            let rootfs = image::build_rootfs_component(&squashfs, &verity.hash_tree);
            check_rootfs_fits_slot(rootfs.bytes.len() as u64, SLOT_SIZE_BYTES)?;
                                                                                                            
                                                                                                          
                                                                                                          
                                                                                                        
                                  
            if cfg.weights.is_some() {
                phase_banner("weights", build_start);
            }
            let weights = bake_weights(tools, cfg)?;
            let weights_cmdline = match &cfg.weights_anchor {
                WeightsAnchor::BootCmdline => weights.as_ref().map(|w| boot_fs::WeightsCmdline {
                    verity_root_hash: &w.verity_root_hash,
                    verity_hash_offset: w.component.verity_hash_offset,
                }),
                WeightsAnchor::RuntimeRecord(_) => None,
            };
            let weights_record = match (&cfg.weights_anchor, weights.as_ref()) {
                (WeightsAnchor::RuntimeRecord(inputs), Some(w)) => {
                    Some(render_signed_weights_record(inputs, w)?)
                }
                _ => None,
            };
            let extlinux_conf = boot_fs::render_boot_fs_extlinux(
                &verity.root_hash,
                rootfs.verity_hash_offset,
                cfg.net.as_deref(),
                cfg.firmware,
                weights_cmdline,
            );
            phase_banner("boot-fs", build_start);
            let boot = tools.bake_boot_fs(
                &kernel.vmlinuz,
                &initramfs,
                &extlinux_conf,
                cfg.firmware,
                cfg.source_date_epoch,
            )?;
            phase_banner("persist-skeleton", build_start);
            let persist_skeleton = tools.bake_persist_skeleton(
                cfg.operator_pubkey.as_deref().unwrap_or("").as_bytes(),
                cfg.source_date_epoch,
                weights_record.as_deref(),
            )?;
            check_persist_skeleton_no_journal(&persist_skeleton)?;
            phase_banner("image assemble", build_start);
            let (img, layout) = image::assemble_img(
                &boot,
                &persist_skeleton,
                &rootfs,
                weights.as_ref().map(|w| &w.component),
                cfg.firmware,
                cfg.image_version,
                cfg.min_delegation_ctr,
            );
            check_baked_verity_offset(&extlinux_conf, layout.rootfs_verity_hash_offset)?;
            (
                img,
                layout,
                kernel.vmlinuz,
                initramfs,
                verity.root_hash,
                None,
            )
        }
        Firmware::Uefi => {
                                                                                           
                                                                                               
            phase_banner("kernel compile", build_start);
            let kernel = tools.build_kernel(cfg.source_date_epoch, &frandom_seed)?;
            phase_banner("config-assert", build_start);
            kernel::assert_kernel_config(&kernel.dot_config, &kernel_pins)?;
            phase_banner("squashfs", build_start);
            let squashfs = tools.pack_squashfs(root, cfg.source_date_epoch, &xattr_pseudo)?;
            assert_squashfs_block_aligned(squashfs.len())?;
            phase_banner("verity", build_start);
            let verity = tools.build_verity(&squashfs)?;
            phase_banner("initramfs", build_start);
            let initramfs = tools.build_initramfs(cfg.source_date_epoch)?;
            phase_banner("rootfs assemble", build_start);
            let rootfs = image::build_rootfs_component(&squashfs, &verity.hash_tree);
            check_rootfs_fits_slot(rootfs.bytes.len() as u64, SLOT_SIZE_BYTES)?;
                                                                                                            
                                                                                                       
                                                
            if cfg.weights.is_some() {
                phase_banner("weights", build_start);
            }
            let weights = bake_weights(tools, cfg)?;
            let weights_cmdline = match &cfg.weights_anchor {
                WeightsAnchor::BootCmdline => weights.as_ref().map(|w| boot_fs::WeightsCmdline {
                    verity_root_hash: &w.verity_root_hash,
                    verity_hash_offset: w.component.verity_hash_offset,
                }),
                WeightsAnchor::RuntimeRecord(_) => None,
            };
            let weights_record = match (&cfg.weights_anchor, weights.as_ref()) {
                (WeightsAnchor::RuntimeRecord(inputs), Some(w)) => {
                    Some(render_signed_weights_record(inputs, w)?)
                }
                _ => None,
            };
                                                                                           
                                                                                               
                                                                                             
                                                                                               
            let cmdline = boot_fs::render_uefi_cmdline(
                &verity.root_hash,
                rootfs.verity_hash_offset,
                cfg.net.as_deref(),
                weights_cmdline,
            );
            let initrd_sha256_hex = {
                use sha2::{Digest, Sha256};
                format!("{:x}", Sha256::digest(&initramfs))
            };
                                                                                           
                                                                                          
                                                                     
            phase_banner("boot-fs", build_start);
            let loader = tools.build_efi_loader(
                &cmdline,
                &initrd_sha256_hex,
                cfg.sb_required,
                cfg.source_date_epoch,
            )?;
                                                                                             
                                                                                           
                                                                                         
            let boot =
                tools.bake_esp(&loader, &kernel.vmlinuz, &initramfs, cfg.source_date_epoch)?;
            phase_banner("persist-skeleton", build_start);
            let persist_skeleton = tools.bake_persist_skeleton(
                cfg.operator_pubkey.as_deref().unwrap_or("").as_bytes(),
                cfg.source_date_epoch,
                weights_record.as_deref(),
            )?;
            check_persist_skeleton_no_journal(&persist_skeleton)?;
            phase_banner("image assemble", build_start);
            let (img, layout) = image::assemble_img(
                &boot,
                &persist_skeleton,
                &rootfs,
                weights.as_ref().map(|w| &w.component),
                cfg.firmware,
                cfg.image_version,
                cfg.min_delegation_ctr,
            );
                                                                                             
                                                                                             
            check_baked_verity_offset(&cmdline, layout.rootfs_verity_hash_offset)?;
            (
                img,
                layout,
                kernel.vmlinuz,
                initramfs,
                verity.root_hash,
                Some(loader),
            )
        }
    };
    let outputs = image::write_image_outputs(
        &cfg.out_dir,
        &cfg.image_label,
        &img,
        &layout,
        &vmlinuz,
        &initramfs,
    )
    .map_err(|source| BuildError::Io {
        path: cfg.out_dir.display().to_string(),
        source,
    })?;

                                                                                                
                                                                                                       
                                                                                                     
                                                     
    eprintln!(
        "=== build complete (total {}s) ===",
        build_start.elapsed().as_secs()
    );

    Ok(BuildOutputs {
        outputs,
        root_hash,
        loader_pe,
    })
}

/// dha Component E: the baked weights volume — the squashfs+dm-verity partition component (reusing
/// [`image::RootfsComponent`]) + its verity root hash (for the `fb.weights-hash=` cmdline token). Held
/// across the firmware match so the borrowed [`boot_fs::WeightsCmdline`] outlives the arm's render.
struct WeightsBake {
    component: image::RootfsComponent,
    verity_root_hash: String,
}

                                                                                                    
/// GGUF sha256 was already verified fail-closed at the TOP of [`build()`]; here we pack the single-file
/// `model.gguf` squashfs (NO IMA — data, not exec), build its dm-verity tree, and wrap the two into a
/// component exactly like the rootfs. Firmware-independent (the render + assemble differ by arm, the
/// volume does not). A tampered/absent GGUF has already aborted the build before this point.
fn bake_weights<T: BuildTools>(
    tools: &T,
    cfg: &BuildConfig,
) -> Result<Option<WeightsBake>, BuildError> {
    let Some(w) = cfg.weights.as_ref() else {
        return Ok(None);
    };
    let squashfs = tools.pack_weights_squashfs(
        &w.gguf_path,
        w.mmproj.as_ref().map(|m| m.path.as_path()),
        cfg.source_date_epoch,
    )?;
    let verity = tools.build_verity(&squashfs)?;
    let component = image::build_rootfs_component(&squashfs, &verity.hash_tree);
    Ok(Some(WeightsBake {
        component,
        verity_root_hash: verity.root_hash,
    }))
}

/// Hotswap v4 (§7): render the SIGNED initial weights record baked at `/persist/weights/current`.
/// The byte layouts are the fb-weights `stores.rs` CROSS-REPO WIRE CONTRACT, mirrored here and
/// pinned by goldens on BOTH sides:
/// - manifest (the signed artifact): `verity-root-hash=<64hex>\nverity-offset=<u64>\n
///   image-sha256=<64hex>\nimage-size=<u64>\n` — canonical, byte-stable;
/// - record: `b"FBW1" ‖ floor_ctr u64-LE ‖ manifest_len u64-LE ‖ manifest ‖ sig[254]`, where the
///   baked floor = the signing delegation's `monotonic_ctr` (the boot verify's `min_ctr`).
///
/// The signer callback comes from the CLI boundary (operator artifact keys, `Purpose::Weights`);
/// a signing failure ABORTS the build — a v4 box never ships an unverifiable record.
fn render_signed_weights_record(
    inputs: &WeightsRecordInputs,
    baked: &WeightsBake,
) -> Result<Vec<u8>, BuildError> {
    let manifest = render_weights_manifest_bytes(
        &baked.verity_root_hash,
        baked.component.verity_hash_offset,
        &baked.component.bytes,
    );
    let signed = (inputs.sign)(&manifest).map_err(|e| BuildError::WeightsRecordSigning {
        reason: e.to_string(),
    })?;
    let mut record = Vec::with_capacity(4 + 8 + 8 + manifest.len() + signed.sig.len());
    record.extend_from_slice(b"FBW1");
    record.extend_from_slice(&signed.delegation_ctr.to_le_bytes());
    record.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
    record.extend_from_slice(&manifest);
    record.extend_from_slice(&signed.sig);
    Ok(record)
}

/// The canonical weights-manifest bytes (the SIGNED artifact — the fb-weights `stores.rs` 4-line
/// grammar): shared by the bake's initial record and `orchard deploy-model`'s push, so the two
/// producers can never drift from each other or from the box-side parser.
pub fn render_weights_manifest_bytes(
    verity_root_hash: &str,
    verity_hash_offset: u64,
    image: &[u8],
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    format!(
        "verity-root-hash={}\nverity-offset={}\nimage-sha256={:x}\nimage-size={}\n",
        verity_root_hash,
        verity_hash_offset,
        Sha256::digest(image),
        image.len()
    )
    .into_bytes()
}

/// dha Component E: the fail-closed weights integrity gate — STREAM-hash the operator GGUF and compare
/// to the `models.toml` pin (`io::copy` into the hasher, so a multi-GiB GGUF is never held in a `Vec`).
/// Called at the top of [`build()`] before any tool work: a tampered/wrong file aborts fail-fast, never
/// reaching the squashfs+dm-verity bake. The pin `sha256` is already-format-validated by `Models::load`.
                                                                                                       
/// re-reading the same path — an operator swapping the file in between would bake unpinned content. Out of
/// the threat model (the build host is the trusted single operator, same posture as the install-time-TCB
/// ceiling), and the baked image stays internally verity-consistent regardless; the load-bearing property
/// is that the pin is tied to the file AT CHECK TIME. Closing it would need a 2nd 2-GiB hash of the staged
/// copy (the fail-fast pre-kernel-build abort is worth keeping over folding the two reads).
fn verify_weights_sha256(w: &WeightsInput) -> Result<(), BuildError> {
    verify_one_gguf(&w.gguf_path, &w.sha256, w.bytes)?;
                                                                                                        
                                                                                     
    if let Some(m) = &w.mmproj {
        verify_one_gguf(&m.path, &m.sha256, m.bytes)?;
    }
    Ok(())
}

/// Size-then-hash: the pinned `bytes` is checked FIRST so a wrong file (the common operator slip — the
/// 4B pair instead of the 2B, a truncated download) aborts immediately instead of after streaming a
/// sha256 over multiple GiB. The size check is a fast-fail convenience, NOT the integrity gate: the
/// sha256 below is, and it runs on every accepted file regardless.
fn verify_one_gguf(path: &Path, want_sha: &str, want_bytes: u64) -> Result<(), BuildError> {
    use sha2::{Digest, Sha256};
    let meta = std::fs::metadata(path).map_err(|source| BuildError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if meta.len() != want_bytes {
        return Err(BuildError::WeightsSizeMismatch {
            path: path.display().to_string(),
            want: want_bytes,
            got: meta.len(),
        });
    }
    let mut file = std::fs::File::open(path).map_err(|source| BuildError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|source| BuildError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let got = format!("{:x}", hasher.finalize());
    if got != want_sha {
        return Err(BuildError::WeightsShaMismatch {
            path: path.display().to_string(),
            want: want_sha.to_string(),
            got,
        });
    }
    Ok(())
}

/// H-1: confirm the `fb.verity-hash-offset` baked into slot A's APPEND equals the `.img` layout's
/// rootfs verity offset. Both derive from `rootfs.verity_hash_offset` today, so this is the
                                                                                                 
/// render/assemble divergence fails the build LOUD rather than shipping a boot-looping image. Parses
/// the value ACTUALLY in the APPEND (not the input), so it also catches a render bug. Fails closed if
/// the field is missing.
/// M-1: fail at BUILD if the rootfs component (padded squashfs + verity tree) overflows the A/B slot —
/// the cheapest place. Without this a too-large rootfs only fails on the target box at install
/// (`check_image_fits`, fail-closed but worst-time), re-opening the "build-ok-but-install-fatal" class
/// the init-tree presence guards closed for the boot partition.
fn check_rootfs_fits_slot(rootfs_len: u64, slot: u64) -> Result<(), BuildError> {
    if rootfs_len > slot {
        return Err(BuildError::RootfsTooLarge {
            size: rootfs_len,
            slot,
        });
    }
    Ok(())
}

/// H-1, BOTH firmwares: the `fb.verity-hash-offset` ACTUALLY baked into the boot cmdline
/// carrier (the SeaBIOS slot-A APPEND / the UEFI loader cmdline — same token grammar, ONE
/// parser) must equal the `.img` layout's rootfs verity offset; a render/assemble divergence
/// fails the build LOUD rather than shipping a boot-looping image.
fn check_baked_verity_offset(cmdline_carrier: &str, layout_offset: u64) -> Result<(), BuildError> {
    let append = boot_fs::parse_verity_hash_offset(cmdline_carrier).ok_or(BuildError::Tool {
        tool: "render_boot_fs_extlinux/render_uefi_cmdline",
        reason: "no fb.verity-hash-offset in the baked boot cmdline".into(),
    })?;
    if append != layout_offset {
        return Err(BuildError::VerityOffsetMismatch {
            append,
            layout: layout_offset,
        });
    }
    Ok(())
}

                                                                                                           
/// unpadded squashfs but the runtime + the rescue-key recompute hash the PADDED squashfs, and they agree
/// ONLY because mksquashfs 4 KiB-aligns its output. Assert it so a future mksquashfs change fails the
/// build LOUD rather than silently desyncing the root hash → an unbootable image / a wrong rescue-key
/// fingerprint. Shared by both firmware arms (the SeaBIOS error is byte-identical to the pre-branch inline check).
fn assert_squashfs_block_aligned(len: usize) -> Result<(), BuildError> {
    if !len.is_multiple_of(image::BLOCK_SIZE) {
        return Err(BuildError::Tool {
            tool: "pack_squashfs",
            reason: format!(
                "squashfs length {} is not a multiple of the {}-byte verity block size; the \
                 build (unpadded) and runtime (padded) dm-verity root hashes would diverge",
                len,
                image::BLOCK_SIZE
            ),
        });
    }
    Ok(())
}

                                                                                                 
                                                                                                
                                     

                                                                                                          
/// PRODUCED bytes, like the H-1 verity tripwire, independent of HOW a journal might have got there. The
/// ext4 superblock is at byte 1024; `s_feature_compat` (`__le32`) at offset 0x5C; `HAS_JOURNAL` = 0x0004.
/// box-init's `prepare-persist` gates the first-boot grow + journal-add on journal-ABSENCE, so a journaled
/// skeleton would skip the grow and silently strand the box at the ~16 MiB skeleton size with no fail-safe.
fn check_persist_skeleton_no_journal(persist: &[u8]) -> Result<(), BuildError> {
    const FEATURE_COMPAT_OFF: usize = 1024 + 0x5C;
    const HAS_JOURNAL: u32 = 0x0004;
    let bytes = persist
        .get(FEATURE_COMPAT_OFF..FEATURE_COMPAT_OFF + 4)
        .ok_or(BuildError::Tool {
            tool: "bake_persist_skeleton",
            reason: "persist.img too small to hold an ext4 superblock".into(),
        })?;
    let feature_compat = u32::from_le_bytes(bytes.try_into().expect("4 bytes"));
    if feature_compat & HAS_JOURNAL != 0 {
        return Err(BuildError::PersistSkeletonHasJournal);
    }
    Ok(())
}

/// Render the static in-image config files into the staging tree (build-pipeline
/// step 6). Whitelist-shaped (no operator-mutable config). The forbidden-component
/// and dropbear-no-PAM build-time CHECKS run separately in [`run_hardening_checks`]
                                                                                    
fn render_configs(
    staging: &Path,
    domain: &str,
    recovery_authorized_keys: Option<&str>,
    manifest: &fb_manifest::ValidatedManifest,
    image_version: u64,
    min_delegation_ctr: u64,
    artifact_root_pub: Option<&Path>,
) -> Result<(), BuildError> {
    use crate::{config, service_tree};
                                                                                                       
                                                                                                          
                                                                                                           
    let ctx = fb_manifest::PlaceholderCtx {
        domain: domain.to_string(),
        source_date_epoch: 0,
    };
    let m = manifest.manifest();
    let write = |rel: &str, content: &str| -> Result<(), BuildError> {
        let path = staging.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| BuildError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
        std::fs::write(&path, content).map_err(|source| BuildError::Io {
            path: path.display().to_string(),
            source,
        })
    };
    write(
        "etc/haproxy/haproxy.cfg",
        &config::haproxy_config(&m.edge, &ctx)
            .map_err(|e| BuildError::Config(config::ConfigError::Manifest(e)))?,
    )?;
                                                                                                    
                                                                                                
                                                                                                    
                                                                                       
    write("etc/ima/policy", config::IMA_POLICY)?;
    write("etc/fstab", config::FSTAB)?;
                                                                                                         
                                                                                                      
                                                                                                   
                                                                                                            
                                                                                                    
                                                                                                        
                                                                                                
    write("etc/recipes/image-version", &format!("{image_version}\n"))?;
    write(
        "etc/recipes/min-delegation-ctr",
        &format!("{min_delegation_ctr}\n"),
    )?;
                                                                                                
                                                                                                   
                                                                                                       
                                                                                                        
                                                                                                         
                                                                                          
    if let Some(pub_path) = artifact_root_pub {
        let bytes = std::fs::read(pub_path).map_err(|source| BuildError::Io {
            path: pub_path.display().to_string(),
            source,
        })?;
        let dest = staging.join("etc/recipes/artifact-root.pub");
        std::fs::write(&dest, &bytes).map_err(|source| BuildError::Io {
            path: dest.display().to_string(),
            source,
        })?;
    }
                                                                                                      
                                                                                                                
                                                                                                     
                                                                                                  
    write("etc/passwd", &config::passwd(&m.identities))?;
    write("etc/group", &config::group(&m.identities))?;
                                                                                                 
    write(
        "etc/nftables.conf",
                                                                                                     
                                                         
        &service_tree::nftables_config(&m.nftables, service_tree::NetMode::Static),
    )?;
                                                                                                      
                                                                                                     
                                                                                                     
                                                                                                      
                                                                                                     
                                                                                                     
    let topology = fb_manifest::topology::Topology {
        schema_version: fb_manifest::SCHEMA_VERSION,
        boot_hooks: m.boot_hooks.clone(),
                                                                                                   
                                                                                                   
                                                                      
        persist: m.persist.clone(),
                                                                                                      
                                                                                                        
                                                                                                            
        resource_domain: m.resource_domain.clone(),
    };
    write(
        "etc/box-topology.toml",
        &fb_manifest::topology::render_topology(&topology)
            .expect("the reference topology serializes (round-trip-tested in fb-manifest)"),
    )?;
    write("etc/dropbear/rescue-banner", service_tree::RESCUE_BANNER)?;
                                                                                                 
                                                                                              
                                                                                                   
                                                                                            
                                                                          
    let recovery_keys = match recovery_authorized_keys {
        Some(line) => format!("{}\n", line.trim_end()),
        None => "# operator recovery pubkey staged at deploy time (deploy-and-transition plan)\n"
            .to_string(),
    };
    write("etc/ssh/recovery_authorized_keys", &recovery_keys)?;
                                                                                                   
                                                                                                    
    for (k, v) in service_tree::box_env(&m.env, &ctx) {
        write(&format!("etc/recipes/env/{k}"), &v)?;
    }
                                                                                                 
                                                                                               
    write("etc/box-domain", &format!("{domain}\n"))?;
                                                                                                   
                                                                                                   
                                                                                                    
    write("etc/fb-backup/config", &config::fb_backup_config(&m.backup))?;
                                                                                                     
                                                                                                     
                                                                                             
    symlink_in(
        staging,
        "root/.ssh/authorized_keys",
        "/persist/etc/ssh/authorized_keys.d/root",
    )?;
                                                                                                       
                                                                                                          
    symlink_in(staging, "etc/resolv.conf", "/run/resolv.conf")?;
                                                                                                        
                                                                                                        
                                                                                                        
                                                                                                      
    for dir in ["proc", "sys", "dev", "run", "tmp", "persist", "boot"] {
        let path = staging.join(dir);
        std::fs::create_dir_all(&path).map_err(|source| BuildError::Io {
            path: path.display().to_string(),
            source,
        })?;
    }
    Ok(())
}

/// Create a symlink at `staging/<rel>` → `target` (an absolute in-image path), creating the parent
/// dir. The image-builder runs on the operator's Linux host (the crate already uses `std::os::unix`
/// unconditionally), so no cross-platform guard is needed.
fn symlink_in(staging: &Path, rel: &str, target: &str) -> Result<(), BuildError> {
    let path = staging.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| BuildError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    std::os::unix::fs::symlink(target, &path).map_err(|source| BuildError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Build-time hardening assertions over the staged tree (spec defense layers 6/7,
                                                                               
/// systemd / package-manager / PAM) + the dropbear-links-no-PAM `ldd` check. Fails
/// the build (fail-closed) on any violation.
fn run_hardening_checks<T: BuildTools>(root: &Path, tools: &T) -> Result<(), BuildError> {
    use crate::config;
    let paths = collect_staging_paths(root)?;
                                                                                                     
                                                                                              
    config::check_required_components(paths.iter().map(String::as_str))?;
                                                                                                    
                                                                                                  
                                                                                                     
                                                                                   
    config::check_required_path_commands(paths.iter().map(String::as_str))?;
    config::check_no_forbidden_components(paths.iter().map(String::as_str))?;
                                                                                                     
                                                                                                     
                                                                                                         
                                                                                                  
                                    
    check_root_home_not_group_other_writable(root)?;
                                                                                                       
                                                                                                  
                                                                                                 
                                                                                                  
                                                                                                      
    let needed = tools.collect_needed(root)?;
    config::check_no_pam_needed(&needed)?;
    let available = collect_available_sonames(root)?;
    config::check_link_completeness(&needed, &available)?;
    Ok(())
}

/// Assert the staged `/root` (the rescue auth-chain home; `/root/.ssh` is a runtime-shadowed symlink)
/// is not group/other-writable — dropbear's `checkpubkeyperms` rejects the recovery key otherwise
/// (the bug-3 lockout class). Assert-if-present: a real build always stages `/root` (the
/// `/root/.ssh` symlink's parent), and skipping when absent avoids a false-positive on staging order.
fn check_root_home_not_group_other_writable(root: &Path) -> Result<(), BuildError> {
    use std::os::unix::fs::PermissionsExt;
    let home = root.join("root");
    if let Ok(meta) = std::fs::symlink_metadata(&home) {
        let mode = meta.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(BuildError::Tool {
                tool: "rescue-auth-perms",
                reason: format!(
                    "/root is group/other-writable (mode {:o}); dropbear checkpubkeyperms would \
                     reject the rescue recovery key → lockout. Stage /root mode 0700/0755.",
                    mode & 0o7777
                ),
            });
        }
    }
    Ok(())
}

/// Collect the shared-object filenames in the staging rootfs's lib dirs (`/lib` + `/usr/lib`,
/// recursive) — the set a DT_NEEDED soname must resolve to (musl resolves by soname = filename). A
/// missing lib dir contributes nothing (the completeness check then catches the gap, fail-closed).
fn collect_available_sonames(root: &Path) -> Result<std::collections::HashSet<String>, BuildError> {
    let mut set = std::collections::HashSet::new();
    for libdir in ["lib", "usr/lib"] {
        let mut stack = vec![root.join(libdir)];
        while let Some(dir) = stack.pop() {
            if !dir.exists() {
                continue;
            }
            let entries = std::fs::read_dir(&dir).map_err(|source| BuildError::Io {
                path: dir.display().to_string(),
                source,
            })?;
            for entry in entries {
                let entry = entry.map_err(|source| BuildError::Io {
                    path: dir.display().to_string(),
                    source,
                })?;
                let path = entry.path();
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    stack.push(path);
                } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    set.insert(name.to_string());
                }
            }
        }
    }
    Ok(set)
}

/// Collect every staged path as a leading-slash absolute-style string (so markers
/// like `/sbin/apk` match), for [`run_hardening_checks`].
fn collect_staging_paths(root: &Path) -> Result<Vec<String>, BuildError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|source| BuildError::Io {
            path: dir.display().to_string(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| BuildError::Io {
                path: dir.display().to_string(),
                source,
            })?;
            let path = entry.path();
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(format!("/{}", rel.to_string_lossy()));
            }
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                stack.push(path);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AcquireError, PinnedPackage};
    use std::cell::RefCell;

    /// The fake dm-verity root hash the `FakeTools` bakers return — a realistic 64-lowercase-hex
    /// SHA-256 shape (a real verity root digest is 64 hex). The T4 seabios-gpt fixed-geometry render
    /// asserts exactly 64 hex, so the fake must match the real width or `build()` panics on the belt.
    const FAKE_ROOT_HASH: &str = "6d95ad62deadbeef6d95ad62deadbeef6d95ad62deadbeef6d95ad62deadbeef";

    #[test]
    fn build_emits_the_full_phase_banner_sequence() {
        let mut rec: Vec<String> = vec![];
        run_phase_banners_for_test(Firmware::Seabios, false, |name, _e| {
            rec.push(name.to_string())
        });
        assert_eq!(
            rec,
            vec![
                "preflight",
                "sign",
                "kernel compile",
                "config-assert",
                "squashfs",
                "verity",
                "initramfs",
                "rootfs assemble",
                "boot-fs",
                "persist-skeleton",
                "image assemble",
            ]
        );
    }

    #[test]
    fn a_dha_build_inserts_the_weights_banner() {
        let mut rec: Vec<String> = vec![];
        run_phase_banners_for_test(Firmware::Seabios, true, |n, _| rec.push(n.to_string()));
        assert!(rec.iter().any(|p| p == "weights"), "{rec:?}");
                                                              
        let wi = rec.iter().position(|p| p == "weights").unwrap();
        let ra = rec.iter().position(|p| p == "rootfs assemble").unwrap();
        let bf = rec.iter().position(|p| p == "boot-fs").unwrap();
        assert!(ra < wi && wi < bf, "{rec:?}");
    }

    /// Records the order the tool steps ran, and yields fixed fixture bytes.
    struct FakeTools {
        calls: RefCell<Vec<&'static str>>,
        /// Canned `(elf, DT_NEEDED sonames)` for `collect_needed`. Default empty: the fake staging
        /// has no lib files, so empty NEEDED keeps the link-completeness guard satisfied.
        needed: Vec<(String, Vec<String>)>,
        /// The `(cmdline, initrd_sha256_hex)` the UEFI arm fed `build_efi_loader` — the arm test
        /// asserts the loader policy was baked from the rendered cmdline + the REAL initrd digest.
        loader_inputs: RefCell<Option<(String, String)>>,
        /// The `extlinux.conf` APPEND the SeaBIOS/SeabiosGpt arm fed `bake_boot_fs` — the dha weights
        /// test asserts the rendered APPEND carries the `fb.weights-*` triple (proving `build()` wired
        /// `Some(WeightsCmdline)` into the render, not only into `assemble_img`).
        boot_fs_extlinux: RefCell<Option<String>>,
        /// Whether the rootfs staging carried the empty `/models` weights mount dir at `pack_squashfs`
                                                                                         
        models_dir_staged: RefCell<bool>,
        /// The `.config` `build_kernel` returns — the C3 CONFIG-assert runs the firmware-derived
        /// substrate union over it, so a bare-metal (UEFI) build needs a USB-inclusive `.config`.
        /// Default satisfies the shared IMA pin + the vps-kvm forbidden set (no USB).
        dot_config: String,
        /// Hotswap v4: the `EngineWeightsSetup` the build threaded into `build_init_tree` — the
        /// RuntimeRecord arm test asserts `Runtime` reached the servicedir render.
        init_tree_weights: RefCell<Option<crate::service_tree::EngineWeightsSetup>>,
        /// Hotswap v4: the record bytes the build threaded into `bake_persist_skeleton` — the
        /// RuntimeRecord arm test asserts the signed record reached the skeleton (and the
        /// BootCmdline/dha arm asserts None).
        persist_weights_record: RefCell<Option<Vec<u8>>>,
        /// Hotswap v4: the `extra_bins` build_binaries received (RuntimeRecord ⇒ ["fb-weights"]).
        extra_bins_staged: RefCell<Option<Vec<String>>>,
    }
    impl FakeTools {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                needed: Vec::new(),
                loader_inputs: RefCell::new(None),
                boot_fs_extlinux: RefCell::new(None),
                models_dir_staged: RefCell::new(false),
                dot_config: "CONFIG_IMA=y\n".to_string(),
                init_tree_weights: RefCell::new(None),
                persist_weights_record: RefCell::new(None),
                extra_bins_staged: RefCell::new(None),
            }
        }
        /// C3: a bare-metal `.config` — the shared IMA pin PLUS the four USB host/storage drivers the
        /// bare-metal-uefi substrate block asserts present, plus the SCSI/sd disk transports (asserted by
        /// the SHARED block, audit L-1 — not this per-substrate block — and present on both substrates).
        /// Used by the UEFI arm test.
        fn with_baremetal_config(self) -> Self {
            self.with_dot_config(
                "CONFIG_IMA=y\nCONFIG_USB=y\nCONFIG_USB_XHCI_HCD=y\n\
                 CONFIG_USB_EHCI_HCD=y\nCONFIG_USB_STORAGE=y\nCONFIG_SCSI=y\n\
                 CONFIG_BLK_DEV_SD=y\n",
            )
        }
        /// C3: override the `.config` `build_kernel` yields, so a test can drive the SUBSTRATE
                                                                                
        fn with_dot_config(self, c: &str) -> Self {
            Self {
                dot_config: c.to_string(),
                ..self
            }
        }
        /// A dropbear that (wrongly) NEEDs PAM — for the no-PAM-check-fails test.
        fn with_pam_needed() -> Self {
            Self {
                needed: vec![("usr/sbin/dropbear".into(), vec!["libpam.so.0".into()])],
                ..Self::new()
            }
        }
        /// A dropbear NEEDing a soname absent from the (libless) fake staging — for the
        /// link-completeness-fails test.
        fn with_unresolved_needed() -> Self {
            Self {
                needed: vec![("usr/sbin/dropbear".into(), vec!["libmissing.so.7".into()])],
                ..Self::new()
            }
        }
    }
    impl BuildTools for FakeTools {
        fn build_binaries(
            &self,
            staging: &Path,
            manifest: &fb_manifest::ValidatedManifest,
            extra_bins: &[&str],
        ) -> Result<(), BuildError> {
            self.calls.borrow_mut().push("build_binaries");
            self.extra_bins_staged
                .borrow_mut()
                .replace(extra_bins.iter().map(|s| s.to_string()).collect());
            let bin = staging.join("usr/bin");
            std::fs::create_dir_all(&bin).unwrap();
                                                                                                       
                                                                                                    
                                                                      
            for name in crate::build::staged_usr_bin_names(manifest) {
                std::fs::write(bin.join(&name), b"ELF").unwrap();
            }
            for name in extra_bins {
                std::fs::write(bin.join(name), b"ELF").unwrap();
            }
            Ok(())
        }
        fn stage_manifest_files(
            &self,
            staging: &Path,
            manifest: &fb_manifest::ValidatedManifest,
        ) -> Result<Vec<ownership::OwnerException>, BuildError> {
            self.calls.borrow_mut().push("stage_manifest_files");
                                                                                                      
                                                                                                          
                                                                                      
            let mut exceptions = Vec::new();
            let m = manifest.manifest();
            for sf in m.staged_files.as_deref().unwrap_or(&[]) {
                let rel = sf.target.trim_start_matches('/');
                let dest = staging.join(rel);
                std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                std::fs::write(&dest, sf.key.as_bytes()).unwrap();
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(sf.mode))
                        .unwrap();
                }
                if let Some(owner) = &sf.owner {
                    let uid = fb_manifest::validate::resolve_owner(owner, &m.identities).unwrap();
                    exceptions.push(ownership::OwnerException {
                        rel_path: std::path::PathBuf::from(rel),
                        uid,
                        gid: uid,
                    });
                }
            }
            Ok(exceptions)
        }
        fn ima_evm_xattr_pseudo(
            &self,
            _staging: &Path,
            _ima_key: &Path,
            _ima_cert: &Path,
            _owner_exceptions: &[ownership::OwnerException],
        ) -> Result<String, BuildError> {
            self.calls.borrow_mut().push("ima_evm_xattr_pseudo");
            Ok(String::new())
        }
        fn build_kernel(
            &self,
            _epoch: u64,
            _frandom_seed_hex: &str,
        ) -> Result<KernelArtifacts, BuildError> {
            self.calls.borrow_mut().push("build_kernel");
            Ok(KernelArtifacts {
                vmlinuz: vec![0x01; 2048],
                                                                                                     
                dot_config: self.dot_config.clone(),
            })
        }
        fn pack_squashfs(
            &self,
            staging: &Path,
            _epoch: u64,
            _xattr_pseudo: &str,
        ) -> Result<Vec<u8>, BuildError> {
            self.calls.borrow_mut().push("pack_squashfs");
                                                                                                       
            *self.models_dir_staged.borrow_mut() = staging.join("models").is_dir();
                                                                                               
                                                                                                  
                                                                                        
            Ok(vec![0xAB; image::BLOCK_SIZE * 2])
        }
        fn build_verity(&self, _squashfs: &[u8]) -> Result<VerityArtifacts, BuildError> {
            self.calls.borrow_mut().push("build_verity");
            Ok(VerityArtifacts {
                hash_tree: vec![0xCD; 512],                                                                                
                root_hash: FAKE_ROOT_HASH.into(),
            })
        }
        fn pack_weights_squashfs(
            &self,
            _gguf_path: &Path,
            mmproj_path: Option<&Path>,
            _epoch: u64,
        ) -> Result<Vec<u8>, BuildError> {
                                                                                                         
                                                                                           
            self.calls.borrow_mut().push(if mmproj_path.is_some() {
                "pack_weights_squashfs+mmproj"
            } else {
                "pack_weights_squashfs"
            });
                                                                                                       
                                                                                                      
                                                                                                
            Ok(vec![0x77; image::BLOCK_SIZE * 3])
        }
        fn build_initramfs(&self, _epoch: u64) -> Result<Vec<u8>, BuildError> {
            self.calls.borrow_mut().push("build_initramfs");
            Ok(vec![0x02; 1500])
        }
        fn build_efi_loader(
            &self,
            cmdline: &str,
            initrd_sha256_hex: &str,
            _sb_required: bool,
            _epoch: u64,
        ) -> Result<Vec<u8>, BuildError> {
            self.calls.borrow_mut().push("build_efi_loader");
                                                                                       
                                                                                  
            self.loader_inputs
                .borrow_mut()
                .replace((cmdline.to_string(), initrd_sha256_hex.to_string()));
            Ok(vec![0x05; 1024])                        
        }
        fn collect_needed(&self, _root: &Path) -> Result<Vec<(String, Vec<String>)>, BuildError> {
            self.calls.borrow_mut().push("collect_needed");
            Ok(self.needed.clone())
        }
        fn build_init_tree(
            &self,
            staging: &Path,
            _domain: &str,
            _epoch: u64,
            manifest: &fb_manifest::ValidatedManifest,
            weights: crate::service_tree::EngineWeightsSetup,
        ) -> Result<(), BuildError> {
            self.calls.borrow_mut().push("build_init_tree");
            self.init_tree_weights.borrow_mut().replace(weights);
                                                                                                       
                                                                                                   
                                                                                                           
                                                                                                           
            for rel in crate::config::REQUIRED_INIT_PATHS {
                let p = staging.join(rel.trim_start_matches('/'));
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, b"#!/bin/sh\n").unwrap();
            }
                                                                                                      
                                                                                                         
                                                                                                      
            for svc in &manifest.manifest().services {
                let p = staging.join(format!("etc/box-svc/{}/run", svc.name));
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, b"#!/bin/sh\n").unwrap();
            }
                                                                                                     
                                                                                                      
            for applet in crate::config::REQUIRED_BUSYBOX_APPLETS {
                let p = staging.join("bin").join(applet);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, b"applet").unwrap();
            }
            Ok(())
        }
        fn bake_boot_fs(
            &self,
            _vmlinuz: &[u8],
            _initramfs: &[u8],
            extlinux_conf: &str,
            _firmware: Firmware,
            _epoch: u64,
        ) -> Result<Vec<u8>, BuildError> {
            self.calls.borrow_mut().push("bake_boot_fs");
                                                                                                  
                                                            
            self.boot_fs_extlinux
                .borrow_mut()
                .replace(extlinux_conf.to_string());
                                                                                                         
                                                                                                  
                                                                          
            Ok(vec![0xB0; image::BLOCK_SIZE])
        }
        fn bake_esp(
            &self,
            _loader: &[u8],
            _vmlinuz: &[u8],
            _initrd: &[u8],
            _epoch: u64,
        ) -> Result<Vec<u8>, BuildError> {
            self.calls.borrow_mut().push("bake_esp");
            Ok(vec![0xE5; image::BLOCK_SIZE])
        }
        fn bake_persist_skeleton(
            &self,
            _operator_pubkey: &[u8],
            _epoch: u64,
            weights_record: Option<&[u8]>,
        ) -> Result<Vec<u8>, BuildError> {
            self.calls.borrow_mut().push("bake_persist_skeleton");
            *self.persist_weights_record.borrow_mut() = weights_record.map(<[u8]>::to_vec);
            let mut img = vec![0x9E; image::BLOCK_SIZE];
                                                                                                    
                                                                                                               
            img[1024 + 0x5C..1024 + 0x60].fill(0);
            Ok(img)
        }
        fn bake_installer_data(
            &self,
            _box_img: &[u8],
            _box_layout_toml: &[u8],
            _epoch: u64,
        ) -> Result<Vec<u8>, BuildError> {
            self.calls.borrow_mut().push("bake_installer_data");
                                                                                               
            Ok(vec![0xDA; image::BLOCK_SIZE])
        }
    }

    /// Stage the apk-provided load-bearing binaries (so `check_required_components` passes); the
    /// recipes bins come from `FakeTools::build_binaries`.
    fn stage_apk_bins(root: &Path) {
        for p in [
            "usr/sbin/dropbear",
            "usr/sbin/haproxy",
            "usr/bin/s6-svscan",
            "usr/bin/s6-svscanctl",
            "usr/sbin/nft",                                                                       
            "sbin/e2fsck",                                                                             
        ] {
            let path = root.join(p);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"ELF").unwrap();
        }
                                                                                                      
                                                                           
        for cmd in crate::config::REQUIRED_PATH_COMMANDS {
            let path = root.join("usr/bin").join(cmd);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"ELF").unwrap();
        }
    }

    /// Provider that drops a fixture file per pin (stands in for fetch+verify+extract).
    struct FakeProvider;
    impl PackageProvider for FakeProvider {
        fn acquire(&self, pin: &PinnedPackage, staging_root: &Path) -> Result<(), AcquireError> {
            stage_apk_bins(staging_root);
            std::fs::write(staging_root.join(format!("apk-{}", pin.name)), b"x")
                .map_err(AcquireError::Extract)
        }
    }

    /// Provider that stages a forbidden component (systemd) — for the hardening test.
    struct ForbiddenComponentProvider;
    impl PackageProvider for ForbiddenComponentProvider {
        fn acquire(&self, _pin: &PinnedPackage, staging_root: &Path) -> Result<(), AcquireError> {
                                                                                                  
            stage_apk_bins(staging_root);
            let d = staging_root.join("usr/lib/systemd");
            std::fs::create_dir_all(&d).map_err(AcquireError::Extract)?;
            std::fs::write(d.join("systemd"), b"x").map_err(AcquireError::Extract)
        }
    }

    /// Stages haproxy + s6 (recipes bins come from FakeTools) but NOT dropbear — the M-1
    /// fold-verification probe: a tree MISSING /usr/sbin/dropbear must make build() Err.
    struct MissingDropbearProvider;
    impl PackageProvider for MissingDropbearProvider {
        fn acquire(&self, _pin: &PinnedPackage, staging_root: &Path) -> Result<(), AcquireError> {
            for p in ["usr/sbin/haproxy", "usr/bin/s6-svscan"] {
                let path = staging_root.join(p);
                std::fs::create_dir_all(path.parent().unwrap()).map_err(AcquireError::Extract)?;
                std::fs::write(&path, b"ELF").map_err(AcquireError::Extract)?;
            }
            Ok(())
        }
    }

    /// Records every pin name `acquire` sees — proves build() extracts the runtime `packages` and
                                                                            
    #[derive(Default)]
    struct RecordingProvider {
        acquired: RefCell<Vec<String>>,
    }
    impl PackageProvider for RecordingProvider {
        fn acquire(&self, pin: &PinnedPackage, staging_root: &Path) -> Result<(), AcquireError> {
            self.acquired.borrow_mut().push(pin.name.clone());
            stage_apk_bins(staging_root);
            Ok(())
        }
    }

    #[test]
    fn build_does_not_acquire_build_inputs_into_the_rootfs() {
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let c = cfg(tmp.path(), master);
        let (apk_pins, kernel_pins) = pins();                                                 
        let provider = RecordingProvider::default();
        build(&c, &apk_pins, &kernel_pins, &provider, &FakeTools::new()).expect("build ok");
        let acquired = provider.acquired.borrow();
        assert!(
            acquired.contains(&"busybox".to_string()),
            "runtime package IS extracted"
        );
        assert!(
            !acquired.contains(&"linux-virt".to_string()),
            "a build_input must NEVER be extracted into the rootfs (2026-05-27)"
        );
    }

    fn write_master_key(dir: &Path) -> PathBuf {
        let p = dir.join("rescue-seed-master.key");
        std::fs::write(&p, [7u8; 32]).unwrap();
        p
    }

    fn cfg(out: &Path, master: PathBuf) -> BuildConfig {
        let git_sha = "abc123de".repeat(5);                                               
        BuildConfig {
            image_label: git_sha.clone(),                                   
            git_sha,
            source_date_epoch: 1_700_000_000,
            alpine_version: "3.23.0".into(),
            domain: "recipes.example.org".into(),
            image_signing_crt_sha256_hex: "ab".repeat(32),                
            master_key_path: master,
            ima_key_path: out.join("ima.key"),
            ima_cert_path: out.join("ima.crt"),
            out_dir: out.join("out"),
            recovery_authorized_keys: None,
            operator_pubkey: None,
            firmware: Firmware::Seabios,
            net: None,
            sb_required: false,
            manifest: crate::config::sample_manifest(),
            weights: None,
            weights_anchor: WeightsAnchor::BootCmdline,
            image_version: 7,
            min_delegation_ctr: 1_700_000_042,
            artifact_root_pub: None,
        }
    }

    fn pins() -> (PinnedApks, KernelConfigPins) {
        let pkg = |name: &str| PinnedPackage {
            name: name.into(),
            version: "1.0".into(),
            sha256: "00".into(),
            signing_key: "k".into(),
        };
        let apk = PinnedApks {
            alpine_version: "3.23.0".into(),
            packages: vec![pkg("busybox")],
                                                                                                     
                                                                                                    
            build_inputs: vec![pkg("linux-virt")],
        };
        let kernel = KernelConfigPins {
            exact_match: vec!["CONFIG_IMA=y".into()],
            prefix_match: vec![],
            forbidden: vec![],
            forbidden_prefix: vec![],
            forbidden_prefix_allow: vec![],
        };
        (apk, kernel)
    }

    #[test]
    fn build_runs_the_pipeline_in_spec_order_and_emits_the_unsigned_triple() {
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let c = cfg(tmp.path(), master);
        let (apk_pins, kernel_pins) = pins();
        let tools = FakeTools::new();

        let out = build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools).unwrap();

                                                                                                 
                                                                                                    
                                                                                                        
                                                 
        assert_eq!(
            *tools.calls.borrow(),
            vec![
                "build_binaries",
                "collect_needed",
                "build_init_tree",
                "stage_manifest_files",
                "collect_needed",
                "ima_evm_xattr_pseudo",
                "build_kernel",
                "pack_squashfs",
                "build_verity",
                "build_initramfs",
                "bake_boot_fs",
                "bake_persist_skeleton",
            ]
        );
                                                                          
        assert!(out.outputs.img.exists());
        assert!(out.outputs.layout.exists());
        assert!(out.outputs.sha256.exists());
        assert!(
            out.outputs.vmlinuz.exists(),
            "<base>.vmlinuz local kexec artifact"
        );
        assert!(
            out.outputs.initramfs.exists(),
            "<base>.initramfs local kexec artifact"
        );
        assert!(
            !out.outputs.img.with_extension("img.sig").exists(),
            ".sig is forward-debt (operator-sovereign ed25519)"
        );
        assert_eq!(out.root_hash, FAKE_ROOT_HASH);
                                                                                                         
                                                                                                     
                                                                                            
        let layout_toml = std::fs::read_to_string(&out.outputs.layout).unwrap();
        assert!(
            !layout_toml.contains("weights"),
            "non-dha layout must carry no weights keys: {layout_toml:?}"
        );
                                                                                                
        assert!(
            !*tools.models_dir_staged.borrow(),
            "non-dha build must not bake /models"
        );
    }

                                                                                                     
    /// via `BANNER_TAP`) equal `build_phase_names` — the drift-proof guard the replay-only
    /// `build_emits_the_full_phase_banner_sequence` lacks. A seabios (non-dha) build; the conditional
    /// weights banner is covered by the weights-arm test + `build_phase_names(_, true)`.
    #[test]
    fn build_real_emission_matches_build_phase_names() {
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let c = cfg(tmp.path(), master);                                                   
        let (apk_pins, kernel_pins) = pins();
        BANNER_TAP.with(|t| *t.borrow_mut() = Some(Vec::new()));
        build(
            &c,
            &apk_pins,
            &kernel_pins,
            &FakeProvider,
            &FakeTools::new(),
        )
        .unwrap();
        let emitted = BANNER_TAP.with(|t| t.borrow_mut().take().unwrap());
        assert_eq!(
            emitted,
            build_phase_names(Firmware::Seabios, false),
            "build()'s REAL phase_banner emissions must equal build_phase_names (no silent drift)"
        );
    }

    #[test]
    fn seabios_gpt_build_uses_the_extlinux_bake_not_esp() {
                                                                                                         
                                                                                                       
                                                                                                         
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let mut c = cfg(tmp.path(), master);
        c.firmware = Firmware::SeabiosGpt;
        let (apk_pins, kernel_pins) = pins();
        let tools = FakeTools::new();

        let out = build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools).unwrap();

        assert_eq!(
            *tools.calls.borrow(),
            vec![
                "build_binaries",
                "collect_needed",
                "build_init_tree",
                "stage_manifest_files",
                "collect_needed",
                "ima_evm_xattr_pseudo",
                "build_kernel",
                "pack_squashfs",
                "build_verity",
                "build_initramfs",
                "bake_boot_fs",
                "bake_persist_skeleton",
            ],
            "SeabiosGpt takes the SeaBIOS extlinux bake order (no loader/ESP)"
        );
        assert!(
            !tools
                .calls
                .borrow()
                .iter()
                .any(|c| *c == "bake_esp" || *c == "build_efi_loader"),
            "SeabiosGpt is legacy-BIOS — no ESP/loader: {:?}",
            tools.calls.borrow()
        );
                                                                                              
        let layout_toml = std::fs::read_to_string(&out.outputs.layout).unwrap();
        assert!(
            layout_toml.contains("firmware = \"seabios-gpt\""),
            "layout declares seabios-gpt: {layout_toml:?}"
        );
    }

    /// dha Component E (#9-BAKE): a dha build (`cfg.weights = Some`) bakes the weights GGUF into a
    /// squashfs+dm-verity 5th component AND wires it into BOTH the `.img` layout (`assemble_img`) and the
    /// boot cmdline (`render_boot_fs_extlinux`). Proves: (1) `pack_weights_squashfs` + a SECOND
    /// `build_verity` run (over the weights squashfs), (2) the layout carries the weights byte-range keys
    /// with the component-derived sizes, (3) the rendered APPEND carries the `fb.weights-*` triple (the
    /// LOCKED E2 grammar). The REAL bytes are the boot gate; here the fakes exercise the orchestration.
    #[test]
    fn dha_build_bakes_and_wires_the_weights_volume() {
        use sha2::{Digest, Sha256};
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
                                                                                                          
        let gguf_path = tmp.path().join("qwen-fixture.gguf");
        let gguf_bytes = b"GGUF\x00stand-in weights bytes for the orchestration test";
        std::fs::write(&gguf_path, gguf_bytes).unwrap();
        let gguf_sha = format!("{:x}", Sha256::digest(gguf_bytes));

        let mut c = cfg(tmp.path(), master);
        c.weights = Some(WeightsInput {
            gguf_path: gguf_path.clone(),
            sha256: gguf_sha,
            bytes: gguf_bytes.len() as u64,
            mmproj: None,
        });
        c.firmware = Firmware::SeabiosGpt;                                                 
        let (apk_pins, kernel_pins) = pins();
        let tools = FakeTools::new();

        let out = build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools).unwrap();

                                                                                               
        assert!(
            *tools.models_dir_staged.borrow(),
            "a dha build must bake the empty /models mount dir into the rootfs (else E3 reboot-loops)"
        );
                                                                                                
        assert_eq!(
            tools.extra_bins_staged.borrow().as_deref(),
            Some(&[][..]),
            "a BootCmdline build must stage no fb-weights"
        );

                                                                                                         
        let calls = tools.calls.borrow().clone();
        assert!(
            calls.contains(&"pack_weights_squashfs"),
            "the weights squashfs pack must run for a dha build: {calls:?}"
        );
        assert_eq!(
            calls.iter().filter(|c| **c == "build_verity").count(),
            2,
            "dm-verity runs over BOTH the rootfs squashfs and the weights squashfs: {calls:?}"
        );

                                                                                                         
                                                                                                        
        let bs = image::BLOCK_SIZE as u64;
        let rootfs_size = bs * 2 + 512;
        let weights_offset = bs + bs + rootfs_size;                           
        let layout_toml = std::fs::read_to_string(&out.outputs.layout).unwrap();
        assert!(
            layout_toml.contains(&format!("weights_offset = {weights_offset}")),
            "weights_offset (after rootfs): {layout_toml:?}"
        );
        assert!(
            layout_toml.contains(&format!("weights_size = {}", bs * 3 + 512)),
            "weights_size = padded squashfs + hash tree: {layout_toml:?}"
        );
        assert!(
            layout_toml.contains(&format!("weights_verity_hash_offset = {}", bs * 3)),
            "weights hash tree begins at the padded squashfs size: {layout_toml:?}"
        );

                                                                                                            
                                                                                                            
        let append = tools
            .boot_fs_extlinux
            .borrow()
            .clone()
            .expect("APPEND captured");
        assert!(
            append.contains(&format!(
                "fb.weights-dev=PARTUUID={} fb.weights-hash={FAKE_ROOT_HASH} fb.weights-offset={} ",
                boot_fs::WEIGHTS_PARTUUID,
                bs * 3
            )),
            "APPEND carries the weights cmdline triple: {append:?}"
        );
    }

    /// Hotswap v4 §7 — the RuntimeRecord fixture: the dha stand-in weights setup with the anchor
    /// flipped to RuntimeRecord (a FIXED fake signer: sig=[0xAB;254], ctr=7) + the dha tenant
    /// manifest (it carries the resource-domain ENGINE the anchor requires).
    fn runtime_cfg(tmp: &Path, master: PathBuf) -> BuildConfig {
        use sha2::{Digest, Sha256};
        let gguf_path = tmp.join("qwen-fixture.gguf");
        let gguf_bytes = b"GGUF\x00stand-in weights bytes for the orchestration test";
        std::fs::write(&gguf_path, gguf_bytes).unwrap();
        let mut c = cfg(tmp, master);
        c.weights = Some(WeightsInput {
            gguf_path,
            sha256: format!("{:x}", Sha256::digest(gguf_bytes)),
            bytes: gguf_bytes.len() as u64,
            mmproj: None,
        });
        c.firmware = Firmware::SeabiosGpt;
        c.manifest = fb_manifest::parse_and_validate(
            include_str!("../dha-tenant.toml"),
            &crate::config::os_identities(),
        )
        .expect("the dha stand-in manifest validates");
        c.weights_anchor = WeightsAnchor::RuntimeRecord(WeightsRecordInputs {
            sign: Box::new(|_manifest| {
                Ok(SignedWeightsManifest {
                    sig: [0xAB; 254],
                    delegation_ctr: 7,
                })
            }),
            health: WeightsHealth {
                port: 8377,
                path: "/v1/completions".to_string(),
                body: "{\"prompt\":\"2+2=\",\"max_tokens\":1}".to_string(),
            },
        });
        c
    }

                                                                                               
    /// weights component into the layout but renders NO `fb.weights-*` cmdline token (the initramfs
    /// fatal-mount skip — the whole no-brick premise), threads `EngineWeightsSetup::Runtime` into
    /// the servicedir render, bakes the two runbook files, and hands the persist skeleton the
    /// SIGNED record with the EXACT fb-weights `stores.rs` byte layout (the cross-repo contract
    /// golden — fb-weights pins the same bytes from the parse side).
    #[test]
    fn runtime_anchor_bakes_record_and_no_cmdline_triple() {
        use sha2::{Digest, Sha256};
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let c = runtime_cfg(tmp.path(), master);
        let (apk_pins, kernel_pins) = pins();
        let tools = FakeTools::new();

        let out = build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools).unwrap();

                                                                                                    
        let bs = image::BLOCK_SIZE as u64;
        let layout_toml = std::fs::read_to_string(&out.outputs.layout).unwrap();
        assert!(
            layout_toml.contains(&format!("weights_size = {}", bs * 3 + 512)),
            "the weights DATA partition bakes under the runtime anchor too: {layout_toml:?}"
        );

                                                                              
        let append = tools
            .boot_fs_extlinux
            .borrow()
            .clone()
            .expect("APPEND captured");
        assert!(
            !append.contains("fb.weights-"),
            "a RuntimeRecord build must render NO weights cmdline token: {append:?}"
        );

                                                                                                 
                                                                                                      
        assert_eq!(
            *tools.init_tree_weights.borrow(),
            Some(crate::service_tree::EngineWeightsSetup::Runtime),
            "build_init_tree must receive EngineWeightsSetup::Runtime"
        );
        assert_eq!(
            tools.extra_bins_staged.borrow().as_deref(),
            Some(&["fb-weights".to_string()][..]),
            "a RuntimeRecord build stages /usr/bin/fb-weights"
        );

                                                                                               
                                                                                                          
                                                                                                  
                                                               
        let mut component = vec![0x77u8; image::BLOCK_SIZE * 3];
        component.extend_from_slice(&[0xCD; 512]);
        let manifest = format!(
            "verity-root-hash={FAKE_ROOT_HASH}\nverity-offset={}\nimage-sha256={:x}\nimage-size={}\n",
            bs * 3,
            Sha256::digest(&component),
            bs * 3 + 512
        );
        let mut expected = Vec::new();
        expected.extend_from_slice(b"FBW1");
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
        expected.extend_from_slice(manifest.as_bytes());
        expected.extend_from_slice(&[0xAB; 254]);
        assert_eq!(
            tools.persist_weights_record.borrow().as_deref(),
            Some(expected.as_slice()),
            "the baked record must match the fb-weights stores.rs byte contract exactly"
        );
    }

    /// Hotswap v4 §7 — the fail-fast coherence gates: a RuntimeRecord anchor without a weights
    /// input, or with a manifest lacking a resource-domain engine, refuses BEFORE any tool work;
    /// a signer failure aborts (a v4 box never ships an unverifiable record).
    #[test]
    fn runtime_anchor_gates_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let (apk_pins, kernel_pins) = pins();

                                                             
        let mut c = runtime_cfg(tmp.path(), master.clone());
        c.weights = None;
        let tools = FakeTools::new();
        assert!(matches!(
            build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools),
            Err(BuildError::RuntimeAnchorWithoutWeights)
        ));
        assert!(tools.calls.borrow().is_empty(), "fail-fast, before tools");

                                                                                                    
        let mut c = runtime_cfg(tmp.path(), master.clone());
        c.manifest = crate::config::sample_manifest();
        let tools = FakeTools::new();
        assert!(matches!(
            build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools),
            Err(BuildError::RuntimeAnchorWithoutEngine)
        ));

                                                                                   
        let mut c = runtime_cfg(tmp.path(), master);
        if let WeightsAnchor::RuntimeRecord(inputs) = &mut c.weights_anchor {
            inputs.sign = Box::new(|_| Err("no Weights delegation".to_string()));
        }
        let tools = FakeTools::new();
        assert!(matches!(
            build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools),
            Err(BuildError::WeightsRecordSigning { .. })
        ));
    }

                                                                                                        
    /// packer, and it must be held to the same fail-closed sha gate as the text half. A silently-dropped
    /// mmproj would still produce a valid single-file volume and a green build, so this asserts the
    /// pair-ness explicitly rather than inferring it from success.
    #[test]
    fn a_vl_profile_stages_the_mmproj_and_verifies_its_sha() {
        use sha2::{Digest, Sha256};
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());

        let gguf_path = tmp.path().join("qwen-fixture.gguf");
        let gguf_bytes: &[u8] = b"GGUF\x00stand-in text weights";
        std::fs::write(&gguf_path, gguf_bytes).unwrap();
        let mm_path = tmp.path().join("mmproj-fixture.gguf");
        let mm_bytes: &[u8] = b"GGUF\x00stand-in vision projector";
        std::fs::write(&mm_path, mm_bytes).unwrap();

        let vl_weights = |mm_sha: String| WeightsInput {
            gguf_path: gguf_path.clone(),
            sha256: format!("{:x}", Sha256::digest(gguf_bytes)),
            bytes: gguf_bytes.len() as u64,
            mmproj: Some(WeightsFile {
                path: mm_path.clone(),
                sha256: mm_sha,
                bytes: mm_bytes.len() as u64,
            }),
        };

                                                       
        let mut c = cfg(tmp.path(), master.clone());
        c.weights = Some(vl_weights(format!("{:x}", Sha256::digest(mm_bytes))));
        c.firmware = Firmware::SeabiosGpt;
        let (apk_pins, kernel_pins) = pins();
        let tools = FakeTools::new();
        build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools)
            .expect("a VL weights build must succeed");
        let calls = tools.calls.borrow().clone();
        assert!(
            calls.contains(&"pack_weights_squashfs+mmproj"),
            "the projector must reach pack_weights_squashfs — a dropped mmproj still bakes a valid \
             single-file volume, so success alone proves nothing: {calls:?}"
        );

                                                                                                       
                                                                                           
        let mut bad = cfg(tmp.path(), master);
        bad.weights = Some(vl_weights("00".repeat(32)));
        bad.firmware = Firmware::SeabiosGpt;
        let tools = FakeTools::new();
        let err = build(&bad, &apk_pins, &kernel_pins, &FakeProvider, &tools)
            .expect_err("a mismatched mmproj sha must abort the build");
        assert!(
            matches!(err, BuildError::WeightsShaMismatch { ref path, .. } if path.contains("mmproj")),
            "the abort must name the projector, not the text half: {err:?}"
        );
        assert!(
            tools.calls.borrow().is_empty(),
            "the integrity gate runs BEFORE any tool work (fail-fast): {:?}",
            tools.calls.borrow()
        );
    }

    /// The size pre-check is a FAST FAIL, not the integrity gate — but it must still fail CLOSED. A file
    /// whose length differs from the pin aborts before the multi-GiB hash (the usual operator slip: the
    /// 4B pair instead of the 2B, or a truncated download).
    #[test]
    fn a_wrong_size_gguf_aborts_before_the_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let gguf_path = tmp.path().join("qwen-fixture.gguf");
        std::fs::write(&gguf_path, b"short").unwrap();
        let mut c = cfg(tmp.path(), master);
        c.weights = Some(WeightsInput {
            gguf_path,
            sha256: "00".repeat(32),
            bytes: 9_999_999,                                              
            mmproj: None,
        });
        c.firmware = Firmware::SeabiosGpt;
        let (apk_pins, kernel_pins) = pins();
        let tools = FakeTools::new();
        let err = build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools)
            .expect_err("a wrong-size GGUF must abort");
        assert!(
            matches!(err, BuildError::WeightsSizeMismatch { .. }),
            "expected the size gate, got {err:?}"
        );
    }

    /// dha Component E (#9-BAKE): the weights integrity gate is FAIL-CLOSED and fail-FAST — a GGUF whose
    /// bytes don't hash to the `models.toml` pin aborts the build BEFORE any tool runs (a tampered/wrong
    /// weights file must never reach the squashfs+dm-verity bake). This is the load-bearing layer: a
    /// direct lib caller bypasses the CLI's resolution, so `build()` re-hashes here (the domain/net
    /// belt-and-suspenders class).
    #[test]
    fn dha_build_rejects_a_weights_gguf_that_mismatches_the_pin() {
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let gguf_path = tmp.path().join("qwen-fixture.gguf");
        let gguf_bytes: &[u8] = b"the actual weights bytes";
        std::fs::write(&gguf_path, gguf_bytes).unwrap();
        let mut c = cfg(tmp.path(), master);
        c.weights = Some(WeightsInput {
            gguf_path,
            sha256: "00".repeat(32),                                                       
                                                                                                      
                                                                                                     
                                                                 
            bytes: gguf_bytes.len() as u64,
            mmproj: None,
        });
        c.firmware = Firmware::SeabiosGpt;                                                                  
        let (apk_pins, kernel_pins) = pins();
        let tools = FakeTools::new();

        let err = build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools).unwrap_err();
        assert!(
            matches!(err, BuildError::WeightsShaMismatch { .. }),
            "a mismatched weights GGUF must fail closed: {err:?}"
        );
                                                                                             
        assert!(
            tools.calls.borrow().is_empty(),
            "the sha gate aborts before any build tool runs: {:?}",
            tools.calls.borrow()
        );
    }

                                                                                                        
    /// GPT partition; a dha `.img` is always GPT). Fail-fast — before any tool — the build-time twin of the
    /// install-time `compute_partition_layout` MBR-weights guard. The default firmware is SeaBIOS, so this
    /// guards the accidental `--firmware`-omitted dha build.
    #[test]
    fn dha_build_rejects_weights_on_seabios_mbr() {
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let gguf_path = tmp.path().join("qwen-fixture.gguf");
        std::fs::write(&gguf_path, b"weights bytes").unwrap();
        let mut c = cfg(tmp.path(), master);                                    
        c.weights = Some(WeightsInput {
            gguf_path,
            sha256: "00".repeat(32),                                                                 
            bytes: b"weights bytes".len() as u64,
            mmproj: None,
        });
        let (apk_pins, kernel_pins) = pins();
        let tools = FakeTools::new();
        let err = build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools).unwrap_err();
        assert!(
            matches!(err, BuildError::WeightsRequireGptFirmware),
            "weights on MBR SeaBIOS must fail closed at build: {err:?}"
        );
        assert!(
            tools.calls.borrow().is_empty(),
            "the GPT-firmware guard aborts before any tool: {:?}",
            tools.calls.borrow()
        );
    }

                                                                                                 
    /// WEIGHTS_MOUNT_DIR` (a cross-crate DUPLICATED constant — separate `panic=abort` workspaces, same as
    /// [`boot_fs::WEIGHTS_PARTUUID`]). A drift breaks the weights mount on every dha boot (E3 fails closed
    /// on the absent dir → reboot loop). Cross-check by eye vs the fruit-basket constant.
    #[test]
    fn weights_mount_dir_is_the_canonical_literal() {
        assert_eq!(WEIGHTS_MOUNT_DIR, "/models");
    }

    #[test]
    fn uefi_build_uses_plain_kernel_loader_then_esp() {
                                                                                               
                                                                                                     
                                                                                                 
                                                                                        
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let mut c = cfg(tmp.path(), master);
        c.firmware = Firmware::Uefi;
        let (apk_pins, kernel_pins) = pins();
                                                                                                         
                                                                
        let tools = FakeTools::new().with_baremetal_config();

        let out = build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools).unwrap();

        let calls = tools.calls.borrow().clone();
        assert_eq!(
            calls,
            vec![
                "build_binaries",
                "collect_needed",
                "build_init_tree",
                "stage_manifest_files",
                "collect_needed",
                "ima_evm_xattr_pseudo",
                                                                                         
                                                                                    
                "build_kernel",
                "pack_squashfs",
                "build_verity",
                "build_initramfs",
                "build_efi_loader",
                "bake_esp",
                "bake_persist_skeleton",
            ]
        );
        assert!(
            !calls
                .iter()
                .any(|c| c.contains("uefi_params") || c.ends_with("_uefi")),
            "no kernel-stub-era machinery on the loader path: {calls:?}"
        );
                                                                                          
                                                                                          
                                           
        let (cmdline, digest) = tools.loader_inputs.borrow().clone().expect("loader baked");
        assert!(
            cmdline.contains(&format!("fb.root-hash={FAKE_ROOT_HASH}")),
            "{cmdline:?}"
        );
        assert!(
            cmdline.contains("fb.verity-hash-offset=8192"),
            "{cmdline:?}"
        );
        assert!(cmdline.contains("fb.firmware=uefi"), "{cmdline:?}");
        let expected_digest = {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(vec![0x02u8; 1500]))
        };
        assert_eq!(digest, expected_digest, "digest of the exact initrd bytes");
                                                                                             
                                                                                               
        assert!(out.outputs.img.exists());
        assert!(out.outputs.layout.exists());
        assert!(out.outputs.sha256.exists());
        assert!(out.outputs.initramfs.exists());
        let emitted = std::fs::read(&out.outputs.vmlinuz).unwrap();
        assert_eq!(
            emitted,
            vec![0x01; 2048],
            "the vmlinuz sidecar is the one plain shared kernel"
        );
        assert_eq!(out.root_hash, FAKE_ROOT_HASH);
    }

    #[test]
    fn build_installer_usb_orchestrates_digest_cmdline_loader_and_partitions() {
                                                                                                         
                                                                                                           
        use crate::installer_usb::{build_installer_usb, InstallerUsbInputs};

        let signed_img = vec![0x77u8; 4096];                             
        let layout_toml = b"[layout]\nfirmware = \"uefi\"\n";
        let vmlinuz = vec![0x01u8; 2048];
        let initramfs = vec![0x02u8; 1500];
        let tools = FakeTools::new();

        let usb = build_installer_usb(
            &tools,
            &InstallerUsbInputs {
                signed_img: &signed_img,
                box_layout_toml: layout_toml,
                vmlinuz: &vmlinuz,
                initramfs: &initramfs,
                root_hash: "6d95ad62deadbeef",
                verity_offset: 8192,
                install_to: Some("nvme0n1"),
                sb_required: true,
                source_date_epoch: 1_700_000_000,
            },
        )
        .unwrap();

                                                                                                   
        assert_eq!(
            *tools.calls.borrow(),
            vec!["build_efi_loader", "bake_esp", "bake_installer_data"]
        );

                                                                                                       
                                                                                                             
        let (cmdline, initrd_digest) = tools.loader_inputs.borrow().clone().expect("loader baked");
        let expected_img_digest = {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(&signed_img))
        };
        assert!(cmdline.contains("fb.mode=installer"), "{cmdline:?}");
        assert!(
            cmdline.contains(&format!("fb.image-sha256={expected_img_digest}")),
            "the cmdline bakes the whole-file box.img digest: {cmdline:?}"
        );
        assert!(
            cmdline.contains("fb.root-hash=6d95ad62deadbeef"),
            "{cmdline:?}"
        );
        assert!(
            cmdline.contains("fb.verity-hash-offset=8192"),
            "{cmdline:?}"
        );
        assert!(cmdline.contains("fb.install-to=nvme0n1"), "{cmdline:?}");
        let expected_initrd_digest = {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(&initramfs))
        };
        assert_eq!(
            initrd_digest, expected_initrd_digest,
            "the loader gates the shared initrd"
        );

                                                                                           
        let entries = &usb.img[2 * 512..2 * 512 + 128 * 128];
        let esp_uuid =
            crate::gpt::guid_to_mixed_endian(crate::boot_fs::INSTALLER_ESP_PARTUUID).unwrap();
        let data_uuid =
            crate::gpt::guid_to_mixed_endian(crate::boot_fs::INSTALLER_DATA_PARTUUID).unwrap();
        assert_eq!(
            &entries[16..32],
            &esp_uuid,
            "p1 unique GUID = INSTALLER_ESP_PARTUUID"
        );
        assert_eq!(
            &entries[128 + 16..128 + 32],
            &data_uuid,
            "p2 unique GUID = INSTALLER_DATA_PARTUUID"
        );
    }

    #[test]
    fn check_rootfs_fits_slot_fails_closed_on_overflow() {
                                                                                                   
        check_rootfs_fits_slot(SLOT_SIZE_BYTES, SLOT_SIZE_BYTES).expect("exactly slot-sized fits");
        let err = check_rootfs_fits_slot(SLOT_SIZE_BYTES + 1, SLOT_SIZE_BYTES)
            .expect_err("one byte over the slot must fail closed");
        assert!(
            matches!(err, BuildError::RootfsTooLarge { size, slot }
                if size == SLOT_SIZE_BYTES + 1 && slot == SLOT_SIZE_BYTES),
            "got {err:?}"
        );
    }

    #[test]
    fn check_baked_verity_offset_fails_closed_on_mismatch() {
                                                                                                  
                                                                                          
        let good =
            boot_fs::render_boot_fs_extlinux("deadbeef", 14_860_288, None, Firmware::Seabios, None);
        check_baked_verity_offset(&good, 14_860_288).expect("matching offset passes");
        let err = check_baked_verity_offset(&good, 99).expect_err("mismatch must fail closed");
        assert!(
            matches!(
                err,
                BuildError::VerityOffsetMismatch {
                    append: 14_860_288,
                    layout: 99
                }
            ),
            "got {err:?}"
        );
                                             
        assert!(check_baked_verity_offset("APPEND fb.root-hash=x ro", 0).is_err());
    }

    #[test]
    fn check_persist_skeleton_no_journal_fails_closed_on_a_journal() {
                                                                                                       
        let mut img = vec![0u8; 1024 + 0x60];                                                
        check_persist_skeleton_no_journal(&img).expect("no-journal skeleton passes");
        img[1024 + 0x5C] |= 0x04;                   
        assert!(matches!(
            check_persist_skeleton_no_journal(&img),
            Err(BuildError::PersistSkeletonHasJournal)
        ));
                                                                      
        assert!(check_persist_skeleton_no_journal(&[0u8; 100]).is_err());
    }

    /// L-1 regression: an `--allow-dirty` build (`image_label = <sha>-dirty`, `git_sha` CLEAN
    /// 40-hex) succeeds — the dirty taint names the artifact while the clean sha feeds the seed IKM
    /// (`build()` calls the real `PublicInputs::new`). Before the split the `-dirty` value reached
    /// `PublicInputs::new` and was rejected (44 chars, non-hex `-`) → `--allow-dirty` always errored.
    #[test]
    fn build_succeeds_with_a_dirty_image_label() {
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let mut c = cfg(tmp.path(), master);
        c.image_label = format!("{}-dirty", c.git_sha);                              
        let (apk_pins, kernel_pins) = pins();
        let out = build(
            &c,
            &apk_pins,
            &kernel_pins,
            &FakeProvider,
            &FakeTools::new(),
        )
        .expect("a dirty-labeled build derives a valid rescue seed from the clean sha");
        assert!(out.outputs.img.exists());
    }

    #[test]
    fn build_is_reproducible_end_to_end_over_fixed_inputs() {
        let run = || {
            let tmp = tempfile::tempdir().unwrap();
            let master = write_master_key(tmp.path());
            let c = cfg(tmp.path(), master);
            let (apk_pins, kernel_pins) = pins();
            let out = build(
                &c,
                &apk_pins,
                &kernel_pins,
                &FakeProvider,
                &FakeTools::new(),
            )
            .unwrap();
            let img = std::fs::read(&out.outputs.img).unwrap();
                                                  
            drop(tmp);
            img
        };
        assert_eq!(
            run(),
            run(),
            "two builds over identical inputs -> byte-identical .img"
        );
    }

    #[test]
    fn build_aborts_on_kernel_config_regression() {
                                                                                           
                                              
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let c = cfg(tmp.path(), master);
        let apk_pins = pins().0;
        let bad_kernel_pins = KernelConfigPins {
            exact_match: vec!["CONFIG_SECURITY_LOCKDOWN_LSM=y".into()],                           
            prefix_match: vec![],
            forbidden: vec![],
            forbidden_prefix: vec![],
            forbidden_prefix_allow: vec![],
        };
        let err = build(
            &c,
            &apk_pins,
            &bad_kernel_pins,
            &FakeProvider,
            &FakeTools::new(),
        )
        .unwrap_err();
        assert!(matches!(err, BuildError::KernelConfig(_)));
        assert!(!c.out_dir.exists(), "no outputs written when a step fails");
    }

                                                                                                   
    /// (seabios) build whose kernel `.config` RE-ENABLES a forbidden USB driver must FAIL the bake —
    /// the vps-kvm `forbidden` set is unioned into the config-assert on the production path. Were
    /// `union()` a no-op (the regression this guards), the build would wrongly SUCCEED. This is the
    /// first `build()`-level test that actually reaches `assert_kernel_config`'s `forbidden` loop.
    #[test]
    fn a_vps_kvm_build_refuses_a_config_that_re_enables_a_forbidden_usb_driver() {
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let c = cfg(tmp.path(), master);                                 
        let (apk_pins, kernel_pins) = pins();
                                                                                                
        let tools = FakeTools::new().with_dot_config("CONFIG_IMA=y\nCONFIG_USB=y\n");
        let err = build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools).unwrap_err();
        assert!(
            matches!(err, BuildError::KernelConfig(kernel::ConfigAssertError::Missing(ref m))
                if m.contains("CONFIG_USB=y") && m.contains("forbidden")),
            "vps-kvm must refuse a re-enabled USB driver: {err:?}"
        );
    }

                                                                                                     
    /// the required USB host/storage stack must FAIL (the bare-metal `exact_match` block is unioned in). The
    /// existing UEFI happy-path test uses `with_baremetal_config`; this is its negative, so a `union()`
    /// that dropped the bare-metal block would be caught here (the happy path alone cannot catch it).
    #[test]
    fn a_bare_metal_build_refuses_a_config_missing_the_required_usb_stack() {
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let mut c = cfg(tmp.path(), master);
        c.firmware = Firmware::Uefi;                       
        let (apk_pins, kernel_pins) = pins();
                                                                                                   
        let tools = FakeTools::new().with_dot_config("CONFIG_IMA=y\n");
        let err = build(&c, &apk_pins, &kernel_pins, &FakeProvider, &tools).unwrap_err();
        assert!(
            matches!(err, BuildError::KernelConfig(kernel::ConfigAssertError::Missing(ref m))
                if m.contains("CONFIG_USB=y") && m.contains("not in .config")),
            "bare-metal must refuse a config missing the USB stack: {err:?}"
        );
    }

    #[test]
    fn build_aborts_when_dropbear_links_pam() {
                                                                                      
                                                             
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let c = cfg(tmp.path(), master);
        let (apk_pins, kernel_pins) = pins();
        let err = build(
            &c,
            &apk_pins,
            &kernel_pins,
            &FakeProvider,
            &FakeTools::with_pam_needed(),
        )
        .unwrap_err();
        assert!(matches!(err, BuildError::Config(_)), "got {err:?}");
        assert!(
            !c.out_dir.exists(),
            "no outputs written when a hardening check fails"
        );
    }

    #[test]
    fn build_aborts_on_unresolved_link() {
                                                                                                  
                                                                                               
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let c = cfg(tmp.path(), master);
        let (apk_pins, kernel_pins) = pins();
        let err = build(
            &c,
            &apk_pins,
            &kernel_pins,
            &FakeProvider,
            &FakeTools::with_unresolved_needed(),
        )
        .unwrap_err();
        assert!(matches!(err, BuildError::Config(_)), "got {err:?}");
        assert!(
            !c.out_dir.exists(),
            "no outputs when link-completeness fails"
        );
    }

    #[test]
    fn build_aborts_on_forbidden_component() {
                                                                                          
                                          
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let c = cfg(tmp.path(), master);
        let (apk_pins, kernel_pins) = pins();
        let err = build(
            &c,
            &apk_pins,
            &kernel_pins,
            &ForbiddenComponentProvider,
            &FakeTools::new(),
        )
        .unwrap_err();
        assert!(matches!(err, BuildError::Config(_)), "got {err:?}");
        assert!(!c.out_dir.exists());
    }

    #[test]
    fn build_aborts_when_dropbear_absent() {
                                                                                                 
                                                                                                       
                                                                       
        let tmp = tempfile::tempdir().unwrap();
        let master = write_master_key(tmp.path());
        let c = cfg(tmp.path(), master);
        let (apk_pins, kernel_pins) = pins();
        let err = build(
            &c,
            &apk_pins,
            &kernel_pins,
            &MissingDropbearProvider,
            &FakeTools::new(),
        )
        .unwrap_err();
        assert!(matches!(err, BuildError::Config(_)), "got {err:?}");
        assert!(
            !c.out_dir.exists(),
            "no outputs written when a required component is absent"
        );
    }

    /// Box migration of the (#[ignore]'d, preserved) NixOS `authorizedkeysfile_routing` sentries
    /// (`tests/openssh_authorized_keys_routing.rs`): the box re-establishes the SAME property — the
    /// operator's staged pubkey is the SOLE `authorized_keys` source — via a rootfs symlink, with NONE
    /// of NixOS's activation/tmpfiles/systemd write channels. Asserts `render_configs` routes
                                                                                
                                                           
    #[test]
    fn authorized_keys_routes_to_the_sole_persist_staged_source() {
        let staging = tempfile::tempdir().unwrap();
        render_configs(
            staging.path(),
            "box.example.org",
            None,
            &crate::config::sample_manifest(),
            7,
            1_700_000_042,
            None,
        )
        .unwrap();
        let link = staging.path().join("root/.ssh/authorized_keys");
        let meta = std::fs::symlink_metadata(&link).expect("authorized_keys present");
        assert!(
            meta.file_type().is_symlink(),
            "authorized_keys must be a symlink (the sole source lives on /persist, not the rootfs)"
        );
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            std::path::Path::new("/persist/etc/ssh/authorized_keys.d/root"),
            "routed to the operator-staged pubkey on /persist"
        );
    }

    /// The rootfs must carry the FHS mountpoint dirs (no alpine-baselayout ships them): the initramfs
    /// MS_MOVEs the API mounts onto /proc /sys /dev during switch_root, and the fstab + mount-persist
    /// target /run /tmp /persist /boot. A missing /proc was the switch_root ENOENT the boot-test caught.
    #[test]
    fn render_configs_creates_the_mountpoint_dirs() {
        let staging = tempfile::tempdir().unwrap();
        render_configs(
            staging.path(),
            "box.example.org",
            None,
            &crate::config::sample_manifest(),
            7,
            1_700_000_042,
            None,
        )
        .unwrap();
        for dir in ["proc", "sys", "dev", "run", "tmp", "persist", "boot"] {
            assert!(
                staging.path().join(dir).is_dir(),
                "/{dir} mountpoint dir must exist in the rootfs (switch_root MS_MOVE / fstab target)"
            );
        }
    }

                                                                                                        
    /// target at boot. The regression guard for the symlink emit — it is NOT in `REQUIRED_INIT_PATHS`
    /// (that const is write-looped as regular files by `FakeTools::build_init_tree`, and resolv.conf is a
    /// symlink). A creation failure already fails the build via `symlink_in`'s `?`.
    #[test]
    fn render_configs_emits_resolv_conf_symlink() {
        let staging = tempfile::tempdir().unwrap();
        render_configs(
            staging.path(),
            "box.example.org",
            None,
            &crate::config::sample_manifest(),
            7,
            1_700_000_042,
            None,
        )
        .unwrap();
        let link = staging.path().join("etc/resolv.conf");
        assert!(
            link.symlink_metadata().unwrap().file_type().is_symlink(),
            "/etc/resolv.conf must be a symlink (not a regular file)"
        );
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            std::path::Path::new("/run/resolv.conf")
        );
    }

    #[test]
    fn render_configs_bakes_recovery_pubkey_or_placeholder() {
                                                                                            
        let staging = tempfile::tempdir().unwrap();
        render_configs(
            staging.path(),
            "box.example.org",
            Some("ssh-ed25519 AAAATESTKEY operator@host"),
            &crate::config::sample_manifest(),
            7,
            1_700_000_042,
            None,
        )
        .unwrap();
        let baked =
            std::fs::read_to_string(staging.path().join("etc/ssh/recovery_authorized_keys"))
                .unwrap();
        assert_eq!(baked, "ssh-ed25519 AAAATESTKEY operator@host\n");

                                                                                                  
                                        
        let staging2 = tempfile::tempdir().unwrap();
        render_configs(
            staging2.path(),
            "box.example.org",
            None,
            &crate::config::sample_manifest(),
            7,
            1_700_000_042,
            None,
        )
        .unwrap();
        let placeholder =
            std::fs::read_to_string(staging2.path().join("etc/ssh/recovery_authorized_keys"))
                .unwrap();
        assert!(placeholder.starts_with("# operator recovery pubkey"));
        assert!(!placeholder.contains("ssh-ed25519"));
    }

    #[test]
    fn version_stamped_unconditional_and_crosschecked() {
                                                                                                     
                                                                                                        
                                                                                              
        const VER: u64 = 5;
        const CTR: u64 = 1_700_000_099;

                                                                                                   
                                                                                                     
                                                                                                      
                                                                   
        let staging = tempfile::tempdir().unwrap();
                                                                                                       
                                                                                                          
        let anchor = staging.path().join("artifact-root.pub");
        std::fs::write(&anchor, "ab".repeat(32) + "\n").unwrap();
        render_configs(
            staging.path(),
            "box.example.org",
            None,
            &crate::config::sample_manifest(),
            VER,
            CTR,
            Some(anchor.as_path()),
        )
        .unwrap();
        let rootfs_ver =
            std::fs::read_to_string(staging.path().join("etc/recipes/image-version")).unwrap();
        let rootfs_ctr =
            std::fs::read_to_string(staging.path().join("etc/recipes/min-delegation-ctr")).unwrap();
        assert_eq!(
            rootfs_ver,
            format!("{VER}\n"),
            "decimal u64 + LF (box .trim()s)"
        );
        assert_eq!(rootfs_ctr, format!("{CTR}\n"));
                                                                                             
        assert_eq!(
            std::fs::read_to_string(staging.path().join("etc/recipes/artifact-root.pub")).unwrap(),
            "ab".repeat(32) + "\n",
            "artifact-root.pub copied verbatim onto the rootfs (fb-update apply anchor)"
        );

                                                                                                   
                                           
        let rc = image::build_rootfs_component(&vec![0xAB; image::BLOCK_SIZE], &vec![0xCD; 512]);
        for fw in [Firmware::Seabios, Firmware::SeabiosGpt, Firmware::Uefi] {
            let (_img, layout) = image::assemble_img(
                &vec![0u8; image::BLOCK_SIZE],
                &vec![0u8; image::BLOCK_SIZE],
                &rc,
                None,
                fw,
                VER,
                CTR,
            );
            let toml = image::render_layout_toml(&layout);
            assert!(
                toml.contains(&format!("image_version = {VER}")),
                "{fw:?} sidecar missing image_version: {toml}"
            );
            assert!(
                toml.contains(&format!("min_delegation_ctr = {CTR}")),
                "{fw:?} sidecar missing min_delegation_ctr: {toml}"
            );
                                                                                                     
                                                             
            assert_eq!(layout.image_version.to_string(), rootfs_ver.trim());
            assert_eq!(layout.min_delegation_ctr.to_string(), rootfs_ctr.trim());
        }
    }
}
