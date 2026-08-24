//! `build_tools_host.rs` — the production [`crate::build::BuildTools`] impl (Task 2.3-R.2).
//!
//! Each method shells out to the pinned Alpine build container (`crates/image-builder/Containerfile`)
//! via `docker run`, wrapping the validated argv builders ([`crate::squashfs`] /
//! [`crate::verity`] / [`crate::ima_evm`]) and `build-kernel.sh`. The orchestration LOGIC is
//! fake-tested in [`crate::build`]; this seam is integration-verified against the REAL container
                                                                                                  
//!
//! Container invariants: source trees are bind-mounted READ-ONLY (the build-env rule); only the
//! explicit output dirs are writable. Ownership is now explicit: the rootfs pack drops mksquashfs
//! `-all-root` for per-inode `m` pseudo-lines from the `OwnershipMap` (default `0:0`, manifest
//! exceptions non-`0:0`) + a `chown 0:0 /staging` for the root inode (which `-pf` cannot set); the
//! weights pack keeps `-all-root` (D1/F-1). IMA/EVM signing is NOW pure host-Rust
//! ([`crate::ima_evm_signer`], RFC-6979) emitting a mksquashfs `-pf` pseudo-file: no CAP_SYS_ADMIN, no
//! live `setxattr` (the xattr bytes are injected at pack). evmctl survives only as that signer's
//! differential-test oracle (`crate::ima_evm_signer`'s `#[ignore]`d in-container fidelity check).
//!
//! All seven `BuildTools` methods are wired + integration-verified against the real container
//! (the `#[ignore]`d tests below). `build_kernel`/`build_initramfs` require their inputs via
//! [`HostBuildTools::with_kernel`]/[`HostBuildTools::with_initramfs`] (the `deploy build` CLI arm,
//! R.3, populates them) and return an explicit `BuildError::Tool` if invoked unconfigured.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::build::{BuildError, BuildTools, KernelArtifacts, VerityArtifacts};
use crate::firmware::Firmware;
use crate::{ima_evm_signer, ownership, squashfs, verity};

/// Read a PEM certificate and return its DER bytes — `ima_evm_signer` derives the keyid from the
/// leaf cert's SubjectKeyIdentifier, and the ceremony writes `ima.crt` as PEM.
fn load_cert_der(path: &Path) -> Result<Vec<u8>, BuildError> {
    let pem = std::fs::read(path).map_err(|source| BuildError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let (_, parsed) = x509_parser::pem::parse_x509_pem(&pem).map_err(|e| BuildError::Tool {
        tool: "ima cert PEM",
        reason: format!("parse {}: {e}", path.display()),
    })?;
    Ok(parsed.contents)
}

/// Production build tools: shell out to the pinned Alpine container.
pub struct HostBuildTools {
    /// The pinned build-container image ref (a tag today; an `@sha256` digest after Task 2.3-R.4).
    pub image: String,
    /// The recipes repo root — bind-mounted READ-ONLY for the musl binary build (`build_binaries`);
    /// also locates `build-kernel.sh`.
    pub repo_root: PathBuf,
    /// Kernel-build inputs (`build_kernel`). `None` until set via [`HostBuildTools::with_kernel`];
    /// the `deploy build` CLI arm (R.3) populates them — methods other than `build_kernel` ignore them.
    pub kernel: Option<KernelInputs>,
    /// Initramfs-build inputs (`build_initramfs`). `None` until set via
    /// [`HostBuildTools::with_initramfs`]; the R.3 CLI arm populates them.
    pub initramfs: Option<InitramfsInputs>,
    /// The staged, pinned syslinux source tarball (`orchard prime` output) + its `[syslinux].sha256`
                                                                                                       
    /// + VBR). `None` until set via [`HostBuildTools::with_syslinux_source`]; only `bake_boot_fs` uses it.
    pub syslinux_source: Option<SyslinuxSource>,
                                                                                               
    /// [`HostBuildTools::with_pins`]; the bake entry populates them. `build_binaries`/`build_initramfs`/
    /// `build_init_tree` FETCH+VERIFY each pinned binary from the store instead of compiling it.
    pub store: Option<Box<dyn crate::artifact_store::ArtifactStore>>,
    pub pins: Option<crate::pin_manifest::PinManifest>,
}

/// The kernel-build inputs. `build_kernel` takes only `source_date_epoch` (the [`BuildTools`] trait),
/// so these live on the struct rather than the call. BASE_CONFIG is Alpine's `config-virt` extracted
/// from the pinned `linux-virt` apk (R.3 extracts it).
pub struct KernelInputs {
    /// The staged, pinned kernel source TARBALL (`orchard prime` output) — re-verified at
                                                                                             
    pub tarball: PathBuf,
    /// `pins.toml` `[kernel].sha256` — the consume gate. Required: no pin, no build.
    pub sha256: String,
    /// BASE_CONFIG: Alpine's `config-virt` (from the pinned `linux-virt` apk).
    pub base_config: PathBuf,
    /// HARDENING_FRAGMENT: the committed `kernel-hardening.config`.
    pub hardening_fragment: PathBuf,
    /// C3 SUBSTRATE_FRAGMENT: the committed per-substrate hardening fragment, ALWAYS merged after the
    /// shared one by `build-kernel.sh`. The caller (`build_image`) picks it from the firmware-derived
    /// substrate: `kernel-hardening-vpskvm.config` (force-DISABLES the USB host/storage stack the base
    /// ships — the disk transports SCSI/ATA/NVMe STAY, USB-only) for vps-kvm, `kernel-hardening-baremetal.config`
    /// (force-ENABLES the USB stack for USB-media boot) for bare-metal-uefi. `kernel-config-pins-<substrate>.toml`'s
    /// assert then holds by construction.
    pub substrate_fragment: PathBuf,
    /// CA_CERT: the operator CA cert → `CONFIG_SYSTEM_TRUSTED_KEYS` (`.builtin_trusted_keys`).
    pub ca_cert: PathBuf,
}

/// The staged, pinned syslinux source tarball + its `[syslinux].sha256` — the same
                                                               
pub struct SyslinuxSource {
    /// The staged `.tar.xz` (`orchard prime` output).
    pub tarball: PathBuf,
    /// `pins.toml` `[syslinux].sha256` — the consume gate.
    pub sha256: String,
}

/// Read a staged, pinned source tarball and extract a FRESH per-build tree from it, re-verifying the
                                                                                              
/// full-consumption assert, then `tar` unpack into a fresh empty dir. Returns the RAII `TempDir` (keep
/// it alive across the container run) + the inner top-level source dir to mount. Fail-closed: an absent
/// tarball or a pin mismatch aborts before any container runs (no `.img` byte).
///
/// The extraction dest sits INSIDE a 0700 holder tempdir so the primitive's temp-`.tar` (created in
                                                                                       
fn staged_source_tree(
    tarball: &Path,
    sha256: &str,
    ceiling: u64,
    what: &'static str,
) -> Result<(tempfile::TempDir, PathBuf), BuildError> {
    let xz = std::fs::read(tarball).map_err(|source| BuildError::Tool {
        tool: what,
        reason: format!(
            "staged source tarball not found at {} ({source}) — run `orchard prime` (or `make prime`) first",
            tarball.display()
        ),
    })?;
    let holder = tempfile::tempdir().map_err(|e| BuildError::Io {
        path: format!("{what} extract holder tempdir"),
        source: e,
    })?;
    let dest = holder.path().join("src");
    std::fs::create_dir(&dest).map_err(|e| BuildError::Io {
        path: dest.display().to_string(),
        source: e,
    })?;
    let (_verified, inner) = crate::sources::extract_verified_xz(&xz, sha256, ceiling, &dest)
        .map_err(|e| BuildError::Tool {
            tool: what,
            reason: format!("verify-at-consumption of {}: {e}", tarball.display()),
        })?;
    Ok((holder, inner))
}

/// The initramfs-build inputs: the IMA + EVM leaf cert DERs the kernel loads from the initramfs
/// `/etc/keys/x509_{ima,evm}.der` at boot (`IMA_LOAD_X509`/`EVM_LOAD_X509`), and the operator root
/// pubkey baked at `/etc/recipes/artifact-root.pub` (the restore verify anchor, C1). From `generate-keys`.
pub struct InitramfsInputs {
    /// The IMA leaf cert (DER) → initramfs `/etc/keys/x509_ima.der`.
    pub ima_cert_der: PathBuf,
    /// The EVM leaf cert (DER) → initramfs `/etc/keys/x509_evm.der`.
    pub evm_cert_der: PathBuf,
    /// The operator ed25519 ROOT pubkey (raw 64-char hex, `generate-keys`' `artifact-root.pub`) →
    /// initramfs `/etc/recipes/artifact-root.pub` — the restore-from tarball verify anchor read by
                                                                                                     
    pub artifact_root_pub: PathBuf,
}

/// One bind mount for a `docker run`: (host path, container path, read-only).
type Mount<'a> = (&'a Path, &'a str, bool);

impl HostBuildTools {
    pub fn new(image: impl Into<String>, repo_root: impl Into<PathBuf>) -> Self {
        Self {
            image: image.into(),
            repo_root: repo_root.into(),
            kernel: None,
            initramfs: None,
            syslinux_source: None,
            store: None,
            pins: None,
        }
    }

    /// Attach the kernel-build inputs (required before `build_kernel`).
    pub fn with_kernel(mut self, kernel: KernelInputs) -> Self {
        self.kernel = Some(kernel);
        self
    }

    /// Attach the initramfs-build inputs (required before `build_initramfs`).
    pub fn with_initramfs(mut self, initramfs: InitramfsInputs) -> Self {
        self.initramfs = Some(initramfs);
        self
    }

    /// Attach the staged, pinned syslinux source (tarball + `[syslinux].sha256`; required before
                                                            
    pub fn with_syslinux_source(mut self, src: SyslinuxSource) -> Self {
        self.syslinux_source = Some(src);
        self
    }

                                                                                                       
    /// `build_initramfs`/`build_init_tree` fetch their pinned binaries).
    pub fn with_pins(
        mut self,
        store: Box<dyn crate::artifact_store::ArtifactStore>,
        pins: crate::pin_manifest::PinManifest,
    ) -> Self {
        self.store = Some(store);
        self.pins = Some(pins);
        self
    }

                                                                                                 
    /// audited `bake_persist_skeleton` container shape parameterized, plus the restore-specific
    /// legs: the owner floor + per-entry `xargs -0 chown -h` from the staging parse's NUL spec,
    /// the fixed [`crate::build::RESTORE_BAKE_EPOCH`] on BOTH normalization legs, and the
                                                                                                
    /// the restore assembler's leg (the `orchard restore-image` verb), not an `orchard build`
    /// pipeline seam — nothing fakes it.
    ///
    /// Runs the DOUBLE-BAKE internally (two container runs, byte-compare) and fail-louds on
    /// divergence — the §3c determinism self-check; non-reproducible bytes never leave here.
    pub fn bake_restore_image(
        &self,
        staged: &crate::restore_image::StagedRestore,
        plan: crate::restore_image::SizePlan,
    ) -> Result<Vec<u8>, BuildError> {
        let a = self.bake_restore_image_once(staged, plan)?;
        let b = self.bake_restore_image_once(staged, plan)?;
        if a != b {
            return Err(BuildError::Tool {
                tool: "mke2fs (bake_restore_image)",
                reason: "double-bake divergence — two container bakes over the identical staged \
                         tree produced different bytes; the restore assembler must be \
                         deterministic (self-check), refusing to emit"
                    .into(),
            });
        }
        Ok(a)
    }

    /// One container bake over the staged tree (the double-bake's single leg).
    fn bake_restore_image_once(
        &self,
        staged: &crate::restore_image::StagedRestore,
        plan: crate::restore_image::SizePlan,
    ) -> Result<Vec<u8>, BuildError> {
        let spec_dir = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "bake_restore_image spec tempdir".into(),
            source: e,
        })?;
        std::fs::write(spec_dir.path().join("owners.nul"), &staged.owners_nul).map_err(|e| {
            BuildError::Io {
                path: "owners.nul".into(),
                source: e,
            }
        })?;
        let out = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "bake_restore_image out tempdir".into(),
            source: e,
        })?;
        let imgbuild = self.repo_root.join("crates/image-builder");
        let epoch = crate::build::RESTORE_BAKE_EPOCH.to_string();
        let (uid, gid) = staged.resolved_db_owner;
                                                                                         
                                                                                                  
                                                                                                  
                                                                                                 
                                                                                               
                                                                          
        let script = format!(
            "set -e
mkdir -p /work
cp -a /stage/. /work/
chown -R 0:0 /work/etc
chown 0:0 /work
chown -R {uid}:{gid} /work/{root}
cd /work && xargs -0 -n 2 chown -h -- < /spec/owners.nul
find /work -depth -exec touch -h -d @{epoch} {{}} +
MKE2FS_CONFIG=/imgbuild/mke2fs.conf mke2fs -t ext4 -F -q -b 4096 -L persist -U {uuid_fs} -E hash_seed={seed},lazy_itable_init=0,lazy_journal_init=0 -O ^has_journal -N {inodes} -d /work /out/restore.img {blocks}
chmod a+r /out/restore.img",
            root = staged.root,
            uuid_fs = crate::build::PERSIST_FS_UUID,
            seed = crate::build::BAKE_HASH_SEED,
            inodes = plan.inodes,
            blocks = plan.blocks,
        );
        self.docker_run(
            "mke2fs (bake_restore_image)",
            &[
                (staged.stage.path(), "/stage", true),
                (spec_dir.path(), "/spec", true),
                (imgbuild.as_path(), "/imgbuild", true),
                (out.path(), "/out", false),
            ],
            false,
            &[("SOURCE_DATE_EPOCH", epoch.as_str())],
            &["sh".to_string(), "-c".to_string(), script],
        )?;
        std::fs::read(out.path().join("restore.img")).map_err(|e| BuildError::Io {
            path: "restore.img".into(),
            source: e,
        })
    }

                                                                                                  
    /// binaries errors loud if `with_pins` was not called (no silent skip).
    fn pins_and_store(
        &self,
    ) -> Result<
        (
            &crate::pin_manifest::PinManifest,
            &dyn crate::artifact_store::ArtifactStore,
        ),
        BuildError,
    > {
        let pins = self.pins.as_ref().ok_or_else(|| BuildError::Tool {
            tool: "pinned-binary fetch",
            reason: "no consume-pins manifest configured — call HostBuildTools::with_pins".into(),
        })?;
        let store = self.store.as_deref().ok_or_else(|| BuildError::Tool {
            tool: "pinned-binary fetch",
            reason: "no artifact store configured — call HostBuildTools::with_pins".into(),
        })?;
        Ok((pins, store))
    }

    /// Run `argv` (argv[0] = the tool binary) inside the container; return captured stdout.
    /// Fail-closed: a non-zero exit (or a spawn failure) is a `BuildError::Tool` carrying stderr.
    fn docker_run(
        &self,
        tool: &'static str,
        mounts: &[Mount<'_>],
        cap_sys_admin: bool,
        envs: &[(&str, &str)],
        argv: &[String],
    ) -> Result<Vec<u8>, BuildError> {
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm"]);
                                                                                                  
                                                                                                     
                                                                                                      
                                                                                                  
                                                                                                    
        if cap_sys_admin {
            cmd.args(["--cap-add", "SYS_ADMIN"]);
        }
        for (host, cont, ro) in mounts {
            let spec = if *ro {
                format!("{}:{cont}:ro", host.display())
            } else {
                format!("{}:{cont}", host.display())
            };
            cmd.args(["-v", &spec]);
        }
        for (k, v) in envs {
            cmd.args(["-e", &format!("{k}={v}")]);
        }
        cmd.arg(&self.image);
        cmd.args(argv);
        let out = cmd.output().map_err(|e| BuildError::Tool {
            tool,
            reason: format!("spawn `docker run`: {e}"),
        })?;
        if !out.status.success() {
            return Err(BuildError::Tool {
                tool,
                reason: format!(
                    "exit {:?}: {}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            });
        }
        Ok(out.stdout)
    }

    /// Build the B1 syslinux template — the unpatched `ldlinux.sys` core + the VBR (`ldlinux.bss`) —
    /// from the pinned source tarball + the committed Alpine patches, via `build-syslinux-template.sh`
    /// in the container. Byte-reproducible (the script pins HEXDATE/DATE). No `CAP_SYS_ADMIN`. The
    /// script + patches + `mke2fs.conf` live in the repo (bind RO); the tarball is the one external
    /// input. Returns `(core, vbr)`. Used only by `bake_boot_fs`.
    fn build_syslinux_template(
        &self,
        source_date_epoch: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), BuildError> {
        let src = self
            .syslinux_source
            .as_ref()
            .ok_or_else(|| BuildError::Tool {
                tool: "make bios (build_syslinux_template)",
                reason:
                    "syslinux source not configured — call HostBuildTools::with_syslinux_source"
                        .into(),
            })?;
                                                                                                   
                                                                                       
        let (_src_tree, src_dir) = staged_source_tree(
            &src.tarball,
            &src.sha256,
            crate::sources::SYSLINUX_TAR_CEILING,
            "make bios (syslinux template)",
        )?;
        let out = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "build_syslinux_template out tempdir".into(),
            source: e,
        })?;
        let imgbuild = self.repo_root.join("crates/image-builder");
        let epoch = source_date_epoch.to_string();
        self.docker_run(
            "make bios (syslinux template)",
            &[
                                                                                                  
                                                               
                (src_dir.as_path(), "/syslinux-src", false),
                (imgbuild.as_path(), "/imgbuild", true),
                (out.path(), "/out", false),
            ],
            false,                                              
            &[
                ("SOURCE_DATE_EPOCH", epoch.as_str()),
                ("SYSLINUX_SRC", "/syslinux-src"),
                ("SYSLINUX_PATCHES", "/imgbuild/syslinux-patches"),
                ("OUT", "/out"),
            ],
            &[
                "sh".to_string(),
                "/imgbuild/build-syslinux-template.sh".to_string(),
            ],
        )?;
        let core = std::fs::read(out.path().join("ldlinux.sys")).map_err(|e| BuildError::Io {
            path: "ldlinux.sys (syslinux template core)".into(),
            source: e,
        })?;
        let vbr = std::fs::read(out.path().join("ldlinux.bss")).map_err(|e| BuildError::Io {
            path: "ldlinux.bss (syslinux template VBR)".into(),
            source: e,
        })?;
        Ok((core, vbr))
    }
}

/// The persist authorized-keys directory, relative to the persist filesystem root (0700 in the
/// baked image; the dir every skeleton stages even when no key is present).
pub(crate) const PERSIST_AUTHORIZED_KEYS_DIR: &str = "etc/ssh/authorized_keys.d";
/// The operator login key's path inside the persist filesystem. `pub`: the `orchard prod
/// --restore-from` preflight reads THIS path out of a staged restore image (via
/// `syslinux_install::read_file`) to cross-check the baked key against `--pubkey` — one shared
                                                                            
pub const PERSIST_AUTHORIZED_KEYS_PATH: &str = "etc/ssh/authorized_keys.d/root";

/// Stage the persist SKELETON SET into `stage_root` — the ONE definition both the build's
                                                                                                 
/// cannot drift between the two). Host-side, std-fs, unprivileged; ownership (root:root for this
/// subtree) is applied in-container by each caller's script. Empty pubkey ⇒ the dir only, no
/// `root` key file (the un-loginable-skeleton contract — mirrors the recovery-pubkey placeholder
/// so a bare build still produces a bootable persist).
pub(crate) fn stage_persist_skeleton(
    stage_root: &std::path::Path,
    operator_pubkey: &[u8],
) -> Result<(), BuildError> {
    use std::os::unix::fs::PermissionsExt;
    let akd = stage_root.join(PERSIST_AUTHORIZED_KEYS_DIR);
    std::fs::create_dir_all(&akd).map_err(|e| BuildError::Io {
        path: akd.display().to_string(),
        source: e,
    })?;
    std::fs::set_permissions(&akd, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        BuildError::Io {
            path: akd.display().to_string(),
            source: e,
        }
    })?;
    if !operator_pubkey.is_empty() {
        let rootkey = stage_root.join(PERSIST_AUTHORIZED_KEYS_PATH);
        std::fs::write(&rootkey, operator_pubkey).map_err(|e| BuildError::Io {
            path: rootkey.display().to_string(),
            source: e,
        })?;
        std::fs::set_permissions(&rootkey, std::fs::Permissions::from_mode(0o644)).map_err(
            |e| BuildError::Io {
                path: rootkey.display().to_string(),
                source: e,
            },
        )?;
    }
    Ok(())
}

impl BuildTools for HostBuildTools {
                                                                                            
    /// [`crate::build::OS_BINS`] ∪ the manifest's tenant bins ([`crate::build::staged_usr_bin_names`] —
    /// `creatine`/`dha-orchestrator`/`epa` for a dha box). Orchard COMPILES none (not in its workspace);
    /// each is `fetch_verified` by its store key and dropped 0755 (a+rx) under `/usr/bin`, disjoint from
    /// the `/etc` subtree `render_configs` writes host-side, so root ownership blocks nothing.
    fn build_binaries(
        &self,
        staging: &Path,
        manifest: &fb_manifest::ValidatedManifest,
        extra_bins: &[&str],
    ) -> Result<(), BuildError> {
                                                                                                          
                                                                                                    
                                                                                                         
                                                                                                
        let (pins, store) = self.pins_and_store()?;
        let bin_dir = staging.join("usr/bin");
        std::fs::create_dir_all(&bin_dir).map_err(|e| BuildError::Io {
            path: bin_dir.display().to_string(),
            source: e,
        })?;
        let mut names = crate::build::staged_usr_bin_names(manifest);
        names.extend(extra_bins.iter().map(|s| s.to_string()));
        for name in names {
                                                                                                     
                                              
            let store_key = crate::build::bin_store_key(&name);
            let pin = pins.artifact(store_key)?;
            let verified = store.fetch_verified(store_key, &pin.sha256)?;
            let dest = bin_dir.join(&name);
            verified.write_to(&dest).map_err(|e| BuildError::Io {
                path: dest.display().to_string(),
                source: e,
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).map_err(
                    |e| BuildError::Io {
                        path: dest.display().to_string(),
                        source: e,
                    },
                )?;
            }
        }
        Ok(())
    }

                                                                                             
    /// [`crate::staged_files::stage_manifest_files`] with the configured (pins, store) — the SAME
    /// verify-at-consumption seam as [`Self::build_binaries`]; a missing/mismatched pin or a path-escape
                                                                                            
    fn stage_manifest_files(
        &self,
        staging: &Path,
        manifest: &fb_manifest::ValidatedManifest,
    ) -> Result<Vec<ownership::OwnerException>, BuildError> {
        let (pins, store) = self.pins_and_store()?;
        crate::staged_files::stage_manifest_files(staging, manifest, pins, store)
    }

    /// Compile the rambutan UEFI SB loader in-container (SB-loader plan Task 3.2). The per-build
    /// POLICY arrives as env consumed by rambutan's build.rs (fail-closed: an absent var panics
    /// the loader build; `RECIPES_LOADER_DEV` is never set here, so the dev escape cannot leak
    /// into a real artifact). The repo mounts RO; cargo writes to a separate target dir;
    /// `--locked` against rambutan's committed Cargo.lock. SOURCE_DATE_EPOCH + the crate's
    /// `/debug:none` link keep the PE byte-reproducible (the rambutan repro gate); NO post-link
                        
    fn build_efi_loader(
        &self,
        cmdline: &str,
        initrd_sha256_hex: &str,
        sb_required: bool,
        source_date_epoch: u64,
    ) -> Result<Vec<u8>, BuildError> {
        let target = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "build_efi_loader target tempdir".into(),
            source: e,
        })?;
        let epoch = source_date_epoch.to_string();
                                                                                                    
                                                                                                        
                                                                                                        
                                                                                                         
        let script = [
            "cd /repo/vendor/rambutan",
            "&& cargo build --release --locked --target x86_64-unknown-uefi",
            "&& cp /target/x86_64-unknown-uefi/release/rambutan.efi /target/rambutan-out.efi",
            "&& chmod a+r /target/rambutan-out.efi",
        ]
        .join(" ");
        self.docker_run(
            "cargo (build_efi_loader)",
            &[
                (self.repo_root.as_path(), "/repo", true),
                (target.path(), "/target", false),
            ],
            false,
            &[
                ("CARGO_TARGET_DIR", "/target"),
                ("CARGO_HOME", "/target/cargo-home"),
                ("RECIPES_LOADER_CMDLINE", cmdline),
                ("RECIPES_LOADER_INITRD_SHA256", initrd_sha256_hex),
                (
                    "RECIPES_LOADER_SB_REQUIRED",
                    if sb_required { "1" } else { "0" },
                ),
                ("SOURCE_DATE_EPOCH", epoch.as_str()),
            ],
            &["sh".to_string(), "-c".to_string(), script],
        )?;
        std::fs::read(target.path().join("rambutan-out.efi")).map_err(|e| BuildError::Io {
            path: "rambutan-out.efi (the built loader PE)".into(),
            source: e,
        })
    }

    /// Sign every regular file with the in-tree DETERMINISTIC signer ([`ima_evm_signer`], RFC-6979
    /// ECDSA) and render a mksquashfs `-pf` pseudo-file (`security.ima`/`security.evm` per file). This
    /// is **pure host-Rust** — it reads the staging files + the leaf key/cert and computes the xattr
    /// bytes in-process; the bytes are injected into the image at pack time (`pack_squashfs -pf`).
    /// Replacing the old `evmctl` setxattr step removes the build's only CAP_SYS_ADMIN requirement,
    /// and makes the sigs reproducible (evmctl's OpenSSL nonce was random). evmctl survives only as the
    /// fidelity oracle in `ima_evm_signer`'s differential test. Fail-closed: any read/parse/sign error
    /// (bad key, missing SKID, unsafe path) aborts the build before any `.img` write.
    fn ima_evm_xattr_pseudo(
        &self,
        staging: &Path,
        ima_key: &Path,
        ima_cert: &Path,
        owner_exceptions: &[ownership::OwnerException],
    ) -> Result<String, BuildError> {
        let key_pem = std::fs::read_to_string(ima_key).map_err(|source| BuildError::Io {
            path: ima_key.display().to_string(),
            source,
        })?;
        let cert_der = load_cert_der(ima_cert)?;
        let sign_err = |e: ima_evm_signer::SignError| BuildError::Tool {
            tool: "ima_evm_signer",
            reason: e.to_string(),
        };
        let signer = ima_evm_signer::ImaEvmSigner::new(&key_pem, &cert_der).map_err(sign_err)?;
                                                                                                   
                                                                                                    
                                                                                                     
                                
        let map = ownership::OwnershipMap::build(staging, owner_exceptions).map_err(|e| {
            BuildError::Tool {
                tool: "ownership_map",
                reason: e.to_string(),
            }
        })?;
        ima_evm_signer::pseudo_manifest(staging, &signer, &map).map_err(sign_err)
    }

    /// Build the custom kernel via the validated `build-kernel.sh` (run in the container): merge
    /// BASE_CONFIG + the hardening fragment, `olddefconfig`, embed the operator CA cert into
    /// `CONFIG_SYSTEM_TRUSTED_KEYS`, `make bzImage`. KSRC mounts RW (the script `mrproper`s + builds
    /// in-tree); config/fragment/CA + the script mount RO; bzImage + .config copy to a writable out
    /// dir (root-written → `chmod a+r` for the host read). `build()` then `assert_kernel_config`s the
    /// returned `.config` against the pins (the R8 silent-drop guard).
    fn build_kernel(
        &self,
        source_date_epoch: u64,
        frandom_seed_hex: &str,
    ) -> Result<KernelArtifacts, BuildError> {
        let k = self.kernel.as_ref().ok_or_else(|| BuildError::Tool {
            tool: "make (build_kernel)",
            reason: "kernel inputs not configured — call HostBuildTools::with_kernel".into(),
        })?;
                                                                                                   
                                                    
        let (_src_tree, src_dir) = staged_source_tree(
            &k.tarball,
            &k.sha256,
            crate::sources::KERNEL_TAR_CEILING,
            "make (build_kernel)",
        )?;
        let script = self.repo_root.join("crates/image-builder/build-kernel.sh");
        let out = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "build_kernel out tempdir".into(),
            source: e,
        })?;
        let epoch = source_date_epoch.to_string();
        let cmd = [
            "sh /build-kernel.sh",
            "&& cp /ksrc/arch/x86/boot/bzImage /out/bzImage",
            "&& cp /ksrc/.config /out/dotconfig",
            "&& chmod a+r /out/bzImage /out/dotconfig",
        ]
        .join(" ");
        let mut mounts: Vec<Mount<'_>> = vec![
                                                                                          
                                                                                         
                                                                                                 
                                      
            (src_dir.as_path(), "/ksrc", false),
            (k.base_config.as_path(), "/base.config", true),
            (k.hardening_fragment.as_path(), "/hardening.config", true),
            (k.ca_cert.as_path(), "/ca.pem", true),
            (script.as_path(), "/build-kernel.sh", true),
            (out.path(), "/out", false),
        ];
        let mut envs: Vec<(&str, &str)> = vec![
            ("KSRC", "/ksrc"),
            ("BASE_CONFIG", "/base.config"),
            ("HARDENING_FRAGMENT", "/hardening.config"),
            ("CA_CERT", "/ca.pem"),
            ("SOURCE_DATE_EPOCH", epoch.as_str()),
            ("FRANDOM_SEED", frandom_seed_hex),
        ];
                                                                                                             
                                                                                              
                                                                                                              
        mounts.push((k.substrate_fragment.as_path(), "/substrate.config", true));
        envs.push(("SUBSTRATE_FRAGMENT", "/substrate.config"));
        self.docker_run(
            "make",
            &mounts,
            false,
            &envs,
            &["sh".to_string(), "-c".to_string(), cmd],
        )?;
        let vmlinuz = std::fs::read(out.path().join("bzImage")).map_err(|e| BuildError::Io {
            path: "bzImage".into(),
            source: e,
        })?;
        let dot_config =
            std::fs::read_to_string(out.path().join("dotconfig")).map_err(|e| BuildError::Io {
                path: ".config".into(),
                source: e,
            })?;
        Ok(KernelArtifacts {
            vmlinuz,
            dot_config,
        })
    }

                                                                                               
                                                                                              
                                                                                

    /// `mksquashfs <staging> <out> -comp xz -xattrs -no-fragments -mkfs-time E -fstime E` with
    /// `Ownership::Map` (per-inode `m` pseudo-lines from the `OwnershipMap`, NOT `-all-root` — spec
    /// D1/F-1). mksquashfs cannot set the ROOT inode's owner via `-pf` (`/ m …` is rejected — verified
    /// empirically), so a non-recursive `chown 0:0 /staging` forces the root to `0:0` (what `-all-root`
    /// did for it, required for D5 byte-identity); the original owner is captured + restored after the
    /// pack so the host staging tempdir's RAII cleanup is unchanged. Every non-root inode's owner comes
    /// from its `m` line (default `0:0`), so staging ownership is irrelevant for them (D3/F-9).
    /// R.4: `-mkfs-time`/`-fstime` fix only the SUPERBLOCK timestamps, NOT per-inode mtimes — and a
    /// fresh staging tree carries wall-clock mtimes (apk extract / cargo / config render), which
                                                                                               
    /// differed ONLY in mtimes, content byte-identical). So first clamp every staged file's mtime to
    /// `SOURCE_DATE_EPOCH` (`touch -h -d`, mirroring `build_initramfs`) — hence staging mounts RW.
    /// The clamp runs AFTER IMA/EVM signing (build() order) and is safe: IMA signs file CONTENT, and
    /// portable EVM covers uid/gid/mode + the `security.ima` xattr — neither is mtime. Output to a
    /// writable scratch mount; packed bytes read back. (SYS_ADMIN not added — reading `security.*`
    /// xattrs needs no capability.)
    fn pack_squashfs(
        &self,
        staging: &Path,
        source_date_epoch: u64,
        xattr_pseudo: &str,
    ) -> Result<Vec<u8>, BuildError> {
        let out_dir = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "pack_squashfs out tempdir".into(),
            source: e,
        })?;
                                                                                                        
                                                                                                        
                                                                                                     
                                                                                                   
                                                                                      
        let pseudo_dir = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "pack_squashfs pseudo tempdir".into(),
            source: e,
        })?;
        let pseudo_path = pseudo_dir.path().join("xattr.pseudo");
        let mut mounts: Vec<(&Path, &str, bool)> = vec![
            (staging, "/staging", false),
            (out_dir.path(), "/out", false),
        ];
        let pf = if xattr_pseudo.is_empty() {
            None
        } else {
            std::fs::write(&pseudo_path, xattr_pseudo).map_err(|e| BuildError::Io {
                path: pseudo_path.display().to_string(),
                source: e,
            })?;
            mounts.push((pseudo_path.as_path(), "/xattr.pseudo", true));
            Some(Path::new("/xattr.pseudo"))
        };
                                                                                                  
                                                                                                 
                                                                                                    
                                                                                                   
                                                                                                   
        let cmd = squashfs::pack_shell_cmd(
            Path::new("/staging"),
            Path::new("/out/rootfs.sqfs"),
            source_date_epoch,
            squashfs::Ownership::Map,
            pf,
        );
        self.docker_run(
            "mksquashfs",
            &mounts,
            false,
            &[],
            &["sh".to_string(), "-c".to_string(), cmd],
        )?;
        let out_path = out_dir.path().join("rootfs.sqfs");
        std::fs::read(&out_path).map_err(|e| BuildError::Io {
            path: out_path.display().to_string(),
            source: e,
        })
    }

    /// `veritysetup format --no-superblock --salt=<fixed> <data> <hash>`; parse the `Root hash:`
    /// line from stdout + read the hash-tree file. Deterministic via the fixed salt; superblock-less
    /// so the init's dm table reads the tree at the hash offset directly (BOOT-CRITICAL, QEMU 2026-05-28).
    fn build_verity(&self, squashfs: &[u8]) -> Result<VerityArtifacts, BuildError> {
        let work = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "build_verity work tempdir".into(),
            source: e,
        })?;
        let data_host = work.path().join("rootfs.sqfs");
        std::fs::write(&data_host, squashfs).map_err(|e| BuildError::Io {
            path: data_host.display().to_string(),
            source: e,
        })?;
                                                                                                
                                                                                                     
        let cmd = format!(
            "veritysetup {} && chmod a+r /work/verity.hash",
            verity::veritysetup_format_argv(
                Path::new("/work/rootfs.sqfs"),
                Path::new("/work/verity.hash"),
            )
            .join(" ")
        );
        let stdout = self.docker_run(
            "veritysetup",
            &[(work.path(), "/work", false)],
            false,
            &[],
            &["sh".to_string(), "-c".to_string(), cmd],
        )?;
        let text = String::from_utf8_lossy(&stdout);
        let root_hash = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("Root hash:"))
            .map(|h| h.trim().to_string())
            .ok_or_else(|| BuildError::Tool {
                tool: "veritysetup",
                reason: format!("no `Root hash:` line in output:\n{text}"),
            })?;
        let hash_path = work.path().join("verity.hash");
        let hash_tree = std::fs::read(&hash_path).map_err(|e| BuildError::Io {
            path: hash_path.display().to_string(),
            source: e,
        })?;
        Ok(VerityArtifacts {
            hash_tree,
            root_hash,
        })
    }

    /// dha Component E: pack the operator's weights GGUF into a deterministic single-file squashfs under
    /// the canonical name [`crate::models::MODEL_GGUF_NAME`] (`model.gguf`). NO IMA/EVM `-pf` pseudo — the
    /// weights are DATA `creatine` `read(2)`s, not an `execve` target the Option-C policy appraises;
    /// dm-verity ([`Self::build_verity`], mounted DEFAULT/opt-0 = EIO) is the integrity anchor. Mirrors
    /// [`Self::pack_squashfs`]'s proven determinism: copy the GGUF into a scratch staging dir, clamp every
    /// staged mtime to `SOURCE_DATE_EPOCH` (`-mkfs-time`/`-fstime` fix only the superblock, R.4), then
    /// `mksquashfs` → read the packed bytes back. The multi-GiB copy + in-`Vec` read are a build-host cost
    /// (forward-debt: stream the pack if the dha `.img` memory footprint bites). Boot-gate-proven, not host-TDD.
    fn pack_weights_squashfs(
        &self,
        gguf_path: &Path,
        mmproj_path: Option<&Path>,
        source_date_epoch: u64,
    ) -> Result<Vec<u8>, BuildError> {
        let staging = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "pack_weights_squashfs staging tempdir".into(),
            source: e,
        })?;
        let out_dir = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "pack_weights_squashfs out tempdir".into(),
            source: e,
        })?;
                                                                                              
                                                                                                         
                                                      
        let staged = staging.path().join(crate::models::MODEL_GGUF_NAME);
        std::fs::copy(gguf_path, &staged).map_err(|e| BuildError::Io {
            path: gguf_path.display().to_string(),
            source: e,
        })?;
                                                                                                      
                                                                                                      
                                                                                                 
                                                            
        if let Some(mmproj) = mmproj_path {
            let staged_mm = staging.path().join(crate::models::MMPROJ_GGUF_NAME);
            std::fs::copy(mmproj, &staged_mm).map_err(|e| BuildError::Io {
                path: mmproj.display().to_string(),
                source: e,
            })?;
        }
        let mounts: Vec<Mount<'_>> = vec![
            (staging.path(), "/staging", false),
            (out_dir.path(), "/out", false),
        ];
                                                                                                    
                                                                                                    
                                                                          
        let cmd = squashfs::pack_shell_cmd(
            Path::new("/staging"),
            Path::new("/out/weights.sqfs"),
            source_date_epoch,
            squashfs::Ownership::AllRoot,
            None,
        );
        self.docker_run(
            "mksquashfs",
            &mounts,
            false,
            &[],
            &["sh".to_string(), "-c".to_string(), cmd],
        )?;
        let out_path = out_dir.path().join("weights.sqfs");
        std::fs::read(&out_path).map_err(|e| BuildError::Io {
            path: out_path.display().to_string(),
            source: e,
        })
    }

    /// Build the initramfs cpio: the static PID-1 `/init` + the kernel-loaded IMA/EVM leaf certs +
    /// the mountpoints. `initramfs-init` is a SEPARATE workspace (panic=abort) built static via its
    /// own `+crt-static` `.cargo/config.toml` (early boot has no rootfs `.so`s). The leaf certs land
    /// at `/etc/keys/x509_{ima,evm}.der` — the kernel loads them onto `.ima`/`.evm` at boot via
    /// `IMA_LOAD_X509`/`EVM_LOAD_X509` (the CA in `.builtin_trusted_keys` only authorizes the link).
    /// Deterministic (R.4): sorted + `--owner 0:0` + `--renumber-inodes`/`--ignore-devno` fix every
    /// newc field except mtime, and `touch -h -d @SOURCE_DATE_EPOCH` (depth-first, below) pins mtime
    /// — so the cpio PACKAGING is byte-reproducible. The init-binary CONTENT reproducibility (the
    /// Rust build) is validated by the double-build gate; cross-machine path-remap is a further step.
    fn build_initramfs(&self, source_date_epoch: u64) -> Result<Vec<u8>, BuildError> {
        let inputs = self.initramfs.as_ref().ok_or_else(|| BuildError::Tool {
            tool: "cpio (build_initramfs)",
            reason: "initramfs inputs not configured — call HostBuildTools::with_initramfs".into(),
        })?;
                                                                                                      
                                                                                                        
                                         
        let (pins, store) = self.pins_and_store()?;
        let pin = pins.artifact("initramfs-init")?;
        let verified = store.fetch_verified("initramfs-init", &pin.sha256)?;
        let initbin = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "initramfs-init bin tempdir".into(),
            source: e,
        })?;
        let initbin_path = initbin.path().join("initramfs-init");
        verified
            .write_to(&initbin_path)
            .map_err(|e| BuildError::Io {
                path: initbin_path.display().to_string(),
                source: e,
            })?;
        let out = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "build_initramfs out tempdir".into(),
            source: e,
        })?;
        let epoch = source_date_epoch.to_string();
                                                                                                    
                                                                                                          
                                                                                                      
                                                                                                        
        let mbr_check = format!(
            "&& echo \"{}  /usr/share/syslinux/mbr.bin\" | sha256sum -c -",
            crate::build::MBR_BIN_SHA256
        );
                                                                                                         
                                                                                                  
                                                   
        let gptmbr_check = format!(
            "&& echo \"{}  /usr/share/syslinux/gptmbr.bin\" | sha256sum -c -",
            crate::build::GPTMBR_BIN_SHA256
        );
        let script = [
                                                                                                    
                                                                                     
            "set -e; set -o pipefail",
            "&& mkdir -p /iroot/etc/keys /iroot/etc/recipes /iroot/proc /iroot/sys /iroot/dev /iroot/sysroot",
            "&& mkdir -p /iroot/usr/share/syslinux",
                                                                                                  
                                                                                                  
                                                                                          
                                                                                                     
                                                                                             
                                                                                                  
                                                                                                 
                                                                                           
                                                                                         
            "&& mknod -m 600 /iroot/dev/console c 5 1 && mknod -m 666 /iroot/dev/null c 1 3",
            "&& cp /init-bin /iroot/init && chmod 0755 /iroot/init",                                                            
            "&& cp /ima.der /iroot/etc/keys/x509_ima.der",
            "&& cp /evm.der /iroot/etc/keys/x509_evm.der",
                                                                                                     
                                                                                                
            "&& cp /artifact-root.pub /iroot/etc/recipes/artifact-root.pub",
                                                                                                   
                                                                                           
            mbr_check.as_str(),
            "&& cp /usr/share/syslinux/mbr.bin /iroot/usr/share/syslinux/mbr.bin",
                                                                                                         
                                                                                                    
            gptmbr_check.as_str(),
            "&& cp /usr/share/syslinux/gptmbr.bin /iroot/usr/share/syslinux/gptmbr.bin",
            "&& cd /iroot",
                                                                                                
                                                                                                   
            "&& find . -mindepth 1 -depth -exec touch -h -d \"@$SOURCE_DATE_EPOCH\" {} +",
            "&& find . -mindepth 1 | LC_ALL=C sort | cpio -o -H newc --owner 0:0 --renumber-inodes --ignore-devno > /out/initramfs.cpio",
            "&& chmod a+r /out/initramfs.cpio",
        ]
        .join(" ");
        self.docker_run(
            "cpio",
            &[
                (initbin_path.as_path(), "/init-bin", true),
                (inputs.ima_cert_der.as_path(), "/ima.der", true),
                (inputs.evm_cert_der.as_path(), "/evm.der", true),
                (
                    inputs.artifact_root_pub.as_path(),
                    "/artifact-root.pub",
                    true,
                ),
                (out.path(), "/out", false),
            ],
            false,
            &[("SOURCE_DATE_EPOCH", epoch.as_str())],                             
            &["sh".to_string(), "-c".to_string(), script],
        )?;
        std::fs::read(out.path().join("initramfs.cpio")).map_err(|e| BuildError::Io {
            path: "initramfs.cpio".into(),
            source: e,
        })
    }

                                                                                             
                                                                              
                                                                                            
                                                                                             
                          

    /// readelf the DT_NEEDED sonames of every ELF in the staging rootfs (bind RO; NO execution —
    /// readelf reads headers only). Emits `(elf-relative-path, NEEDED sonames)`; non-ELF / static
    /// files contribute nothing. Feeds `check_no_pam_needed` + `check_link_completeness`. Replaces
    /// the old single-binary `ldd`, which resolved against the CONTAINER's libs rather than the
    /// staging rootfs (a false positive); the load-bearing presence guard remains
    /// `config::check_required_components`.
    fn collect_needed(&self, root: &Path) -> Result<Vec<(String, Vec<String>)>, BuildError> {
                                                                                                   
                                                                                                 
          
                                                                                                         
                                                                                                          
                                                                                                        
                                                                                                    
                                                                                                       
                                                                                                      
                                                                                                          
                                                                       
        let script = r#"cd /staging || exit 1
command -v readelf >/dev/null 2>&1 || { echo "readelf missing in the build container" >&2; exit 1; }
find . -type f | while IFS= read -r f; do
  n=$(readelf -d "$f" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | tr '\n' ' ')
  [ -n "$n" ] && printf '%s\t%s\n' "${f#./}" "$n"
done
exit 0"#;
        let argv = vec!["sh".to_string(), "-c".to_string(), script.to_string()];
        let out = self.docker_run("readelf", &[(root, "/staging", true)], false, &[], &argv)?;
        Ok(parse_readelf_needed(&String::from_utf8_lossy(&out)))
    }

                                                                                                      
    /// servicedir tree + the `.s6-svscan` handlers (`service_tree::write_servicedir_tree`) — the staging
    /// tree is host-owned, so these writes succeed; `-all-root` + the signer's hardcoded 0:0 normalize
    /// ownership at pack, only the file MODE feeds the EVM hash. Container-side: build `box-init` (the
    /// standalone panic=abort static-musl PID-1, its own workspace) with the container's pinned rust —
    /// version-coherent, mirroring `build_initramfs` — and stage it at `/usr/bin/box-init`. Then
    /// `busybox --install -s` creates the applet symlinks (rm/mkdir/mount/mountpoint/chown/…): the
    /// extract-only build ships only `/bin/busybox` + the apk's own few symlinks, so the rest are absent
    /// until this runs — and the run scripts + box-init's oneshots need them at runtime. The applets are
    /// symlinks the signer skips (`lstat`); the busybox they point at is signed. `/sbin/init` is a
    /// RELATIVE symlink → `../usr/bin/box-init` — relative so initramfs-init's pre-`switch_root`
    /// `.exists()` (which FOLLOWS the symlink) resolves it WITHIN `/sysroot`; an absolute target resolves
    /// against the initramfs root → false-negative "no init" (the boot regression, `7f909f3`). box-init
    /// is cp'd as root → chown'd to the build user so the host-side signer can `setxattr` it at step 8
    /// (ownership normalized at pack). NO `s6-rc-compile`/`s6-linux-init-maker` — both dropped with their
    /// subsystems. Fail-closed via the `set -e` chain. Integration-verified
    /// (`build_init_tree_assembles_servicedirs_and_box_init` below + the QEMU boot-to-services gate).
    fn build_init_tree(
        &self,
        staging: &Path,
        domain: &str,
        source_date_epoch: u64,
        manifest: &fb_manifest::ValidatedManifest,
        weights: crate::service_tree::EngineWeightsSetup,
    ) -> Result<(), BuildError> {
                                                                                                       
                                                                                                         
                                                                                                      
        crate::service_tree::write_servicedir_tree(
            staging,
            domain,
            source_date_epoch,
            manifest,
            weights,
        )
        .map_err(|source| BuildError::Io {
            path: "box-svc servicedir tree".into(),
            source,
        })?;
                                                                                                   
                                                                                             
                                                                                                       
                                                                                                      
                                                                                                        
                                                                                                      
                                                                                                    
                                                                                                       
                                                                                                        
                                                                                                
                                                                                                     
        let (pins, store) = self.pins_and_store()?;
        let pin = pins.artifact("box-init")?;
        let verified = store.fetch_verified("box-init", &pin.sha256)?;
        let binstage = tempfile::tempdir().map_err(|source| BuildError::Io {
            path: "box-init bin tempdir".into(),
            source,
        })?;
        let binpath = binstage.path().join("box-init");
        verified
            .write_to(&binpath)
            .map_err(|source| BuildError::Io {
                path: binpath.display().to_string(),
                source,
            })?;
        let owner = std::fs::metadata(staging).map_err(|source| BuildError::Io {
            path: staging.display().to_string(),
            source,
        })?;
        let (uid, gid) = (owner.uid(), owner.gid());
                                                                                               
                                                                                                   
                                                                                                    
                                                                                                          
                                                   
        let script = format!(
            "set -e && \
             mkdir -p /staging/usr/bin /staging/sbin && \
             cp /box-init-bin /staging/usr/bin/box-init && \
             chmod 0755 /staging/usr/bin/box-init && \
             chroot /staging /bin/busybox --install -s && \
             ln -sf ../usr/bin/box-init /staging/sbin/init && \
             chown {uid}:{gid} /staging/usr/bin/box-init"
        );
        self.docker_run(
            "box-init stage + init tree",
            &[
                (binpath.as_path(), "/box-init-bin", true),
                (staging, "/staging", false),
            ],
            false,
            &[],                                                                                     
            &["sh".to_string(), "-c".to_string(), script],
        )?;
        Ok(())
    }

    /// Bake the boot-fs (O3). Build the B1 template (container, no CAP) → prep the on-disk `ldlinux.sys`
    /// host-side → stage the geometry + `mke2fs -d` the ext4 mount-free (container, no CAP) → B1-patch
    /// `ldlinux.sys` + the VBR in place host-side. Zero `extlinux`, zero loop-mount, zero `CAP_SYS_ADMIN`.
    ///
                                                                                                   
    /// `/slot-a/*` layout with the loader home in `/slot-a`; `SeabiosGpt` stages the two-label layout —
    /// loader home `/syslinux/{ldlinux.sys,ldlinux.c32,extlinux.conf}`, kernels `/slot-a/{vmlinuz,
    /// initramfs}`, and an EMPTY `/slot-b/` dir at genesis (fb-update's staging target, R1-11).
    fn bake_boot_fs(
        &self,
        vmlinuz: &[u8],
        initramfs: &[u8],
        extlinux_conf: &str,
        firmware: Firmware,
        source_date_epoch: u64,
    ) -> Result<Vec<u8>, BuildError> {
                                                                    
        let (core, vbr) = self.build_syslinux_template(source_date_epoch)?;
                                                                                                    
        let ondisk_ldlinux = syslinux_install::prepare_ldlinux_sys(&core);

                                                                                                  
                                                                                                  
                                                                                                        
                                                                                                    
                                                                                                    
                                                                    
        let stage = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "bake_boot_fs stage tempdir".into(),
            source: e,
        })?;
        let two_label = matches!(firmware, Firmware::SeabiosGpt);
        let loader_home = if two_label { "syslinux" } else { "slot-a" };
                                                                                                    
                                                
        let slot_a = stage.path().join("slot-a");
        std::fs::create_dir_all(&slot_a).map_err(|e| BuildError::Io {
            path: slot_a.display().to_string(),
            source: e,
        })?;
        let home = stage.path().join(loader_home);
        std::fs::create_dir_all(&home).map_err(|e| BuildError::Io {
            path: home.display().to_string(),
            source: e,
        })?;
        for (dir, name, bytes) in [
            (&slot_a, "vmlinuz", vmlinuz),
            (&slot_a, "initramfs", initramfs),
            (&home, "extlinux.conf", extlinux_conf.as_bytes()),
            (&home, "ldlinux.sys", ondisk_ldlinux.as_slice()),
        ] {
            let p = dir.join(name);
            std::fs::write(&p, bytes).map_err(|e| BuildError::Io {
                path: p.display().to_string(),
                source: e,
            })?;
        }

        let out = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "bake_boot_fs out tempdir".into(),
            source: e,
        })?;
        let imgbuild = self.repo_root.join("crates/image-builder");
        let epoch = source_date_epoch.to_string();
        let blocks = crate::build::BOOT_FS_SIZE_BYTES / 4096;
                                                                                                       
                                                                                                       
                                                                                                           
                                                                                                              
        let genesis_slot_b = if two_label {
            "mkdir -p /work/slot-b\n"
        } else {
            ""
        };
        let script = format!(
            "set -e
mkdir -p /work
cp -a /stage/slot-a /work/
cp -a /stage/{loader_home} /work/
{genesis_slot_b}echo \"{c32sha}  /usr/share/syslinux/ldlinux.c32\" | sha256sum -c -
cp /usr/share/syslinux/ldlinux.c32 /work/{loader_home}/
ln -s {loader_home}/extlinux.conf /work/extlinux.conf
chown -R 0:0 /work
find /work -depth -exec touch -h -d @{epoch} {{}} +
MKE2FS_CONFIG=/imgbuild/mke2fs.conf mke2fs -t ext4 -F -q -b 4096 -U {uuid} -E hash_seed={seed},lazy_itable_init=0,lazy_journal_init=0 -O ^has_journal -d /work /out/boot.img {blocks}
chmod a+r /out/boot.img",
            c32sha = crate::build::LDLINUX_C32_SHA256,
            uuid = crate::build::BOOT_FS_UUID,
            seed = crate::build::BAKE_HASH_SEED,
        );
        self.docker_run(
            "mke2fs (bake_boot_fs)",
            &[
                (stage.path(), "/stage", true),
                (imgbuild.as_path(), "/imgbuild", true),
                (out.path(), "/out", false),
            ],
            false,                                                
            &[("SOURCE_DATE_EPOCH", epoch.as_str())],
            &["sh".to_string(), "-c".to_string(), script],
        )?;
        let mut bootfs =
            std::fs::read(out.path().join("boot.img")).map_err(|e| BuildError::Io {
                path: "boot.img".into(),
                source: e,
            })?;

                                                                                                     
                                                                                                         
        let geo = syslinux_install::Geometry {
            heads: 64,
            sectors: 32,
            hidden: 2048,
            total_sectors: crate::build::BOOT_FS_SIZE_BYTES / 512,
        };
        let install_dir = format!("/{loader_home}");
        syslinux_install::install_into_bootfs(&mut bootfs, &vbr, &install_dir, &geo).map_err(
            |e| BuildError::Tool {
                tool: "syslinux-install",
                reason: e.to_string(),
            },
        )?;
        Ok(bootfs)
    }

    /// Bake the UEFI ESP: a deterministic FAT16 image (= BOOT_FS_SIZE_BYTES) holding the THREE boot
    /// files (SB-loader plan L6): `/EFI/BOOT/BOOTX64.EFI` = the rambutan loader, `\vmlinuz` = the
    /// plain shared kernel, `\initrd` = the shared initramfs. Mount-free + no-CAP via mtools (NO
    /// dosfstools): `dd` a zeroed fixed-size image, `mformat` it FAT16 with a FIXED volume serial,
    /// `mmd` the dir tree, `mcopy` each file after clamping its mtime to SOURCE_DATE_EPOCH.
    /// Byte-reproducible (verified empirically: same epoch → byte-identical, different epoch → the
    /// FAT timestamps move). Fail-closed BEFORE any tool runs if the payload cannot fit the fixed
    /// boot-partition size (the GPT layout pins it; a runtime initrd is a few MiB). §9.5's signed-USB
    /// installer REUSES this same fixed-size 3-file ESP (its 2nd rambutan loader + the shared
    /// kernel/initrd); the hundreds-of-MB `box.img` rides the SEPARATE ext4 data partition
    /// ([`Self::bake_installer_data`]), never the ESP. `/in` mounts RW only so the throwaway staged
    /// copies can be `touch`ed.
    fn bake_esp(
        &self,
        loader: &[u8],
        vmlinuz: &[u8],
        initrd: &[u8],
        source_date_epoch: u64,
    ) -> Result<Vec<u8>, BuildError> {
                                                                                          
                                                                                            
                                       
        let payload = loader.len() + vmlinuz.len() + initrd.len();
        let budget = (crate::build::BOOT_FS_SIZE_BYTES as usize).saturating_sub(4 * 1024 * 1024);
        if payload > budget {
            return Err(BuildError::Tool {
                tool: "mformat (bake_esp)",
                reason: format!(
                    "ESP payload {payload} B (loader {} + vmlinuz {} + initrd {}) exceeds the \
                     {} B boot partition minus FAT overhead — the three boot files must fit the \
                     fixed GPT boot-partition size",
                    loader.len(),
                    vmlinuz.len(),
                    initrd.len(),
                    crate::build::BOOT_FS_SIZE_BYTES,
                ),
            });
        }
        let in_dir = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "bake_esp in tempdir".into(),
            source: e,
        })?;
        for (name, bytes) in [
            ("BOOTX64.EFI", loader),
            ("vmlinuz", vmlinuz),
            ("initrd", initrd),
        ] {
            std::fs::write(in_dir.path().join(name), bytes).map_err(|e| BuildError::Io {
                path: name.into(),
                source: e,
            })?;
        }
        let out = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "bake_esp out tempdir".into(),
            source: e,
        })?;
        let mib = crate::build::BOOT_FS_SIZE_BYTES / (1024 * 1024);
        let epoch = source_date_epoch.to_string();
        let script = format!(
            "set -e; \
             dd if=/dev/zero of=/out/esp.img bs=1M count={mib} status=none && \
             mformat -i /out/esp.img -v RECIPESESP -N deadbeef :: && \
             mmd -i /out/esp.img ::/EFI ::/EFI/BOOT && \
             touch -h -d @$SOURCE_DATE_EPOCH /in/BOOTX64.EFI /in/vmlinuz /in/initrd && \
             mcopy -i /out/esp.img /in/BOOTX64.EFI ::/EFI/BOOT/BOOTX64.EFI && \
             mcopy -i /out/esp.img /in/vmlinuz ::/vmlinuz && \
             mcopy -i /out/esp.img /in/initrd ::/initrd && \
             chmod a+r /out/esp.img"
        );
        self.docker_run(
            "mformat",
            &[(in_dir.path(), "/in", false), (out.path(), "/out", false)],
            false,
            &[("SOURCE_DATE_EPOCH", epoch.as_str())],
            &["sh".to_string(), "-c".to_string(), script],
        )?;
        std::fs::read(out.path().join("esp.img")).map_err(|e| BuildError::Io {
            path: "esp.img".into(),
            source: e,
        })
    }

    /// Bake the persist-skeleton (O3): a small `LABEL=persist` ext4 carrying the operator pubkey at
    /// `/etc/ssh/authorized_keys.d/root` (0644) under `authorized_keys.d` (0700), root-owned. mke2fs -d,
    /// no CAP. The box `resize2fs`-grows it on first boot. Hotswap v4: a `weights_record` stages the
    /// signed initial record at `weights/current` (0600 under `weights/` 0700, root-owned by the
    /// container `chown -R 0:0` like every skeleton inode) — the fb-weights boot read + swap floor.
    fn bake_persist_skeleton(
        &self,
        operator_pubkey: &[u8],
        source_date_epoch: u64,
        weights_record: Option<&[u8]>,
    ) -> Result<Vec<u8>, BuildError> {
        let stage = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "bake_persist_skeleton stage tempdir".into(),
            source: e,
        })?;
                                                                                                      
                                                                                      
        stage_persist_skeleton(stage.path(), operator_pubkey)?;
        if let Some(record) = weights_record {
            use std::os::unix::fs::PermissionsExt;
            let wdir = stage.path().join("weights");
            std::fs::create_dir_all(&wdir).map_err(|e| BuildError::Io {
                path: wdir.display().to_string(),
                source: e,
            })?;
            std::fs::set_permissions(&wdir, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| BuildError::Io {
                    path: wdir.display().to_string(),
                    source: e,
                },
            )?;
            let current = wdir.join("current");
            std::fs::write(&current, record).map_err(|e| BuildError::Io {
                path: current.display().to_string(),
                source: e,
            })?;
            std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| BuildError::Io {
                    path: current.display().to_string(),
                    source: e,
                },
            )?;
        }

        let out = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "bake_persist_skeleton out tempdir".into(),
            source: e,
        })?;
        let imgbuild = self.repo_root.join("crates/image-builder");
        let epoch = source_date_epoch.to_string();
        let blocks = crate::build::PERSIST_SKELETON_SIZE_BYTES / 4096;
        let script = format!(
            "set -e
mkdir -p /work
cp -a /stage/. /work/
chown -R 0:0 /work
find /work -depth -exec touch -h -d @{epoch} {{}} +
MKE2FS_CONFIG=/imgbuild/mke2fs.conf mke2fs -t ext4 -F -q -b 4096 -L persist -U {uuid} -E hash_seed={seed},lazy_itable_init=0,lazy_journal_init=0 -O ^has_journal -d /work /out/persist.img {blocks}
chmod a+r /out/persist.img",
            uuid = crate::build::PERSIST_FS_UUID,
            seed = crate::build::BAKE_HASH_SEED,
        );
        self.docker_run(
            "mke2fs (bake_persist_skeleton)",
            &[
                (stage.path(), "/stage", true),
                (imgbuild.as_path(), "/imgbuild", true),
                (out.path(), "/out", false),
            ],
            false,
            &[("SOURCE_DATE_EPOCH", epoch.as_str())],
            &["sh".to_string(), "-c".to_string(), script],
        )?;
        std::fs::read(out.path().join("persist.img")).map_err(|e| BuildError::Io {
            path: "persist.img".into(),
            source: e,
        })
    }

    fn bake_installer_data(
        &self,
        box_img: &[u8],
        box_layout_toml: &[u8],
        source_date_epoch: u64,
    ) -> Result<Vec<u8>, BuildError> {
        let stage = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "bake_installer_data stage tempdir".into(),
            source: e,
        })?;
        std::fs::write(stage.path().join("box.img"), box_img).map_err(|e| BuildError::Io {
            path: "box.img".into(),
            source: e,
        })?;
        std::fs::write(stage.path().join("box.layout.toml"), box_layout_toml).map_err(|e| {
            BuildError::Io {
                path: "box.layout.toml".into(),
                source: e,
            }
        })?;

        let out = tempfile::tempdir().map_err(|e| BuildError::Io {
            path: "bake_installer_data out tempdir".into(),
            source: e,
        })?;
        let imgbuild = self.repo_root.join("crates/image-builder");
        let epoch = source_date_epoch.to_string();
                                                                                                     
                                                                                                          
                                                                                             
        let payload = box_img.len() + box_layout_toml.len();
        let fs_bytes = payload + payload / 16 + 16 * 1024 * 1024;
        let blocks = fs_bytes.div_ceil(4096);
        let script = format!(
            "set -e
mkdir -p /work
cp -a /stage/. /work/
chown -R 0:0 /work
find /work -depth -exec touch -h -d @{epoch} {{}} +
MKE2FS_CONFIG=/imgbuild/mke2fs.conf mke2fs -t ext4 -F -q -b 4096 -U {uuid} -E hash_seed={seed},lazy_itable_init=0,lazy_journal_init=0 -O ^has_journal -d /work /out/data.img {blocks}
chmod a+r /out/data.img",
            uuid = crate::build::INSTALLER_DATA_FS_UUID,
            seed = crate::build::BAKE_HASH_SEED,
        );
        self.docker_run(
            "mke2fs (bake_installer_data)",
            &[
                (stage.path(), "/stage", true),
                (imgbuild.as_path(), "/imgbuild", true),
                (out.path(), "/out", false),
            ],
            false,
            &[("SOURCE_DATE_EPOCH", epoch.as_str())],
            &["sh".to_string(), "-c".to_string(), script],
        )?;
        std::fs::read(out.path().join("data.img")).map_err(|e| BuildError::Io {
            path: "data.img".into(),
            source: e,
        })
    }
}

/// Parse `collect_needed`'s container output — lines `<relpath>\t<soname> <soname> …` — into
/// `(elf, NEEDED sonames)`. Pure; unit-tested offline (the container readelf step is integration-
/// tested). A line with no sonames is dropped.
fn parse_readelf_needed(text: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some((path, sonames)) = line.split_once('\t') {
            let sonames: Vec<String> = sonames.split_whitespace().map(String::from).collect();
            if !sonames.is_empty() {
                out.push((path.to_string(), sonames));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE: &str = "recipes-imgbuild:dev";

                                                                                                                 

    /// A valid single-topdir `.tar.xz` carrying `linux-9.9/Makefile` (built in-test, no committed
    /// binary) + its sha256.
    fn kernel_tarball_fixture() -> (Vec<u8>, String) {
        use sha2::{Digest, Sha256};
        let tar = {
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            let data = b"# fixture Makefile\n";
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(0);
            b.append_data(&mut h, "linux-9.9/Makefile", &data[..])
                .unwrap();
            b.into_inner().unwrap()
        };
        let mut enc = liblzma::write::XzEncoder::new(Vec::new(), 6);
        std::io::Write::write_all(&mut enc, &tar).unwrap();
        let xz = enc.finish().unwrap();
        let sha = hex::encode(Sha256::digest(&xz));
        (xz, sha)
    }

    #[test]
    fn staged_source_tree_extracts_fresh_per_call() {
        let (xz, sha) = kernel_tarball_fixture();
        let tmp = tempfile::tempdir().unwrap();
        let tarball = tmp.path().join("linux-9.9.tar.xz");
        std::fs::write(&tarball, &xz).unwrap();
        let (h1, inner1) =
            staged_source_tree(&tarball, &sha, crate::sources::KERNEL_TAR_CEILING, "t").unwrap();
        assert!(
            inner1.join("Makefile").is_file(),
            "the fresh tree carries the source"
        );
        let (h2, inner2) =
            staged_source_tree(&tarball, &sha, crate::sources::KERNEL_TAR_CEILING, "t").unwrap();
        assert_ne!(
            inner1, inner2,
            "each build gets its OWN throwaway extraction (RW-race closed by construction)"
        );
        drop((h1, h2));
    }

    #[test]
    fn staged_source_tree_refuses_an_absent_tarball() {
        let err = staged_source_tree(
            Path::new("/no/such/linux-9.9.tar.xz"),
            &"0".repeat(64),
            crate::sources::KERNEL_TAR_CEILING,
            "make (build_kernel)",
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("orchard prime") && msg.contains("/no/such/linux-9.9.tar.xz"),
            "an absent tarball names the path + the prime step, got: {msg}"
        );
    }

    #[test]
    fn staged_source_tree_refuses_a_tampered_tarball_and_leaves_no_tree() {
        let (mut xz, orig_sha) = kernel_tarball_fixture();
        let mid = xz.len() / 2;
        xz[mid] ^= 0xff;                                                      
        let tmp = tempfile::tempdir().unwrap();
        let tarball = tmp.path().join("linux-9.9.tar.xz");
        std::fs::write(&tarball, &xz).unwrap();
        let before = std::fs::read_dir(tmp.path()).unwrap().count();
        let err = staged_source_tree(
            &tarball,
            &orig_sha,
            crate::sources::KERNEL_TAR_CEILING,
            "make (build_kernel)",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("verify-at-consumption"),
            "a tampered tarball fails the consume gate, got: {err}"
        );
                                                                                                       
                              
        assert_eq!(
            std::fs::read_dir(tmp.path()).unwrap().count(),
            before,
            "a refused extraction leaves no tree behind"
        );
    }

    #[test]
    fn build_kernel_refuses_an_absent_staged_tarball_before_docker() {
                                                                                                     
                                           
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let tools = HostBuildTools::new(IMAGE, &repo_root).with_kernel(KernelInputs {
            tarball: "/no/such/linux-9.9.tar.xz".into(),
            sha256: "0".repeat(64),
            base_config: "/tmp/x".into(),
            hardening_fragment: "/tmp/x".into(),
            substrate_fragment: "/tmp/x".into(),
            ca_cert: "/tmp/x".into(),
        });
        let Err(err) = tools.build_kernel(1_700_000_000, &"ab".repeat(32)) else {
            panic!("an absent kernel tarball must fail the build");
        };
        assert!(
            err.to_string().contains("orchard prime"),
            "an absent kernel tarball names the prime step, got: {err}"
        );
    }

    #[test]
    fn build_syslinux_template_refuses_an_absent_staged_tarball_before_docker() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let tools = HostBuildTools::new(IMAGE, &repo_root).with_syslinux_source(SyslinuxSource {
            tarball: "/no/such/syslinux-9.9.tar.xz".into(),
            sha256: "0".repeat(64),
        });
        let err = tools.build_syslinux_template(1_700_000_000).unwrap_err();
        assert!(
            err.to_string().contains("orchard prime"),
            "an absent syslinux tarball names the prime step, got: {err}"
        );
    }

    /// Integration: `build_binaries` cross-compiles + stages the three in-image musl binaries.
                                                                                                
    /// binaries from the store (no compile) and stages each at `/usr/bin/<bin>`. Needs the populated
    /// store + `consume-pins.toml`, so `#[ignore]` (the boot-gate provides them). Asserts each is an ELF.
    #[test]
    #[ignore = "needs the populated artifact store; fetches + stages the pinned app binaries"]
    fn build_binaries_stages_three_musl_elf_bins() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let pins = crate::pin_manifest::PinManifest::load(&repo_root.join("consume-pins.toml"))
            .expect("load consume-pins.toml");
        let store: Box<dyn crate::artifact_store::ArtifactStore> = Box::new(
            crate::artifact_store::DirStore::new(repo_root.join("../artifact-store")),
        );
        let tools = HostBuildTools::new(IMAGE, &repo_root).with_pins(store, pins);
        let staging = tempfile::tempdir().unwrap();
                                                                                                           
                                                                                                         
        let manifest = fb_manifest::parse_and_validate(
            include_str!("../toy-tenant.toml"),
            &crate::config::os_identities(),
        )
        .expect("the toy manifest validates");
        tools
            .build_binaries(staging.path(), &manifest, &[])
            .unwrap();
        for bin in ["recipes", "recipes-admin", "fb-acme"] {
            let p = staging.path().join("usr/bin").join(bin);
            let bytes = std::fs::read(&p).unwrap_or_else(|e| panic!("{bin} not staged: {e}"));
            assert_eq!(&bytes[0..4], b"\x7fELF", "{bin} is an ELF binary");
        }
    }

    /// Integration (SB-loader plan Task 3.2 seam): `build_efi_loader` compiles the rambutan PE
    /// in-container with the policy baked — the produced PE EMBEDS the exact cmdline string
    /// (efi_main consumes the const, so it lives in .rdata), and an identical-input rebuild is
    /// byte-identical (the Task-1.8 repro property at the integration level, across the
    /// container boundary).
    #[test]
    #[ignore = "needs docker + the container; two cold loader builds"]
    fn build_efi_loader_bakes_the_cmdline_and_is_reproducible() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let tools = HostBuildTools::new(IMAGE, &repo_root);
        let cmdline = "ro seam-test-cmdline fb.root-hash=ab fb.verity-hash-offset=4096";
        let digest = "cd".repeat(32);
        let pe1 = tools
            .build_efi_loader(cmdline, &digest, true, 1_700_000_000)
            .expect("loader build A");
        assert_eq!(&pe1[0..2], b"MZ", "a PE/COFF image");
        let needle = cmdline.as_bytes();
        assert!(
            pe1.windows(needle.len()).any(|w| w == needle),
            "the baked cmdline must be embedded in the loader PE"
        );
        let pe2 = tools
            .build_efi_loader(cmdline, &digest, true, 1_700_000_000)
            .expect("loader build B");
        assert_eq!(
            pe1, pe2,
            "identical inputs must produce a byte-identical PE"
        );
    }

    /// rcgen P-256 leaf (PEM key + cert) for the signer tests. `ExplicitNoCa` is used ONLY because it
    /// emits a SubjectKeyIdentifier `keyid_from_skid` reads (wrapping-agnostic); it does NOT mirror
    /// production (generate-keys uses `NoCa`+custom-SKID+AKID — the kernel rejects ExplicitNoCa here).
    fn test_leaf_pem() -> (String, String) {
        let mut params =
            rcgen::CertificateParams::new(vec!["recipes-ima-test".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        (kp.serialize_pem(), cert.pem())
    }

    /// `ima_evm_xattr_pseudo` signs every regular file (PURE host-Rust — no container, no
    /// CAP_SYS_ADMIN) and renders the mksquashfs `-pf` pseudo-file. Determinism + framing fidelity vs
    /// the kernel live in `ima_evm_signer` (offline tests + the in-container evmctl differential
    /// oracle); here we verify the HostBuildTools wiring: key PEM + cert PEM → manifest, on the host.
    #[test]
    fn ima_evm_xattr_pseudo_signs_tree_host_side() {
        let (key_pem, cert_pem) = test_leaf_pem();
        let kd = tempfile::tempdir().unwrap();
        std::fs::write(kd.path().join("ima.key"), &key_pem).unwrap();
        std::fs::write(kd.path().join("ima.crt"), &cert_pem).unwrap();
        let staging = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(staging.path().join("usr/bin")).unwrap();
        std::fs::write(staging.path().join("usr/bin/recipes"), b"\x7fELFfake").unwrap();
        let tools = HostBuildTools::new(IMAGE, ".");
        let manifest = tools
            .ima_evm_xattr_pseudo(
                staging.path(),
                &kd.path().join("ima.key"),
                &kd.path().join("ima.crt"),
                &[],
            )
            .expect("host-side signing succeeds");
        assert!(manifest.contains("/usr/bin/recipes x security.ima=0s"));
        assert!(manifest.contains("/usr/bin/recipes x security.evm=0s"));
    }

    /// Task 5: a manifest-declared owner exception threads through `ima_evm_xattr_pseudo` → the
    /// `OwnershipMap` → the pseudo's mode-first `m` line for the declared owner, and the file is still
    /// signed (as that owner). Proves the whole host-side seam from the exception list to the `-pf`.
    #[test]
    fn ima_evm_xattr_pseudo_bakes_declared_owner_exception() {
        use std::os::unix::fs::PermissionsExt;
        let (key_pem, cert_pem) = test_leaf_pem();
        let kd = tempfile::tempdir().unwrap();
        std::fs::write(kd.path().join("ima.key"), &key_pem).unwrap();
        std::fs::write(kd.path().join("ima.crt"), &cert_pem).unwrap();
        let staging = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(staging.path().join("etc")).unwrap();
        let cfg = staging.path().join("etc/box.json");
        std::fs::write(&cfg, b"{}").unwrap();
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o600)).unwrap();
        let tools = HostBuildTools::new(IMAGE, ".");
        let exceptions = [ownership::OwnerException {
            rel_path: "etc/box.json".into(),
            uid: 5000,
            gid: 5000,
        }];
        let pseudo = tools
            .ima_evm_xattr_pseudo(
                staging.path(),
                &kd.path().join("ima.key"),
                &kd.path().join("ima.crt"),
                &exceptions,
            )
            .expect("host-side signing with an owner exception");
                                                                     
        assert!(
            pseudo.contains("/etc/box.json m 600 5000 5000"),
            "declared owner m line:\n{pseudo}"
        );
                                                                   
        assert!(
            pseudo.contains("/etc/box.json x security.ima=0s"),
            "still signed:\n{pseudo}"
        );
    }

    /// Fail-closed: an unparseable IMA key aborts (`BuildError::Tool`) before any image is produced.
    #[test]
    fn ima_evm_xattr_pseudo_fails_closed_on_bad_key() {
        let (_k, cert_pem) = test_leaf_pem();
        let kd = tempfile::tempdir().unwrap();
        std::fs::write(kd.path().join("ima.key"), b"not a real key").unwrap();
        std::fs::write(kd.path().join("ima.crt"), &cert_pem).unwrap();
        let staging = tempfile::tempdir().unwrap();
        std::fs::write(staging.path().join("f"), b"x").unwrap();
        let tools = HostBuildTools::new(IMAGE, ".");
        let err = tools
            .ima_evm_xattr_pseudo(
                staging.path(),
                &kd.path().join("ima.key"),
                &kd.path().join("ima.crt"),
                &[],
            )
            .expect_err("must fail closed on an unloadable key");
        assert!(matches!(err, BuildError::Tool { .. }), "got {err:?}");
    }

    /// Integration: `build_kernel` produces a real bzImage whose `.config` carries the pins. Runs
    /// the full kernel compile (slow), so `#[ignore]`. Requires staged inputs: config-virt at
    /// /tmp/recipes-kconfig (apk add linux-virt=6.18.34-r0), ca.pem at /tmp/recipes-ca (openssl),
    /// the staged kernel tarball at /tmp/recipes-kbuild/linux-<version>.tar.xz (`orchard prime`).
    #[test]
    #[ignore = "needs docker + staged kernel inputs; runs the full kernel build (slow)"]
    fn build_kernel_produces_a_real_bzimage() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let crate_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root_pins = crate::pins::Pins::load(&repo_root).unwrap();
        let kernel = KernelInputs {
            tarball: root_pins.kernel_tarball_path(std::path::Path::new("/tmp/recipes-kbuild")),
            sha256: root_pins.kernel.sha256.clone(),
            base_config: "/tmp/recipes-kconfig/config-virt".into(),
            hardening_fragment: crate_dir.join("kernel-hardening.config"),
            substrate_fragment: crate_dir.join("kernel-hardening-vpskvm.config"),
            ca_cert: "/tmp/recipes-ca/ca.pem".into(),
        };
        let tools = HostBuildTools::new(IMAGE, &repo_root).with_kernel(kernel);
        let k = tools
            .build_kernel(1_700_000_000, &"ab".repeat(32))
            .expect("kernel builds");
        assert!(
            k.vmlinuz.len() > 1_000_000,
            "bzImage is a real kernel, got {} bytes",
            k.vmlinuz.len()
        );
        assert!(
            k.dot_config.contains("CONFIG_IMA=y"),
            ".config carries the IMA pin"
        );
        assert!(
            k.dot_config.contains("# CONFIG_MODULES is not set"),
            ".config has MODULES=n (the hardening fragment)"
        );
    }

    /// Integration: `build_initramfs` fetches the pinned init + packs it with the leaf certs into a
    /// newc cpio. The cert DERs are opaque to this method (the kernel validates them at boot), so the
    /// test uses dummy DER bytes + checks the cpio carries `/init` + both `x509_*.der`. `#[ignore]`.
    #[test]
    #[ignore = "needs the populated store + docker; fetches the pinned init + packs the cpio"]
    fn build_initramfs_packs_init_and_leaf_certs() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let certdir = tempfile::tempdir().unwrap();
        std::fs::write(certdir.path().join("ima.der"), b"DER-IMA-LEAF").unwrap();
        std::fs::write(certdir.path().join("evm.der"), b"DER-EVM-LEAF").unwrap();
        std::fs::write(certdir.path().join("artifact-root.pub"), b"AA".repeat(32)).unwrap();
        let inputs = InitramfsInputs {
            ima_cert_der: certdir.path().join("ima.der"),
            evm_cert_der: certdir.path().join("evm.der"),
            artifact_root_pub: certdir.path().join("artifact-root.pub"),
        };
                                                                                                
                                                                                                     
                                                                          
        let pins = crate::pin_manifest::PinManifest::load(&repo_root.join("consume-pins.toml"))
            .expect("load consume-pins.toml");
        let store: Box<dyn crate::artifact_store::ArtifactStore> = Box::new(
            crate::artifact_store::DirStore::new(repo_root.join("../artifact-store")),
        );
        let tools = HostBuildTools::new(IMAGE, &repo_root)
            .with_initramfs(inputs)
            .with_pins(store, pins);
        let cpio = tools
            .build_initramfs(1_700_000_000)
            .expect("initramfs builds");
        assert_eq!(&cpio[0..6], b"070701", "newc cpio magic");
        let text = String::from_utf8_lossy(&cpio);
        assert!(text.contains("init"), "cpio carries /init");
        assert!(
            text.contains("x509_ima.der"),
            "cpio carries the IMA leaf cert"
        );
        assert!(
            text.contains("x509_evm.der"),
            "cpio carries the EVM leaf cert"
        );
        assert!(
            text.contains("artifact-root.pub"),
            "cpio carries the operator root pubkey (the restore verify anchor, C1)"
        );
        assert!(
            text.contains("syslinux/mbr.bin"),
            "cpio carries the SeaBIOS mbr.bin stage-1"
        );
        assert!(
            text.contains("gptmbr.bin"),
            "cpio carries the SeabiosGpt gptmbr.bin stage-1 (T7)"
        );
    }

                                                                                                      
    /// produce a BYTE-IDENTICAL cpio. Post-splice `build_initramfs` FETCHES the pinned `initramfs-init`
    /// from the store (no compile) and packs it + the leaf certs into the cpio with a fixed-mtime
    /// `touch -h -d @SOURCE_DATE_EPOCH`; the deterministic PACK of the fixed pinned init is what makes
    /// the initramfs reproducible (defense layer 8). The 2s gap advances the wall clock, so a leaked
    /// mtime would diverge. Needs the populated store; `#[ignore]` (packs twice, slow).
    #[test]
    #[ignore = "needs the populated store + docker; fetches the pinned init + packs the cpio twice"]
    fn build_initramfs_is_byte_reproducible() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let certdir = tempfile::tempdir().unwrap();
        std::fs::write(certdir.path().join("ima.der"), b"DER-IMA-LEAF").unwrap();
        std::fs::write(certdir.path().join("evm.der"), b"DER-EVM-LEAF").unwrap();
        std::fs::write(certdir.path().join("artifact-root.pub"), b"AA".repeat(32)).unwrap();
        let build = || {
            let pins = crate::pin_manifest::PinManifest::load(&repo_root.join("consume-pins.toml"))
                .expect("load consume-pins.toml");
            let store: Box<dyn crate::artifact_store::ArtifactStore> = Box::new(
                crate::artifact_store::DirStore::new(repo_root.join("../artifact-store")),
            );
            let inputs = InitramfsInputs {
                ima_cert_der: certdir.path().join("ima.der"),
                evm_cert_der: certdir.path().join("evm.der"),
                artifact_root_pub: certdir.path().join("artifact-root.pub"),
            };
            HostBuildTools::new(IMAGE, &repo_root)
                .with_initramfs(inputs)
                .with_pins(store, pins)
                .build_initramfs(1_700_000_000)
                .expect("initramfs builds")
        };
        let a = build();
        std::thread::sleep(std::time::Duration::from_secs(2));                          
        let b = build();
        assert_eq!(
            a, b,
            "two initramfs builds over identical inputs must be byte-identical"
        );
    }

    /// THE B1 GATE: the boot-fs bake is byte-reproducible. Two bakes over identical inputs (a 2s
    /// wall-clock gap between) must be byte-identical AND exactly `BOOT_FS_SIZE_BYTES`. Exercises the
    /// whole B1 chain end to end: build the syslinux template (pinned source + the 4 Alpine patches) →
    /// `prepare_ldlinux_sys` → `mke2fs -d` (no CAP) → `install_into_bootfs` (the patch). A green run is
    /// the determinism half of the Task-4 gate (the boot half is the QEMU disk-boot, Task 13).
    /// Requires the staged syslinux tarball at /tmp/recipes-syslinux/ (run `orchard prime`)
    /// + docker. SLOW (two template builds + two ext4 bakes).
    #[test]
    #[ignore = "needs docker + the syslinux tarball (`orchard prime`); bakes the boot-fs twice (slow)"]
    fn bake_boot_fs_is_byte_reproducible() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let root_pins = crate::pins::Pins::load(&repo_root).unwrap();
        let tarball =
            root_pins.syslinux_tarball_path(std::path::Path::new("/tmp/recipes-syslinux"));
        assert!(
            tarball.exists(),
            "run `orchard prime` first (expected {})",
            tarball.display()
        );
        let conf = crate::boot_fs::render_boot_fs_extlinux(
            &"de".repeat(32),
            8192,
            None,
            crate::firmware::Firmware::Seabios,
            None,
        );
        let build = || {
            HostBuildTools::new(IMAGE, &repo_root)
                .with_syslinux_source(SyslinuxSource {
                    tarball: tarball.clone(),
                    sha256: root_pins.syslinux.sha256.clone(),
                })
                .bake_boot_fs(
                    b"VMLINUZ-FIXTURE",
                    b"INITRAMFS-FIXTURE",
                    &conf,
                    crate::firmware::Firmware::Seabios,
                    1_700_000_000,
                )
                .expect("boot-fs bakes")
        };
        let a = build();
        std::thread::sleep(std::time::Duration::from_secs(2));                          
        let b = build();
        assert_eq!(
            a, b,
            "two boot-fs bakes over identical inputs must be byte-identical"
        );
        assert_eq!(
            a.len() as u64,
            crate::build::BOOT_FS_SIZE_BYTES,
            "the boot-fs is exactly the boot partition size"
        );
    }

    /// os-update A/B v1 T5: the seabios-gpt two-label boot-fs bakes byte-reproducibly AND with the
    /// right geometry on produced bytes — the loader home is `/syslinux/`, the active kernel is under
    /// `/slot-a/`, and an EMPTY `/slot-b/` directory exists at genesis (fb-update's staging target,
    /// R1-11) with NO slot-b files. Reads back through the same no-priv ext4 reader `fb-update` uses.
    /// Same docker + `orchard prime` prerequisites as the MBR gate.
    #[test]
    #[ignore = "needs docker + the syslinux tarball (`orchard prime`); bakes the boot-fs twice (slow)"]
    fn bake_boot_fs_seabios_gpt_two_label_geometry_is_reproducible() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let root_pins = crate::pins::Pins::load(&repo_root).unwrap();
        let tarball =
            root_pins.syslinux_tarball_path(std::path::Path::new("/tmp/recipes-syslinux"));
        assert!(
            tarball.exists(),
            "run `orchard prime` first (expected {})",
            tarball.display()
        );
        let conf = crate::boot_fs::render_boot_fs_extlinux(
            &"ab".repeat(32),
            8192,
            None,
            crate::firmware::Firmware::SeabiosGpt,
            None,
        );
        let build = || {
            HostBuildTools::new(IMAGE, &repo_root)
                .with_syslinux_source(SyslinuxSource {
                    tarball: tarball.clone(),
                    sha256: root_pins.syslinux.sha256.clone(),
                })
                .bake_boot_fs(
                    b"VMLINUZ-FIXTURE",
                    b"INITRAMFS-FIXTURE",
                    &conf,
                    crate::firmware::Firmware::SeabiosGpt,
                    1_700_000_000,
                )
                .expect("seabios-gpt boot-fs bakes")
        };
        let a = build();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let b = build();
        assert_eq!(a, b, "two seabios-gpt bakes must be byte-identical");
        assert_eq!(a.len() as u64, crate::build::BOOT_FS_SIZE_BYTES);

                                                                                                       
        let staged_conf = syslinux_install::read_file(&a, "syslinux/extlinux.conf")
            .expect("/syslinux/extlinux.conf");
        assert_eq!(
            staged_conf,
            conf.as_bytes(),
            "the two-label conf is staged verbatim"
        );
        syslinux_install::read_file(&a, "syslinux/ldlinux.sys")
            .expect("the loader lives in /syslinux");
                                                                                                     
                                                                                                   
        syslinux_install::read_file(&a, "slot-a/vmlinuz").expect("slot-a kernel present");
        assert!(
            syslinux_install::read_file(&a, "slot-b/vmlinuz").is_err(),
            "slot-b files must be absent at genesis"
        );
    }

                                                                                                       
    /// gate, despite the ESP carrying the whole UEFI `.img` determinism story). The FAT write via mtools
                                                                                                         
    /// proved both: without it the two ESPs differ, with it they are identical) — so this gate, with a 2s
    /// wall-clock gap between bakes, is exactly what catches a future mtools that drops SOURCE_DATE_EPOCH
                                                                                                  
    #[test]
    #[ignore = "needs docker; bakes the ESP twice (mtools FAT); run via make boot-gate (the -p recipes-image-builder --ignored sweep)"]
    fn bake_esp_is_byte_reproducible() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let build = || {
            HostBuildTools::new(IMAGE, &repo_root)
                .bake_esp(
                    b"LOADER-FIXTURE",
                    b"VMLINUZ-FIXTURE",
                    b"INITRAMFS-FIXTURE",
                    1_700_000_000,
                )
                .expect("ESP bakes")
        };
        let a = build();
        std::thread::sleep(std::time::Duration::from_secs(2));                          
        let b = build();
        assert_eq!(
            a, b,
            "two ESP bakes over identical inputs must be byte-identical (mtools must honor SOURCE_DATE_EPOCH)"
        );
        assert_eq!(
            a.len() as u64,
            crate::build::BOOT_FS_SIZE_BYTES,
            "the ESP is exactly the boot partition size"
        );
    }

    /// The persist-skeleton bake is byte-reproducible (root-owned inodes + fixed UUID/seed/times) and
    /// exactly `PERSIST_SKELETON_SIZE_BYTES`. Needs docker; SLOW-ish (two small ext4 bakes).
    #[test]
    #[ignore = "needs docker; bakes the persist-skeleton twice (slow-ish)"]
    fn bake_persist_skeleton_is_byte_reproducible() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let pubkey =
            b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEYTESTKEYTESTKEYTESTKEYTEST operator\n";
        let build = || {
            HostBuildTools::new(IMAGE, &repo_root)
                .bake_persist_skeleton(pubkey, 1_700_000_000, None)
                .expect("persist-skeleton bakes")
        };
        let a = build();
        std::thread::sleep(std::time::Duration::from_secs(2));                          
        let b = build();
        assert_eq!(
            a, b,
            "two persist-skeleton bakes over identical inputs must be byte-identical"
        );
        assert_eq!(
            a.len() as u64,
            crate::build::PERSIST_SKELETON_SIZE_BYTES,
            "the persist-skeleton is exactly PERSIST_SKELETON_SIZE_BYTES"
        );
    }

    #[test]
    fn stage_persist_skeleton_stages_the_audited_shape() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        stage_persist_skeleton(d.path(), b"PUBKEY\n").unwrap();
        let akd = d.path().join(PERSIST_AUTHORIZED_KEYS_DIR);
        let meta = std::fs::metadata(&akd).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o700);
        let key = d.path().join(PERSIST_AUTHORIZED_KEYS_PATH);
        assert_eq!(std::fs::read(&key).unwrap(), b"PUBKEY\n");
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o7777,
            0o644
        );
                                                                                             
        let d2 = tempfile::tempdir().unwrap();
        stage_persist_skeleton(d2.path(), b"").unwrap();
        assert!(d2.path().join(PERSIST_AUTHORIZED_KEYS_DIR).is_dir());
        assert!(!d2.path().join(PERSIST_AUTHORIZED_KEYS_PATH).exists());
    }

    /// Build a well-formed gz data tar for the restore bake tests: `(path, bytes, uid:gid 100)`
    /// entries via the normal Builder path (the fb-backup shape).
    #[cfg(test)]
    fn restore_test_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut b = tar::Builder::new(gz);
        for (path, bytes) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(bytes.len() as u64);
            h.set_mode(0o644);
            h.set_uid(100);
            h.set_gid(100);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            b.append_data(&mut h, path, *bytes).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    /// A deterministic, incompressible xorshift64 blob (the repro-gate pattern used across the
    /// bake tests) — high-entropy so neither gzip nor the fs layout can collapse it.
    #[cfg(test)]
    fn xorshift_blob(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        let mut blob = vec![0u8; len];
        for chunk in blob.chunks_mut(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            chunk.copy_from_slice(&x.to_le_bytes()[..chunk.len()]);
        }
        blob
    }

    /// The restore-image bake: deterministic (double-bake internal + a SECOND full call
    /// byte-identical), identity-checked (label/journal/magic), and the staged pubkey readable
    /// back out of the produced bytes via the SAME reader the ceremony preflight uses (§5-4
    /// proven on the real recipe output). Owner assertions on the BOOTED image ride the §6 gate
    /// (stat over SSH); bake-side, the owner SPEC is asserted from the staging parse.
    #[test]
    #[ignore = "produced-bytes: needs docker + recipes-imgbuild:dev; run via make boot-gate suite 1"]
    fn restore_image_bakes_deterministic_with_identity_and_owners() {
        use crate::restore_image::{
            check_restore_identity, plan_size, stage_restore, RestoreImageSpec,
        };
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
                                                                                            
                                                                                               
                                                                                        
        let blobs: Vec<Vec<u8>> = (0..5)
            .map(|i| xorshift_blob(16 << 20, 0x9E37_79B9_7F4A_7C15 ^ (i as u64)))
            .collect();
        let smalls: Vec<(String, Vec<u8>)> = (0..300)
            .map(|i| {
                (
                    format!("images/f{i}.txt"),
                    format!("small file {i}").into_bytes(),
                )
            })
            .collect();
        let mut entries: Vec<(&str, &[u8])> = vec![("sentinel.txt", b"SENTINEL-BYTES")];
        let blob_names: Vec<String> = (0..5).map(|i| format!("images/blob{i}.bin")).collect();
        for (i, name) in blob_names.iter().enumerate() {
            entries.push((name.as_str(), &blobs[i]));
        }
        for (name, bytes) in &smalls {
            entries.push((name.as_str(), bytes.as_slice()));
        }
        let tar_gz = restore_test_tar(&entries);
        let pubkey = b"ssh-ed25519 AAAARESTOREBAKEKEY gate@test\n";
        let spec = RestoreImageSpec {
            data_tar_gz: &tar_gz,
            db: b"SQLITE-FIXTURE-BYTES",
            operator_pubkey: pubkey,
            root: "recipes",
            db_target: "recipes.db",
            db_owner: None,
        };
        let staged = stage_restore(&spec).expect("stages");
        assert_eq!(staged.resolved_db_owner, (100, 100), "uniform tar derives");
        let spec_str = String::from_utf8_lossy(&staged.owners_nul).into_owned();
        assert!(spec_str.contains("100:100\0recipes/images/blob0.bin\0"));
        assert!(spec_str.contains("100:100\0recipes/recipes.db\0"));
        let plan = plan_size(staged.content_bytes, staged.file_count).expect("plans");

        let tools = HostBuildTools::new(IMAGE, &repo_root);
        let img = tools.bake_restore_image(&staged, plan).expect("bakes");
        assert_eq!(
            img.len() as u64,
            plan.blocks * 4096,
            "exactly the planned size"
        );
                                                                                      
        check_restore_identity(&img).expect("identity holds");
                                                                                                 
        let key = syslinux_install::read_file(
            &img,
            crate::build_tools_host::PERSIST_AUTHORIZED_KEYS_PATH,
        )
        .expect("staged key reads back");
        assert_eq!(key, pubkey);
                                                                                         
        let sentinel =
            syslinux_install::read_file(&img, "recipes/sentinel.txt").expect("sentinel reads");
        assert_eq!(sentinel, b"SENTINEL-BYTES");
                                                                                                 
                                                                                
        let img2 = tools
            .bake_restore_image(&staged, plan)
            .expect("bakes again");
        assert_eq!(img, img2, "cross-run determinism");
    }

                                                                                                   
    /// whose ratio-derived inode count would be exhausted) assembles because `-N` is explicit.
    #[test]
    #[ignore = "produced-bytes: inode-dense assembly (gate-proof); needs docker"]
    fn restore_image_assembles_inode_dense_content() {
        use crate::restore_image::{
            check_restore_identity, plan_size, stage_restore, RestoreImageSpec,
        };
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let files: Vec<(String, Vec<u8>)> = (0..5000)
            .map(|i| (format!("images/tiny{i}.dat"), vec![b'x'; 1024]))
            .collect();
        let entries: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let tar_gz = restore_test_tar(&entries);
        let spec = RestoreImageSpec {
            data_tar_gz: &tar_gz,
            db: b"DB",
            operator_pubkey: b"ssh-ed25519 AAAAK inode@test\n",
            root: "recipes",
            db_target: "recipes.db",
            db_owner: None,
        };
        let staged = stage_restore(&spec).expect("stages");
        let plan = plan_size(staged.content_bytes, staged.file_count).expect("plans");
        assert!(
            plan.inodes > 10_000,
            "inode demand is explicit ({} for {} entries) — the floor-class ratio (4096 B/inode \
             on a 16 MiB image = 4096 inodes) would have exhausted at ~4k files",
            plan.inodes,
            staged.file_count
        );
        let tools = HostBuildTools::new(IMAGE, &repo_root);
                                                                                               
        let img = tools
            .bake_restore_image(&staged, plan)
            .expect("inode-dense bake succeeds");
        check_restore_identity(&img).expect("identity holds");
    }

    /// One-off fixture emitter for syslinux-install's `read_file` positive test: bakes the persist
    /// skeleton with a KNOWN pubkey + epoch and writes `target/persist-fixture.img`, which is then
    /// `gzip -9`'d into `crates/syslinux-install/tests/fixtures/persist-skeleton-16m.img.gz`.
    /// Re-run this (then re-gzip) if the skeleton bake recipe ever changes — the committed fixture's
    /// provenance is documented in the consuming test (`read_file_reads_the_staged_pubkey_from_a_real_bake`).
    #[test]
    #[ignore = "needs docker; one-off emitter for the syslinux-install read_file fixture"]
    fn emit_persist_skeleton_fixture_for_syslinux_install() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let img = HostBuildTools::new(IMAGE, &repo_root)
            .bake_persist_skeleton(
                b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8lxt94RGN2sG/6ECF1NEO49z1nsPu61qOPl0dQ4HGJ restore-fixture@test\n",
                1_700_000_000,
                None,
            )
            .expect("persist-skeleton bakes");
        let out = repo_root.join("target/persist-fixture.img");
        std::fs::write(&out, &img).expect("fixture written");
        eprintln!("fixture written: {}", out.display());
    }

    /// Integration: the determinism-critical pair against the REAL container — real `mksquashfs`
    /// and `veritysetup`. Validates the docker-run plumbing AND the load-bearing reproducibility
    /// claims (squashfs bytes, verity root hash, hash-tree all stable over fixed inputs).
    /// Needs the `recipes-imgbuild:dev` container + docker; run with `--ignored`.
    #[test]
    #[ignore = "needs the recipes-imgbuild:dev container (docker); run with --ignored"]
    fn pack_squashfs_then_verity_is_reproducible_against_real_container() {
        let tools = HostBuildTools::new(IMAGE, ".");
        let staging = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(staging.path().join("etc")).unwrap();
        std::fs::write(staging.path().join("etc/hello"), b"recipes").unwrap();
        std::fs::write(staging.path().join("etc/fstab"), b"# fstab\n").unwrap();
                                                                                                      
                                                                                                         
                                                                                                       
                                                                                                     
                                                                                                   
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut blob = vec![0u8; 2 << 20];
        for chunk in blob.chunks_mut(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            chunk.copy_from_slice(&x.to_le_bytes()[..chunk.len()]);
        }
        std::fs::write(staging.path().join("etc/blob.bin"), &blob).unwrap();
                                                                                                   
                                                                                                    
                                                                                             
        let pseudo = "/etc/hello x security.ima=0saGVsbG8=\n";

        let sqfs = tools
            .pack_squashfs(staging.path(), 1_700_000_000, pseudo)
            .unwrap();
        assert!(!sqfs.is_empty());
        assert_eq!(&sqfs[0..4], b"hsqs", "squashfs superblock magic");

        let v = tools.build_verity(&sqfs).unwrap();
        assert_eq!(
            v.root_hash.len(),
            64,
            "sha256 verity root hash is 64 hex chars"
        );
        assert!(v.root_hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!v.hash_tree.is_empty());

                                                                                                     
                                                                                                  
                                                                                                  
                                                                                                    
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(98_765);
        for f in ["etc/hello", "etc/fstab", "etc/blob.bin"] {
            std::fs::File::options()
                .write(true)
                .open(staging.path().join(f))
                .unwrap()
                .set_modified(later)
                .unwrap();
        }
                                                                                               
                                                                                                      
                                                                                                       
                                                                                                    
                                                                                     
        std::fs::File::open(staging.path())
            .unwrap()
            .set_modified(later)
            .unwrap();
        let sqfs2 = tools
            .pack_squashfs(staging.path(), 1_700_000_000, pseudo)
            .unwrap();
        assert_eq!(
            sqfs, sqfs2,
            "squashfs reproducible despite perturbed mtimes — the clamp normalizes"
        );
        let v2 = tools.build_verity(&sqfs2).unwrap();
        assert_eq!(v.root_hash, v2.root_hash, "verity root hash reproducible");
        assert_eq!(
            v.hash_tree, v2.hash_tree,
            "verity hash-tree bytes reproducible"
        );
    }

    /// Integration: `collect_needed` readelf's every ELF's DT_NEEDED in a staging tree (the
    /// completeness + no-PAM guards' input). Stage a known dynamic musl binary + a non-ELF file.
    #[test]
    #[ignore = "needs the recipes-imgbuild:dev container (docker); run with --ignored"]
    fn collect_needed_reports_dynamic_elf_libs() {
        let tools = HostBuildTools::new(IMAGE, ".");
        let dir = tempfile::tempdir().unwrap();
        let bin_dir = dir.path().join("usr/bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let copy = Command::new("docker")
            .args(["run", "--rm", "-v"])
            .arg(format!("{}:/out", bin_dir.display()))
            .args([IMAGE, "cp", "/usr/bin/evmctl", "/out/evmctl"])
            .status()
            .unwrap();
        assert!(copy.success(), "stage a binary out of the container");
        std::fs::write(dir.path().join("etc-config"), b"not an elf").unwrap();

        let needed = tools.collect_needed(dir.path()).unwrap();
        let evmctl = needed
            .iter()
            .find(|(p, _)| p.ends_with("evmctl"))
            .expect("evmctl's NEEDED collected");
        assert!(!evmctl.1.is_empty(), "lists shared objects: {:?}", evmctl.1);
        assert!(
            evmctl.1.iter().all(|s| !s.contains("libpam")),
            "evmctl must not link PAM"
        );
        assert!(
            !needed.iter().any(|(p, _)| p.ends_with("etc-config")),
            "a non-ELF file contributes nothing"
        );
    }

    /// Offline (no container): the readelf-output parser splits path↔sonames and drops empty lines.
    #[test]
    fn parse_readelf_needed_splits_path_and_sonames() {
        let text = "usr/sbin/dropbear\tlibc.musl-x86_64.so.1 libutmps.so.0.1\n\
                    etc/config\t\n\
                    usr/sbin/haproxy\tlibssl.so.3\n";
        let parsed = parse_readelf_needed(text);
        assert_eq!(parsed.len(), 2, "the empty-sonames line is dropped");
        assert_eq!(
            parsed[0],
            (
                "usr/sbin/dropbear".to_string(),
                vec![
                    "libc.musl-x86_64.so.1".to_string(),
                    "libutmps.so.0.1".to_string()
                ]
            )
        );
        assert_eq!(
            parsed[1],
            (
                "usr/sbin/haproxy".to_string(),
                vec!["libssl.so.3".to_string()]
            )
        );
    }

    /// Integration: build a representative staging rootfs (the runtime apks) then assemble the init
    /// layer. Asserts box-init builds + stages at `/usr/bin/box-init`, `/sbin/init` is the RELATIVE
    /// symlink to it, the servicedir tree + `.s6-svscan` handlers are emitted, and `busybox --install`
    /// recreated the applet symlinks — the end-to-end verify-don't-assert closure for `build_init_tree`
                                                                  
    #[test]
    #[ignore = "needs docker + the container; apk-builds a rootfs + cargo-builds box-init + assembles the init tree"]
    fn build_init_tree_assembles_servicedirs_and_box_init() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let staging = tempfile::tempdir().unwrap();
                                                                                                    
                                                                                                       
        let setup = Command::new("docker")
            .args(["run", "--rm", "-v"])
            .arg(format!("{}:/staging", staging.path().display()))
            .args([
                IMAGE,
                "sh",
                "-c",
                "mkdir -p /staging/etc/apk && cp -r /etc/apk/keys /staging/etc/apk/keys && \
                 cp /etc/apk/repositories /staging/etc/apk/repositories && \
                 apk add --root /staging --initdb --no-cache busybox musl s6 s6-portable-utils \
                   >/dev/null 2>&1 && \
                 rm -f /staging/bin/rm /staging/bin/mkdir /staging/bin/mv /staging/bin/cp \
                   /staging/bin/chmod /staging/bin/mountpoint && \
                 chmod -R a+rwX /staging",
            ])
            .status()
            .unwrap();
        assert!(setup.success(), "representative staging rootfs built");

                                                                                                 
                                                                                                  
                                                   
        let pins = crate::pin_manifest::PinManifest::load(&repo_root.join("consume-pins.toml"))
            .expect("load consume-pins.toml");
        let store: Box<dyn crate::artifact_store::ArtifactStore> = Box::new(
            crate::artifact_store::DirStore::new(repo_root.join("../artifact-store")),
        );
        let tools = HostBuildTools::new(IMAGE, &repo_root).with_pins(store, pins);
        tools
            .build_init_tree(
                staging.path(),
                "box.example.org",
                1_700_000_000,
                &crate::config::sample_manifest(),
                crate::service_tree::EngineWeightsSetup::None,
            )
            .expect("init tree assembles");

                                                                                      
        assert!(
            staging.path().join("usr/bin/box-init").is_file(),
            "box-init is fetched + staged at /usr/bin/box-init"
        );
                                                                                   
        assert_eq!(
            std::fs::read_link(staging.path().join("sbin/init")).unwrap(),
            std::path::Path::new("../usr/bin/box-init"),
            "/sbin/init must be a RELATIVE symlink to box-init — an absolute target resolves against \
             the initramfs root in the pre-switch_root .exists() check → false-negative 'no init'"
        );
                                                                                                       
                                                                                                       
                                                                                                  
        assert!(staging.path().join("etc/box-svc/blogd/run").is_file());
        assert!(!staging.path().join("etc/box-svc/blogd/supervise").exists());
                                                               
        assert!(staging
            .path()
            .join("etc/box-svc/.s6-svscan/finish")
            .is_file());
                                                                                           
        assert!(
            staging.path().join("bin/rm").symlink_metadata().is_ok(),
            "busybox --install -s recreated the applet symlinks"
        );
    }
}
