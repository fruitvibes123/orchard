                                                                                    
//! key set, the committed Alpine trust anchors, the pinned kernel source + config-virt, and the
//! `HostBuildTools` container shell-outs into the image-builder's `build()` → the UNSIGNED `.img`
//! triple. The CLI arm in `admin.rs` is thin; this is the testable orchestration (mirrors the
//! `keys` / `fingerprints` modules — logic in the lib, where the `pub(crate)` key helpers live).
//!
//! Artifact `.sig` sidecars are the ed25519 dragonfruit bundles, signed by the operator AFTER the
//! build when an artifact key set is present (Spec 2 §2/§3, C2; the menu's software/docker rungs);
                                                                                                      

use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;

use recipes_image_builder::build::{self, BuildConfig, BuildOutputs, WeightsInput};
use recipes_image_builder::build_tools_host::{HostBuildTools, InitramfsInputs, KernelInputs};
pub use recipes_image_builder::firmware::Firmware;
use recipes_image_builder::kernel::KernelConfigPins;
use recipes_image_builder::{
    AlpineApkProvider, Fetcher, HttpFetcher, PackageProvider, PinnedApks, TrustedKeys,
};

use crate::deploy::keys::{DeployKeyError, pem_cert_to_der, read_pem};

/// Re-exported so the `orchard build --domain` value_parser shares the one validator.
pub use recipes_image_builder::config::validate_domain;

/// The default staging dir for the kernel source tarball (`orchard prime`'s `--kbuild-dir` default).
/// The version-specific leaf comes from `pins.toml`, so the kernel version lives in exactly one place.
pub const DEFAULT_KBUILD_DIR: &str = "/tmp/recipes-kbuild";

/// The default staged kernel source TARBALL (`<DEFAULT_KBUILD_DIR>/linux-<pins.toml kernel.version>.tar.xz`),
/// derived from the central manifest so a kernel bump is a single `pins.toml` edit. `orchard prime`
                                                                                         
pub fn default_kernel_xz(
    repo_root: &Path,
) -> Result<PathBuf, recipes_image_builder::pins::PinsError> {
    Ok(recipes_image_builder::pins::Pins::load(repo_root)?
        .kernel_tarball_path(Path::new(DEFAULT_KBUILD_DIR)))
}

/// The default staging dir for the syslinux source tarball (`orchard prime`'s `--syslinux-dir`
/// default). The version-specific tarball name comes from `pins.toml`.
pub const DEFAULT_SYSLINUX_DIR: &str = "/tmp/recipes-syslinux";

/// The default pinned syslinux source tarball (`<DEFAULT_SYSLINUX_DIR>/syslinux-<pins.toml
/// syslinux.version>.tar.xz`), derived from the central manifest so a syslinux bump is a single
/// `pins.toml` edit. Override with `--syslinux-src`.
pub fn default_syslinux_src(
    repo_root: &Path,
) -> Result<PathBuf, recipes_image_builder::pins::PinsError> {
    Ok(recipes_image_builder::pins::Pins::load(repo_root)?
        .syslinux_tarball_path(Path::new(DEFAULT_SYSLINUX_DIR)))
}

#[derive(Debug, thiserror::Error)]
pub enum BuildImageError {
    #[error("signing keys not found at {0}; run 'orchard generate-keys' to bootstrap")]
    KeysMissing(String),
    #[error("kernel source tarball not found at {0}; run `orchard prime` (or `make prime`) first")]
    KernelSourceMissing(String),
    #[error(
        "syslinux source tarball not found at {0}; run `orchard prime` (or `make prime`) first"
    )]
    SyslinuxSourceMissing(String),
    #[error(
        "config-virt not found in the pinned linux-virt apk; the apk closure is stale — \
         run `orchard refresh-apk-lock`"
    )]
    ConfigVirtMissing,
    #[error(
        "git working tree is dirty; commit/stash first (usually the `generate-keys` write to \
         `crates/image-builder/pinned-cert-fingerprints.toml` — commit it), or pass --allow-dirty \
         (names the image <sha>-dirty)"
    )]
    DirtyTree,
    #[error(
        "orchard was compiled from commit {embedded} but HEAD is {head} — its image-builder \
         orchestration is STALE; recompile (cargo build -p orchard) \
         or pass --allow-dirty"
    )]
    StaleBinary { embedded: String, head: String },
    #[error(transparent)]
    Config(#[from] recipes_image_builder::config::ConfigError),
    #[error(transparent)]
    Keys(#[from] DeployKeyError),
    #[error(transparent)]
    Build(#[from] build::BuildError),
    #[error(transparent)]
    Acquire(#[from] recipes_image_builder::AcquireError),
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Other(String),
    #[error("{kind} pubkey {path}: {msg}")]
    Pubkey {
        kind: &'static str,
        path: String,
        msg: String,
    },
}

/// Inputs for one `deploy build`. The CLI arm supplies the operator-tunable bits; everything else
/// is read from the repo (pins, trust anchors, `build-kernel.sh`) or derived (git sha / epoch / uuid).
#[derive(Clone)]
pub struct BuildImageOpts {
    /// The operator key set dir (the 7-file `generate-keys` output).
    pub keys_dir: PathBuf,
    /// The recipes repo root (pins, trust anchors, `build-kernel.sh`, the app source).
    pub repo_root: PathBuf,
    /// The artifact store (C5-resolved at the CLI; the env/default reads left this layer —
                              
    pub artifact_store: PathBuf,
    /// The staged, pinned kernel source TARBALL (`orchard prime` output) — re-verified at consumption
                                                                                                       
    /// an extracted tree to the `.tar.xz`. Defaults to `default_kernel_xz`; override with `--ksrc`.
    pub kernel_src: PathBuf,
    /// The staged, pinned syslinux source TARBALL (`orchard prime` output) — re-verified at
                                                                                               
    /// extraction by `bake_boot_fs`. Defaults to `default_syslinux_src`; override with `--syslinux-src`.
    pub syslinux_src: PathBuf,
    /// Output dir for the `.img` triple.
    pub out_dir: PathBuf,
    /// The deployment domain (haproxy cert path).
    pub domain: String,
    /// The pinned build-container image ref (e.g. `recipes-imgbuild:dev`).
    pub container_image: String,
    /// Allow building from a dirty git working tree (taints the artifact NAME →
    /// `<sha>-dirty`; the rescue seed stays keyed on the clean commit — L-1, gate added in L-3).
    pub allow_dirty: bool,
    /// The operator recovery pubkey path to bake into `/etc/ssh/recovery_authorized_keys` — the
    /// rescue dropbear's sole authorized key (in-rootfs, so it authenticates when `/persist` is
    /// unmountable). `None` ships the deploy-time placeholder. Validated derive-not-cat
                                                                                                      
    pub recovery_pubkey: Option<PathBuf>,
    /// The operator's NORMAL-boot pubkey baked into the persist-skeleton's `authorized_keys` (the box's
    /// everyday login). `None` bakes an un-loginable skeleton (same posture as the recovery placeholder).
    /// Validated derive-not-cat, like `recovery_pubkey`.
    pub operator_pubkey: Option<PathBuf>,
    /// Hotswap v4 (`--weights-anchor runtime`): anchor the weights volume via the persisted SIGNED
    /// record + runtime dm-verity (NO `fb.weights-*` cmdline) instead of the dha boot-anchored
    /// triple. Requires the weights input, a `models.toml` `[health]` pin, and a HOST-rung artifact
    /// key set carrying the `Purpose::Weights` delegation (`orchard redelegate --purpose weights`).
    pub runtime_weights: bool,
    /// The boot firmware to build for (default SeaBIOS — Infomaniak is BIOS-only). `Uefi` builds the
    /// GPT + FAT ESP + the rambutan SB loader (OVMF-boot-proven); only its production substrate is
                               
    pub firmware: Firmware,
    /// The operator `fb.net=` VALUE baked into the boot-fs APPEND (network spec C1; e.g.
    /// `mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3`). `None` bakes no token ⇒ the box diverts
    /// to rescue/link-only. `mode=dhcp` is accepted as the documented seam (build-A fail-closes it at
    /// bring-up). Validated [`validate_net`] at the CLI boundary + here (the load-bearing layer).
    pub net: Option<String>,
    /// UEFI only (SB-loader plan): bake `SB_REQUIRED=true` into the rambutan loader (the SB rung —
    /// the loader refuses to run with Secure Boot disabled). `false` = the SB-off rung. Ignored on
    /// SeaBIOS. Threads into [`crate::deploy::build_image::Firmware`]'s `BuildConfig.sb_required`.
    pub sb_required: bool,
    /// The operator-supplied service manifest (`--manifest <path>`) the bake renders the tenant
    /// topology from — parsed + validated through the §5.3 fail-closed gate. `None` bakes the pinned
    /// reference tenant (byte-identical to today's box). The non-recipes generalization seam
                                                                        
    pub manifest_path: Option<PathBuf>,
    /// os-update A/B v1 (§4i): the per-stream monotonic image serial (`--image-version`), stamped
    /// firmware-unconditionally into the rootfs + `.layout.toml`; the box's version-floor anti-rollback
    /// compares against it. The operator OWNS the sequence (sovereign); the box-side `version ≤ floor`
    /// refusal is the enforcement. Defaults to `0` at the CLI for an unversioned dev/smoke build.
    pub image_version: u64,
                                                                                              
                                                                                            
    pub dha_weights_gguf: Option<PathBuf>,
    /// The projector GGUF (`--dha-mmproj-gguf`; replaced `RECIPES_DHA_MMPROJ_GGUF`). `None` with a
    /// weights input ⇒ the pinned file name resolved beside the model GGUF (D16); pin-verified
    /// either way.
    pub dha_mmproj_gguf: Option<PathBuf>,
}

/// Validate the operator `--net` value (the `fb.net=` cmdline VALUE). The load-bearing invariant:
/// it must be ONE whitespace-free token, because `/proc/cmdline` is whitespace-tokenized — a space
/// would truncate `fb.net=` mid-value → a black-holed/partial config that box-init's parser
/// can't recover (network spec R1-4). The FULL grammar (mode/ip/gw/dns + address semantics) is
/// box-init's `parse_net` at boot (fail-closed → rescue); this boundary check just rejects the shapes
/// that would corrupt the cmdline token or silently no-op. Returns the value unchanged on success.
pub fn validate_net(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("--net value is empty".to_string());
    }
                                                                                                           
                                                                                                         
                                                                                                            
    if !s.bytes().all(|b| b.is_ascii_graphic() && b != b'"') {
        return Err(format!(
            "--net must be one token of printable non-quote ASCII (fb.net rides a single cmdline token): {s:?}"
        ));
    }
    if !s.starts_with("mode=") {
        return Err(format!(
            "--net must start with `mode=static` or `mode=dhcp`: {s:?}"
        ));
    }
    Ok(s.to_string())
}

                                                                                                 
/// (`Substrate::from_firmware`); `--substrate` is a belt-and-braces operator ASSERTION, never an
/// independent input — it can only agree or abort, never SELECT. `None` ⇒ ok (the derivation
/// stands). `Some(s)` ⇒ ok iff `s` equals the firmware-derived token, else a fail-closed refusal
/// naming BOTH the derived value and the operator's (the profile-merge refusal shape).
pub fn check_substrate_flag(firmware: Firmware, flag: Option<&str>) -> Result<(), String> {
    use recipes_image_builder::firmware::Substrate;
    let derived = Substrate::from_firmware(firmware).as_str();
    match flag {
        None => Ok(()),
        Some(s) if s == derived => Ok(()),
        Some(s) => Err(format!(
            "--substrate {s:?} contradicts the firmware-derived substrate {derived:?} \
             (--firmware {} ⇒ {derived}); the substrate is DERIVED from --firmware, not chosen \
             independently — to TARGET a different substrate change --firmware (uefi ⇒ bare-metal-uefi; \
             seabios/seabios-gpt ⇒ vps-kvm), or drop --substrate / pass --substrate {derived} to accept it",
            firmware.as_str()
        )),
    }
}

/// Orchestrate a `deploy build`: produce the UNSIGNED `.img` triple from the operator key set +
/// pins. Fail-closed: a missing key set / kernel source / config-virt aborts before any build work.
pub fn build_image(opts: &BuildImageOpts) -> Result<BuildOutputs, BuildImageError> {
                                                                                                     
                                                                                              
                                                                       
    recipes_image_builder::config::validate_domain(&opts.domain)?;

                                                                                             
                                                                                                      
                                                                       
    let net = opts
        .net
        .as_deref()
        .map(validate_net)
        .transpose()
        .map_err(BuildImageError::Other)?;

                                                                                                  
                                                                                                       
                                                                                                          
                                                                                                 
                                                                                              
                                                                                                         
                                                                                                       
                                                                                                  

                                                                                                  
                                                                                                       
                                                                                      
                                                    
    let recovery_authorized_keys = opts
        .recovery_pubkey
        .as_deref()
        .map(|p| read_validated_pubkey("recovery", p))
        .transpose()?;
    let operator_authorized_keys = opts
        .operator_pubkey
        .as_deref()
        .map(|p| read_validated_pubkey("operator", p))
        .transpose()?;

    let key = |name: &str| opts.keys_dir.join(name);

                                                           
    if !key("ima.key").is_file() {
        return Err(BuildImageError::KeysMissing(
            opts.keys_dir.display().to_string(),
        ));
    }
    if !opts.kernel_src.is_file() {
        return Err(BuildImageError::KernelSourceMissing(
            opts.kernel_src.display().to_string(),
        ));
    }
                                                                                                       
                                                                                                     
    if !opts.syslinux_src.is_file() {
        return Err(BuildImageError::SyslinuxSourceMissing(
            opts.syslinux_src.display().to_string(),
        ));
    }
                                                                                                  
                                                                                              
                                                                                                
                                                                                             
    let dirty = !git_output(
        &opts.repo_root,
        &["--no-optional-locks", "status", "--porcelain"],
    )?
    .is_empty();
    if dirty && !opts.allow_dirty {
        return Err(BuildImageError::DirtyTree);
    }

                                                                                                           
                                                                                                        
                                                                                                      
    let weights = resolve_weights_input(
        &opts.repo_root,
        opts.manifest_path.as_deref(),
        opts.dha_weights_gguf.as_deref(),
        opts.dha_mmproj_gguf.as_deref(),
    )?;

    let ib = opts.repo_root.join("crates/image-builder");

                            
    let apk_pins = PinnedApks::from_toml_str(&read_file_string(&ib.join("pinned-apks.toml"))?)?;
                                                                                                    
                                                                                     
    let root_pins = recipes_image_builder::pins::Pins::load(&opts.repo_root)
        .map_err(|e| BuildImageError::Other(format!("pins.toml: {e}")))?;
    let kernel_pins =
        KernelConfigPins::from_toml_str(&read_file_string(&ib.join("kernel-config-pins.toml"))?)
            .map_err(|e| BuildImageError::Other(format!("kernel-config-pins.toml: {e}")))?;
    let trusted_keys = load_trusted_keys(&ib.join("alpine-trusted-keys"))?;

                                                                                         
                                                                                           
                                                                                              
                                                                                                    
                                                                                               
    let drift_pins = apk_pins.clone();
    let drift_cell: std::cell::OnceCell<std::collections::BTreeMap<String, Option<String>>> =
        std::cell::OnceCell::new();
    let drift_lookup = move |name: &str| -> Option<String> {
        let gone = drift_cell.get_or_init(|| {
            let scan = recipes_image_builder::apk_drift::apk_drift_scan_scoped(
                &drift_pins,
                &HttpFetcher::new(),
                recipes_image_builder::apk_drift::DriftScope::AllPackages,
            );
            if !scan.checked {
                return std::collections::BTreeMap::new();
            }
            scan.packages
                .into_iter()
                .filter(|p| p.state == recipes_image_builder::apk_drift::DriftState::Gone)
                .map(|p| (p.name, p.available))
                .collect()
        });
        gone.get(name).and_then(Clone::clone)
    };
    let provider = AlpineApkProvider {
        alpine_version: apk_pins.alpine_version.clone(),
        trusted_keys,
        fetcher: HttpFetcher::new(),
        drift_lookup: Some(Box::new(drift_lookup)),
    };

                                                                                             
    let cfg_temp = tempfile::tempdir().map_err(io_at(Path::new("config-virt tempdir")))?;
    let base_config = cfg_temp.path().join("config-virt");
    extract_config_virt(&provider, &apk_pins, &base_config)?;

                                                                                                      
    let der_temp = tempfile::tempdir().map_err(io_at(Path::new("leaf-der tempdir")))?;
    let ima_der_path = der_temp.path().join("x509_ima.der");
    let ima_der = pem_cert_to_der(&read_pem(&key("ima.crt"))?)?;
    std::fs::write(&ima_der_path, &ima_der).map_err(io_at(&ima_der_path))?;

                                                                                                   
                                                                                                  
    let image_signing_crt_sha256_hex =
        image_signing_fingerprint(&ib.join("pinned-cert-fingerprints.toml"))?;

                                                                                                 
                                                                                                      
                                                                                                     
                                                            
                                                                                                      
                                    
    let git_sha = git_output(&opts.repo_root, &["rev-parse", "HEAD"])?;
                                                                                                     
                                                                                                       
                                                                                                        
    check_build_freshness(
        option_env!("RECIPES_BUILD_GIT_SHA"),
        &git_sha,
        opts.allow_dirty,
    )?;
    let label = image_label(&git_sha, dirty);
    let source_date_epoch: u64 =
        git_output(&opts.repo_root, &["show", "-s", "--format=%ct", "HEAD"])?
            .parse()
            .map_err(|e| BuildImageError::Other(format!("git commit epoch parse: {e}")))?;
                                                                                                   
                                                                                                       
    let pins = recipes_image_builder::pin_manifest::PinManifest::load(
        &opts.repo_root.join("consume-pins.toml"),
    )
    .map_err(|e| BuildImageError::Other(format!("load consume-pins.toml: {e}")))?;
                                                                                                          
                                                                                                       
                                                                                                     
                                                                                                    
                                                                                               
                                                                                                  
    let n_src =
        recipes_image_builder::vendor::verify_vendored_tree(&opts.repo_root.join("vendor"), &pins)
            .map_err(|e| BuildImageError::Other(format!("vendor/ integrity: {e}")))?;
    if n_src < 4 {
        return Err(BuildImageError::Other(format!(
            "vendor/ integrity: only {n_src} source drop(s) verified, expected >= 4 (consume-pins truncated?)"
        )));
    }
    let store: Box<dyn recipes_image_builder::artifact_store::ArtifactStore> = Box::new(
        recipes_image_builder::artifact_store::DirStore::new(&opts.artifact_store),
    );

                                                                                                         
                                                                                                     
                                                                                                        
                                                                                                      
                                                                                   
    let manifest = match opts.manifest_path.as_deref() {
        Some(p) => recipes_image_builder::config::load_manifest(p)?,
        None => {
            let pin = pins.artifact("service-manifest").map_err(|e| {
                BuildImageError::Other(format!("consume-pins service-manifest: {e}"))
            })?;
            let verified = store
                .fetch_verified("service-manifest", &pin.sha256)
                .map_err(|e| BuildImageError::Other(format!("fetch service-manifest: {e}")))?;
            let toml = std::str::from_utf8(verified.bytes()).map_err(|e| {
                BuildImageError::Other(format!("pinned service-manifest is not utf-8: {e}"))
            })?;
            recipes_image_builder::config::parse_validated_manifest(toml)?
        }
    };

    let tools = HostBuildTools::new(opts.container_image.clone(), opts.repo_root.clone())
        .with_kernel(KernelInputs {
            tarball: opts.kernel_src.clone(),
            sha256: root_pins.kernel.sha256.clone(),
            base_config,
            hardening_fragment: ib.join("kernel-hardening.config"),
                                                                                                        
                                                                                                        
                                                        
            substrate_fragment: ib.join(
                match recipes_image_builder::firmware::Substrate::from_firmware(opts.firmware) {
                    recipes_image_builder::firmware::Substrate::VpsKvm => {
                        "kernel-hardening-vpskvm.config"
                    }
                    recipes_image_builder::firmware::Substrate::BareMetalUefi => {
                        "kernel-hardening-baremetal.config"
                    }
                },
            ),
            ca_cert: key("signing-ca.crt"),
        })
        .with_initramfs(InitramfsInputs {
            ima_cert_der: ima_der_path.clone(),
            evm_cert_der: ima_der_path,                                                     
            artifact_root_pub: key("artifact-root.pub"),                                 
        })
        .with_syslinux_source(recipes_image_builder::build_tools_host::SyslinuxSource {
            tarball: opts.syslinux_src.clone(),
            sha256: root_pins.syslinux.sha256.clone(),
        })
        .with_pins(store, pins);

                                                                                                   
                                                                                                 
                                                             
    let weights_anchor = resolve_weights_anchor(opts, weights.is_some())?;

    let cfg = BuildConfig {
        git_sha,
        image_label: label,
        source_date_epoch,
        alpine_version: apk_pins.alpine_version.clone(),
        domain: opts.domain.clone(),
        image_signing_crt_sha256_hex,
        master_key_path: key("rescue-seed-master.key"),
        ima_key_path: key("ima.key"),
        ima_cert_path: key("ima.crt"),
        out_dir: opts.out_dir.clone(),
        recovery_authorized_keys,
                                                                                                   
                                                                                                 
                                                                  
        operator_pubkey: operator_authorized_keys,
                                                                                                  
                                                                                         
        firmware: opts.firmware,
                                                                                                        
        net,
                                                                                                     
                                                                                                         
        sb_required: opts.sb_required,
                                                                                                       
                                                                                                          
        manifest,
                                                                                                      
        weights,
        weights_anchor,
                                                                                                     
                                                                                                    
                                                                                           
                                                                                                       
        image_version: opts.image_version,
        min_delegation_ctr: super::artifact_keys::read_updateimage_ctr(&opts.keys_dir)
            .map_err(|e| {
                BuildImageError::Other(format!(
                    "reading the UpdateImage delegation for min_delegation_ctr: {e}"
                ))
            })?
            .unwrap_or(0),
                                                                                                   
                                                                                                  
        artifact_root_pub: Some(key("artifact-root.pub")),
    };

    let built = build::build(&cfg, &apk_pins, &kernel_pins, &provider, &tools)?;

                                                                                                
                                                                                                    
                                                                                                  
                                                                                            
                                                                                   
    {
        let provenance = crate::ceremony::gate_record::compose(
            &cfg.image_label,
            crate::ceremony::gate_record::BuildParams {
                domain: cfg.domain.clone(),
                                                                                          
                                                                                         
                net: cfg.net.clone().unwrap_or_default(),
                firmware: cfg.firmware.as_str().to_string(),
                image_version: cfg.image_version,
                git_sha: cfg.git_sha.clone(),
            },
            &built.outputs.img,
            &built.outputs.layout,
            &built.outputs.vmlinuz,
            &built.outputs.initramfs,
        )
        .map_err(|e| BuildImageError::Other(e.to_string()))?;
        crate::ceremony::gate_record::write(&built.outputs.img, &provenance)
            .map_err(|e| BuildImageError::Other(e.to_string()))?;
    }

                                                                                                    
                                                                                                 
                                                                                                  
                                                                                              
                                                                  
    if let Some(line) = &cfg.operator_pubkey {
        let fpr = pubkey_sha256_fingerprint(line)?;
        let path = built.outputs.img.with_extension("operator-pubkey.fpr");
        std::fs::write(&path, format!("{fpr}\n")).map_err(io_at(&path))?;
    }

                                                                                            
                                                                                               
                                                                                             
                                                                       
    if let Some(loader_pe) = &built.loader_pe {
        use sha2::{Digest, Sha256};
        let loader_path = built.outputs.img.with_extension("loader.efi");
        std::fs::write(&loader_path, loader_pe).map_err(io_at(&loader_path))?;
        let vmlinuz_bytes = std::fs::read(&built.outputs.vmlinuz).map_err(io_at(Path::new(
            built.outputs.vmlinuz.to_str().unwrap_or("vmlinuz"),
        )))?;
        let name = |p: &Path| {
            p.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string()
        };
        let manifest = super::sign_sb::SignManifest {
            loader: super::sign_sb::ManifestEntry {
                file: name(&loader_path),
                sha256: format!("{:x}", Sha256::digest(loader_pe)),
            },
            vmlinuz: super::sign_sb::ManifestEntry {
                file: name(&built.outputs.vmlinuz),
                sha256: format!("{:x}", Sha256::digest(&vmlinuz_bytes)),
            },
        };
        let manifest_path = built.outputs.img.with_extension("sign-manifest.toml");
        let body = toml::to_string(&manifest)
            .map_err(|e| BuildImageError::Other(format!("sign-manifest serialize: {e}")))?;
        std::fs::write(
            &manifest_path,
            format!(
                "# Unsigned-PE digests for `deploy sign-sb` (SB rungs only; SB-off rungs skip the verb).\n\
                 # Written by `deploy build --firmware uefi`.\n{body}"
            ),
        )
        .map_err(io_at(&manifest_path))?;
    }

    Ok(built)
}

/// The `SHA256:…` fingerprint of a validated OpenSSH pubkey line (`ssh-keygen -lf` field 2).
/// Input is the already-validated single pubkey line from `read_validated_pubkey`.
pub(crate) fn pubkey_sha256_fingerprint(pubkey_line: &str) -> Result<String, BuildImageError> {
    let out =
        ssh_keygen_pipe(&["-l", "-f", "/dev/stdin"], pubkey_line.as_bytes()).ok_or_else(|| {
            BuildImageError::Other("ssh-keygen -lf failed on the validated operator pubkey".into())
        })?;
    out.split_whitespace()
        .find(|f| f.starts_with("SHA256:"))
        .map(str::to_string)
        .ok_or_else(|| {
            BuildImageError::Other(format!(
                "no SHA256: field in ssh-keygen -lf output: {out:?}"
            ))
        })
}

/// Validate + extract a single SSH public-key line from an operator-supplied path, baking-safe
                                                                                       
/// `ssh-keygen -y -f /dev/stdin` so a privkey passed by typo yields only its pubkey half (the secret
/// never reaches the rootfs); a pubkey input is validated (`ssh-keygen -l`) and used directly. `kind`
/// ("operator"/"recovery") labels the error + the wrong-path hint.
                                                                                              
                                                                                                 
                                                                              
pub fn read_validated_pubkey(kind: &'static str, path: &Path) -> Result<String, BuildImageError> {
    let err = |msg: String| BuildImageError::Pubkey {
        kind,
        path: path.display().to_string(),
        msg,
    };
    let buf = std::fs::read(path).map_err(|e| err(format!("read: {e}")))?;
                                                                                                      
                                                                                                    
                                                                  
    if buf.len() > 64 * 1024 {
        return Err(err(format!(
            "file is {} bytes — implausibly large for an SSH key (>64 KiB); wrong --{kind}-pubkey path?",
            buf.len()
        )));
    }
                                                                                       
    let derived = ssh_keygen_pipe(&["-y", "-f", "/dev/stdin"], &buf).and_then(|out| {
        out.lines()
            .map(str::trim)
            .find(|l| is_ssh_pubkey_line(l))
            .map(str::to_string)
    });
    if let Some(line) = derived {
        return Ok(line);
    }
                                                                                               
    if ssh_keygen_pipe(&["-l", "-f", "/dev/stdin"], &buf).is_some() {
        let text = String::from_utf8_lossy(&buf);
        if let Some(line) = text.lines().map(str::trim).find(|l| is_ssh_pubkey_line(l)) {
            return Ok(line.to_string());
        }
    }
    Err(err(
        "not a valid SSH key (expected an OpenSSH pubkey, or a privkey to derive from)".to_string(),
    ))
}

/// Run `ssh-keygen <args>` feeding `input` on stdin (no temp file); `Some(stdout)` iff it exits 0.
pub(crate) fn ssh_keygen_pipe(args: &[&str], input: &[u8]) -> Option<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("ssh-keygen")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(input).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// An OpenSSH public-key line starts with a key type (`ssh-…`, `ecdsa-sha2-…`, `sk-…`).
fn is_ssh_pubkey_line(line: &str) -> bool {
    match line.split_whitespace().next() {
        Some(kind) => {
            kind.starts_with("ssh-") || kind.starts_with("ecdsa-sha2-") || kind.starts_with("sk-")
        }
        None => false,
    }
}

/// Load every `*.rsa.pub` trust anchor under `dir` into `TrustedKeys` (key = filename sans
/// `.rsa.pub`, matching `pinned-apks.toml`'s `signing_key`; value = the SPKI-PEM bytes).
pub(crate) fn load_trusted_keys(dir: &Path) -> Result<TrustedKeys, BuildImageError> {
    let mut keys: TrustedKeys = HashMap::new();
    for entry in std::fs::read_dir(dir).map_err(io_at(dir))? {
        let path = entry.map_err(io_at(dir))?.path();
        if let Some(key_name) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".rsa.pub"))
        {
            let bytes = std::fs::read(&path).map_err(io_at(&path))?;
            keys.insert(key_name.to_string(), bytes);
        }
    }
    if keys.is_empty() {
        return Err(BuildImageError::Other(format!(
            "no .rsa.pub trust anchors in {}",
            dir.display()
        )));
    }
    Ok(keys)
}

/// Fetch + verify + extract the pinned `linux-virt` apk into a scratch dir and copy out Alpine's
/// `/boot/config-<ver>-virt` (the kernel BASE_CONFIG) to `dest`.
fn extract_config_virt<F: Fetcher>(
    provider: &AlpineApkProvider<F>,
    apk_pins: &PinnedApks,
    dest: &Path,
) -> Result<(), BuildImageError> {
    let pin = apk_pins
        .build_inputs
        .iter()
        .find(|p| p.name == "linux-virt")
        .ok_or_else(|| {
            BuildImageError::Other("no linux-virt build_input pin in pinned-apks.toml".into())
        })?;
    let staging = tempfile::tempdir().map_err(io_at(Path::new("linux-virt staging")))?;
    provider.acquire(pin, staging.path())?;
    let boot = staging.path().join("boot");
    let config = std::fs::read_dir(&boot)
        .map_err(io_at(&boot))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("config-") && n.ends_with("-virt"))
        })
        .ok_or(BuildImageError::ConfigVirtMissing)?;
    std::fs::copy(&config, dest).map_err(io_at(dest))?;
    Ok(())
}

/// Read the by-construction image-signing cert sha256 from the committed pin (`"sha256:<hex>"`).
fn image_signing_fingerprint(toml_path: &Path) -> Result<String, BuildImageError> {
    #[derive(serde::Deserialize)]
    struct Fp {
        fingerprint: String,
    }
    #[derive(serde::Deserialize)]
    struct Doc {
        image_signing: Fp,
    }
    let doc: Doc = toml::from_str(&read_file_string(toml_path)?)
        .map_err(|e| BuildImageError::Other(format!("pinned-cert-fingerprints.toml: {e}")))?;
    doc.image_signing
        .fingerprint
        .strip_prefix("sha256:")
        .map(str::to_string)
        .ok_or_else(|| {
            BuildImageError::Other("image_signing fingerprint missing sha256: prefix".into())
        })
}

/// dha Component E: resolve the optional weights build input. `dha_weights_gguf` NONE ⇒ a non-dha
                                                                                                
/// sha256 pins of the `models.toml` profile THIS tenant manifest selects (D15 — by manifest file stem,
/// fail-closed); `build()` re-hashes each file against its pin FAIL-CLOSED (this resolution is early
/// feedback, that re-hash is the load-bearing gate). The flag is the weights-build opt-in
                                                                                                   
/// changes produced bytes is a build parameter; the CLI refuses a set env var with the flag cure).
/// The existence check here fails fast with a friendly error before the expensive apk/kernel work
/// (mirrors the kernel/syslinux source checks).
///
/// D16 — the projector's path: `dha_mmproj_gguf` when set, else the pinned `file` name resolved
/// NEXT TO the model GGUF (the operator's model dir holds both). Either way `build()` verifies its
/// pinned sha256, so the convenience fallback cannot introduce unpinned content — a wrong file
/// aborts the build.
fn resolve_weights_input(
    repo_root: &Path,
    manifest_path: Option<&Path>,
    dha_weights_gguf: Option<&Path>,
    dha_mmproj_gguf: Option<&Path>,
) -> Result<Option<WeightsInput>, BuildImageError> {
    let Some(gguf) = dha_weights_gguf else {
        return Ok(None);
    };
    let gguf_path = gguf.to_path_buf();
    if !gguf_path.is_file() {
        return Err(BuildImageError::Other(format!(
            "--dha-weights-gguf {} is not a file (the operator supplies the weights GGUF out-of-band)",
            gguf_path.display()
        )));
    }
    let models = recipes_image_builder::models::Models::load(repo_root)
        .map_err(|e| BuildImageError::Other(format!("load models.toml: {e}")))?;
    let profile = models
        .profile_for_manifest(manifest_path)
        .map_err(|e| BuildImageError::Other(e.to_string()))?;

    let mmproj = match profile.weights.mmproj.as_ref() {
        None => None,
        Some(pin) => {
            let path = match dha_mmproj_gguf {
                Some(p) => p.to_path_buf(),
                None => gguf_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(&pin.file),
            };
            if !path.is_file() {
                return Err(BuildImageError::Other(format!(
                    "this manifest's models.toml profile pins a vision projector ({}) but {} is not a \
                     file — supply it beside the model GGUF, or pass --dha-mmproj-gguf",
                    pin.file,
                    path.display()
                )));
            }
            Some(recipes_image_builder::build::WeightsFile {
                path,
                sha256: pin.sha256.clone(),
                bytes: pin.bytes,
            })
        }
    };

    Ok(Some(WeightsInput {
        gguf_path,
        sha256: profile.weights.sha256.clone(),
        bytes: profile.weights.bytes,
        mmproj,
    }))
}

/// Hotswap v4: resolve `--weights-anchor runtime` into the image-builder [`WeightsAnchor`] — the
/// signer closure over the OPERATOR's host-rung artifact key set (`Purpose::Weights`) + the
/// `models.toml` `[health]` probe. Fail-closed on every missing prerequisite; `BootCmdline` (the
/// pre-v4 default) when the flag is absent. The delegation's `monotonic_ctr` becomes the baked
/// record's initial anti-rollback floor (the `min_delegation_ctr` threading pattern).
fn resolve_weights_anchor(
    opts: &BuildImageOpts,
    have_weights: bool,
) -> Result<recipes_image_builder::build::WeightsAnchor, BuildImageError> {
    use recipes_image_builder::build::{SignedWeightsManifest, WeightsAnchor, WeightsRecordInputs};
    if !opts.runtime_weights {
        return Ok(WeightsAnchor::BootCmdline);
    }
    if !have_weights {
        return Err(BuildImageError::Other(
            "--weights-anchor runtime requires a weights input (pass --dha-weights-gguf)"
                .to_string(),
        ));
    }
    let models = recipes_image_builder::models::Models::load(&opts.repo_root)
        .map_err(|e| BuildImageError::Other(format!("load models.toml: {e}")))?;
                                                                                                       
                                                                                       
    let profile = models
        .profile_for_manifest(opts.manifest_path.as_deref())
        .map_err(|e| BuildImageError::Other(e.to_string()))?;
    let Some(h) = profile.health.clone() else {
        return Err(BuildImageError::Other(
            "--weights-anchor runtime requires a [health] section in this manifest's models.toml \
             profile (the swap's real-inference probe: port/path/body)"
                .to_string(),
        ));
    };
                                                                                        
                                                                
    let delegation_ctr = match super::artifact_keys::read_weights_ctr(&opts.keys_dir) {
        Ok(Some(c)) => c,
        Ok(None) | Err(super::keys::DeployKeyError::MissingDelegation { .. }) => {
            return Err(BuildImageError::Other(
                "the artifact key material has no Purpose::Weights delegation — run \
                 `orchard redelegate --purpose weights`"
                    .to_string(),
            ));
        }
        Err(e) => {
            return Err(BuildImageError::Other(format!(
                "read the Weights delegation: {e}"
            )));
        }
    };
                                                                                                   
                                                                                        
    use super::artifact_sign::SignPlan;
    let pin_path = super::pinned_artifact_root_path(&opts.repo_root);
    let plan = super::artifact_sign::plan_signing(&opts.keys_dir, &pin_path)
        .map_err(|e| BuildImageError::Other(format!("plan the weights-record signing: {e}")))?;
                                                                                             
                       
    #[allow(clippy::type_complexity)]
    let sign: Box<dyn Fn(&[u8]) -> Result<SignedWeightsManifest, String>> = match plan {
        SignPlan::Host(set) => Box::new(move |manifest: &[u8]| {
            let sig_vec =
                super::artifact_sign::sign_bytes(&set, dragonfruit::Purpose::Weights, manifest)
                    .map_err(|e| e.to_string())?;
            let sig: [u8; 254] = sig_vec
                .try_into()
                .map_err(|_| "weights bundle is not 254 bytes".to_string())?;
            Ok(SignedWeightsManifest {
                sig,
                delegation_ctr,
            })
        }),
        SignPlan::Docker => {
                                                                                   
                                                                                        
                                                                                        
            eprintln!(
                "weights record: docker-rung sign — the passphrase prompt arrives \
                 MID-build; keep the terminal attended"
            );
            let keys_dir = opts.keys_dir.clone();
            Box::new(move |manifest: &[u8]| {
                let sig_vec = super::artifact_sign::docker_sign_manifest_bytes(
                    &keys_dir,
                    dragonfruit::Purpose::Weights,
                    manifest,
                    "weights-manifest",
                )?;
                let sig: [u8; 254] = sig_vec
                    .try_into()
                    .map_err(|_| "weights bundle is not 254 bytes".to_string())?;
                Ok(SignedWeightsManifest {
                    sig,
                    delegation_ctr,
                })
            })
        }
                                                                                           
                                                                                               
                                                                                                  
                                                                                                  
                                                                                                
                                                                             
        SignPlan::UnsignedFloor => {
            return Err(BuildImageError::Other(
                "a v4 box requires a signed weights record, and no signing rung is \
                 configured (no keys, no committed pinned-artifact-root.toml) — run \
                 `orchard generate-keys --artifact-signing …`"
                    .to_string(),
            ));
        }
    };
    Ok(WeightsAnchor::RuntimeRecord(WeightsRecordInputs {
        sign,
        health: recipes_image_builder::build::WeightsHealth {
            port: h.port,
            path: h.path,
            body: h.body,
        },
    }))
}

/// Where the image triple lands when neither a flag nor the profile names a directory. ONE home:
/// `build`'s merge, the ceremony's spine default and the ceremony runner's artifact lookup all
/// read it, so a change moves all three together.
pub const DEFAULT_OUT_DIR: &str = "/tmp";

/// The artifact-identity label (L-1): the clean `git_sha`, suffixed `-dirty` for an `--allow-dirty`
/// build. Names the `.img` triple so a dirty build is distinguishable. The
/// CLEAN `git_sha` (NOT this label) feeds the rescue-seed IKM — `PublicInputs::new` requires exactly
/// 40 hex chars, which a `<sha>-dirty` value fails (44 chars, non-hex `-`).
fn image_label(git_sha: &str, dirty: bool) -> String {
    if dirty {
        format!("{git_sha}-dirty")
    } else {
        git_sha.to_string()
    }
}

pub(crate) fn git_output(repo_root: &Path, args: &[&str]) -> Result<String, BuildImageError> {
    let out = std::process::Command::new("git")
        .current_dir(repo_root)
        .args(args)
        .output()
        .map_err(|e| BuildImageError::Other(format!("spawn git {args:?}: {e}")))?;
    if !out.status.success() {
        return Err(BuildImageError::Other(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn read_file_string(path: &Path) -> Result<String, BuildImageError> {
    std::fs::read_to_string(path).map_err(io_at(path))
}

fn io_at(path: &Path) -> impl Fn(std::io::Error) -> BuildImageError {
    let path = path.display().to_string();
    move |source| BuildImageError::Io {
        path: path.clone(),
        source,
    }
}

                                                                                                      
/// into this binary) differs from `head` (the working-tree HEAD `deploy build` resolved). The
/// image-builder orchestration is compiled in, so a not-recompiled binary ships a stale tree under a
/// fresh label. A `None`/"unknown" embedded sha (a git-less build of orchard) is never stale —
/// fail-safe. `allow_dirty` does NOT silently mask a mismatch (I-2): staleness is orthogonal to a
/// dirty tree, so under `--allow-dirty` it downgrades the hard error to a stderr warning rather than
/// vanishing without a trace.
fn check_build_freshness(
    embedded: Option<&str>,
    head_sha: &str,
    allow_dirty: bool,
) -> Result<(), BuildImageError> {
    let Some(embedded) = embedded.filter(|&e| e != "unknown" && e != head_sha) else {
        return Ok(());                                                                     
    };
    if allow_dirty {
        eprintln!(
            "warning: orchard was compiled from {embedded} but HEAD is {head_sha}; \
             --allow-dirty proceeds with possibly-stale image-builder orchestration"
        );
        return Ok(());
    }
    Err(BuildImageError::StaleBinary {
        embedded: embedded.to_string(),
        head: head_sha.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

                                                                                                     
    #[test]
    fn explicit_substrate_mismatch_refuses() {
                                                                                  
        let e = check_substrate_flag(Firmware::Seabios, Some("bare-metal-uefi")).unwrap_err();
        assert!(
            e.contains("vps-kvm") && e.contains("bare-metal-uefi"),
            "{e}"
        );
                                                              
        assert!(check_substrate_flag(Firmware::Seabios, Some("vps-kvm")).is_ok());
        assert!(check_substrate_flag(Firmware::SeabiosGpt, Some("vps-kvm")).is_ok());
        assert!(check_substrate_flag(Firmware::Uefi, Some("bare-metal-uefi")).is_ok());
        assert!(check_substrate_flag(Firmware::Seabios, None).is_ok());
                                                              
        assert!(check_substrate_flag(Firmware::Uefi, Some("vps-kvm")).is_err());
    }

                                                                                                       
    /// git-less ("unknown"/absent) embed both skip it (fail-safe — never a false hard stop).
    #[test]
    fn check_build_freshness_flags_only_a_real_mismatch() {
        let head = "a".repeat(40);
        let other = "0".repeat(40);
                                      
        assert!(check_build_freshness(Some(&head), &head, false).is_ok());
                                                             
        assert!(matches!(
            check_build_freshness(Some(&other), &head, false),
            Err(BuildImageError::StaleBinary { .. })
        ));
                                               
        assert!(check_build_freshness(Some(&other), &head, true).is_ok());
                                                                  
        assert!(check_build_freshness(Some("unknown"), &head, false).is_ok());
        assert!(check_build_freshness(None, &head, false).is_ok());
    }

                                                                                                   
                                                                                                     
                                                                                                   

    /// The dirty-tree refusal names BOTH likely fixes: commit the `generate-keys` fingerprint write
    /// (the usual cause), or `--allow-dirty` for a throwaway build.
    #[test]
    fn dirty_tree_refusal_names_both_cures() {
        let msg = BuildImageError::DirtyTree.to_string();
        assert!(
            msg.contains("--allow-dirty"),
            "names the throwaway cure: {msg}"
        );
        assert!(
            msg.contains("pinned-cert-fingerprints.toml"),
            "names the usual cause — the generate-keys fingerprint write to commit: {msg}"
        );
    }

    /// The config-virt refusal names the stale-apk-closure cure.
    #[test]
    fn config_virt_missing_names_the_refresh_cure() {
        let msg = BuildImageError::ConfigVirtMissing.to_string();
        assert!(
            msg.contains("refresh-apk-lock"),
            "a stale apk closure is fixed by refresh-apk-lock: {msg}"
        );
    }

    /// Regression lock: the refusals that already carry a cure keep it, and no CLI message
    /// re-introduces the stale guide §4.4 pointer (the code already says `orchard prime`).
    #[test]
    fn build_refusals_keep_their_existing_cures() {
        assert!(
            BuildImageError::KeysMissing("/k".into())
                .to_string()
                .contains("orchard generate-keys")
        );
        let ksrc = BuildImageError::KernelSourceMissing("/k".into()).to_string();
        assert!(ksrc.contains("orchard prime"), "{ksrc}");
        let ssrc = BuildImageError::SyslinuxSourceMissing("/s".into()).to_string();
        assert!(ssrc.contains("orchard prime"), "{ssrc}");
        assert!(
            !ssrc.contains("4.4"),
            "no stale §4.4 cross-ref in a CLI message: {ssrc}"
        );
        let stale = BuildImageError::StaleBinary {
            embedded: "a".repeat(40),
            head: "b".repeat(40),
        }
        .to_string();
        assert!(
            stale.contains("cargo build -p orchard") && stale.contains("--allow-dirty"),
            "{stale}"
        );
    }

    /// M-2 regression lock (audit I-3): `build_image` rejects an invalid domain at the load-bearing
    /// layer — `validate_domain` is the first call, so it errs before any keys/kernel/docker work
    /// (no external deps needed). A newline-bearing domain is the haproxy-directive-injection vector.
    #[test]
    fn build_image_rejects_invalid_domain() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = BuildImageOpts {
            keys_dir: tmp.path().into(),
            repo_root: tmp.path().into(),
            artifact_store: tmp.path().into(),
            kernel_src: tmp.path().into(),
            syslinux_src: tmp.path().into(),
            out_dir: tmp.path().into(),
            domain: "evil.com\nbind *:80".into(),
            container_image: "x".into(),
            allow_dirty: true,
            recovery_pubkey: None,
            operator_pubkey: None,
            firmware: Firmware::Seabios,
            net: None,
            sb_required: false,
            manifest_path: None,
            image_version: 0,
            runtime_weights: false,
            dha_weights_gguf: None,
            dha_mmproj_gguf: None,
        };
        assert!(matches!(
            build_image(&opts),
            Err(BuildImageError::Config(_))
        ));
    }

    /// L-1 regression lock: the dirty taint lands on the label, never on the seed input. A clean
    /// build's label equals its sha; a dirty build appends `-dirty`. The sha that feeds the
    /// rescue-seed IKM stays the verbatim 40-hex (locked end-to-end in `recipes_image_builder`'s
    /// `build_succeeds_with_a_dirty_image_label`).
    #[test]
    fn image_label_taints_artifact_not_seed() {
        let sha = "abc123de".repeat(5);          
        assert_eq!(image_label(&sha, false), sha, "clean build: label == sha");
        assert_eq!(
            image_label(&sha, true),
            format!("{sha}-dirty"),
            "dirty build: label tainted"
        );
    }

    /// R.4 reproducibility GATE (defense layer 8 — an independent rebuild to an identical hash makes
    /// a build-host compromise detectable). Two full `deploy build`s over IDENTICAL inputs must yield
    /// a byte-identical `.img`. This is the empirical proof that closes `build-kernel.sh`'s
    /// "intended-not-proven" determinism + the whole-`.img` reproducibility. Needs the throwaway key
    /// set (`/tmp/recipes-test-keys`, a `generate-keys` run), the staged kernel source TARBALL
                                                                                                       
    /// each build re-verifies + extracts fresh), and docker `recipes-imgbuild:dev`. Runs TWO full
    /// builds (kernel compile + musl app build ×2) → VERY slow; `#[ignore]`.
    #[test]
    #[ignore = "needs docker + /tmp/recipes-test-keys + /tmp/recipes-kbuild; runs TWO full builds (very slow)"]
    fn build_twice_is_byte_identical() {
        use sha2::{Digest, Sha256};
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")                                                           
            .canonicalize()
            .unwrap();
        let keys = std::path::PathBuf::from("/tmp/recipes-test-keys");
        let ksrc = default_kernel_xz(&repo_root).unwrap();
        let syslinux_src = default_syslinux_src(&repo_root).unwrap();
        assert!(
            keys.join("rescue-seed-master.key").exists(),
            "throwaway key set must be staged"
        );
        assert!(
            ksrc.is_file(),
            "pinned kernel source tarball must be staged (run `orchard prime`)"
        );
        assert!(
            syslinux_src.is_file(),
            "pinned syslinux source tarball must be staged (run `orchard prime`)"
        );
        assert!(
            repo_root
                .join("crates/image-builder/pinned-cert-fingerprints.toml")
                .exists(),
            "the committed fingerprints pin must exist — run `deploy generate-keys` (it writes the pin)"
        );
                                                                                                      
                                                                                                       
        let opts = |out: std::path::PathBuf| BuildImageOpts {
            keys_dir: keys.clone(),
            repo_root: repo_root.clone(),
            artifact_store: crate::deploy::context::store_default(&repo_root),
            kernel_src: ksrc.clone(),
            syslinux_src: syslinux_src.clone(),
            out_dir: out,
            domain: "recipes.example.org".into(),
            container_image: "recipes-imgbuild:dev".into(),
            allow_dirty: true,
            recovery_pubkey: None,
            operator_pubkey: None,
            firmware: Firmware::Seabios,
            net: None,
            sb_required: false,
            manifest_path: None,
            image_version: 0,
            runtime_weights: false,
            dha_weights_gguf: None,
            dha_mmproj_gguf: None,
        };
        let out_a = tempfile::tempdir().unwrap();
        let out_b = tempfile::tempdir().unwrap();
        let a = build_image(&opts(out_a.path().into())).expect("build A");
        let b = build_image(&opts(out_b.path().into())).expect("build B");
        let sha = |p: &std::path::Path| format!("{:x}", Sha256::digest(std::fs::read(p).unwrap()));
        assert_eq!(
            sha(&a.outputs.img),
            sha(&b.outputs.img),
            "two deploy builds over identical inputs must produce a byte-identical .img"
        );
    }

    /// DIAGNOSTIC: build twice and hash each `.img` component separately — slice
    /// `boot-fs ‖ persist-skeleton ‖ squashfs ‖ verity` via the `.layout.toml` offsets — to ISOLATE which
    /// component is non-deterministic when `build_twice_is_byte_identical` fails. **RESOLVED
    /// (2026-05-28):** the hunt found vmlinuz + initramfs SAME, squashfs (+ downstream verity) DIFF →
    /// narrowed to the `recipes` musl binary, then to the FromForm/rust-embed causes (6/n) + the
    /// mksquashfs root-inode mtime; all FIXED, the gate is GREEN. Kept as a regression diagnostic.
    /// Same prereqs as the gate.
    #[test]
    #[ignore = "diagnostic: isolates the non-deterministic .img component"]
    fn repro_component_diff() {
        use sha2::{Digest, Sha256};
        fn components(img_path: &std::path::Path, layout_path: &std::path::Path) -> [String; 4] {
            let img = std::fs::read(img_path).unwrap();
            let lt: toml::Value = std::fs::read_to_string(layout_path)
                .unwrap()
                .parse()
                .unwrap();
            let t = &lt["layout"];
            let g = |k: &str| t[k].as_integer().unwrap() as usize;
            let sha = |b: &[u8]| format!("{:x}", Sha256::digest(b));
            let (bo, bs) = (g("boot_offset"), g("boot_size"));
            let (po, ps) = (g("persist_skeleton_offset"), g("persist_skeleton_size"));
            let ro = g("rootfs_offset");
            let vh = g("rootfs_verity_hash_offset");                                          
            [
                sha(&img[bo..bo + bs]),           
                sha(&img[po..po + ps]),                    
                sha(&img[ro..ro + vh]),                          
                sha(&img[ro + vh..]),                                                                    
            ]
        }
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")                                                           
            .canonicalize()
            .unwrap();
        let opts = |out: std::path::PathBuf| BuildImageOpts {
            keys_dir: "/tmp/recipes-test-keys".into(),
            repo_root: repo_root.clone(),
            artifact_store: crate::deploy::context::store_default(&repo_root),
            kernel_src: default_kernel_xz(&repo_root).unwrap(),
            syslinux_src: default_syslinux_src(&repo_root).unwrap(),
            out_dir: out,
            domain: "recipes.example.org".into(),
            container_image: "recipes-imgbuild:dev".into(),
            allow_dirty: true,
            recovery_pubkey: None,
            operator_pubkey: None,
            firmware: Firmware::Seabios,
            net: None,
            sb_required: false,
            manifest_path: None,
            image_version: 0,
            runtime_weights: false,
            dha_weights_gguf: None,
            dha_mmproj_gguf: None,
        };
        let (out_a, out_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let a = build_image(&opts(out_a.path().into())).expect("build A");
        let b = build_image(&opts(out_b.path().into())).expect("build B");
        let (ha, hb) = (
            components(&a.outputs.img, &a.outputs.layout),
            components(&b.outputs.img, &b.outputs.layout),
        );
        for (i, name) in ["boot-fs", "persist-skel", "squashfs", "verity"]
            .iter()
            .enumerate()
        {
            println!(
                "{name:10} {}  A={} B={}",
                if ha[i] == hb[i] { "SAME" } else { "DIFF" },
                ha[i],
                hb[i]
            );
        }
    }

    #[test]
    fn operator_pubkey_fingerprint_matches_ssh_keygen_lf() {
                                                                                                    
                                                                                                  
                                                                 
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("id");
        assert!(
            std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-q", "-f"])
                .arg(&priv_path)
                .status()
                .expect("spawn ssh-keygen")
                .success()
        );
        let pub_path = dir.path().join("id.pub");
        let line = read_validated_pubkey("operator", &pub_path).expect("pubkey accepted");

        let fpr = pubkey_sha256_fingerprint(&line).expect("fingerprint derives");
        assert!(fpr.starts_with("SHA256:"), "{fpr}");

                                                                                              
        let reference = std::process::Command::new("ssh-keygen")
            .args(["-l", "-f"])
            .arg(&pub_path)
            .output()
            .expect("spawn ssh-keygen -lf");
        assert!(reference.status.success());
        let reference_fpr = String::from_utf8_lossy(&reference.stdout)
            .split_whitespace()
            .find(|f| f.starts_with("SHA256:"))
            .expect("reference SHA256: field")
            .to_string();
        assert_eq!(fpr, reference_fpr);
    }

    #[test]
    fn recovery_pubkey_validates_derive_not_cat() {
                                       
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("id");
        assert!(
            std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-q", "-f"])
                .arg(&priv_path)
                .status()
                .expect("spawn ssh-keygen")
                .success()
        );
        let pub_path = dir.path().join("id.pub");
        let pub_b64 = std::fs::read_to_string(&pub_path)
            .unwrap()
            .split_whitespace()
            .nth(1)
            .expect("pubkey base64")
            .to_string();

                                                                                                  
        let from_pub = read_validated_pubkey("recovery", &pub_path).expect("pubkey accepted");
        assert!(from_pub.starts_with("ssh-ed25519 "));
        assert!(from_pub.contains(&pub_b64));

                                                                                                    
        let from_priv =
            read_validated_pubkey("recovery", &priv_path).expect("privkey derives pubkey");
        assert!(from_priv.starts_with("ssh-ed25519 "));
        assert!(from_priv.contains(&pub_b64));
        assert!(
            !from_priv.contains("PRIVATE"),
            "must never bake private-key material into the rootfs"
        );

                                
        let junk = dir.path().join("junk");
        std::fs::write(&junk, b"definitely not a key\n").unwrap();
        assert!(read_validated_pubkey("recovery", &junk).is_err());
    }
}
