//! `deploy dryrun` — boot a built `.img` in QEMU/KVM and verify the runtime contract.
//!
//! This formalizes the Plan-3.4v2 re-boot-gate harness into Rust: slice the concatenated `.img`
//! per its `.layout.toml` sidecar, recompute the dm-verity root hash from the rootfs data slice
//! (deterministic — [`recipes_image_builder::verity::FIXED_SALT`] + 4096 block sizes, no
//! superblock), stage a `/persist` ext4 disk carrying an *ephemeral* operator pubkey (root-owned via
//! `fakeroot` so dropbear's `checkpubkeyperms` accepts it), boot under QEMU with user-net hostfwd,
//! then assert the spec's Phase-3 runtime contract:
//!   1. dropbear accepts the operator pubkey (SSH pubkey-only auth succeeds),
//!   2. recipes answers an HTTP probe (via haproxy on :443),
//!   3. the rootfs is read-only.
//!
//! [`boot_rescue_and_verify`] is the sibling rescue-path entry: it boots with a corrupt `/persist`
//! to force the rescue bundle, then asserts ONLY the rescue dropbear comes up (recipes absent),
//! reachable by the baked recovery pubkey, with the deterministically-derived host key + the banner.
//!
//! The QEMU child is RAII-killed on [`Drop`] on every exit path (return, `?`, panic) unless
//! [`DryrunOpts::keep_running`]. This is the reusable QEMU/boot core the operator-facing
//! `orchard dryrun` (build → boot → verify) calls after a fresh build, and the
//! env-gated `tests/deploy_dryrun.rs` calls against a pre-built image (building in-test is ~14min).
//!
//! Host tools required (operator-local smoke; preflighted with an actionable error): `qemu-system-x86_64`
//! (+ `/dev/kvm`), `veritysetup`, `ssh-keygen`, `ssh`, `curl`, `fakeroot`, `mke2fs`.

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use recipes_image_builder::verity::{parse_veritysetup_root_hash, veritysetup_format_argv};

mod acme_lifecycle;
mod assertions;
mod install_dha;
mod install_hotswap;
mod install_seabios;
mod install_uefi;
mod installer_usb;
mod qemu;
mod rescue;
mod runtime;
mod update_seabios;
mod usb_repro;

                                                                                                    
                                                                                            
pub use acme_lifecycle::*;
pub use install_dha::*;
pub use install_hotswap::*;
pub use install_seabios::*;
pub use install_uefi::*;
pub use installer_usb::*;
pub use qemu::*;
pub use rescue::*;
pub use runtime::*;
pub use update_seabios::*;
pub use usb_repro::*;

/// Host tools the dryrun shells out to; preflighted up front for a clear error.
const REQUIRED_HOST_TOOLS: [&str; 7] = [
    "qemu-system-x86_64",
    "veritysetup",
    "ssh-keygen",
    "ssh",
    "curl",
    "fakeroot",
    "mke2fs",
];

#[derive(Debug, thiserror::Error)]
pub enum DryrunError {
    #[error(
        "required host tool not found on PATH: {0} \
         (dryrun needs: qemu-system-x86_64, veritysetup, ssh-keygen, ssh, curl, fakeroot, mke2fs)"
    )]
    HostToolMissing(String),
    #[error("/dev/kvm is not available — dryrun boots with -enable-kvm and needs KVM")]
    KvmUnavailable,
                                                                                                       
    /// KVM boot, so a gate pointed at a bench fixture fails loudly instead of greening on the wrong
    /// artifact.
    #[error("prod-shape guard: {0}")]
    ProdShapeGuard(String),
    #[error("layout sidecar {path}: {msg}")]
    LayoutParse { path: String, msg: String },
    #[error("slice {out}: expected {expected} bytes, copied {got} (image/layout mismatch?)")]
    SliceShort {
        out: String,
        expected: u64,
        got: u64,
    },
    #[error("verity fb.root-hash recompute: {0}")]
    VerityRecompute(String),
    #[error("ephemeral operator-key ssh-keygen: {0}")]
    KeygenFailed(String),
    #[error("/persist disk staging (fakeroot mke2fs): {0}")]
    PersistStage(String),
    #[error("qemu launch: {0}")]
    QemuLaunch(String),
    #[error("boot failed: {0}")]
    BootFailed(String),
    #[error("boot/service timeout: {0}")]
    BootTimeout(String),
    #[error("recipes HTTP probe failed: {0}")]
    HttpAssertFailed(String),
    #[error("supervised-service probe failed: {0}")]
    ServiceNotSupervised(String),
    #[error("rootfs is NOT read-only (mount options for /: {0})")]
    RootfsNotReadOnly(String),
    #[error("rescue mode leaked a normal service: {0}")]
    RescueServicesLeaked(String),
    #[error("rescue host key mismatch — VM presented {got}, offline precompute is {expected}")]
    RescueHostKeyMismatch { expected: String, got: String },
    #[error("rescue banner missing/unexpected: {0}")]
    RescueBannerMissing(String),
                                             
    #[error("boot-fs rootfs-dev byte-patch: {0}")]
    BootFsPatch(String),
    #[error("staging the install disk: {0}")]
    InstallDiskStage(String),
    #[error("installer phase: {0}")]
    InstallFailed(String),
    #[error("/proc/cmdline rootfs-dev assertion: {0}")]
    CmdlineAssertFailed(String),
    #[error("persist resize2fs-grow assertion: {0}")]
    PersistNotGrown(String),
    #[error("bootable-last violated — a disk with no MBR boot code booted to the runtime: {0}")]
    UnexpectedBoot(String),
                                                                
    #[error("dha boot-gate check failed: {0}")]
    DhaCheckFailed(String),
                                                 
    #[error("hotswap boot-gate check failed: {0}")]
    HotswapCheckFailed(String),
                                                                             
    #[error("ACME cert-lifecycle check failed: {0}")]
    AcmeLifecycle(String),
    #[error("io {context}: {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },
}

impl DryrunError {
    fn io(context: impl Into<String>) -> impl FnOnce(std::io::Error) -> DryrunError {
        let context = context.into();
        move |source| DryrunError::Io { context, source }
    }
}

/// What "the box serves" means for this tenant — assertion 2 of the dryrun contract.
#[derive(Debug, Clone)]
pub enum ServiceCheck {
    /// The reference (recipes) box: recipes answers via haproxy on `:443` (the HTTP contract).
    RecipesHttp,
                                                                                                     
    /// over SSH via `s6-svstat /run/service/<name>`. Proves "boots to running SERVICES" without a
    /// recipes-specific HTTP contract — the box-init topology + supervision generalize to any tenant.
    SupervisedUp(String),
}

/// Knobs for a dryrun boot. [`Default`] mirrors the spec: SSH on `127.0.0.1:2222`.
#[derive(Debug, Clone)]
pub struct DryrunOpts {
    /// Assertion 2: the runtime "serves" contract — recipes HTTP (default) or a named supervised
    /// service (the non-recipes generalization). The reference box uses [`ServiceCheck::RecipesHttp`].
    pub service_check: ServiceCheck,
    /// Leave the VM running after a SUCCESSFUL verify (suppresses the RAII shutdown); the driver
    /// leaks the workdir so the ephemeral key survives and prints the connection command. A FAILED
    /// boot is always torn down — the returned error carries the console-log tail for diagnosis.
    pub keep_running: bool,
    /// Host port forwarded to guest 22 (dropbear). Spec: `dryrun` ⇒ `127.0.0.1:2222`.
    pub ssh_port: u16,
    /// Host port forwarded to the guest's tenant HTTPS port ([`Self::guest_https_port`]).
    pub https_port: u16,
                                                                                                           
    /// The reference tenant serves on 443 (haproxy); a tenant declaring a different `probe.port` is
    /// forwarded + probed THERE instead of a hardcoded 443. Set from the manifest via
    /// [`Self::with_http_probe`]; [`Default`] is 443 (the reference).
    pub guest_https_port: u16,
    /// The URL path the HTTP "tenant alive" probe requests — the manifest's `probe.path` (§5.1f). The
    /// reference probes `/`; a tenant declaring a different `probe.path` is probed THERE. Manifest-driven
                                                                    
    pub probe_path: String,
    /// How long to wait for dropbear-up and for recipes to answer.
    pub boot_timeout: Duration,
    /// Guest RAM (MiB).
    pub memory_mb: u32,
    /// Make the guest network HERMETIC (`-netdev user,…,restrict=on`): the hostfwd inbound ports
    /// still work (SSH/HTTPS assertions unaffected), but the guest gets NO outbound NAT/DNS.
    ///
                                                                                                   
    /// runs a real `fb-acme-renew` longrun, so a box booted under open NAT places a live **Let's
    /// Encrypt production** order from the operator's public IP — the same hazard `DebianE2eOpts`
    /// closed by defaulting hermetic. `b34c31f`'s `--memory-mb` first made `orchard dryrun` able to
    /// boot a weights box all the way to services-up, which is what connected this default to the
                                                                                               
    /// --keep-running`) is its exact trigger. `dryrun/acme_lifecycle.rs` sets it explicitly on, so
    /// that gate is unaffected; a future operator needing outbound gets a `--allow-network` opt-out,
                                                                                          
    pub restrict_net: bool,
                                                                                                     
    /// PRODUCTION shape before spending a KVM boot — whole-image buffering cannot fit (`image +
    /// INSTALL_MIN_RAM_BYTES > guest RAM`) plus a weights-payload floor against the profile's pinned
    /// bytes (see [`assert_prod_weights_shape`], which documents why the naive `image > RAM` is FALSE
    /// at the prod config). `None` (the default) for every non-weights dryrun path, unaffected.
    pub weights_proof: Option<ProdWeightsProof>,
}

impl Default for DryrunOpts {
    fn default() -> Self {
        DryrunOpts {
            service_check: ServiceCheck::RecipesHttp,
            keep_running: false,
            ssh_port: 2222,
            https_port: 8443,
            guest_https_port: 443,
            probe_path: "/".to_string(),
            boot_timeout: Duration::from_secs(180),
            memory_mb: 1024,
                                                                                            
                                                                                                   
                                                                                                 
            restrict_net: true,
            weights_proof: None,
        }
    }
}

impl DryrunOpts {
                                                                                                         
    /// the dryrun forwards to + the URL path it requests. This is what makes `probe.port`/`probe.path`
    /// CONSUMED rather than validated-but-inert: the reference gate derives them from the pinned
    /// service-manifest it fetches+verifies from the store (`probe.port`/`probe.path`), so a tenant
    /// declaring `probe.port = 8080` is forwarded + probed on 8080, not a hardcoded 443. (The reference
    /// probe IS 443/`/`, so the
    /// reference dryrun is behavior-identical — the wiring is proven non-inert by the unit test below.)
    pub fn with_http_probe(mut self, port: u16, path: &str) -> Self {
        self.guest_https_port = port;
        self.probe_path = path.to_string();
        self
    }
}

/// The `[layout]` offsets/sizes the QEMU harness needs from the build's `.layout.toml` sidecar. The
/// `-kernel` [`boot_and_verify`] dryrun uses ONLY the rootfs trio (vmlinuz/initramfs come from the
/// LOCAL build artifacts beside the `.img`, [`local_artifact`]); the disk-boot install gate
/// ([`install_disk_and_verify`]) additionally slices + byte-patches the boot-fs region (`boot_offset`
/// / `boot_size`). (All byte units.)
pub(crate) struct Layout {
    /// Boot-fs component offset/size — used by the disk-boot install gate to slice the boot-fs out of
    /// the `.img` and byte-patch its `fb.rootfs-dev` sentinel; ignored by the `-kernel` dryrun.
    pub(crate) boot_offset: u64,
    pub(crate) boot_size: u64,
    /// Persist-skeleton component offset/size — the offset feeds the streaming `fb.image-layout`
                                                                                            
                                                            
    pub(crate) persist_skeleton_offset: u64,
    pub(crate) persist_skeleton_size: u64,
    pub(crate) rootfs_offset: u64,
    pub(crate) rootfs_size: u64,
    /// Offset of the dm-verity hash tree *within* the rootfs slot (= the data length).
    pub(crate) rootfs_verity_hash_offset: u64,
    /// dha Component E/F (O4=(a) GPT): the weights component's byte range within the `.img` (appended
    /// after rootfs). `Some` only for a dha `.img`; a non-dha sidecar has no weights keys (`None`). The
    /// dha boot-gate F5 leg reads it to offline-corrupt a weights block (→ dm-verity EIO on page-in).
    pub(crate) weights_offset: Option<u64>,
    pub(crate) weights_size: Option<u64>,
}

/// RAII handle around the QEMU child: killed on `Drop` (any exit path) unless `keep_running`.
pub(crate) struct QemuGuard {
    child: Child,
    keep_running: bool,
}

impl QemuGuard {
    /// Adopt a QEMU child this module did not spawn (the `prod_e2e` Debian-guest harness builds its
    /// own QEMU argv — reboot-permitting, cdrom-seeded — but reuses [`wait_for_ssh`], which needs a
    /// `QemuGuard` to poll for an early exit + RAII-tear-down on any return path).
    pub(crate) fn adopt(child: Child, keep_running: bool) -> Self {
        QemuGuard {
            child,
            keep_running,
        }
    }

    /// Wait for QEMU to exit ON ITS OWN, up to `timeout`. Used by the one path that wants a GRACEFUL
    /// shutdown rather than the RAII kill: [`super::prod_e2e::prepare_kexec_fixture`], which powers
    /// the guest off from inside and must not have its qcow2 torn out mid-writeback — a killed QEMU
    /// can leave the fixture's filesystem dirty, and the whole point of the fixture is that it boots
    /// clean every time afterwards.
    ///
    /// `Drop` still runs after this and is harmless either way: both its `kill` and `wait` ignore
    /// errors, so reaping an already-reaped child is a no-op.
    pub(crate) fn wait_for_exit(&mut self, timeout: Duration) -> Result<(), String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => {
                    return Err(format!("qemu exited {status} (expected a clean poweroff)"));
                }
                Ok(None) => {}
                Err(e) => return Err(format!("wait on qemu child: {e}")),
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "qemu did not exit within {}s of the in-guest poweroff",
                    timeout.as_secs()
                ));
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }
}

impl Drop for QemuGuard {
    fn drop(&mut self) {
        if !self.keep_running {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// `<dir>/<stem>.layout.toml` for `<dir>/<stem>.img`.
pub(crate) fn layout_sidecar(img: &Path) -> PathBuf {
    img.with_extension("layout.toml")
}

                                                                                               
///
/// Both re-anchored gates assert the streaming installer handles an image LARGER than the guest RAM. The
/// image and the RAM both come from the runner, so without a floor the proof can silently decay: a
/// smaller fixture, or a bumped guest, leaves the bare `RAM < image` predicate passing on a one-byte
/// margin while proving nothing about production. This carries the pinned comparand that makes the
/// assertion self-defending.
#[derive(Debug, Clone, Copy)]
pub struct ProdWeightsProof {
    /// Σ of the resolved `models.toml` profile's pinned GGUF `bytes`. Passed IN rather than read here:
    /// the harness stays manifest-agnostic, and the calling gate names which profile it is proving.
    pub pinned_payload_bytes: u64,
}

/// Resolve the payload floor from the pins the image was BUILT from — the `models.toml` profile the
                                                     
///
/// The gates call this instead of hardcoding a byte count so the floor cannot drift away from the pins
/// silently: re-pin the profile and the floor moves with it; point a gate at the wrong manifest and the
/// fail-closed profile lookup says so by name.
pub fn weights_proof_for_manifest(
    repo_root: &Path,
    manifest_path: &Path,
) -> Result<ProdWeightsProof, String> {
    let models = recipes_image_builder::models::Models::load(repo_root)
        .map_err(|e| format!("load models.toml for the gate's payload floor: {e}"))?;
    let profile = models
        .profile_for_manifest(Some(manifest_path))
        .map_err(|e| e.to_string())?;
    Ok(ProdWeightsProof {
        pinned_payload_bytes: profile.weights.payload_bytes(),
    })
}

/// The baked weights component must retain at least this fraction (70%) of the pinned payload.
///
/// **Calibrated on PRODUCED BYTES, after a 90% floor rejected the real prod image.** squashfs gain over
/// a GGUF payload is strongly data-dependent, and the observed range is much wider than "high-entropy
/// quantized data stores verbatim" suggests:
///
/// - bench fixture (`qwen2.5-coder-1.5b-q2_k`, quantized only): 740,515,840 / 752,880,192 = **0.984**
/// - prod pair (`qwen3-vl-2b-q4km` + an **f16** mmproj): 1,715,101,696 / 1,926,804,800 = **0.890**
///
/// The f16 projector is not quantized, so it compresses far better than the q4_K text half — an 11%
/// whole-volume gain. A 90% floor was calibrated on the bench number alone and would have aborted
                                                                                                         
/// that compresses better still (a larger f16/f32 projector), while preserving the discrimination the
/// floor exists for: bench 740 MB vs prod 1715 MB are **2.3× apart**, so a bench fixture supplied where
/// production is required still lands far below the floor and is rejected.
const PAYLOAD_FLOOR_NUM: u64 = 7;
const PAYLOAD_FLOOR_DEN: u64 = 10;

/// Assert the artifact under test really is the PRODUCTION shape before a gate spends a KVM boot on it.
///
/// Two checks, each closing a distinct way the re-anchored proof could rot:
///
/// 1. **Whole-image buffering cannot fit:** `image + INSTALL_MIN_RAM_BYTES > guest RAM`. This is the
                                                                                                           
                                                                                                    
///    old path provably could not have installed this artifact and the streaming path's O(chunk) peak
///    is what makes the deploy possible.
///
///    **Why not the naive `image > RAM`.** MEASURED on the produced prod `.img` (boot 128 MiB +
///    persist 16 MiB + rootfs 24.7 MiB = 168.7 MiB base; weights component 1,715,101,696): the image
///    is **1,892,032,512 B = 1804.4 MiB** — well UNDER the 2048 MiB guest. `image > RAM` is simply
///    false at prod, so asserting it would fail the gate on the genuine production artifact. (The
///    "~3.3 GiB / 1.6×" figure this cycle was briefed with assumed a ~1.5 GiB base.)
///
///    **The margin is THIN — 12.4 MiB.** 1804.4 + 256 = 2060.4 vs 2048.0. It holds on produced bytes,
///    but it is not comfortable: a future pin that compresses better, or a smaller rootfs, could flip
///    this leg to failing. That is a property of the prod config itself (a ~1.8 GiB image in a 2 GiB
///    box), not of this predicate — but treat a failure here as "re-measure and re-decide the
///    criterion", NOT as "loosen the constant".
///
/// 2. **The payload floor** — the `.layout.toml` must declare a weights component whose size is at
///    least 70% of the profile's pinned bytes (see PAYLOAD_FLOOR_NUM for why 70 and not 90). Kills the
///    two runner-supplied divergences the env seam
///    allows: pointing the gate at a NON-weights box (no weights keys at all), or at a bench/small
///    -fixture weights box. It is also what keeps check 1 honest: without it, an arbitrarily padded
///    image could satisfy the sum while carrying no production payload at all.
///
/// **Stated limit:** this proves the payload's SIZE, not its BYTES. The volume's squashfs sha is not the
/// GGUF sha, and stamping GGUF shas into `.layout.toml` would change a sidecar the box-side installer
/// parses — a fruit-basket coupling this cycle deliberately avoids. Exact-byte provenance lives where it
/// belongs: the build's fail-closed sha verification over every pinned GGUF. This is a divergence
/// tripwire over runner-supplied env, not a second integrity layer.
pub(crate) fn assert_prod_weights_shape(
    box_img: &Path,
    guest_mem_mb: u32,
    proof: ProdWeightsProof,
) -> Result<(), String> {
    let img_len = std::fs::metadata(box_img)
        .map_err(|e| format!("stat {}: {e}", box_img.display()))?
        .len();
    let ram = u64::from(guest_mem_mb) * 1024 * 1024;

                                                                                                        
                                                                                             
    let floor = super::prod::INSTALL_MIN_RAM_BYTES;
    if img_len.saturating_add(floor) <= ram {
        return Err(format!(
            "prod-shape guard: image {img_len} bytes + the {floor}-byte installer minimum fits inside \
             guest RAM {ram} bytes — the retired whole-image-in-RAM installer could have handled this \
             artifact, so the leg would prove nothing about streaming. Supply the PRODUCTION \
             weights image"
        ));
    }

    let layout = parse_layout(&layout_sidecar(box_img))
        .map_err(|e| format!("prod-shape guard: read the .layout.toml beside the image: {e}"))?;
    let Some(weights_size) = layout.weights_size else {
        return Err(format!(
            "prod-shape guard: {} declares NO weights component (its .layout.toml carries no weights \
             keys) — this leg must run against a weights box, not a plain 3-component image",
            box_img.display()
        ));
    };
                                                                                                   
                                                                                                       
                                                                                                          
                                                                                                           
                                                                                            
    if weights_size.saturating_mul(PAYLOAD_FLOOR_DEN)
        < proof.pinned_payload_bytes.saturating_mul(PAYLOAD_FLOOR_NUM)
    {
        return Err(format!(
            "prod-shape guard: the baked weights component is {weights_size} bytes but the pinned \
             profile payload is {} bytes — the image under test carries a SMALLER payload than the \
             profile this leg claims to prove (a bench fixture where production is required)",
            proof.pinned_payload_bytes
        ));
    }
    Ok(())
}

fn preflight() -> Result<(), DryrunError> {
    for tool in REQUIRED_HOST_TOOLS {
        let found = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {tool}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !found {
            return Err(DryrunError::HostToolMissing(tool.to_string()));
        }
    }
    if !Path::new("/dev/kvm").exists() {
        return Err(DryrunError::KvmUnavailable);
    }
    Ok(())
}

pub(crate) fn parse_layout(path: &Path) -> Result<Layout, DryrunError> {
    let err = |msg: String| DryrunError::LayoutParse {
        path: path.display().to_string(),
        msg,
    };
    let contents = std::fs::read_to_string(path).map_err(|e| err(format!("read: {e}")))?;
    let value: toml::Value = toml::from_str(&contents).map_err(|e| err(e.to_string()))?;
    let table = value
        .get("layout")
        .ok_or_else(|| err("missing [layout] table".to_string()))?;
    let field = |k: &str| -> Result<u64, DryrunError> {
        table
            .get(k)
            .and_then(|v| v.as_integer())
            .filter(|i| *i >= 0)
            .map(|i| i as u64)
            .ok_or_else(|| err(format!("missing or non-positive-integer layout.{k}")))
    };
                                                                                                            
                                                                             
    let field_opt = |k: &str| -> Result<Option<u64>, DryrunError> {
        match table.get(k) {
            None => Ok(None),
            Some(v) => v
                .as_integer()
                .filter(|i| *i >= 0)
                .map(|i| Some(i as u64))
                .ok_or_else(|| err(format!("non-positive-integer layout.{k}"))),
        }
    };
    Ok(Layout {
        boot_offset: field("boot_offset")?,
        boot_size: field("boot_size")?,
        persist_skeleton_offset: field("persist_skeleton_offset")?,
        persist_skeleton_size: field("persist_skeleton_size")?,
        rootfs_offset: field("rootfs_offset")?,
        rootfs_size: field("rootfs_size")?,
        rootfs_verity_hash_offset: field("rootfs_verity_hash_offset")?,
        weights_offset: field_opt("weights_offset")?,
        weights_size: field_opt("weights_size")?,
    })
}

/// A LOCAL build artifact beside the `.img` (`<stem>.vmlinuz` / `<stem>.initramfs`), failing closed if
/// absent. Under O3 these are emitted as separate files (NOT sliced from the `.img`); the dryrun boots
/// them via `-kernel`/`-initrd`, mirroring the on-box installer's kexec of the local vmlinuz+initramfs
              
pub(crate) fn local_artifact(img: &Path, ext: &str) -> Result<PathBuf, DryrunError> {
    let p = img.with_extension(ext);
    if !p.is_file() {
        return Err(DryrunError::io(format!("local {ext} artifact"))(
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "{} not found beside the .img (the build emits it — rebuild)",
                    p.display()
                ),
            ),
        ));
    }
    Ok(p)
}

/// Copy `size` bytes from `img` at `offset` into `out` (pure-Rust `dd`).
pub(crate) fn slice(img: &Path, offset: u64, size: u64, out: &Path) -> Result<(), DryrunError> {
    let mut input = File::open(img).map_err(DryrunError::io(format!("open {}", img.display())))?;
    input
        .seek(SeekFrom::Start(offset))
        .map_err(DryrunError::io(format!(
            "seek {} to {offset}",
            img.display()
        )))?;
    let mut bounded = std::io::Read::take(input, size);
    let mut output =
        File::create(out).map_err(DryrunError::io(format!("create {}", out.display())))?;
    let copied = std::io::copy(&mut bounded, &mut output)
        .map_err(DryrunError::io(format!("copy into {}", out.display())))?;
    if copied != size {
        return Err(DryrunError::SliceShort {
            out: out.display().to_string(),
            expected: size,
            got: copied,
        });
    }
    Ok(())
}

/// Recompute the dm-verity root hash from the data-only slice, reusing the build's exact argv
/// (fixed salt + 4096 block sizes + `--no-superblock`) so the result matches the signed cmdline.
pub(crate) fn recompute_verity_root_hash(
    data: &Path,
    hash_out: &Path,
) -> Result<String, DryrunError> {
    let argv = veritysetup_format_argv(data, hash_out);
    let output = Command::new("veritysetup")
        .args(&argv)
        .output()
        .map_err(|e| DryrunError::VerityRecompute(format!("spawn veritysetup: {e}")))?;
    if !output.status.success() {
        return Err(DryrunError::VerityRecompute(format!(
            "veritysetup format exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_veritysetup_root_hash(&stdout).ok_or_else(|| {
        DryrunError::VerityRecompute(format!(
            "no valid 'Root hash:' line in veritysetup output:\n{stdout}"
        ))
    })
}

/// Last ~30 lines of the QEMU console log (boot diagnostics on failure).
pub(crate) fn console_tail(console: &Path) -> String {
    match std::fs::read_to_string(console) {
        Ok(text) => {
                                                                                                       
                                                                                                   
                                                                                                   
                                                                                                
            if let Some(out) = std::env::var_os("RECIPES_DRYRUN_CONSOLE_OUT") {
                let _ = std::fs::write(&out, &text);
            }
            let mut lines: Vec<&str> = text.lines().rev().take(30).collect();
            lines.reverse();
            lines.join("\n")
        }
        Err(_) => "(console log unavailable)".to_string(),
    }
}

/// Run a host tool (mke2fs/debugfs for the rc=4 corruption staging), mapping a non-zero exit or spawn
/// failure into a `DryrunError`. Mirrors the error shape of the other dryrun subprocess calls.
fn run_tool(tool: &str, args: &[&str]) -> Result<(), DryrunError> {
    let status = Command::new(tool)
        .args(args)
        .status()
        .map_err(DryrunError::io(format!("spawn {tool}")))?;
    if !status.success() {
        return Err(DryrunError::PersistStage(format!(
            "{tool} {args:?} failed ({status})"
        )));
    }
    Ok(())
}

/// Round `bytes` up to the next whole MiB (so the source-fs sector count is exact).
fn round_up_mib(bytes: u64) -> u64 {
    bytes.div_ceil(1024 * 1024) * (1024 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a fake `.img` of `img_len` bytes plus a `.layout.toml` beside it, so the prod-shape guard
    /// can be exercised without a real bake. `weights_size` `None` renders a layout with NO weights keys
    /// (the non-weights box shape).
    ///
    /// SPARSE (`set_len`, not a filled `Vec`): these fixtures are ~1.8 GiB each and the guard only
    /// `stat`s the file, so materializing the bytes would cost gigabytes of RAM and disk per case for
    /// no added coverage.
    fn fake_image(dir: &Path, img_len: u64, weights_size: Option<u64>) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let img = dir.join("fake.img");
        File::create(&img).unwrap().set_len(img_len).unwrap();
        let mut layout = String::from(
            "[layout]\nboot_offset = 0\nboot_size = 4096\npersist_skeleton_offset = 4096\n\
             persist_skeleton_size = 4096\nrootfs_offset = 8192\nrootfs_size = 4096\n\
             rootfs_verity_hash_offset = 2048\n",
        );
        if let Some(w) = weights_size {
            layout.push_str(&format!("weights_offset = 12288\nweights_size = {w}\n"));
        }
        std::fs::write(layout_sidecar(&img), layout).unwrap();
        img
    }

    /// The prod box: 2048 MiB guest. The other constants are MEASURED off the REAL produced prod `.img`
    /// (`orchard build --manifest prod-cotenant.toml`, 2026-07-24) — not projections. An earlier
    /// revision used a projection that over-estimated the image by ~170 MiB and under-estimated squashfs
    /// compression; it therefore missed a payload floor that REJECTED the real artifact.
    const PROD_RAM_MB: u32 = 2048;
    /// The pinned payload: `qwen3-vl-2b-instruct-q4km` + the f16 mmproj.
    const VL_PAIR_PAYLOAD: u64 = 1_926_804_800;
    /// The real prod image: 1804.4 MiB — BELOW the 2048 MiB guest (which is exactly why `image > RAM`
    /// is the wrong assertion), clearing the unbufferability bar by only **12.4 MiB**.
    const PROD_IMG_LEN: u64 = 1_892_032_512;
    /// The real baked weights component — 0.890 of the pinned payload (the f16 projector compresses
    /// ~11%, far more than the bench fixture's 1.6%). This is the value a 0.9 floor wrongly rejected.
    const PROD_WEIGHTS_COMPONENT: u64 = 1_715_101_696;

    /// The guard must FIRE on every prod-shape violation — a guard that only ever passes is not a
    /// guard. Each case is a concrete way the re-anchored proof could silently decay.
    #[test]
    fn the_prod_shape_guard_fires_on_every_violation() {
        let tmp = tempfile::tempdir().unwrap();
        let proof = ProdWeightsProof {
            pinned_payload_bytes: VL_PAIR_PAYLOAD,
        };

                                                                                                         
                                                                                                      
                                                                                                     
                                                                                                  
        let good = fake_image(tmp.path(), PROD_IMG_LEN, Some(PROD_WEIGHTS_COMPONENT));
        assert_prod_weights_shape(&good, PROD_RAM_MB, proof)
            .expect("the REAL produced prod image must pass both floors");

                                                                                                       
                                                                                                 
                             
        let small = fake_image(&tmp.path().join("a"), 917_729_280, Some(VL_PAIR_PAYLOAD));
        let e = assert_prod_weights_shape(&small, PROD_RAM_MB, proof).unwrap_err();
        assert!(e.contains("fits inside guest RAM"), "{e}");

                                                                                     
        let ram = u64::from(PROD_RAM_MB) * 1024 * 1024;
        let boundary = fake_image(
            &tmp.path().join("b"),
            ram - super::super::prod::INSTALL_MIN_RAM_BYTES,
            Some(VL_PAIR_PAYLOAD),
        );
        assert!(
            assert_prod_weights_shape(&boundary, PROD_RAM_MB, proof).is_err(),
            "image + floor == RAM must fail: buffering still fits"
        );

                                                                                                            
        let plain = fake_image(&tmp.path().join("c"), PROD_IMG_LEN, None);
        let e = assert_prod_weights_shape(&plain, PROD_RAM_MB, proof).unwrap_err();
        assert!(e.contains("NO weights component"), "{e}");

                                                                                                     
                                                                                                       
                                                    
        let bench = fake_image(&tmp.path().join("d"), PROD_IMG_LEN, Some(752_880_192));
        let e = assert_prod_weights_shape(&bench, PROD_RAM_MB, proof).unwrap_err();
        assert!(e.contains("SMALLER payload"), "{e}");
    }

    /// REGRESSION PIN for the defect produced bytes caught: the payload floor must tolerate the real,
    /// data-dependent squashfs gain without opening the door to a materially smaller payload.
    ///
    /// A 90% floor looked safe against the bench fixture (which compresses only 1.6%) and REJECTED the
    /// genuine prod image (which compresses 11.0%, because its mmproj is f16 rather than quantized).
    /// The floor now sits at 70%: it covers the measured range with headroom for a future pin that
    /// compresses better still, while a bench-sized payload is 2.3× below the prod one and is rejected.
    #[test]
    fn the_payload_floor_tolerates_real_compression_but_not_a_smaller_model() {
        let tmp = tempfile::tempdir().unwrap();
        let proof = ProdWeightsProof {
            pinned_payload_bytes: VL_PAIR_PAYLOAD,
        };

                                                                                                      
        let real = fake_image(tmp.path(), PROD_IMG_LEN, Some(PROD_WEIGHTS_COMPONENT));
        assert_prod_weights_shape(&real, PROD_RAM_MB, proof)
            .expect("the measured 0.890 compression ratio must pass the floor");

                                                                          
        let compressible = fake_image(
            &tmp.path().join("w"),
            PROD_IMG_LEN,
            Some(VL_PAIR_PAYLOAD * 75 / 100),
        );
        assert_prod_weights_shape(&compressible, PROD_RAM_MB, proof)
            .expect("a more-compressible pin must not trip the floor");

                                                                                                
        let bad = fake_image(
            &tmp.path().join("x"),
            PROD_IMG_LEN,
            Some(VL_PAIR_PAYLOAD / 2),
        );
        assert!(assert_prod_weights_shape(&bad, PROD_RAM_MB, proof).is_err());

                                                                                                       
                                                      
        let bench = fake_image(&tmp.path().join("y"), PROD_IMG_LEN, Some(740_515_840));
        assert!(
            assert_prod_weights_shape(&bench, PROD_RAM_MB, proof).is_err(),
            "the bench weights component must not pass where production is required"
        );
    }

    #[test]
    fn with_http_probe_consumes_the_manifest_probe_target() {
                                                                                                         
                                                                                                         
                                                                                                       
                                                                                                            
        let d = DryrunOpts::default();
        assert_eq!(d.guest_https_port, 443);
        assert_eq!(d.probe_path, "/");
        let o = DryrunOpts::default().with_http_probe(8080, "/health");
        assert_eq!(
            o.guest_https_port, 8080,
            "the guest HTTPS port is the declared probe.port"
        );
        assert_eq!(
            o.probe_path, "/health",
            "the probe URL path is the declared probe.path"
        );
    }

    #[test]
    fn dryrun_opts_default_is_hermetic() {
                                                                                          
                                                                                                   
                                                                                                
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                               
        assert!(
            DryrunOpts::default().restrict_net,
            "orchard dryrun must be hermetic by default"
        );
        assert!(
            super::qemu::user_netdev_arg(&DryrunOpts::default()).contains(",restrict=on"),
            "the default DryrunOpts must RENDER restrict=on in the -netdev arg"
        );
    }

    #[test]
    fn round_up_mib_rounds_to_whole_mebibytes() {
        const MIB: u64 = 1024 * 1024;
        assert_eq!(round_up_mib(0), 0);
        assert_eq!(round_up_mib(1), MIB);
        assert_eq!(round_up_mib(MIB), MIB);
        assert_eq!(round_up_mib(MIB + 1), 2 * MIB);
                                                                                                       
        let fs = round_up_mib(166_653_952 + 64 * MIB);
        assert_eq!(fs % MIB, 0);
        assert!(fs >= 166_653_952 + 64 * MIB);
    }
}
