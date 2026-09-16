//! `orchard update <host> --image <img>` — the operator-push A/B OS-update ceremony (os-update A/B v1
//! T21, component C-E). Eight steps, all fail-closed, never auto-retrying:
//!
//! 1. clocked LOCAL verify of the `.img`/vmlinuz/initramfs `.sig` triple (refuse an unsigned build);
//! 2. read the target `.img`'s baked `image_version`/`min_delegation_ctr` + `firmware` from its
//!    `.layout.toml`, and `root_hash`/`verity_hash_offset` from the boot-fs `extlinux.conf`; refuse a
//!    non-`seabios-gpt` image (the MBR box migrates via the GPT takeover, never a pushed update);
//! 3. connect under a persisted host-key PIN ([`super::host_pins`]) + read `fb-update status`;
//! 4. compose the signed manifest (`version = image_version`, the §4a field set);
//! 5. EXPLICIT operator authorize (y/N; `--confirmed` for a scripted fleet loop — never silent);
//! 6. sign the manifest with the `UpdateImage` delegation (fail-closed "run `orchard redelegate`" if a
//!    legacy key set lacks it);
//! 7. stream the framed apply pipe (`manifest ‖ bundle ‖ rootfs ‖ kernel ‖ initramfs`) to `fb-update
//!    apply` over ssh (no scp on the box, by design);
//! 8. watch: bounded reconnect poll → `fb-update status` → report COMMITTED / ROLLED-BACK / UNREACHABLE.
//!
//! Structure: [`prepare_local_image`] does the image-dependent steps 1/2/4 (verify, layout, firmware
//! refuse, compose + slice) → a [`PreparedPush`]; [`run_ceremony`] does the orchestration steps 3/5–8
//! behind [`UpdateOps`] (host-key fingerprint, y/N prompt, the two ssh execs, the watch poll) so it is
//! `FakeOps`-testable. All composition / parsing / framing / report logic is pure.

use std::path::{Path, PathBuf};

use dragonfruit::Purpose;
use sha2::{Digest, Sha256};

use super::artifact_sign::sign_bytes;
use super::build_image::Firmware;
use super::host_pins::{self, HostPinOpts, PinError, PinOutcome, PinnedKey};
use super::keys::DeployKeyError;

/// §4a size bounds (mirror the box-side apply guards; the ceremony refuses BEFORE streaming so a
/// too-large component never leaves the operator host).
const SLOT_SIZE_BYTES: u64 = 64 * 1024 * 1024;
const SLOT_BOOT_BUDGET: u64 = 56 * 1024 * 1024;

/// The side effects the ceremony drives, behind a trait so the orchestration is `FakeOps`-testable.
pub trait UpdateOps {
    /// The box's presented SSH host-key fingerprint (for the [`host_pins`] resolve, step 3).
    fn host_fingerprint(&self) -> Result<String, String>;
    /// Prompt the operator for a y/N decision. Used for BOTH the step-5 push authorize (which
    /// `--confirmed` pre-authorizes, so this is not called for it under `--confirmed`) AND the
    /// step-3 first-contact host-key trust prompt (`resolve_or_bootstrap_pin`), which runs regardless
                                                                                             
    fn confirm_authorize(&self, summary: &str) -> Result<bool, String>;
    /// Run `fb-update status` over ssh under the resolved pin; return the machine-readable block (§4g).
    fn fb_update_status(&self) -> Result<String, String>;
    /// Stream the framed apply pipe to `fb-update apply` over ssh (step 7). The box arms + reboots.
    fn fb_update_apply(&self, framed: &[u8]) -> Result<(), String>;
    /// Watch (step 8): bounded reconnect poll of `fb-update status`, keyed on WHICH host key the box
    /// presents. The runtime host key is image-derived, so the box answering under the pushed image's
    /// POST-FLIP key is cryptographic proof the PEER booted that image (`WatchOutcome::Settled{post_flip:
    /// true}`); answering under the PRE-PUSH pin means the old image (rollback / never-armed,
    /// `post_flip: false`); no settled answer under either key within the window is `TimedOut`. This
    /// proves the IMAGE the peer runs, not WHICH box it is: the key is deterministic in the image, so
    /// two same-version boxes share it (BOOT-1). That is sufficient here — the ceremony already fixed
    /// the target host in step 3 under the durable pin — but it does not turn the watch into a box
    /// identity check. The impl owns the poll cadence/deadline; the verdict rests on `post_flip`, never
                                                    
    fn watch_for_settled_status(&self) -> Result<WatchOutcome, String>;
}

/// The step-8 watch result. `Settled` carries which of the two accepted keys the box presented and
/// its parsed-elsewhere status block; `TimedOut` carries an operator-facing diagnosis (the last probe
/// failure reason, and — since a slow commit may have rotated the key past the deadline — the derived
/// post-flip fingerprint the operator would pin to recover).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchOutcome {
    Settled { post_flip: bool, block: String },
    TimedOut { note: String },
}

/// How the operator authorized the push (step 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorize {
    /// Interactive y/N via [`UpdateOps::confirm_authorize`].
    Interactive,
    /// `--confirmed`: a scripted fleet loop pre-authorized the push. NOT a silent host-key TOFU — the
    /// host-pin store's first-contact bootstrap stays non-silent regardless; this only skips the push y/N.
    Confirmed,
}

/// The image-independent ceremony inputs (host, keys, authorize mode, the host-pin store).
pub struct CeremonyOpts<'a> {
    pub host: &'a str,
    pub keys_dir: &'a Path,
    pub authorize: Authorize,
    pub host_pin: HostPinOpts<'a>,
}

/// The result of [`prepare_local_image`] — everything derived from the local `.img` (steps 1/2/4),
/// ready for the orchestration to sign + stream. The manifest is composed but NOT yet signed.
pub struct PreparedPush {
    pub firmware: Firmware,
    pub manifest: UpdateManifest,
    pub manifest_wire: String,
    /// The runtime host key the box will present AFTER a committed flip — derived offline from the
    /// pushed image (`oneshots_offline::offline_runtime_hostkey`, the same derivation `deploy prod`'s
    /// reconnect leg pins). The runtime host key is IMAGE-DERIVED, so a committed A/B flip rotates it
    /// BY CONSTRUCTION: the watch must accept it (else every committed update reads UNREACHABLE
                                                                                                       
    /// re-pins to it on COMMITTED.
    pub post_flip_hostkey: PostFlipHostKey,
    components: Components,
}

/// The image-derived post-flip runtime host key, in the two forms the ceremony needs: the
/// `SHA256:…` fingerprint (the pin store's format) and the `ssh-ed25519 AAAA…` pubkey line (the
/// watch's known_hosts entry). Construct through [`PostFlipHostKey::new`], which RECOMPUTES the
/// fingerprint from the pubkey line and refuses a pair that does not correspond — so a swapped OR a
/// well-formed-but-mismatched `(pubkey, fingerprint)` pair is refused, not a silent single-key watch
                                                                                            
/// fingerprint have no narrower shared newtype in the tree), but no construction site can populate
/// them with an inconsistent pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostFlipHostKey {
    fingerprint: String,
    pubkey_line: String,
}

impl PostFlipHostKey {
    /// Build from the two derived forms, refusing a swapped, malformed, or non-corresponding pair.
    /// `pubkey_line` must be an `ssh-ed25519 <base64>` line; `fingerprint` must be the OpenSSH
    /// `SHA256:…` of THAT key (recomputed and compared here).
    pub fn new(pubkey_line: String, fingerprint: String) -> Result<Self, String> {
        let b64 = pubkey_line
            .trim()
            .strip_prefix("ssh-ed25519 ")
            .ok_or_else(|| {
                format!(
                    "post-flip host key: pubkey line {pubkey_line:?} is not an ssh-ed25519 key line \
                     (arguments swapped?)"
                )
            })?
                                                                                            
            .split_whitespace()
            .next()
            .unwrap_or_default();
        use base64::Engine as _;
        let wire = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("post-flip host key: pubkey blob is not valid base64: {e}"))?;
        use sha2::{Digest, Sha256};
        let recomputed = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&wire))
        );
        if recomputed != fingerprint.trim() {
            return Err(format!(
                "post-flip host key: fingerprint {fingerprint:?} does not correspond to the pubkey \
                 line (recomputed {recomputed:?})"
            ));
        }
        Ok(PostFlipHostKey {
            fingerprint: fingerprint.trim().to_string(),
            pubkey_line,
        })
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    pub fn pubkey_line(&self) -> &str {
        &self.pubkey_line
    }
}

/// What the ceremony did to the durable host-pin store — surfaced to the CLI so a failed rotation is
                                                                                                 
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinAction {
    /// No commit, or the box already presented the pinned key (no rotation needed).
    Unchanged,
    /// The pin was superseded to the image-derived post-flip fingerprint (old pin archived).
    Superseded { to: String },
    /// A commit happened but the pin could NOT be rotated — the next contact refuses against the
    /// stale pin until resolved by hand. The verdict stays COMMITTED (the box state is a fact), but
    /// the CLI exits non-zero so a fleet loop sees it.
    SupersedeFailed { detail: String },
}

/// The full step-8 outcome: the terminal verdict plus what happened to the pin store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyOutcome {
    pub report: UpdateReport,
    pub pin: PinAction,
}

impl CeremonyOutcome {
    /// The CLI's zero-exit predicate for the whole ceremony: a clean commit AND a pin store left
    /// consistent with it. A COMMITTED flip whose supersede FAILED exits non-zero, because the next
    /// contact refuses against the now-stale pin and under `--confirmed` the warning line alone is
                                                                                                
    /// expression there is unreachable from any test (`PreparedPush` has no public constructor,
                
    pub fn is_success(&self) -> bool {
        self.report.is_success() && !matches!(self.pin, PinAction::SupersedeFailed { .. })
    }

                                                                                                  
    /// leads with the verdict summary and APPENDS the pin failure when there is one — the two are
    /// independent (a supersede runs on any key-rotating outcome, so a SupersedeFailed can sit under
    /// UNREACHABLE as well as COMMITTED), so keying on the pin action alone would mislabel an
    /// UNREACHABLE verdict as "COMMITTED but …". Meaningful only when `!is_success()`; on the success
    /// path it returns the verdict summary harmlessly.
    pub fn exit_reason(&self) -> String {
        match &self.pin {
            PinAction::SupersedeFailed { detail } => format!(
                "{} — additionally, the host pin could NOT be rotated ({detail}); the pin store is \
                 now inconsistent with the box and the next contact will refuse until re-pinned by \
                 hand",
                self.report.summary()
            ),
            _ => self.report.summary(),
        }
    }
}

/// The terminal verdict of a push (step 8), with an honest exit intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateReport {
    /// The box booted the new slot, health-probed, and committed it (floors advanced).
    Committed { version: u64 },
    /// The new slot failed its probation (panic / bad verity / unhealthy tenant) and the box rolled
    /// back to the old slot — the update did NOT take, but the box is serving.
    RolledBack { version: u64 },
    /// The box never came back within the watch window. Names the M1-residual signal explicitly.
    Unreachable { note: String },
}

impl UpdateReport {
    /// A non-zero exit for the operator-facing CLI on anything but a clean commit (honest exits).
    pub fn is_success(&self) -> bool {
        matches!(self, UpdateReport::Committed { .. })
    }
    /// The one-line operator-facing verdict.
    pub fn summary(&self) -> String {
        match self {
            UpdateReport::Committed { version } => {
                format!("COMMITTED — the box is serving v{version}.")
            }
            UpdateReport::RolledBack { version } => format!(
                "ROLLED-BACK — the box is serving v{version}; the pushed update did not take \
                 (the new slot failed probation and rolled back, or the push never armed)."
            ),
            UpdateReport::Unreachable { note } => format!("UNREACHABLE — {note}"),
        }
    }
}

/// The parsed subset of the §4g `fb-update status` block the ceremony consumes. Extra keys are ignored
/// (forward-compatible); the ones we read are required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxStatus {
    pub firmware: String,
    pub active_slot: String,
    pub image_version: u64,
    pub version_floor: u64,
    pub minctr_floor: u64,
    pub probation: bool,
    pub backup_age_secs: Option<u64>,
    pub uptime_secs: Option<u64>,
}

/// Parse the machine-readable `fb-update status` block (§4g): `key = value` lines, LF. Required keys
/// fail closed; unknown keys are ignored.
pub fn parse_status(block: &str) -> Result<BoxStatus, String> {
    let mut map = std::collections::HashMap::new();
    for line in block.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("status line without `=`: {line:?}"))?;
        map.insert(k.trim().to_string(), v.trim().to_string());
    }
    let req = |k: &str| -> Result<String, String> {
        map.get(k)
            .cloned()
            .ok_or_else(|| format!("status missing required key `{k}`"))
    };
    let req_u64 = |k: &str| -> Result<u64, String> {
        req(k)?
            .parse::<u64>()
            .map_err(|_| format!("status key `{k}` is not a u64"))
    };
    let opt_u64 = |k: &str| -> Option<u64> { map.get(k).and_then(|s| s.parse::<u64>().ok()) };
    Ok(BoxStatus {
        firmware: req("firmware")?,
        active_slot: req("active_slot")?,
        image_version: req_u64("image_version")?,
        version_floor: req_u64("version_floor")?,
        minctr_floor: req_u64("minctr_floor")?,
                                                                                               
                                                                                                     
                                                                                              
                                                                                             
        probation: req("probation")? != "none",
        backup_age_secs: opt_u64("backup_age_secs"),
        uptime_secs: opt_u64("uptime_secs"),
    })
}

/// The §4a update manifest, composed from the target `.img`'s local artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateManifest {
    pub version: u64,
    pub image_sha256: [u8; 32],
    pub root_hash: String,
    pub verity_hash_offset: u64,
    pub rootfs_sha256: [u8; 32],
    pub rootfs_size: u64,
    pub kernel_sha256: [u8; 32],
    pub kernel_size: u64,
    pub initramfs_sha256: [u8; 32],
    pub initramfs_size: u64,
}

impl UpdateManifest {
    /// Serialize to the exact §4a wire text (`key = value`, LF, `firmware = seabios-gpt`, fixed field
    /// order). The box's hand-rolled parser + the ceremony's composer MUST agree byte-for-byte.
    pub fn to_wire(&self) -> String {
        format!(
            "format = 1\n\
             firmware = seabios-gpt\n\
             version = {}\n\
             image_sha256 = {}\n\
             root_hash = {}\n\
             verity_hash_offset = {}\n\
             rootfs_sha256 = {}\n\
             rootfs_size = {}\n\
             kernel_sha256 = {}\n\
             kernel_size = {}\n\
             initramfs_sha256 = {}\n\
             initramfs_size = {}\n",
            self.version,
            hex64(&self.image_sha256),
            self.root_hash,
            self.verity_hash_offset,
            hex64(&self.rootfs_sha256),
            self.rootfs_size,
            hex64(&self.kernel_sha256),
            self.kernel_size,
            hex64(&self.initramfs_sha256),
            self.initramfs_size,
        )
    }
}

fn hex64(b: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// The component bytes the frame streams, resolved from the local `.img` + its sidecars.
struct Components {
    rootfs: Vec<u8>,
    kernel: Vec<u8>,
    initramfs: Vec<u8>,
}

impl PreparedPush {
    /// The composed (unsigned) §4a manifest. The produced-bytes gate CLONES this, mutates one field
    /// (a bad `root_hash`, a shrunk `version`, a flipped `firmware`), re-signs, and re-frames to drive
    /// a refusal/rollback case — the exact wire the ceremony would send, minus one deliberate defect.
    pub fn manifest(&self) -> &UpdateManifest {
        &self.manifest
    }
    /// The three component byte-slices in stream order (rootfs ‖ kernel ‖ initramfs). The gate streams
    /// these verbatim for a happy push, or a truncated/corrupt clone for the unloadable-kernel case.
    pub fn components(&self) -> (&[u8], &[u8], &[u8]) {
        (
            &self.components.rootfs,
            &self.components.kernel,
            &self.components.initramfs,
        )
    }
}

/// Frame the §4c apply pipe from explicit parts — the PUBLIC sibling of [`frame_apply_stream`] the
/// `make boot-gate-update` harness uses to stream a MUTATED variant (the ceremony frames from its own
/// [`Components`]; the gate frames arbitrary bytes so it can inject a defect). Same byte layout:
/// `u64-le manifest_len ‖ manifest ‖ u64-le bundle_len ‖ bundle ‖ rootfs ‖ kernel ‖ initramfs`.
pub fn frame_apply_pipe(
    manifest: &[u8],
    bundle: &[u8],
    rootfs: &[u8],
    kernel: &[u8],
    initramfs: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        16 + manifest.len() + bundle.len() + rootfs.len() + kernel.len() + initramfs.len(),
    );
    out.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
    out.extend_from_slice(manifest);
    out.extend_from_slice(&(bundle.len() as u64).to_le_bytes());
    out.extend_from_slice(bundle);
    out.extend_from_slice(rootfs);
    out.extend_from_slice(kernel);
    out.extend_from_slice(initramfs);
    out
}

/// Frame the §4c apply pipe: `u64-le manifest_len ‖ manifest ‖ u64-le bundle_len ‖ bundle ‖ rootfs ‖
/// kernel ‖ initramfs`. EOF-exact by construction (the box refuses trailing bytes).
fn frame_apply_stream(manifest: &[u8], bundle: &[u8], comps: &Components) -> Vec<u8> {
    frame_apply_pipe(
        manifest,
        bundle,
        &comps.rootfs,
        &comps.kernel,
        &comps.initramfs,
    )
}

/// The `.img` sidecar path with a REPLACED extension (`recipes-image-x.img` → `…-x.layout.toml`).
fn sibling(image: &Path, ext: &str) -> PathBuf {
    image.with_extension(ext)
}

/// Read the NEW image's dm-verity `root_hash` + `verity_hash_offset` from the boot-fs `extlinux.conf`'s
/// slot APPEND (the values live ONLY in the baked APPEND + build output — context map). Byte-faithful:
/// the `fb.root-hash` token is passed through verbatim (the box keeps it un-normalized, R6-1).
///
/// `pub(crate)` so `orchard status`'s `--image` comparison (`deploy::status::compare_image`) reads the
                                                                                                       
/// plan's file-structure line named `verify.rs`, but this reader has always lived here beside the other
/// update local-image readers; lifted in place keeps the ceremony's call site untouched).
pub(crate) fn read_root_hash_and_offset(
    img: &[u8],
    boot_offset: u64,
    boot_size: u64,
) -> Result<(String, u64), String> {
    let boot = img
        .get(boot_offset as usize..(boot_offset + boot_size) as usize)
        .ok_or("layout boot range exceeds .img")?;
    let conf = syslinux_install::read_file(boot, "syslinux/extlinux.conf")
        .map_err(|e| format!("read boot-fs syslinux/extlinux.conf: {e}"))?;
    let conf = String::from_utf8(conf).map_err(|e| format!("extlinux.conf not utf-8: {e}"))?;
    let token = |key: &str| -> Option<String> {
        conf.split_whitespace()
            .find_map(|t| t.strip_prefix(key))
            .map(str::to_string)
    };
    let root_hash =
        token("fb.root-hash=").ok_or("boot-fs extlinux.conf has no fb.root-hash token")?;
    let offset = token("fb.verity-hash-offset=")
        .ok_or("boot-fs extlinux.conf has no fb.verity-hash-offset token")?
        .parse::<u64>()
        .map_err(|_| "fb.verity-hash-offset is not a u64".to_string())?;
    Ok((root_hash, offset))
}

/// Steps 1/2/4 — everything derived from the local `.img`: verify the sig triple (refuse unsigned),
/// parse the `.layout.toml` (refuse a non-seabios-gpt image, row 16), read the boot-fs root hash, slice
/// the rootfs component + read the kernel/initramfs sidecars, and compose the size-bounded manifest.
pub fn prepare_local_image(image: &Path, keys_dir: &Path) -> Result<PreparedPush, String> {
                                                                                                      
                                                                                                       
                                                                    
    let pin = super::artifact_verify::read_root_pin(keys_dir, None)
        .map_err(|e| format!("update: reading the operator artifact pin: {e}"))?
        .ok_or_else(|| {
            "update: no operator artifact pin (artifact-root.pub) — the update path requires a signed \
             build; run `orchard generate-keys --artifact-signing …` and sign this image"
                .to_string()
        })?;
    super::artifact_verify::preflight_verify_triple(
        Some(&pin),
        image,
        &sibling(image, "vmlinuz"),
        &sibling(image, "initramfs"),
    )
    .map_err(|e| format!("update: refusing to push an unsigned/invalid build — {e}"))?;

                                  
    let layout_str = std::fs::read_to_string(sibling(image, "layout.toml"))
        .map_err(|e| format!("update: read layout: {e}"))?;
    let layout = super::verify::parse_layout(&layout_str)?;
    if layout.firmware != Firmware::SeabiosGpt {
        return Err(format!(
            "update: refusing to push a {:?} image — the A/B update path is seabios-gpt only; an MBR \
             box migrates once via the GPT takeover + restore-from, never a pushed update",
            layout.firmware
        ));
    }

                                                                      
    let img = std::fs::read(image).map_err(|e| format!("update: read {}: {e}", image.display()))?;
    let (off, size) = (layout.rootfs_offset as usize, layout.rootfs_size as usize);
    let rootfs = img
        .get(off..off + size)
        .ok_or_else(|| {
            format!(
                "update: layout rootfs range {off}..{} exceeds .img",
                off + size
            )
        })?
        .to_vec();
    let read_side = |ext: &str| -> Result<Vec<u8>, String> {
        std::fs::read(sibling(image, ext)).map_err(|e| format!("update: read {ext}: {e}"))
    };
    let components = Components {
        rootfs,
        kernel: read_side("vmlinuz")?,
        initramfs: read_side("initramfs")?,
    };
    let (root_hash, verity_hash_offset) =
        read_root_hash_and_offset(&img, layout.boot_offset, layout.boot_size)?;

    let rootfs_size = components.rootfs.len() as u64;
    let kernel_size = components.kernel.len() as u64;
    let initramfs_size = components.initramfs.len() as u64;
    if rootfs_size > SLOT_SIZE_BYTES {
        return Err(format!(
            "update: rootfs {rootfs_size} B exceeds SLOT_SIZE_BYTES {SLOT_SIZE_BYTES} — refusing before stream"
        ));
    }
    if kernel_size + initramfs_size > SLOT_BOOT_BUDGET {
        return Err(format!(
            "update: kernel+initramfs {} B exceeds SLOT_BOOT_BUDGET {SLOT_BOOT_BUDGET}",
            kernel_size + initramfs_size
        ));
    }
    let manifest = UpdateManifest {
        version: layout.image_version,
        image_sha256: Sha256::digest(&img).into(),
        root_hash,
        verity_hash_offset,
        rootfs_sha256: Sha256::digest(&components.rootfs).into(),
        rootfs_size,
        kernel_sha256: Sha256::digest(&components.kernel).into(),
        kernel_size,
        initramfs_sha256: Sha256::digest(&components.initramfs).into(),
        initramfs_size,
    };
                                                                                                  
                                                                                                    
                                                                                                   
                                                                                                   
                                                                                                    
                                                                                                     
                                                                                                   
                                                                                   
    let (pubkey_line, fingerprint) = crate::oneshots_offline::offline_runtime_hostkey_verified(
        &img,
        &layout_str,
        &manifest.root_hash,
    )
    .map_err(|e| format!("update: deriving the post-flip runtime host key: {e}"))?;
    Ok(PreparedPush {
        firmware: layout.firmware,
        manifest_wire: manifest.to_wire(),
        manifest,
        post_flip_hostkey: PostFlipHostKey::new(pubkey_line, fingerprint)?,
        components,
    })
}

/// Interpret the watch outcome (step 8) into the operator verdict, resting on WHICH host key the box
                                                                                                     
/// the box to have answered under the image-derived POST-FLIP key (proof it booted the pushed image)
/// AND to report the pushed version AND to have advanced its anti-rollback floor to at least that
                                                                                                      
                                                                                                      
/// below the pushed version proves the flip is NOT durable (the `Stale` arm clears probation without
/// committing DEFAULT); but a floor at-or-above the pushed version does NOT prove DEFAULT was flipped
/// — the box has a second floor writer (the `seed-update-floors` reconcile) and the §4g status wire
/// carries no DEFAULT-slot field, so full durability is not provable from the block. Any of the three
/// corroborators missing is an inconsistency, reported as UNREACHABLE, never COMMITTED. A pre-push-key
                                                                                                     
/// with the watch's diagnosis.
fn interpret_watch(pushed_version: u64, outcome: WatchOutcome) -> Result<UpdateReport, String> {
    Ok(match outcome {
        WatchOutcome::Settled {
            post_flip: true,
            block,
        } => {
            let s = parse_status(&block)?;
            if s.image_version != pushed_version {
                                                                                                
                                                                                                    
                UpdateReport::Unreachable {
                    note: format!(
                        "the box presents the pushed image's runtime host key but reports v{} not \
                         the pushed v{pushed_version} — inconsistent; inspect the box before retrying",
                        s.image_version
                    ),
                }
            } else if s.version_floor < pushed_version {
                                                                                                      
                                                                                                        
                                                        
                UpdateReport::Unreachable {
                    note: format!(
                        "the box is running v{pushed_version} with probation cleared but its \
                         anti-rollback floor is still v{} — the commit did not make the flip durable \
                         (mark-good cleared the record without advancing the floor); inspect the box, \
                         the next reboot may return to the old slot",
                        s.version_floor
                    ),
                }
            } else {
                UpdateReport::Committed {
                    version: s.image_version,
                }
            }
        }
        WatchOutcome::Settled {
            post_flip: false,
            block,
        } => {
            let s = parse_status(&block)?;
            UpdateReport::RolledBack {
                version: s.image_version,
            }
        }
        WatchOutcome::TimedOut { note } => UpdateReport::Unreachable { note },
    })
}

/// Steps 3/5–8 — the orchestration over a [`PreparedPush`], behind [`UpdateOps`]. Returns the terminal
/// report, or an `Err` for any pre-promotion refusal (host-key change, un-authorized, missing
/// delegation, stream failure). Never auto-retries.
/// `pin_path` is the committed `pinned-artifact-root.toml` (the durable rung-adopted marker
                                                                                               
pub fn run_ceremony(
    prepared: &PreparedPush,
    pin_path: &Path,
    opts: &CeremonyOpts<'_>,
    ops: &dyn UpdateOps,
) -> Result<CeremonyOutcome, String> {
                                                                                                  
    let presented = ops.host_fingerprint()?;
    let pin: PinnedKey = resolve_or_bootstrap_pin(opts, ops, &presented)?;
    let before = parse_status(&ops.fb_update_status()?)?;
    if before.firmware != "seabios-gpt" {
        return Err(format!(
            "update: the box reports firmware={:?}, not seabios-gpt — refusing",
            before.firmware
        ));
    }

                                                                                     
                                                                                               
                                                                                             
                                                                                                
                                                                                               
                             
    if prepared.manifest.version <= before.version_floor {
        return Err(format!(
            "update: refusing to push v{} — the box's anti-rollback floor is already v{} (a re-push \
             of a committed-or-older image). Rebuild with a higher `--image-version` (the box would \
             refuse this as below-floor).",
            prepared.manifest.version, before.version_floor
        ));
    }

                                                                                                   
    let summary = format!(
        "push v{} to {} (active slot {}, at v{}, floor v{}); root_hash {}",
        prepared.manifest.version,
        opts.host,
        before.active_slot,
        before.image_version,
        before.version_floor,
        prepared.manifest.root_hash,
    );
    let authorized = match opts.authorize {
        Authorize::Confirmed => true,
        Authorize::Interactive => ops.confirm_authorize(&summary)?,
    };
    if !authorized {
        return Err(
            "update: operator did not authorize the push — aborted (no changes made)".to_string(),
        );
    }

                                                                                                         
    let bundle = sign_update_manifest(opts.keys_dir, pin_path, prepared.manifest_wire.as_bytes())?;

                                                                                      
    let framed = frame_apply_stream(
        prepared.manifest_wire.as_bytes(),
        &bundle,
        &prepared.components,
    );
    ops.fb_update_apply(&framed)
        .map_err(|e| format!("update: streaming to fb-update apply failed: {e}"))?;

                                                                                                  
    let outcome = ops.watch_for_settled_status()?;
                                                                                                     
                                                                                                
                                                                                                    
                                                                                                       
                                                                                                        
    let key_rotated = matches!(
        outcome,
        WatchOutcome::Settled {
            post_flip: true,
            ..
        }
    );
    let report = interpret_watch(prepared.manifest.version, outcome)?;

                                                                                                     
                                                                                                    
                                                                                                         
                                                                                                     
                                                                 
    let pin_action = if key_rotated {
        let new = prepared.post_flip_hostkey.fingerprint();
        if new != pin.fingerprint {
            match host_pins::supersede_pin(opts.host, &pin.fingerprint, new, &opts.host_pin) {
                Ok(_) => PinAction::Superseded {
                    to: new.to_string(),
                },
                Err(e) => PinAction::SupersedeFailed {
                    detail: e.to_string(),
                },
            }
        } else {
            PinAction::Unchanged
        }
    } else {
        PinAction::Unchanged
    };
    Ok(CeremonyOutcome {
        report,
        pin: pin_action,
    })
}

/// Step 3's pin resolve, threading the interactive first-contact confirm through [`UpdateOps`].
fn resolve_or_bootstrap_pin(
    opts: &CeremonyOpts<'_>,
    ops: &dyn UpdateOps,
    presented: &str,
) -> Result<PinnedKey, String> {
    match host_pins::resolve_host_pin(opts.host, presented, &opts.host_pin) {
        Ok(PinOutcome::Stable(k)) | Ok(PinOutcome::Bootstrapped(k)) => Ok(k),
        Err(PinError::FirstContactNeedsConfirm { presented, .. }) => {
            let ok = ops.confirm_authorize(&format!(
                "FIRST CONTACT with {}: trust the presented SSH host key {presented}? (this pins it)",
                opts.host
            ))?;
            if !ok {
                return Err(
                    "update: operator declined to trust the box's host key — aborted".to_string(),
                );
            }
            host_pins::commit_pin(opts.host, &presented, &opts.host_pin).map_err(|e| e.to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Sign the manifest bytes with the operator's `UpdateImage` delegation — the C1 wire bundle
/// (254 B), routed through the `plan_signing` rung matrix (debt-burndown Component D). `pin_path`
/// is the COMMITTED `pinned-artifact-root.toml` (resolved as the build arm does) — NOT
/// `update.rs`'s preflight `read_root_pin` file (`keys_dir/artifact-root.pub`): the committed
/// toml is the durable "rung adopted" marker plan_signing keys off; `artifact-root.pub` is
/// present whenever any keys exist (audit L-3 — never conflate the two). Fail-closed with the
/// actionable "run `orchard redelegate`" message on a legacy 4-delegation set.
fn sign_update_manifest(
    keys_dir: &Path,
    pin_path: &Path,
    manifest: &[u8],
) -> Result<Vec<u8>, String> {
    use super::artifact_sign::{SignPlan, plan_signing};
    let plan = plan_signing(keys_dir, pin_path).map_err(|e| match e {
        DeployKeyError::MissingDelegation { .. } => e.to_string(),                                      
        other => format!("update: cannot plan the manifest signing: {other}"),
    })?;
    match plan {
        SignPlan::Host(set) => {
            sign_bytes(&set, Purpose::UpdateImage, manifest).map_err(|e| e.to_string())
        }
        SignPlan::Docker => super::artifact_sign::docker_sign_manifest_bytes(
            keys_dir,
            Purpose::UpdateImage,
            manifest,
            "update-manifest",
        ),
        SignPlan::UnsignedFloor => Err(
            "update: no artifact signing rung is configured (no keys, no committed \
             pinned-artifact-root.toml) — an OS update never pushes unsigned; run \
             `orchard generate-keys --artifact-signing …` first"
                .to_string(),
        ),
    }
}

/// How an `ssh … fb-update apply` invocation ended, classified from the exit status + captured
/// stderr. Grounded on the BOX side (`fb_update.rs`): a SUCCESSFUL apply NEVER exits — it prints
/// `armed <slot> — rebooting` to stderr and calls `reboot(2)`, so the ssh session always dies with
/// ssh's OWN exit 255 as the box goes down (a clean remote exit is unreachable on success); a
/// REFUSAL prints `fb-update apply: refused: …` and exits with the `ApplyError` codes 10..=19
/// (`fb-update/src/apply.rs` exit_code), which ssh forwards verbatim (never 255). So exit 255 is the
/// arm-and-reboot shape OR any ssh-local/transport error (ssh(1): "255 if an error occurred"). The
/// classifier cannot tell those apart, and does not try: it enters the WATCH, whose HOST-KEY evidence
/// is what decides the verdict (`interpret_watch` requires the box to present the image-derived
/// post-flip key for COMMITTED). A transport failure that never armed the box therefore cannot yield
/// COMMITTED — the box never presents the post-flip key. The refusal marker is used in the
/// CONSERVATIVE direction only: it demotes a 255 to a hard error (so a refusal whose exit code was
/// lost to a racing drop is still reported), never promotes an exit to success. Because a real
/// refusal reaches this classifier ONLY via the scoped-writer transport ([`stream_apply_and_classify`],
                                                                                               
/// early-refuse classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApplyExit {
    /// Exit 0 — theoretical on the real box (reboot preempts the exit), kept for completeness.
    Streamed,
    /// The connection died (ssh exit 255, or a signal-terminated ssh) with no refusal marker:
    /// proceed to the watch, which is the real confirmation.
    SeveredProceedToWatch { note: String },
    /// The box refused (a real remote exit code, or a refusal marker in stderr) — hard error.
    Refused { detail: String },
}

/// Pure classifier for [`ApplyExit`] — see its doc for the grounding.
pub(crate) fn classify_apply_exit(code: Option<i32>, stderr: &str) -> ApplyExit {
    let refusal_marker = stderr.contains("fb-update apply: refused:");
    match code {
        Some(0) => ApplyExit::Streamed,
        Some(255) | None if !refusal_marker => ApplyExit::SeveredProceedToWatch {
                                                                                                
                                                                                                      
                                                                                                       
            note: format!(
                "the ssh session ended without a box refusal — either a successful arm-and-reboot \
                 (the box reboots out from under the connection) OR an ssh-local/transport failure \
                 that never reached the box; the watch will tell which. ssh output: {:?}",
                stderr.trim()
            ),
        },
        _ => ApplyExit::Refused {
            detail: format!(
                "fb-update apply exited {}: {}",
                code.map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_string()),
                stderr.trim()
            ),
        },
    }
}

/// Stream `framed` to a prepared `ssh … fb-update apply` command (stdin = the frame) and classify the
/// outcome. The write runs on a SCOPED thread while the main thread reaps the child: the box stops
/// reading stdin the instant it fail-closed-refuses (before the ~30 MB of components — `fb-update`
/// verifies bundle + runs the firmware/floor/probation/size guards first), so a serial main-thread
                                                                                                  
/// scoped writer lets `wait_with_output` return the box's real exit + stderr regardless, and write
/// errors are dropped on purpose (the box stopping its read IS the refusal signal). SHARED by the
/// shipped [`SshUpdateOps::fb_update_apply`] and the `make boot-gate-update` harness so the product
                                                                                                
                                                                                                
pub(crate) fn stream_apply_and_classify(
    mut cmd: std::process::Command,
    framed: &[u8],
) -> Result<ApplyExit, String> {
    use std::io::Write as _;
    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn ssh fb-update apply: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("no ssh stdin")?;
    std::thread::scope(|s| {
        s.spawn(move || {
                                                                                                 
                                                                                                  
            let _ = stdin.write_all(framed);
            drop(stdin);                                                                          
        });
        let out = child
            .wait_with_output()
            .map_err(|e| format!("wait fb-update apply: {e}"))?;
        Ok(classify_apply_exit(
            out.status.code(),
            &String::from_utf8_lossy(&out.stderr),
        ))
    })
}

                                                                                                   
/// apply TRANSPORT + classifier are shared with `make boot-gate-update` via
/// [`stream_apply_and_classify`], so the reboot-sever + refusal classification runs on produced bytes
/// there; the `host_pins` resolve/bootstrap path is exercised on a live QEMU box by
/// `make boot-gate-lifecycle`. But this struct's WATCH (the dual single-key probes, `status_under_key`,
/// `timeout_note`) and the COMMITTED `supersede_pin` have NO produced-bytes gate yet — their only
                                                                                                    
/// that band. Host-key trust flows through [`host_pins`]: `host_fingerprint` keyscans the box + stashes
/// the key line; the ssh execs then pin THAT line via a per-invocation `known_hosts` +
/// `StrictHostKeyChecking=yes` (the hardened prod block, no ambient config). The box has no scp/sftp —
/// `fb-update apply` reads the frame from ssh stdin (§4c, by design).
pub struct SshUpdateOps {
    pub host: String,
    pub port: u16,
    /// The operator's SSH identity (pubkey-only login).
    pub identity: PathBuf,
    /// Whether a tty is available for the y/N prompts.
    pub is_tty: bool,
    /// Bounded watch: poll cadence + total deadline for step 8.
    pub watch_poll: std::time::Duration,
    pub watch_deadline: std::time::Duration,
    /// The box's host-key line (`<host> ssh-ed25519 AAAA…`), captured by `host_fingerprint`, reused to
    /// build the PRE-PUSH pinned `known_hosts`.
    host_key_line: std::cell::RefCell<Option<String>>,
    /// The image-derived POST-FLIP runtime key (fingerprint + pubkey line, from [`PostFlipHostKey`]).
    /// The WATCH probes the box under THIS key alone to prove a committed flip (the box presents it by
    /// construction), and under the pre-push key alone to detect a rollback; which key answers is the
                                                                                                     
                                     
    post_flip: Option<PostFlipHostKey>,
}

/// Which host key a watch probe pins — exactly one, so which key ANSWERS is evidence of which image
/// the box booted (the runtime host key is image-derived).
#[derive(Clone, Copy)]
enum WatchKey {
    PrePush,
    PostFlip,
}

                                                                                                                                                            
                                                                                                   
                                                                                                      
                                                                                                
                                                                                                   
                                                                                                  

/// The box's mark-good probation deadline, in seconds of CANDIDATE-SLOT UPTIME. Mirrors fruit-basket
/// `fb-update/src/lib.rs` `MARK_GOOD_DEADLINE_SECS` (orchard does not depend on the box crate; the
/// value is pinned by citation and re-checked if that constant moves). A mark-good-unhealthy rollback
/// fires only after the candidate has been up this long.
const BOX_MARK_GOOD_DEADLINE_SECS: u64 = 300;
/// A generous ESTIMATE (not a measurement — `[UNVERIFIED]` against a real VPS) of ONE seabios-gpt slot
/// boot to the point ssh answers: SeaBIOS POST + dm-verity + s6 + services on a busy VPS. Basis: the
/// produced-bytes gate's `ROLLBACK_DEADLINE` (180 s, `dryrun/update_seabios.rs`), the boot-and-answer
/// budget it applies to the rollback path. Doubling it below is deliberate headroom, NOT two real
/// boots (see the timeline).
const BOX_SLOT_BOOT_BUDGET_SECS: u64 = 180;
/// Margin for the rolled-back slot's mark-good to clear the stale probation record + one poll cadence.
const WATCH_SETTLE_MARGIN_SECS: u64 = 60;

/// The ceremony's watch deadline, measured from apply-return. The box's mark-good deadline is
                                                                                                      
/// worst-case honest settle is roughly `300 (uptime) + one ROLLBACK boot + record clear + a poll`.
/// This budgets `2 × BOX_SLOT_BOOT_BUDGET` (one real rollback boot + one boot-budget of headroom, to
/// absorb the candidate's pre-uptime POST and a 2× error in the unverified boot estimate) + the uptime
/// deadline + a margin = 720 s. Errs LONG on purpose — a too-long deadline only delays a genuine
/// never-settle verdict (the watch returns the instant it settles), while a too-short one misreports a
                                                                                   
const WATCH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(
    2 * BOX_SLOT_BOOT_BUDGET_SECS + BOX_MARK_GOOD_DEADLINE_SECS + WATCH_SETTLE_MARGIN_SECS,
);
                                                                                                   
                                                                                                 
                                                                                                  
                                                                                      
const _: () =
    assert!(WATCH_DEADLINE.as_secs() >= BOX_MARK_GOOD_DEADLINE_SECS + BOX_SLOT_BOOT_BUDGET_SECS);

impl SshUpdateOps {
    pub fn new(host: String, port: u16, identity: PathBuf, is_tty: bool) -> Self {
        SshUpdateOps {
            host,
            port,
            identity,
            is_tty,
            watch_poll: std::time::Duration::from_secs(10),
            watch_deadline: WATCH_DEADLINE,
            host_key_line: std::cell::RefCell::new(None),
            post_flip: None,
        }
    }

    /// Arm the watch with the pushed image's derived post-flip runtime key (fingerprint + pubkey line).
    pub fn with_post_flip_key(mut self, key: PostFlipHostKey) -> Self {
        self.post_flip = Some(key);
        self
    }

    /// The known_hosts host token ssh matches for this target: bare host at the default port,
    /// `[host]:port` otherwise (the same convention `ssh-keyscan -p` emits).
    fn host_token(&self) -> String {
        if self.port == 22 {
            self.host.clone()
        } else {
            format!("[{}]:{}", self.host, self.port)
        }
    }

    /// A per-invocation `known_hosts` pinning EXACTLY the pre-push captured host key. Fail-closed if
    /// `host_fingerprint` has not run.
    fn known_hosts_prepush(&self) -> Result<tempfile::NamedTempFile, String> {
        let line = self
            .host_key_line
            .borrow()
            .clone()
            .ok_or("update: internal — host key not captured before an ssh exec")?;
        let mut f = tempfile::NamedTempFile::new().map_err(|e| format!("known_hosts temp: {e}"))?;
        use std::io::Write as _;
        writeln!(f, "{}", line.trim()).map_err(|e| format!("write known_hosts: {e}"))?;
        Ok(f)
    }

    /// A per-invocation `known_hosts` pinning EXACTLY the image-derived post-flip key (host-scoped by
    /// `host_token`). Fail-closed if the watch was not armed with one.
    fn known_hosts_postflip(&self) -> Result<tempfile::NamedTempFile, String> {
        let key = self
            .post_flip
            .as_ref()
            .ok_or("update: internal — watch not armed with the post-flip key")?;
        let mut f = tempfile::NamedTempFile::new().map_err(|e| format!("known_hosts temp: {e}"))?;
        use std::io::Write as _;
        writeln!(f, "{} {}", self.host_token(), key.pubkey_line().trim())
            .map_err(|e| format!("write known_hosts post-flip line: {e}"))?;
        Ok(f)
    }

    /// The hardened ssh argv (pinned known_hosts, no ambient config) + any per-call `-o` options +
                                                                                                       
    /// options up to the first non-option argument (the remote command); an option placed AFTER the
    /// command is inert on the client and is delivered to the box as command words. Placing them just
    /// before the destination keeps them unambiguously in the client region.
    fn ssh(&self, known_hosts: &Path, extra_opts: &[&str], remote: &str) -> std::process::Command {
                                                                                                     
                                                                                                   
        let base = super::prod_orchestrate::prod_ssh_args(
            &self.host,
            &self.identity,
            known_hosts,
            self.port,
        );
        let (dest, client_args) = base
            .split_last()
            .expect("prod_ssh_args yields a destination");
        let mut cmd = std::process::Command::new("ssh");
        cmd.args(client_args);
        cmd.args(extra_opts);
        cmd.arg(dest);
        cmd.arg(remote);
        cmd
    }

    /// The exact `ssh … fb-update apply` command [`UpdateOps::fb_update_apply`] runs: the hardened
    /// base + the keepalive options in the CLIENT position + the remote command. Split out of
                                                                                                
    /// ORDER defect, and no test of the day looked at the argv at all).
    fn apply_cmd(&self, known_hosts: &Path) -> std::process::Command {
        self.ssh(
            known_hosts,
            &["-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3"],
            "fb-update apply",
        )
    }
}

impl UpdateOps for SshUpdateOps {
    fn host_fingerprint(&self) -> Result<String, String> {
                                                                                                       
        let out = std::process::Command::new("ssh-keyscan")
            .args(["-t", "ed25519", "-p", &self.port.to_string(), &self.host])
            .output()
            .map_err(|e| format!("ssh-keyscan: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text
            .lines()
            .find(|l| l.contains("ssh-ed25519") && !l.trim_start().starts_with('#'))
            .ok_or("ssh-keyscan returned no ed25519 host key")?
            .to_string();
        *self.host_key_line.borrow_mut() = Some(line.clone());
                                                                                   
        let mut f = tempfile::NamedTempFile::new().map_err(|e| format!("keyscan temp: {e}"))?;
        use std::io::Write as _;
        writeln!(f, "{}", line.trim()).map_err(|e| format!("write keyscan: {e}"))?;
        let fpr_out = std::process::Command::new("ssh-keygen")
            .args(["-lf", &f.path().display().to_string()])
            .output()
            .map_err(|e| format!("ssh-keygen -lf: {e}"))?;
                                                                                     
        String::from_utf8_lossy(&fpr_out.stdout)
            .split_whitespace()
            .find(|t| t.starts_with("SHA256:"))
            .map(str::to_string)
            .ok_or_else(|| "ssh-keygen produced no SHA256 fingerprint".to_string())
    }

    fn confirm_authorize(&self, summary: &str) -> Result<bool, String> {
        if !self.is_tty {
            return Err(
                "update: authorization needed but no tty — pass --confirmed for a scripted fleet loop \
                 (never a silent host-key TOFU)"
                    .to_string(),
            );
        }
        eprint!("{summary}\nProceed? [y/N] ");
        use std::io::Write as _;
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("read authorize: {e}"))?;
        Ok(matches!(line.trim(), "y" | "Y" | "yes"))
    }

    fn fb_update_status(&self) -> Result<String, String> {
                                                                                           
        self.status_under_key(WatchKey::PrePush)
            .map_err(|e| e.detail)
    }

    fn fb_update_apply(&self, framed: &[u8]) -> Result<(), String> {
        let kh = self.known_hosts_prepush()?;
                                                                                                   
                                                                                                        
                                                                                                    
                                                                        
        let cmd = self.apply_cmd(kh.path());
                                                                                                     
                                                                                                    
        match stream_apply_and_classify(cmd, framed)? {
            ApplyExit::Streamed => Ok(()),
            ApplyExit::SeveredProceedToWatch { note } => {
                eprintln!("update: {note}");
                Ok(())
            }
            ApplyExit::Refused { detail } => Err(detail),
        }
    }

    fn watch_for_settled_status(&self) -> Result<WatchOutcome, String> {
                                                                                                
                                                                                                        
                                                                                                     
                                                                                                    
                                                                                                       
                                                                                
          
                                                                                               
                                                                                   
        if self.post_flip.is_none() {
            return Err(
                "update: internal — the watch was not armed with the post-flip key (a COMMITTED \
                 verdict is unreachable); this is a construction bug"
                    .to_string(),
            );
        }
                                                                                                   
                                                                                                        
                                                                                                    
                                                                                                       
                                                                                                      
                                                                         
        let start = std::time::Instant::now();
        let mut last_err: Option<String> = None;
        let mut saw_prepush_probation = false;
                                                                                                        
                                                                                                       
                                                                                                    
                                                                                                
                                                                                                     
                                                                                                  
        loop {
            let mut post_flip_mismatch = false;
            let mut prepush_mismatch = false;
            match self.status_under_key(WatchKey::PostFlip) {
                Ok(block) => match parse_status(&block) {
                    Ok(s) if !s.probation => {
                        return Ok(WatchOutcome::Settled {
                            post_flip: true,
                            block,
                        });
                    }
                    Ok(_) => {}                                                          
                    Err(e) => last_err = Some(format!("post-flip status unparseable: {e}")),
                },
                Err(e) if e.host_key_mismatch => post_flip_mismatch = true,
                Err(e) => last_err = Some(e.detail),
            }
            match self.status_under_key(WatchKey::PrePush) {
                Ok(block) => match parse_status(&block) {
                    Ok(s) if !s.probation => {
                        return Ok(WatchOutcome::Settled {
                            post_flip: false,
                            block,
                        });
                    }
                    Ok(_) => saw_prepush_probation = true,                                           
                    Err(e) => last_err = Some(format!("pre-push status unparseable: {e}")),
                },
                Err(e) if e.host_key_mismatch => prepush_mismatch = true,
                Err(e) => last_err = Some(e.detail),
            }
                                                                                                    
                                                                                                     
                                                                                                       
                                                                                                      
            if post_flip_mismatch && prepush_mismatch {
                last_err = Some(
                    "the box presented a host key matching NEITHER the pre-push pin NOR the pushed \
                     image's runtime key — a possible re-key or on-path interception (not a normal \
                     A/B flip)"
                        .to_string(),
                );
            }
            if start.elapsed() >= self.watch_deadline {
                return Ok(WatchOutcome::TimedOut {
                    note: self.timeout_note(last_err.as_deref(), saw_prepush_probation),
                });
            }
            std::thread::sleep(self.watch_poll);
        }
    }
}

/// A watch-probe failure, tagged with whether it was an ssh HOST-KEY verification failure (so the
/// watch can treat the routine pre-flip mismatch on the post-flip probe as expected, and surface a
                                                 
struct ProbeError {
    detail: String,
    host_key_mismatch: bool,
}

impl SshUpdateOps {
    /// One `fb-update status` exec pinned to EXACTLY one key. The key that answers is evidence of the
    /// image the box booted; a host-key mismatch is tagged so the watch can act on it.
    fn status_under_key(&self, which: WatchKey) -> Result<String, ProbeError> {
        let kh = match which {
            WatchKey::PrePush => self.known_hosts_prepush(),
            WatchKey::PostFlip => self.known_hosts_postflip(),
        }
        .map_err(|detail| ProbeError {
            detail,
            host_key_mismatch: false,
        })?;
        let out = self
            .ssh(kh.path(), &[], "fb-update status")
            .output()
            .map_err(|e| ProbeError {
                detail: format!("ssh fb-update status: {e}"),
                host_key_mismatch: false,
            })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let host_key_mismatch = stderr.contains("Host key verification failed");
                                                                                                    
                                                                                                          
                                                                                                  
            let detail = if host_key_mismatch {
                let which = match which {
                    WatchKey::PrePush => "the pre-push pinned key",
                    WatchKey::PostFlip => "the pushed image's runtime key",
                };
                format!(
                    "the box presented a host key that did not match {which} (ssh: Host key \
                     verification failed)"
                )
            } else {
                format!("fb-update status exited {}: {}", out.status, stderr.trim())
            };
            return Err(ProbeError {
                host_key_mismatch,
                detail,
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

                                                                                                      
    /// PRE-PUSH key with a live probation record (`saw_prepush_probation`), its runtime key did NOT
    /// rotate, so the note says the box is up on the old key and may still be rolling back — NO stale
    /// pin. Otherwise the box was never reached under either key, so it may have committed slowly (past
    /// the deadline) and rotated its key, leaving the pin stale — the note names the derived fingerprint
    /// and the recovery command.
    fn timeout_note(&self, last_err: Option<&str>, saw_prepush_probation: bool) -> String {
        let err = last_err
            .map(|e| format!(" Last probe: {e}."))
            .unwrap_or_default();
        if saw_prepush_probation {
            return format!(
                "the box is up on its PRE-PUSH host key with a live probation record but did not \
                 settle within the watch window — fb-mark-good is still deciding (it can ride up to \
                 its full uptime deadline before rolling back). The pin is NOT stale. Re-run \
                 `orchard status` to read the settled verdict.{err}"
            );
        }
        let recover = self
            .post_flip
            .as_ref()
            .map(|k| {
                format!(
                    " If the box committed slowly (past the watch deadline), its runtime host key is \
                     now {} and the stored pin is stale; verify with `orchard derive-rescue-offline \
                     --image <img> --print-fingerprint`, then re-pin deliberately.",
                    k.fingerprint()
                )
            })
            .unwrap_or_default();
        format!(
            "the box did not return a settled status under either the pre-push pin or the pushed \
             image's runtime key within the watch window — a slow boot, a stuck retry loop on the \
             armed slot (armed-vs-never-armed is indistinguishable from here, the M1 residual), or a \
             host-key mismatch. Inspect the box's console/OOB.{err}{recover}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::artifact_keys::{Custody, generate_artifact_keys};
    use std::cell::RefCell;

                                                                                                 
                                                                        
    const POST_FLIP_PUBKEY_LINE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPWxJU2oWqQtuLx5/KVyO/Ue6LSnKAiNTXfC7YvgJ8E9";
    const POST_FLIP_FPR: &str = "SHA256:klzBaauEGBWYJDN3wwX0gXle1bfnBXgbcRQp2Z6WiQA";
                                                                                                   
                                                                                              
    const OTHER_PUBKEY_LINE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBXY1nf9ArKgqROWxVqaMaAXj+lijVHKsofEapyIDjsU";
    const OTHER_FPR: &str = "SHA256:OPPTRnFle2Kkx62LAGSeBZLEKXo1k01cA48w2zOWVxY";

                                                                                                                                                                                                                                                                            
    struct FakeOps {
        fingerprint: String,
        authorize: bool,
        status: String,
        watch: WatchOutcome,
        applied: RefCell<Option<Vec<u8>>>,
    }
    impl Default for FakeOps {
        fn default() -> Self {
            FakeOps {
                fingerprint: "SHA256:box".to_string(),
                authorize: true,
                status: status_block("seabios-gpt", 5, false),
                                                                                                         
                watch: WatchOutcome::Settled {
                    post_flip: true,
                    block: status_block("seabios-gpt", 6, false),
                },
                applied: RefCell::new(None),
            }
        }
    }
    impl UpdateOps for FakeOps {
        fn host_fingerprint(&self) -> Result<String, String> {
            Ok(self.fingerprint.clone())
        }
        fn confirm_authorize(&self, _summary: &str) -> Result<bool, String> {
            Ok(self.authorize)
        }
        fn fb_update_status(&self) -> Result<String, String> {
            Ok(self.status.clone())
        }
        fn fb_update_apply(&self, framed: &[u8]) -> Result<(), String> {
            *self.applied.borrow_mut() = Some(framed.to_vec());
            Ok(())
        }
        fn watch_for_settled_status(&self) -> Result<WatchOutcome, String> {
            Ok(self.watch.clone())
        }
    }

    fn status_block(firmware: &str, version: u64, probation: bool) -> String {
                                                                                                        
                                                                                                    
                                                                                           
        let probation = if probation {
            format!("candidate slot-b version={version} ctr=1700000000 deadline=300")
        } else {
            "none".to_string()
        };
        format!(
            "firmware = {firmware}\nactive_slot = a\nimage_version = {version}\n\
             version_floor = {version}\nminctr_floor = 1700000000\nprobation = {probation}\n\
             backup_age_secs = 120\nuptime_secs = 3600\n"
        )
    }

    /// A directly-constructed PreparedPush (bypasses the boot-fs read — that path is exercised on
    /// produced bytes at T22 + by the pure composer tests). `keys_dir` is a fresh (or legacy) key set so
    /// the sign step is real.
    fn prepared(version: u64) -> PreparedPush {
        let manifest = UpdateManifest {
            version,
            image_sha256: [0x11; 32],
            root_hash: "ab".repeat(32),
            verity_hash_offset: 8192,
            rootfs_sha256: [0x22; 32],
            rootfs_size: 4096,
            kernel_sha256: [0x33; 32],
            kernel_size: 7,
            initramfs_sha256: [0x44; 32],
            initramfs_size: 9,
        };
        PreparedPush {
            firmware: Firmware::SeabiosGpt,
            manifest_wire: manifest.to_wire(),
            manifest,
                                                                                                       
                                                                
            post_flip_hostkey: PostFlipHostKey::new(
                POST_FLIP_PUBKEY_LINE.to_string(),
                POST_FLIP_FPR.to_string(),
            )
            .unwrap(),
            components: Components {
                rootfs: vec![0xA7; 4096],
                kernel: b"VMLINUZ".to_vec(),
                initramfs: b"INITRAMFS".to_vec(),
            },
        }
    }

    fn keyset(dir: &Path, legacy: bool) -> PathBuf {
        let keys = dir.join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Raw).unwrap();
        if legacy {
            for n in [
                "artifact-delegation-update-image.bundle",
                "artifact-delegation-root-hash.bundle",
            ] {
                std::fs::remove_file(keys.join(n)).unwrap();
            }
        }
        keys
    }

    fn opts<'a>(keys: &'a Path, pin_dir: &'a Path, authorize: Authorize) -> CeremonyOpts<'a> {
        CeremonyOpts {
            host: "box.example",
            keys_dir: keys,
            authorize,
            host_pin: HostPinOpts {
                host_fingerprint: Some("SHA256:box"),
                is_tty: false,
                pin_dir,
            },
        }
    }

                                                                                                                                                                                                                                                                
    #[test]
    fn parse_status_reads_the_block() {
        let s = parse_status(&status_block("seabios-gpt", 5, false)).unwrap();
        assert_eq!(s.firmware, "seabios-gpt");
        assert_eq!(s.image_version, 5);
        assert!(!s.probation);
        assert_eq!(s.backup_age_secs, Some(120));
        assert!(
            parse_status("firmware = seabios-gpt\n").is_err(),
            "missing keys fail closed"
        );
    }

    #[test]
    fn manifest_wire_is_the_exact_field_set() {
        let wire = prepared(5).manifest_wire;
        assert!(wire.starts_with("format = 1\nfirmware = seabios-gpt\nversion = 5\n"));
        assert!(wire.contains(&format!("root_hash = {}\n", "ab".repeat(32))));
        assert!(wire.ends_with("initramfs_size = 9\n"));
        assert_eq!(wire.lines().count(), 12, "exactly the §4a 12-field set");
    }

    #[test]
    fn frame_is_length_prefixed_and_eof_exact() {
        let comps = Components {
            rootfs: vec![1, 2, 3],
            kernel: vec![4, 4],
            initramfs: vec![5],
        };
        let framed = frame_apply_stream(b"MANIFEST", &[7u8; dragonfruit::BUNDLE_FILE_LEN], &comps);
        assert_eq!(
            framed.len(),
            8 + 8 + 8 + dragonfruit::BUNDLE_FILE_LEN + 3 + 2 + 1
        );
        assert_eq!(&framed[0..8], &8u64.to_le_bytes());
        assert_eq!(&framed[8..16], b"MANIFEST");
        assert_eq!(
            &framed[16..24],
            &(dragonfruit::BUNDLE_FILE_LEN as u64).to_le_bytes()
        );
    }

    #[test]
    fn interpret_watch_rests_on_the_presented_key_not_the_version() {
                                                                                                  
                                          
        let committed = WatchOutcome::Settled {
            post_flip: true,
            block: status_block("seabios-gpt", 6, false),
        };
        assert_eq!(
            interpret_watch(6, committed).unwrap(),
            UpdateReport::Committed { version: 6 }
        );
                                                                                                      
        let rolled = WatchOutcome::Settled {
            post_flip: false,
            block: status_block("seabios-gpt", 5, false),
        };
        assert_eq!(
            interpret_watch(6, rolled).unwrap(),
            UpdateReport::RolledBack { version: 5 }
        );
                                    
        assert!(matches!(
            interpret_watch(
                6,
                WatchOutcome::TimedOut {
                    note: "n".to_string()
                }
            )
            .unwrap(),
            UpdateReport::Unreachable { .. }
        ));
                                                                                                   
                                                                                                       
                                                                                                       
                                          
        let untouched_same_version = WatchOutcome::Settled {
            post_flip: false,
            block: status_block("seabios-gpt", 6, false),
        };
        assert_eq!(
            interpret_watch(6, untouched_same_version).unwrap(),
            UpdateReport::RolledBack { version: 6 },
            "a same-version answer under the PRE-PUSH key must never read as COMMITTED"
        );
                                                                                                      
        let inconsistent = WatchOutcome::Settled {
            post_flip: true,
            block: status_block("seabios-gpt", 9, false),
        };
        assert!(matches!(
            interpret_watch(6, inconsistent).unwrap(),
            UpdateReport::Unreachable { .. }
        ));
                                                                                                
                                                                                                      
                                                                                       
        let floor_not_advanced = "firmware = seabios-gpt\nactive_slot = b\nimage_version = 6\n\
             version_floor = 5\nminctr_floor = 1700000000\nprobation = none\n\
             backup_age_secs = 120\nuptime_secs = 3600\n"
            .to_string();
        let r = interpret_watch(
            6,
            WatchOutcome::Settled {
                post_flip: true,
                block: floor_not_advanced,
            },
        )
        .unwrap();
        assert!(
            matches!(&r, UpdateReport::Unreachable { note } if note.contains("floor")),
            "a cleared-probation flip with an unadvanced floor must not read COMMITTED: {r:?}"
        );
    }

    #[test]
    fn classify_apply_exit_covers_the_real_box_shapes() {
                                                                                                
                                                                           
        let severed = classify_apply_exit(
            Some(255),
            "fb-update apply: armed slot-b — rebooting\nRead from remote host 179.237.81.150: \
             Connection reset by peer\r\nclient_loop: send disconnect: Broken pipe",
        );
        assert!(
            matches!(severed, ApplyExit::SeveredProceedToWatch { .. }),
            "{severed:?}"
        );
                                                                                              
        assert!(matches!(
            classify_apply_exit(None, "Connection reset by peer"),
            ApplyExit::SeveredProceedToWatch { .. }
        ));
                                                                                                       
        let refused = classify_apply_exit(
            Some(14),
            "fb-update apply: refused: version 1 not above floor 1",
        );
        assert!(matches!(refused, ApplyExit::Refused { .. }), "{refused:?}");
                                                                                                    
                                                                                                      
        assert!(matches!(
            classify_apply_exit(Some(255), "fb-update apply: refused: bad manifest"),
            ApplyExit::Refused { .. }
        ));
                                                                      
        assert!(matches!(
            classify_apply_exit(Some(12), ""),
            ApplyExit::Refused { .. }
        ));
        assert!(matches!(
            classify_apply_exit(Some(0), ""),
            ApplyExit::Streamed
        ));
    }

                                                                                                  
    /// prefix and then fail-closed-refuses must reach the classifier with its EXIT CODE, not with the
    /// writer's `EPIPE`. The stand-in is `sh -c 'head -c … ; echo refused >&2; exit 12'` — the same
    /// shape as `fb-update apply` (it verifies the bundle + runs the firmware/floor/probation/size
    /// guards before reading the ~30 MB of components), driven with a frame far larger than a pipe
    /// buffer so the write CANNOT complete before the child exits.
    ///
    /// Arm 1 is the fixture's own non-vacuity proof and the counterfactual in one: a SERIAL
    /// main-thread `write_all` against the same child returns `BrokenPipe`, which is exactly the
    /// error the pre-fix `fb_update_apply` propagated with `?` in place of the box's verdict. Arm 2
    /// runs the shipped transport against the same child and gets `Refused` with the exit code.
    ///
    /// Model checked: one real child process, one real pipe, on this host's kernel. It does NOT
    /// exercise ssh, the box, or a network socket — that is `make boot-gate-update`'s job.
    #[cfg(unix)]
    #[test]
    fn a_box_that_refuses_after_a_prefix_read_is_classified_from_its_exit_code_not_a_write_error() {
        use std::io::Write as _;
                                                                                                      
        let framed = vec![0xA7u8; 4 * 1024 * 1024];
        let script = "head -c 1024 >/dev/null; \
                      echo 'fb-update apply: refused: version 1 not above floor 1' >&2; exit 12";

                                                                                    
        let mut serial = std::process::Command::new("sh")
            .args(["-c", script])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let werr = serial
            .stdin
            .take()
            .expect("stdin")
            .write_all(&framed)
            .expect_err("a prefix-reading child must break the pipe on a 4 MiB serial write");
        assert_eq!(
            werr.kind(),
            std::io::ErrorKind::BrokenPipe,
            "the counterfactual is EPIPE, got {werr:?}"
        );
        let _ = serial.wait();

                                                                          
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", script]);
        let exit = stream_apply_and_classify(cmd, &framed).expect("the transport reaps the child");
        let ApplyExit::Refused { detail } = exit else {
            panic!("the box's refusal must survive the severed write, got {exit:?}");
        };
        assert!(detail.contains("exited 12"), "no exit code in {detail:?}");
        assert!(
            detail.contains("not above floor 1"),
            "no refusal reason in {detail:?}"
        );
    }

                                                                                                    
    /// remote command); a `-o` placed AFTER the remote command is inert on the client and is delivered
    /// to the box as command words. So the load-bearing property is: every keepalive option precedes
    /// the remote command, each behind its own `-o`. (The exact placement relative to the destination
    /// is incidental — ssh applies options before OR after the destination, as long as they precede the
    /// command — so this pins the boundary the mechanism has, not the shape the current builder emits.)
    #[test]
    fn the_apply_keepalive_options_precede_the_remote_command() {
        let ops = SshUpdateOps::new(
            "box.example".to_string(),
            22,
            PathBuf::from("/k/id_ed25519"),
            false,
        );
        let cmd = ops.apply_cmd(Path::new("/kh"));
        let argv: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
                                                                   
        let cmd_at = argv.len() - 1;
        assert_eq!(
            argv[cmd_at], "fb-update apply",
            "the remote command must be last: {argv:?}"
        );
        for opt in ["ServerAliveInterval=5", "ServerAliveCountMax=3"] {
            let at = argv
                .iter()
                .position(|a| a == opt)
                .unwrap_or_else(|| panic!("{opt} absent from {argv:?}"));
            assert!(
                at < cmd_at,
                "{opt} is at {at}, at or after the remote command at {cmd_at} — ssh would send it to \
                 the box instead of applying it: {argv:?}"
            );
            assert_eq!(argv[at - 1], "-o", "{opt} is not introduced by its own -o");
        }
    }

                                                                                                    
    /// class reports UNREACHABLE instead of ROLLED-BACK. The grounded floor is the mark-good uptime
    /// deadline plus BOTH slot boots (the derived quantity, not the gate's per-phase timeout); the
    /// compile-time assert pins the constant, this pins that `new()` actually hands the constructed ops
    /// a deadline meeting it, so a literal reintroduced here is caught too.
    #[test]
    fn the_constructed_watch_deadline_outlasts_the_derived_mark_good_settle() {
        let ops = SshUpdateOps::new("box.example".to_string(), 22, PathBuf::from("/k"), false);
                                                                                                     
                                                         
        let grounded_floor = BOX_MARK_GOOD_DEADLINE_SECS + BOX_SLOT_BOOT_BUDGET_SECS;
        assert!(
            ops.watch_deadline.as_secs() >= grounded_floor,
            "watch_deadline {:?} is under the derived mark-good settle floor {grounded_floor}s \
             (300s uptime deadline + one {BOX_SLOT_BOOT_BUDGET_SECS}s rollback slot boot)",
            ops.watch_deadline
        );
    }

                                                                                              
    /// well-formed fingerprint OF A DIFFERENT KEY is refused — not just a swapped or malformed pair.
    /// Oracle: two real `ssh-keygen -t ed25519` pairs, each fingerprint printed by `ssh-keygen -lf`.
    #[test]
    fn post_flip_hostkey_refuses_a_wellformed_fingerprint_of_another_key() {
                                                                                                      
        let ok = PostFlipHostKey::new(POST_FLIP_PUBKEY_LINE.to_string(), POST_FLIP_FPR.to_string())
            .expect("the corresponding pair is accepted");
        assert_eq!(ok.fingerprint(), POST_FLIP_FPR);
        assert_eq!(ok.pubkey_line(), POST_FLIP_PUBKEY_LINE);
                                                                                     
        let err = PostFlipHostKey::new(POST_FLIP_PUBKEY_LINE.to_string(), OTHER_FPR.to_string())
            .expect_err("a non-corresponding fingerprint must be refused");
        assert!(err.contains("does not correspond"), "{err}");
                                                                                  
        assert!(
            PostFlipHostKey::new(OTHER_PUBKEY_LINE.to_string(), POST_FLIP_FPR.to_string()).is_err(),
            "the mirror pair must be refused too"
        );
    }

                                                                                                    
    /// the pin, so each is read end to end: the reachable-on-the-old-key arm must say the pin is not
    /// stale AND must not carry the rotate-the-pin recovery hint (following it re-pins the store to a
    /// key the box does not hold); the never-reached arm must carry the derived fingerprint and the
    /// recovery command. The retained last probe error appears in both.
    #[test]
    fn the_timeout_note_says_pin_not_stale_only_when_the_box_answered_on_the_pre_push_key() {
        let ops = SshUpdateOps::new("box.example".to_string(), 22, PathBuf::from("/k"), false)
            .with_post_flip_key(
                PostFlipHostKey::new(POST_FLIP_PUBKEY_LINE.to_string(), POST_FLIP_FPR.to_string())
                    .unwrap(),
            );

                                                                                     
        let a = ops.timeout_note(Some("post-flip status unparseable: bad"), true);
        assert!(a.contains("PRE-PUSH host key"), "{a}");
        assert!(a.contains("The pin is NOT stale."), "{a}");
        assert!(
            !a.contains(POST_FLIP_FPR),
            "arm A must not name the derived fingerprint: {a}"
        );
        assert!(
            !a.contains("derive-rescue-offline"),
            "arm A must not offer the re-pin recovery: {a}"
        );
        assert!(a.contains("post-flip status unparseable: bad"), "{a}");

                                                                                                         
        let b = ops.timeout_note(Some("ssh fb-update status: connect timeout"), false);
        assert!(b.contains("under either the pre-push pin"), "{b}");
        assert!(b.contains(POST_FLIP_FPR), "arm B must name the key: {b}");
        assert!(b.contains("derive-rescue-offline"), "{b}");
        assert!(
            !b.contains("The pin is NOT stale."),
            "arm B must not claim the pin is good: {b}"
        );
        assert!(b.contains("connect timeout"), "{b}");

                                                            
        assert!(!ops.timeout_note(None, true).contains("Last probe:"));
        assert!(!ops.timeout_note(None, false).contains("Last probe:"));
    }

                                                                                                 
    /// flip whose pin write failed is the one that used to slip through as a success.
    #[test]
    fn only_a_committed_flip_with_a_consistent_pin_store_exits_zero() {
        let committed = UpdateReport::Committed { version: 6 };
        let ok = CeremonyOutcome {
            report: committed.clone(),
            pin: PinAction::Superseded {
                to: POST_FLIP_FPR.to_string(),
            },
        };
        assert!(
            ok.is_success(),
            "committed + superseded is the success case"
        );
        assert!(
            CeremonyOutcome {
                report: committed.clone(),
                pin: PinAction::Unchanged,
            }
            .is_success(),
            "committed with the pin already correct is success too"
        );
        assert!(
            !CeremonyOutcome {
                report: committed,
                pin: PinAction::SupersedeFailed {
                    detail: "read-only pin store".to_string(),
                },
            }
            .is_success(),
            "a committed flip with a STALE pin must exit non-zero"
        );
        assert!(
            !CeremonyOutcome {
                report: UpdateReport::RolledBack { version: 5 },
                pin: PinAction::Unchanged,
            }
            .is_success()
        );
        assert!(
            !CeremonyOutcome {
                report: UpdateReport::Unreachable {
                    note: "n".to_string()
                },
                pin: PinAction::Unchanged,
            }
            .is_success()
        );
    }

                                                                                                    
    /// failure when there is one — it does NOT key on the pin action alone (which mislabelled an
    /// UNREACHABLE whose supersede failed as "COMMITTED …"). Asserts the PROPERTY (which verdict leads,
    /// pin clause present-or-absent), not frozen prose.
    #[test]
    fn exit_reason_leads_with_the_verdict_and_appends_the_pin_failure() {
                                                                                                  
        let c = CeremonyOutcome {
            report: UpdateReport::Committed { version: 6 },
            pin: PinAction::SupersedeFailed {
                detail: "read-only pin store".to_string(),
            },
        };
        let r = c.exit_reason();
        assert!(
            r.starts_with(&UpdateReport::Committed { version: 6 }.summary()),
            "must lead with the COMMITTED verdict: {r:?}"
        );
        assert!(r.contains("host pin could NOT be rotated"), "{r:?}");

                                                                                                      
                                                     
        let u = CeremonyOutcome {
            report: UpdateReport::Unreachable {
                note: "boot inconsistency".to_string(),
            },
            pin: PinAction::SupersedeFailed {
                detail: "read-only pin store".to_string(),
            },
        };
        let ru = u.exit_reason();
        assert!(
            ru.starts_with("UNREACHABLE"),
            "must lead with UNREACHABLE: {ru:?}"
        );
        assert!(
            !ru.contains("COMMITTED"),
            "must NOT assert a commit it did not make: {ru:?}"
        );
        assert!(ru.contains("host pin could NOT be rotated"), "{ru:?}");

                                                                     
        let rb = CeremonyOutcome {
            report: UpdateReport::RolledBack { version: 5 },
            pin: PinAction::Unchanged,
        };
        assert_eq!(
            rb.exit_reason(),
            UpdateReport::RolledBack { version: 5 }.summary()
        );
    }

    #[test]
    fn committed_flip_supersedes_the_pin_to_the_post_flip_key() {
                                                                                                 
                                                                                                    
        let dir = tempfile::tempdir().unwrap();
        let keys = keyset(dir.path(), false);
        let pin_dir = dir.path().join("pins");
        let ops = FakeOps::default();
        let outcome = run_ceremony(
            &prepared(6),
            &keys.join("no-pin"),
            &opts(&keys, &pin_dir, Authorize::Confirmed),
            &ops,
        )
        .unwrap();
        assert_eq!(outcome.report, UpdateReport::Committed { version: 6 });
        assert_eq!(
            outcome.pin,
            PinAction::Superseded {
                to: POST_FLIP_FPR.to_string()
            }
        );
        let pin_file = pin_dir.join("box.example");
        let stored = std::fs::read_to_string(&pin_file).unwrap();
        assert_eq!(
            stored.trim(),
            POST_FLIP_FPR,
            "the pin is superseded to the derived post-flip key"
        );
                                                       
        let archives = std::fs::read_dir(&pin_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("superseded"))
            .count();
        assert_eq!(archives, 1);
    }

    #[test]
    fn rolled_back_keeps_the_pre_push_pin() {
                                                                                                   
        let dir = tempfile::tempdir().unwrap();
        let keys = keyset(dir.path(), false);
        let pin_dir = dir.path().join("pins");
        let ops = FakeOps {
            watch: WatchOutcome::Settled {
                post_flip: false,
                block: status_block("seabios-gpt", 5, false),
            },
            ..FakeOps::default()
        };
        let outcome = run_ceremony(
            &prepared(6),
            &keys.join("no-pin"),
            &opts(&keys, &pin_dir, Authorize::Confirmed),
            &ops,
        )
        .unwrap();
        assert_eq!(outcome.report, UpdateReport::RolledBack { version: 5 });
        assert_eq!(outcome.pin, PinAction::Unchanged);
        let stored = std::fs::read_to_string(pin_dir.join("box.example")).unwrap();
        assert_eq!(stored.trim(), "SHA256:box", "the pre-push pin is untouched");
    }

    #[test]
    fn a_post_flip_key_with_wrong_version_still_supersedes_the_pin() {
                                                                                                      
                                                                                                       
                                                                                                     
                                               
        let dir = tempfile::tempdir().unwrap();
        let keys = keyset(dir.path(), false);
        let pin_dir = dir.path().join("pins");
        let ops = FakeOps {
            watch: WatchOutcome::Settled {
                post_flip: true,
                block: status_block("seabios-gpt", 9, false),                            
            },
            ..FakeOps::default()
        };
        let outcome = run_ceremony(
            &prepared(6),
            &keys.join("no-pin"),
            &opts(&keys, &pin_dir, Authorize::Confirmed),
            &ops,
        )
        .unwrap();
        assert!(matches!(outcome.report, UpdateReport::Unreachable { .. }));
        assert_eq!(
            outcome.pin,
            PinAction::Superseded {
                to: POST_FLIP_FPR.to_string()
            },
            "a rotated key must be re-pinned even on the inconsistency arm"
        );
        let stored = std::fs::read_to_string(pin_dir.join("box.example")).unwrap();
        assert_eq!(stored.trim(), POST_FLIP_FPR);
    }

    #[test]
    #[cfg(unix)]
    fn a_committed_flip_whose_pin_write_fails_reports_supersede_failed() {
                                                                                                       
                                                                                                       
                                                                                           
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let keys = keyset(dir.path(), false);
        let pin_dir = dir.path().join("pins");
                                                                                                        
                                    
        host_pins::commit_pin(
            "box.example",
            "SHA256:box",
            &HostPinOpts {
                host_fingerprint: None,
                is_tty: false,
                pin_dir: &pin_dir,
            },
        )
        .unwrap();
        std::fs::set_permissions(&pin_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let outcome = run_ceremony(
            &prepared(6),
            &keys.join("no-pin"),
            &opts(&keys, &pin_dir, Authorize::Confirmed),
            &FakeOps::default(),
        )
        .unwrap();
                                                          
        std::fs::set_permissions(&pin_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(outcome.report, UpdateReport::Committed { version: 6 });
        assert!(
            matches!(outcome.pin, PinAction::SupersedeFailed { .. }),
            "a commit whose pin could not be rotated must report SupersedeFailed, got {:?}",
            outcome.pin
        );
    }

    #[test]
    fn a_below_floor_push_is_refused_before_streaming() {
                                                                                                     
                                                                                             
        let dir = tempfile::tempdir().unwrap();
        let keys = keyset(dir.path(), false);
        let pin_dir = dir.path().join("pins");
        let ops = FakeOps::default();
        let err = run_ceremony(
            &prepared(5),            
            &keys.join("no-pin"),
            &opts(&keys, &pin_dir, Authorize::Confirmed),
            &ops,
        )
        .unwrap_err();
        assert!(err.contains("anti-rollback floor"), "{err}");
        assert!(
            ops.applied.borrow().is_none(),
            "must not stream a below-floor push"
        );
    }

    #[test]
    fn update_with_no_rung_is_a_hard_actionable_error() {
                                                                                       
                                                        
        let dir = tempfile::tempdir().unwrap();
        let err = sign_update_manifest(
            &dir.path().join("no-keys"),
            &dir.path().join("no-pin"),
            b"m",
        )
        .unwrap_err();
        assert!(err.contains("an OS update never pushes unsigned"), "{err}");
        assert!(err.contains("generate-keys"), "not actionable: {err}");
    }

                                                                                                                                                                                                                                             
    #[test]
    fn update_happy_reports_committed() {
        let dir = tempfile::tempdir().unwrap();
        let keys = keyset(dir.path(), false);
        let pin_dir = dir.path().join("pins");
        let ops = FakeOps::default();
        let outcome = run_ceremony(
            &prepared(6),
            &keys.join("no-pin"),
            &opts(&keys, &pin_dir, Authorize::Confirmed),
            &ops,
        )
        .unwrap();
        assert_eq!(outcome.report, UpdateReport::Committed { version: 6 });
                                                                                        
        let framed = ops.applied.borrow().clone().expect("apply was called");
        let mlen = u64::from_le_bytes(framed[0..8].try_into().unwrap()) as usize;
        assert!(framed[8..8 + mlen].starts_with(b"format = 1\nfirmware = seabios-gpt\n"));
    }

    #[test]
    fn update_reports_rolled_back() {
        let dir = tempfile::tempdir().unwrap();
        let keys = keyset(dir.path(), false);
        let pin_dir = dir.path().join("pins");
        let ops = FakeOps {
                                                                 
            watch: WatchOutcome::Settled {
                post_flip: false,
                block: status_block("seabios-gpt", 5, false),
            },
            ..FakeOps::default()
        };
        let outcome = run_ceremony(
            &prepared(6),
            &keys.join("no-pin"),
            &opts(&keys, &pin_dir, Authorize::Confirmed),
            &ops,
        )
        .unwrap();
        assert_eq!(outcome.report, UpdateReport::RolledBack { version: 5 });
    }

    #[test]
    fn update_reports_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let keys = keyset(dir.path(), false);
        let pin_dir = dir.path().join("pins");
        let ops = FakeOps {
            watch: WatchOutcome::TimedOut {
                note: "no answer".to_string(),
            },
            ..FakeOps::default()
        };
        let outcome = run_ceremony(
            &prepared(6),
            &keys.join("no-pin"),
            &opts(&keys, &pin_dir, Authorize::Confirmed),
            &ops,
        )
        .unwrap();
        assert!(matches!(outcome.report, UpdateReport::Unreachable { .. }));
    }

    #[test]
    fn update_never_proceeds_without_authorize() {
        let dir = tempfile::tempdir().unwrap();
        let keys = keyset(dir.path(), false);
        let pin_dir = dir.path().join("pins");
        let ops = FakeOps {
            authorize: false,
            ..FakeOps::default()
        };
        let err = run_ceremony(
            &prepared(6),
            &keys.join("no-pin"),
            &opts(&keys, &pin_dir, Authorize::Interactive),
            &ops,
        )
        .unwrap_err();
        assert!(err.contains("did not authorize"), "{err}");
                                 
        assert!(
            ops.applied.borrow().is_none(),
            "must not stream without authorize"
        );
    }

    #[test]
    fn update_fails_closed_without_updateimage_delegation() {
        let dir = tempfile::tempdir().unwrap();
        let keys = keyset(dir.path(), true);                           
        let pin_dir = dir.path().join("pins");
        let err = run_ceremony(
            &prepared(6),
            &keys.join("no-pin"),
            &opts(&keys, &pin_dir, Authorize::Confirmed),
            &FakeOps::default(),
        )
        .unwrap_err();
        assert!(
            err.contains("orchard redelegate"),
            "actionable message: {err}"
        );
        assert!(
            err.contains("update-image"),
            "names the missing purpose: {err}"
        );
    }

    #[test]
    fn update_refuses_a_box_that_reports_non_gpt_firmware() {
        let dir = tempfile::tempdir().unwrap();
        let keys = keyset(dir.path(), false);
        let pin_dir = dir.path().join("pins");
        let ops = FakeOps {
            status: status_block("seabios", 5, false),
            ..FakeOps::default()
        };
        let err = run_ceremony(
            &prepared(6),
            &keys.join("no-pin"),
            &opts(&keys, &pin_dir, Authorize::Confirmed),
            &ops,
        )
        .unwrap_err();
        assert!(
            err.contains("not seabios-gpt"),
            "{err}"
        );
    }

    #[test]
    fn update_refuses_a_host_key_change() {
        let dir = tempfile::tempdir().unwrap();
        let keys = keyset(dir.path(), false);
        let pin_dir = dir.path().join("pins");
        std::fs::create_dir_all(&pin_dir).unwrap();
                                                                                              
        host_pins::commit_pin(
            "box.example",
            "SHA256:old",
            &HostPinOpts {
                host_fingerprint: None,
                is_tty: false,
                pin_dir: &pin_dir,
            },
        )
        .unwrap();
        let err = run_ceremony(
            &prepared(6),
            &keys.join("no-pin"),
            &opts(&keys, &pin_dir, Authorize::Confirmed),
            &FakeOps::default(),
        )
        .unwrap_err();
        assert!(
            err.contains("does NOT match the stored pin"),
            "host-key change refused: {err}"
        );
    }
}
