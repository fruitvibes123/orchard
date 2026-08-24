                                                                                                 
//! PURE, fully-unit-tested decision units (cmdline builder, discovery parsing, wipe gate, host-key
//! decision, identity comparisons); this module hosts what touches the world: the hardened
//! ssh/scp/kexec `Command` argv builders, the per-target flock, the three-state signal-cancellation
//! machine, and the `deploy_prod` flow that sequences the spec's steps 1-10.
//!
                                                                                                   
//! speaks `StrictHostKeyChecking=no` to an ephemeral localhost-forwarded QEMU guest): prod targets
//! a REAL remote root over an untrusted network, so host keys are pinned via an explicit
//! known-hosts file + `StrictHostKeyChecking=yes`, ambient config is cut (`-F /dev/null`,
//! `GlobalKnownHostsFile=/dev/null`), auth is pubkey-only fail-fast (`BatchMode`,
//! `PasswordAuthentication=no`, `IdentitiesOnly=yes`), and nothing ever passes a shell string
//! locally (`std::process::Command` argv only).

use std::path::{Path, PathBuf};

use crate::deploy::build_image::Firmware;

/// Where the destructive ceremony stands when a cancellation signal (Ctrl-C / SIGTERM) lands —
                                                                                               
/// confirmed" are different worlds: in between, the target may already be rebooting into the
/// installer, which READS the staged `.img` from the old root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelState {
    /// (a) No kexec subprocess spawned yet — abort freely + best-effort remove the staged `.img`.
    PreKexecSpawn,
    /// (b) The `kexec` subprocess is in flight — `-e` MAY have reached the target. Do NOT remove
    /// the staged `.img` (a racing rm would brick a SUCCESSFUL kexec mid-install — the
                                                                                        
    /// console/reconnect".
    KexecInFlight,
    /// (c) `kexec -e` confirmed — past the point of no return; cancellation is a no-op.
    PastNoReturn,
}

/// The staged-`.img` cleanup rule: removal is safe ONLY before the kexec subprocess exists.
pub fn should_remove_staged_img(state: CancelState) -> bool {
    matches!(state, CancelState::PreKexecSpawn)
}

                                                                                                
/// trivially-different spellings of the same target collide on the same lock, then reduce to
/// filename-safe bytes (`[a-z0-9._-]`, everything else → `_`) because the key becomes the lock
/// FILENAME. Sanitization collisions OVER-lock — the safe direction for a destructive ceremony.
/// (Intentionally diverges from a `<host-fingerprint>.lock`: the fingerprint is unknown
/// pre-connect on greenfield.)
pub fn lock_key(ip: &str) -> String {
    ip.trim()
        .to_ascii_lowercase()
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') {
                b as char
            } else {
                '_'
            }
        })
        .collect()
}

/// An exclusive advisory flock for one deploy target, held for the ceremony's lifetime. Dropping
/// it (process exit included — flock releases with the open file description) frees the target.
#[derive(Debug)]
pub struct DeployLock {
    /// Held open: the kernel releases the flock when the last descriptor closes.
    _file: std::fs::File,
    /// The lock file path (left in place on release — flock state lives in the kernel, not the
    /// file's existence; unlinking on drop would race a concurrent acquirer).
    pub path: PathBuf,
}

                                                                                              
/// exclusive `flock` on `<runtime_dir>/recipes-deploy-<lock_key(ip)>.lock`. Fail-closed on a held
/// lock with an operator-actionable message naming the target.
pub fn acquire_deploy_lock(runtime_dir: &Path, ip: &str) -> Result<DeployLock, String> {
    use std::os::fd::AsRawFd;
    std::fs::create_dir_all(runtime_dir)
        .map_err(|e| format!("create lock dir {}: {e}", runtime_dir.display()))?;
    let path = runtime_dir.join(format!("recipes-deploy-{}.lock", lock_key(ip)));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| format!("open lock file {}: {e}", path.display()))?;
                                                                
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(format!(
            "another `deploy prod` against {} appears to be running (flock {} is held) — \
             refusing a concurrent destructive ceremony",
            ip.trim(),
            path.display()
        ));
    }
    Ok(DeployLock { _file: file, path })
}

/// Tie a local subprocess's lifetime to ours — the dryrun `PR_SET_PDEATHSIG` pattern: if `deploy
/// prod` dies mid-leg, the kernel SIGKILLs the child, so no orphan ssh/scp keeps acting on the
/// target after the operator killed the ceremony.
pub fn arm_pdeathsig(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
                                                                                                   
                                                          
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            Ok(())
        });
    }
}

/// The shared hardened option block both [`prod_ssh_args`] and [`prod_scp_args`] carry — kept as
/// ONE builder so the two transports can't drift on the security-relevant posture.
fn hardened_common_args(identity: &Path, known_hosts: &Path) -> Vec<String> {
    vec![
                                                                                              
                                                                                             
        "-F".into(),
        "/dev/null".into(),
        "-i".into(),
        identity.display().to_string(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
                                                                                          
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "-o".into(),
        "GlobalKnownHostsFile=/dev/null".into(),
                                                                                                   
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "PasswordAuthentication=no".into(),
        "-o".into(),
        "KbdInteractiveAuthentication=no".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "LogLevel=ERROR".into(),
    ]
}

/// Hardened ssh argv (everything but the program name + the remote command): explicit identity +
/// pinned known-hosts, no ambient config, no insecure host-key mode, pubkey-only fail-fast.
/// The caller appends the remote command as ONE trailing arg. `port` is the target's sshd port
/// (22 in the real ceremony; a forwarded high port under the QEMU e2e harness — ssh uses `-p`).
pub fn prod_ssh_args(ip: &str, identity: &Path, known_hosts: &Path, port: u16) -> Vec<String> {
    let mut args = hardened_common_args(identity, known_hosts);
    args.push("-p".into());
    args.push(port.to_string());
    args.push(format!("root@{ip}"));
    args
}

/// Hardened scp argv staging `local` to `root@<ip>:<remote_path>` under the same pinned host-key +
/// pubkey-only posture as [`prod_ssh_args`]. NOTE scp spells the port `-P` (capital), unlike ssh.
pub fn prod_scp_args(
    ip: &str,
    identity: &Path,
    known_hosts: &Path,
    port: u16,
    local: &Path,
    remote_path: &str,
) -> Vec<String> {
    let mut args = hardened_common_args(identity, known_hosts);
    args.push("-P".into());
    args.push(port.to_string());
    args.push(local.display().to_string());
    args.push(format!("root@{ip}:{remote_path}"));
    args
}

/// The remote `kexec -l` command line, returned as ONE string (ssh passes it to the target's
/// shell): the `--append` payload is single-quoted so the remote shell hands kexec the WHOLE
/// installer cmdline as one argv entry — a bare space would otherwise split it and silently drop
/// every token after the first. Fail-closed validation before composition: both staged paths must
/// re-pass the [`super::prod::validate_stage_dir`] whitelist, and the append must be printable
/// ASCII free of `'`/`\`/newline/NUL (guaranteed upstream by the whitelisted interpolations —
/// re-checked here so THIS boundary can't be reached with a quote-breaking payload).
pub fn build_kexec_load_command(
    staged_vmlinuz: &str,
    staged_initramfs: &str,
    append: &str,
) -> Result<String, String> {
                                                                                                   
    let vmlinuz = super::prod::validate_stage_dir(staged_vmlinuz)
        .map_err(|e| format!("staged vmlinuz path: {e}"))?;
    let initramfs = super::prod::validate_stage_dir(staged_initramfs)
        .map_err(|e| format!("staged initramfs path: {e}"))?;
                                                                                                  
                                                                                 
    if append.is_empty()
        || !append
            .bytes()
            .all(|b| (b' '..=b'~').contains(&b) && b != b'\'' && b != b'\\')
    {
        return Err(format!(
            "kexec --append contains a quote-breaking or non-printable byte — refusing to \
             compose a remote command from it: {append:?}"
        ));
    }
    Ok(format!(
        "kexec -l {vmlinuz} --initrd={initramfs} --append='{append}'"
    ))
}

                                                                               
                                                                                
                                                                               

use super::prod::{self, WipeConfirmed};

/// Which trust leg a target-facing call rides (distinct identities + known_hosts files):
/// Provisioning = the rented Debian's injected root key (Leg A); Reconnect = the installed box's
/// dropbear + the operator's box-login key, pinned to the derived runtime host key (Leg B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    Provisioning,
    Reconnect,
}

/// The `[layout]` numbers the flow consumes (mapped from the `.layout.toml` sidecar by
/// [`OrchestrationOps::read_image_artifacts`]). All byte units.
#[derive(Debug, Clone, Copy)]
pub struct LayoutInfo {
    pub boot_offset: u64,
    pub boot_size: u64,
    /// The persist-skeleton component's byte offset within the `.img` — needed to EMIT the
                                                                                                 
    /// so the ceremony serializes these numbers onto the append).
    pub persist_skeleton_offset: u64,
    pub persist_skeleton_size: u64,
    pub rootfs_offset: u64,
    pub rootfs_size: u64,
    pub rootfs_verity_hash_offset: u64,
    /// Which boot firmware the `.img` targets (from the `.layout.toml`), gating the MBR-vs-GPT branches
    /// at the sentinel pre-scan and the step-10 boot-fs identity replay. Populated via
    /// [`firmware_deploy_eligible`] (the deploy-prod allowlist), so `Uefi` never lands here — those
    /// branches encode that as `Firmware::Uefi => unreachable!()`. Under the streaming redesign
                                                                                      
    /// `fb.firmware` and the layout token's `fw:` field — the box fail-closes unless the two agree
    /// with each other and the arm (the two-token agreement catches composition bugs; the
    /// mandatory `fb.image-sha256` catches byte divergence).
    pub firmware: Firmware,
    /// The weights component's byte offset within the `.img` — `Some` only for a dha/model
    /// weights `.img` (always seabios-gpt); emitted into `fb.image-layout` alongside
    /// [`LayoutInfo::weights_size`].
    pub weights_offset: Option<u64>,
    /// The declared weights component size — doubles as the weights-partition sizing input
                                                                                            
    /// whole-image RAM preflight is retired; the disk-fit floor is the geometry computation).
    pub weights_size: Option<u64>,
}

/// The local build artifacts the ceremony stages, read ONCE up front. The `.img` itself is NEVER
                                                                                                    
/// the digest is chunked, and only BOUNDED regions (boot for the identity replay, rootfs data for
/// the verity recompute) are ever read.
pub struct ImageArtifacts {
    /// The exact `.img` byte length (`fb.image-raw`'s `<len>`; the window's size).
    pub img_len: u64,
    pub vmlinuz: Vec<u8>,
    pub initramfs: Vec<u8>,
    pub layout: LayoutInfo,
                                                                                                
    pub img_sha_sidecar: String,
                                                                                 
    pub vmlinuz_sha_sidecar: String,
    pub initramfs_sha_sidecar: String,
                                                                                               
    /// pre-sidecar image ⇒ fail closed (rebuild).
    pub operator_pubkey_fpr_sidecar: Option<String>,
    /// Local paths (scp sources) + their on-target file names.
    pub img_path: std::path::PathBuf,
    pub vmlinuz_path: std::path::PathBuf,
    pub initramfs_path: std::path::PathBuf,
    pub layout_path: std::path::PathBuf,
}

impl ImageArtifacts {
    fn file_name(p: &Path) -> Result<String, String> {
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
            .ok_or_else(|| format!("artifact path {} has no utf-8 file name", p.display()))?;
                                                                                             
                                                                                                   
                                                                                 
        prod::validate_artifact_filename(&name)
    }
}

/// The effects seam (the `InstallOps` pattern): every read of the world and every target-facing
/// action goes through here, so the flow's GATE ORDERING is host-testable with a recording fake,
/// and the destructive legs are visible as explicit calls.
pub trait OrchestrationOps {
    fn stdin_is_tty(&self) -> bool;
    fn say(&mut self, msg: &str);
                                                                                               
    /// no-op so wrappers (the e2e `NonInteractiveOps`) need no change; `ProcessOps` prints it,
    /// `FakeOps` records it on a channel SEPARATE from `target_calls` — the nine fail-closed asserts
    /// must stay byte-valid, so a banner may never enter `target_calls`.
    fn step(&mut self, _n: u32, _of: u32, _label: &str) {}
    /// One operator line (TTY confirm / retype); `None` on EOF or non-TTY.
    fn read_line(&mut self, prompt: &str) -> Option<String>;
    /// The SIGINT/SIGTERM flag (poll-based cooperative cancellation — handlers only set a flag).
    fn cancel_requested(&self) -> bool;
    fn sleep_secs(&mut self, secs: u64);
    fn now_epoch(&self) -> i64;
                                                                                             
    /// operator sees the exact endpoint they are authorizing. Read-only.
    fn ssh_port(&self) -> u16;
    /// Does the operator's AMBIENT `~/.ssh/known_hosts` hold a DIFFERENT key for `ip` than
                                                                                                
    /// advisory, NEVER edits known_hosts (the ceremony's hardened legs keep `-F /dev/null`). Default
    /// `None` so wrappers + the mock stay quiet unless a real conflict is present.
    fn ambient_known_hosts_conflict(
        &self,
        _ip: &str,
        _presented_type: &str,
        _presented_key: &str,
    ) -> Option<String> {
        None
    }

    /// Read the `.img` + sidecars + kexec artifacts beside it (local IO, no target contact).
    fn read_image_artifacts(&mut self, image: &Path) -> Result<ImageArtifacts, String>;
    /// `ssh-keygen -lf <pubkey>` → the `SHA256:…` fingerprint of the operator's `--pubkey`.
    fn local_pubkey_fingerprint(&mut self, pubkey: &Path) -> Result<String, String>;
    /// Derive the box's runtime host key from the local `.img` (rescue_keys offline precompute):
    /// `(ssh-ed25519 pubkey line, SHA256:… fingerprint)`.
    fn derive_runtime_hostkey(&mut self, image: &Path) -> Result<(String, String), String>;
    /// Recompute the dm-verity root hash over the `.img`'s rootfs DATA region
    /// `[offset, offset+len)` (veritysetup, local) — region-addressed so the flow never holds
    /// image bytes (the impl stream-copies the region to its veritysetup temp, O(chunk) RAM).
    fn recompute_root_hash(
        &mut self,
        img: &Path,
        rootfs_data_offset: u64,
        rootfs_data_len: u64,
    ) -> Result<String, String>;

    /// The known_hosts host token ssh matches for this target: `host` on port 22, `[host]:port`
    /// otherwise (OpenSSH's non-default-port form). The Leg-B reconnect pin MUST use this so ssh's
    /// `StrictHostKeyChecking` lookup matches the right line (Leg A reuses the `ssh-keyscan -p`
    /// output, which is already correctly host-formatted).
    fn known_hosts_host(&self) -> String;
    /// ssh-keyscan the provisioning target → `(known_hosts line, SHA256:… fingerprint)`.
    fn scan_host_key(&mut self) -> Result<(String, String), String>;
    /// Append the accepted line to the leg's controlled known_hosts file (ssh enforces the pin).
    fn pin_host_key(&mut self, leg: Leg, known_hosts_line: &str) -> Result<(), String>;
    /// Run one remote command over the leg, capturing stdout; Err on spawn/auth/non-zero exit.
    fn ssh_capture(&mut self, leg: Leg, remote_command: &str) -> Result<String, String>;
    /// Stage one local file to `root@<ip>:<remote_path>` (provisioning leg).
    fn scp_stage(&mut self, local: &Path, remote_path: &str) -> Result<(), String>;
    /// Stage small in-RAM bytes to `root@<ip>:<remote_path>` as a FILE — RETAINED for exactly the
                                                                                                 
                                                                                                
    /// it streams onto the raw tail window via [`OrchestrationOps::stage_raw_window`]).
    fn scp_image_bytes(&mut self, bytes: &[u8], remote_path: &str) -> Result<(), String>;
    /// Stream the local `.img` chunk-by-chunk through the (optional) sentinel patch substitution
    /// into a remote `dd of=/dev/<disk> oflag=seek_bytes seek=<offset> conv=notrunc,fsync` on the
                                                                                               
    /// placement via `oflag=seek_bytes` + the chunk-aligned offset; the returned digest is what
    /// `fb.image-sha256` carries). Operator RAM: O(chunk); the build `.img` on disk stays
    /// untouched (the patch is applied in flight, never to the file).
    fn stage_raw_window(
        &mut self,
        local_img: &Path,
        patch: Option<&crate::deploy::stage_stream::PatchSpec>,
        disk: &str,
        offset: u64,
    ) -> Result<[u8; 32], String>;
                                                                                                  
    /// `kexec -e` — the POINT OF NO RETURN, takes the wipe token BY VALUE (the structural
                                                                                            
                                                                                              
    /// connection is `Ok` (the target is rebooting into the installer).
    fn fire_kexec(&mut self, token: WipeConfirmed) -> Result<(), String>;
}

/// `deploy prod` inputs after CLI resolution (the image is already built or `--image`-selected;
/// identities + known-hosts paths live in the [`OrchestrationOps`] implementation).
pub struct DeployProdOpts {
    pub ip: String,
                                                                                               
    pub pubkey: std::path::PathBuf,
    /// The resolved local `.img` (sidecars + vmlinuz/initramfs beside it).
    pub image: std::path::PathBuf,
    /// Leg-A pin: the provisioning host key's `SHA256:…` fingerprint.
    pub host_fingerprint: Option<String>,
    /// Leg-A alternative: an operator-supplied pre-populated known_hosts file (used as-is).
    pub known_hosts: Option<std::path::PathBuf>,
    /// Leg-B pin cross-check (optional — the flow always derives the expected key itself).
    pub runtime_hostkey_fingerprint: Option<String>,
    pub image_stage_dir: String,
    /// `Some` iff `--wipe-confirmed` (the only constructor of the token).
    pub wipe_confirmed: Option<WipeConfirmed>,
    /// How long to poll the Leg-B reconnect (install + reboot + first-boot grow).
    pub reconnect_timeout_secs: u64,
                                                                                          
    /// restore-image` output). `Some` ⇒ the five-leg local restore preflight runs BEFORE any
    /// remote action and the image + its `.sig` are staged + threaded as `fb.restore-from`.
    pub restore_from: Option<std::path::PathBuf>,
    /// The opt-in anti-rollback floor threaded as `fb.min-ctr` (only valid WITH `restore_from`;
    /// the box refuses a below-floor bundle inside its quince verify).
    pub restore_min_ctr: Option<u64>,
    /// The artifact-signing root pin resolved by the CLI arm (`read_root_pin`, fail-closed).
    /// Threaded here because the restore preflight VERIFIES the restore bundle locally — and a
                                                                                             
    /// restore must never ride; the box hard-requires the `.sig` anyway — failing at preflight
    /// is strictly kinder; the image-triple skip exists only for signing-not-adopted greenfield).
    pub artifact_pin: Option<[u8; 32]>,
    /// The profile schema keys whose values came from a `--profile` (Component 5). Display-only: the
    /// C1 pre-wipe summary annotates these values `(profile)`. Empty when no profile was used.
    pub profile_sourced: std::collections::HashSet<String>,
                                                                                                
                                                                                                
    /// imply it.
    pub reclaim_tail: bool,
    /// §5.8: operator override of the reclaim reboot-poll bound (default 1800 s).
    pub reclaim_reboot_timeout_secs: Option<u64>,
}

                                                                                                   
/// ONLY by [`preflight_restore`] on full success — holding one is the proof every leg passed.
#[derive(Debug)]
pub(crate) struct RestorePreflight {
    /// The verified restore image bytes (staged VERBATIM — the same bytes the box dd's).
    pub image_bytes: Vec<u8>,
    /// The sibling `.sig` bundle bytes (staged beside the image; the box re-verifies on its side).
    pub sig_bytes: Vec<u8>,
    /// The image's file name (staging target under the stage dir).
    pub image_name: String,
    /// The `.sig`'s file name.
    pub sig_name: String,
    /// The accepted delegation's monotonic_ctr — PRINTED as the operator's future
                                                 
    pub printed_ctr: u64,
}

/// The five §5 preflight legs, ALL before any remote action (pure local IO):
///  1. the sibling `.sig` exists;
///  2. `verify_artifact_returning(pin, Backup, image)` → PRINT `monotonic_ctr` (the operator's
///     future `--restore-min-ctr` value);
///  3. `check_restore_identity(&bytes)` — the §4b-2/-3 LOCAL MIRROR (label/journal/magic), so a
///     wrong-artifact mixup aborts on the operator's machine, not post-kexec on the box;
///  4. the staged operator key inside the image == `--pubkey` (via `syslinux_install::read_file`
///     at the shared `PERSIST_AUTHORIZED_KEYS_PATH` — closes the BOOT-1 SSH-inaccessible-box
///     class: a restore image baked with a DIFFERENT key would install a box the operator
///     cannot log into);
///  5. `validate_artifact_filename` on the image + `.sig` names (the staging-path guards).
///
                                                                                                 
/// ABORT, not a skip — the image-triple skip exists for signing-not-adopted greenfield; a restore
/// artifact is EXACTLY the thing the signing scheme exists for, and the box will hard-require the
/// `.sig` at `fb.restore-from` time anyway.
pub(crate) fn preflight_restore(
    ops: &mut dyn OrchestrationOps,
    opts: &DeployProdOpts,
) -> Result<Option<RestorePreflight>, String> {
    let Some(image_path) = &opts.restore_from else {
        return Ok(None);
    };
    let pin = opts.artifact_pin.as_ref().ok_or(
        "--restore-from requires an artifact-signing pin in force (artifact-root.pub or \
         --artifact-pin): an UNVERIFIED restore image never rides the ceremony — the box \
         hard-requires the .sig, so failing here is strictly kinder (2)",
    )?;
                                                                                           
                                                                                               
    let image_name = ImageArtifacts::file_name(image_path)
        .map_err(|e| format!("restore preflight: --restore-from name: {e}"))?;
    let sig_path = crate::deploy::artifact_sign::sig_sidecar_path(image_path);
    let sig_name = ImageArtifacts::file_name(&sig_path)
        .map_err(|e| format!("restore preflight: .sig name: {e}"))?;
                                                                                         
    if !sig_path.is_file() {
        return Err(format!(
            "restore preflight: {} has no sibling .sig ({}) — sign it first: \
             orchard sign-backup <image>",
            image_path.display(),
            sig_path.display()
        ));
    }
                                                                           
    let verified = crate::deploy::artifact_verify::verify_artifact_returning(
        pin,
        dragonfruit::Purpose::Backup,
        image_path,
    )
    .map_err(|e| format!("restore preflight: {e}"))?;
    let printed_ctr = verified.monotonic_ctr();
    ops.say(&format!(
        "restore bundle monotonic_ctr = {printed_ctr}  (use as --restore-min-ctr on a future \
         restore to refuse older backups)"
    ));
    let image_bytes = std::fs::read(image_path)
        .map_err(|e| format!("restore preflight: read {}: {e}", image_path.display()))?;
    let sig_bytes = std::fs::read(&sig_path)
        .map_err(|e| format!("restore preflight: read {}: {e}", sig_path.display()))?;
                                                                                                
                                                                                                   
                                                                                                   
                                                                                             
                                                                                                
                                    
    if recipes_image_builder::image::sha256_hex(&image_bytes)
        != hex::encode(verified.artifact_hash())
    {
        return Err(format!(
            "restore preflight: {} changed on disk between the signature verify and the staging \
             read — aborting (never stage bytes that did not verify)",
            image_path.display()
        ));
    }
                                                                                                
                                                                                              
    recipes_image_builder::restore_image::check_restore_identity(&image_bytes)
        .map_err(|e| format!("restore preflight: {e}"))?;
                                                                                                
                                                                  
    let ours = crate::deploy::build_image::read_validated_pubkey("pubkey", &opts.pubkey)
        .map_err(|e| format!("restore preflight: --pubkey: {e}"))?;
    let staged = syslinux_install::read_file(
        &image_bytes,
        recipes_image_builder::build_tools_host::PERSIST_AUTHORIZED_KEYS_PATH,
    )
    .map_err(|e| {
        format!(
            "restore preflight: cannot read the staged operator key out of {}: {e} — not an \
             `orchard restore-image` output?",
            image_path.display()
        )
    })?;
    if staged.trim_ascii() != ours.trim().as_bytes() {
                                                                                                     
                                                                                                    
                                                                                                   
                                                                                                       
                                  
        return Err(format!(
            "restore preflight: the operator key STAGED IN the restore image does not match \
             --pubkey {} — a box restored from it would not accept your key (the BOOT-1 class). \
             Re-assemble with the right --operator-pubkey, and pass the SAME key file to both \
             `restore-image --operator-pubkey` and `prod --pubkey`.",
            opts.pubkey.display()
        ));
    }
    Ok(Some(RestorePreflight {
        image_bytes,
        sig_bytes,
        image_name,
        sig_name,
        printed_ctr,
    }))
}

/// Patch a CLONE of the build `.img` so the installed box's boot-fs APPEND carries
/// `fb.rootfs-dev=/dev/<disk>2` (slot A) instead of the build-baked sentinel. The dd-only
/// installer copies the boot-fs verbatim — without this operator-side patch the box boots the literal
/// sentinel, can't resolve its rootfs, and reboot-loops (the Debian-guest e2e finding). The whole
/// `.img` is returned (only the boot-fs region changes) so the staged bytes + their on-target sha256
/// re-verify are over the EXACT bytes the installer dd's. Fail-closed on a layout/image bounds mismatch.
                                                                                                 
/// the boot region is ever held, for the step-10 identity replay; the sentinel pre-scan does its
/// own bounded read in `stage_stream`). Fail-closed on a layout/file bounds mismatch.
fn read_boot_region(img: &Path, layout: &LayoutInfo) -> Result<Vec<u8>, String> {
    use std::io::{Read as _, Seek as _};
    let mut f = std::fs::File::open(img).map_err(|e| format!("open {}: {e}", img.display()))?;
    f.seek(std::io::SeekFrom::Start(layout.boot_offset))
        .map_err(|e| format!("seek boot region: {e}"))?;
    let boot_size = usize::try_from(layout.boot_size)
        .map_err(|_| "boot_size exceeds addressable memory".to_string())?;
    let mut boot = vec![0u8; boot_size];
    f.read_exact(&mut boot)
        .map_err(|e| format!("boot region exceeds the image (layout/img mismatch): {e}"))?;
    Ok(boot)
}

/// The step-10 LOCAL boot-fs identity hash for the target firmware, over a BOUNDED file read
                                                                                                    
/// local region (the only per-box variance) then hashes; SeaBIOS-on-GPT has NO per-box variance
/// (fixed baked PARTUUID, no patch) so it hashes the RAW boot region — a VERBATIM byte-equality
/// compare against the box, still a FULL assertion (skip the PATCH, never the CHECK).
                                                                                                           
fn local_boot_fs_identity_hash(
    img: &Path,
    layout: &LayoutInfo,
    disk: &str,
) -> Result<String, String> {
    let mut boot = read_boot_region(img, layout)?;
    match layout.firmware {
        Firmware::Seabios => {
                                                                                          
            prod::patch_rootfs_dev(&mut boot, &prod::partition_device_name(disk, 2))
                .map_err(|e| format!("local boot-fs patch replay failed: {e}"))?;
        }
        Firmware::SeabiosGpt => {}
        Firmware::Uefi => {
            unreachable!("uefi is refused by the deploy-prod allowlist (firmware_deploy_eligible)")
        }
    }
    Ok(recipes_image_builder::image::sha256_hex(&boot))
}

/// The operator advisory printed on the destructive path BEFORE the wipe gate (acceptance #7 /
                                                                                          
pub const DESTRUCTIVE_ADVISORY: &str = "\
ADVISORY — read before confirming:
  * STAGING BEGINS RAW WRITES TO THE TARGET DISK. Confirming starts streaming the image onto a
    raw region INSIDE the running system's disk (its probable free space, at the extreme tail)
    while that system is live — from that point 'the old system survives an abort' is probable,
    not guaranteed; recovery from a staging mishap is re-stage or re-provision.
  * POST-KEXEC FAILURES ARE BRICKED-UNTIL-CONSOLE. Once kexec fires there is no SSH path back
    to the old system; a failed install is recoverable only via the provider's VNC/serial
    console (greenfield has no slot-B to fall back to).
  * INSTALL-TIME TCB. The kexec'd installer is staged on — and verified by — this provisioning
    host. A compromised provisioning host controls the installer and can defeat every
    post-install check (they run as installed code). Real assurance requires a FRESH,
    UNCOMPROMISED provisioning host; the staged-artifact hashes only raise the bar
    (documented debt; structural close = a sovereign substrate).";

/// Free-space headroom over the staged artifact bytes (journal/metadata slack on the stage fs).
pub(crate) const STAGE_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;
                                                                                             
const MAX_CLOCK_SKEW_SECS: i64 = 60;

/// The standing note appended to every reclaim-region failure. R6→R13 treadmilled on computing,
/// per failure arm, WHAT to disclose about the target's permanence. This is a constant, and it
/// carries ONLY the facts true on EVERY reclaim-region failure: that permanent changes MAY have
/// been applied, and which ones are possible. The three neutralizations run in SEQUENCE (marker →
/// growroot purge → fstab strip; `reclaim/neutralize.rs`, enumerated by `ceremony_census_tests.rs`),
/// so a refusal inside the sequence leaves a PREFIX applied and the rest not. The note names the
/// SET they are drawn from ("any of"); it never asserts the conjunction as accomplished (R13
                                                                                                      
/// the hook is still armed, and whether the shrink/repartition/reboot completed — are NOT here: they
/// live in the per-arm renderers, each keyed on the STRUCTURAL BOUNDARY that establishes it
/// (`disarm()`'s outcome for the armed fact; `arbitrate`-Ok for the completed-reclaim fact, R13
                                                                                               
                                                                                            
/// `update-initramfs` rebuild). Decision record 2026-08-11-reclaim-tail-disclosure-simplification
/// (re-cut 2026-08-11 for the R12 and R13 folds).
pub(crate) const RECLAIM_STANDING_NOTE: &str = "if any reclaim step reached this target it may carry \
     PERMANENT changes (any of, applied in sequence: cloud-init disabled, the cloud-initramfs-growroot \
     package purged, the x-systemd.growfs option removed from every /etc/fstab entry carrying it), none of them restored on any path. Check which were applied and verify the target before \
     reusing it.";

/// The operator text produced for a reclaim-region failure. A newtype over `String` with a PRIVATE
/// field whose ONLY constructor is [`reclaim_abort_text`], the one function that appends
/// [`RECLAIM_STANDING_NOTE`]. Threaded through every reclaim-region renderer and helper so the note
/// cannot be produced except through that one function: a new note-dropping emitter cannot yield
/// operator text without routing through `reclaim_abort_text`. The type makes that a COMPILE-TIME
                                                                  
/// `reclaim_abort_text_call_sites_are_the_floored_set` failed open on a point-free / aliased / second
/// call). Consumed at the `deploy_prod` / `reclaim_tail_standalone` boundary by
/// [`ReclaimAbort::into_message`]. Accepted residual: a bare `return Err("…".to_string())` written
/// DIRECTLY in `deploy_prod`'s or `reclaim_tail_standalone`'s reclaim block still type-checks (both
/// entry points return `Result<(), String>`) — a visible anti-pattern in review, not the invisible
                                                                                          
/// `plan_and_consent` returned `Result<_, String>` too (mutations M-A / M-B, a new note-dropping
/// refusal in either compiled), so the lock was NOT yet total; both now return `ReclaimAbort`,
/// leaving the two entry points as the exact residual. The lock rests on the TYPE alone (R15
                                                                                                 
/// whole margin over the type was this same declared residual): a bare String refusal in a typed
/// fn is E0308, and a `String`-error helper called with `?` from one is E0277, because no
/// `From<String>` impl exists for `ReclaimAbort` — and none may be added; it would open a silent
/// note-free channel past `reclaim_abort_text`.
pub(crate) struct ReclaimAbort(String);

impl ReclaimAbort {
    /// The `Result<(), String>` boundary conversion: unwrap the rendered operator text. The ONLY
    /// way out of the newtype, so a reclaim-region error must be constructed by `reclaim_abort_text`
    /// (directly or via a renderer) before it can enter a `String` channel.
    pub(crate) fn into_message(self) -> String {
        self.0
    }
}

                                                                                                   
/// rendered operator text leaves the newtype ONLY via `into_message`; the derived Debug would honour
/// `format!("{:?}", …)` and wrap the raw message as `ReclaimAbort("…")`, an out-of-module
/// stringification path the enforcement doc did not enumerate. This shows the type, not the message,
/// and still satisfies the `Debug` bound `.unwrap()` needs.
impl std::fmt::Debug for ReclaimAbort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReclaimAbort(<reclaim operator text; use into_message>)")
    }
}

/// The ONE renderer for reclaim-region failure text: it appends [`RECLAIM_STANDING_NOTE`]
/// unconditionally, so no call site computes what to disclose. `detail` renders any `ReclaimRefusal`
                                                                                                      
/// Returns a [`ReclaimAbort`] — a newtype constructible ONLY here — so the standing note cannot be
/// produced anywhere else; a new reclaim-region emitter must route through this function to yield
                                                                                                     
                                                                                          
pub(crate) fn reclaim_abort_text(detail: impl Into<String>) -> ReclaimAbort {
    ReclaimAbort(format!("{}\n({RECLAIM_STANDING_NOTE})", detail.into()))
}

/// The completed-reclaim disclosure clause. Rendered by the per-arm renderers when the failure is
/// past `arbitrate`-Ok (the shrink, repartition and reboot are durable). Held as one const so the
/// fact attaches at the structural boundary that establishes it, never re-typed per arm (R13
            
const COMPLETED_RECLAIM_CLAUSE: &str = "the RECLAIM HAS RUN: the target's root filesystem was \
    shrunk, its partition repartitioned, and the target rebooted";

/// The staging-span timing fact for a composer/staging failure: no kexec fired, so the target still
/// runs its prior system. Held as one const and interpolated at each output arm of the staging
/// closure (`reclaim_done`, `reclaim_ro`, bare), exactly once per path, never re-typed per arm —
/// the same "carry the fact from the boundary that establishes it" move as [`COMPLETED_RECLAIM_CLAUSE`]
                                                                                                 
                                                            
const NO_KEXEC_OCCURRED_CLAUSE: &str = "the box still runs its prior system — no kexec occurred";

/// A failure at or after the hook write: the target may still be armed. NOT a `String` on purpose:
/// the fields are private, and there is no `Display`/`From<ArmedFailure> for String`, so no code
/// OUTSIDE this module can stringify one — present or future — without passing [`armed_abort`]
/// (disarm + disclosure) or [`completion_disarm_abort`]. The guarantee is scoped: it holds against
/// `Display`/`From` stringification and out-of-module access. SAME-module code can read the private
/// `text` field (`e.text`) directly and is trusted to, because the wrap sites — `armed_abort`,
/// `completion_disarm_abort` — live here (R13 I-1: the earlier "forgetting the wrap is a compile
/// error" claim was true only module-scoped).
/// `reclaim_completed` records whether the failure is past `arbitrate`-Ok (the shrink completed); it
/// is set ONCE at that boundary by [`ArmedFailure::mark_completed`], and the renderers append
                                                                                              
pub(crate) struct ArmedFailure {
    text: String,
    reclaim_completed: bool,
                                                                                                  
    /// so a post-reboot failure is not classified as a pre-reboot initramfs failure. Set at
    /// construction — a `&'static str` from `reclaim::rows`, the same "carry the non-monotone fact
    /// from the boundary that establishes it" move as `reclaim_completed`. `text` is the bare reason
                                                                                                   
    /// nested-row double-prefix on the refusal-derived arms).
    row: &'static str,
}

                                                                                                   
/// refusal text leaves an `ArmedFailure` ONLY via `armed_abort` / `completion_disarm_abort`; the
/// derived Debug was a third out-of-module stringification path (beside `Display`/`From`, which do
/// not exist). Shows the completion flag and a redaction marker, not the raw text.
impl std::fmt::Debug for ArmedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArmedFailure")
            .field("reclaim_completed", &self.reclaim_completed)
            .field(
                "text",
                &"<armed refusal text; use armed_abort/completion_disarm_abort>",
            )
            .finish()
    }
}

impl ArmedFailure {
    /// The failure is NOT known to be past the shrink (pre-`arbitrate` arms, install-time arms).
                                                                 
    pub(crate) fn new(row: &'static str, text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            reclaim_completed: false,
            row,
        }
    }
    /// The failure IS past `arbitrate`-Ok: the shrink, repartition and reboot are done.
    pub(crate) fn completed(row: &'static str, text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            reclaim_completed: true,
            row,
        }
    }
    /// Mark an existing failure as past the `arbitrate`-Ok boundary. Applied at the ONE boundary
    /// site (`reboot_and_arbitrate`), so every arm behind it inherits the fact by construction.
    pub(crate) fn mark_completed(mut self) -> Self {
        self.reclaim_completed = true;
        self
    }
    /// Read access for TEST assertions only — `#[cfg(test)]` so the doc claim above stays true:
    /// production code cannot stringify an `ArmedFailure` except through [`armed_abort`] or
                                                           
    #[cfg(test)]
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
                                                                                                          
    /// `armed_abort`/`completion_disarm_abort` render it; a test that drives `reboot_and_arbitrate`
    /// directly asserts the value here rather than on the bare `text`.
    #[cfg(test)]
    pub(crate) fn row(&self) -> &'static str {
        self.row
    }
}

/// The cooperative cancellation check between gates on the GENERIC ceremony path: BEFORE the kexec
/// subprocess exists the operator can abort freely; `staged` carries the on-target paths to
/// best-effort remove (bounded by the ssh ConnectTimeout). After [`OrchestrationOps::fire_kexec`]
/// the flow never calls this again (PastNoReturn — see [`CancelState`]). Deliberately NOTE-FREE
                                                                                                   
/// so a reclaim disclosure here would fire on targets no reclaim step ever reached. The reclaim
/// region's own cancel points are structurally separate — the two pre-write points call
/// `reclaim::ceremony::reclaim_cancel_check` (which appends the note), and a post-reclaim cancel
/// from the staging span is re-wrapped by the `reclaim_done` gate through [`armed_abort`] (disarm +
/// note + the completed-reclaim fact). Staged-file cleanup is keyed on `should_remove_staged_img`
/// matching `PreKexecSpawn`, so a new `CancelState` variant would silently stop that cleanup.
fn cancel_check(ops: &mut dyn OrchestrationOps, staged: Option<&[String]>) -> Result<(), String> {
    if !ops.cancel_requested() {
        return Ok(());
    }
    if let Some(paths) = staged {
        let rm = format!("rm -f {}", paths.join(" "));
        let _ = ops.ssh_capture(Leg::Provisioning, &rm);                                          
    }
    Err("cancelled by operator signal BEFORE kexec (staged files best-effort removed)".to_string())
}

                                                                                                   
/// reclaim hook — there is no hook file to remove, so no cleanup command is issued. Renders the
                                                                                                    
                                                                                                      
pub(crate) fn no_disarm_outcome(r: crate::deploy::reclaim::ReclaimRefusal) -> ReclaimAbort {
    reclaim_abort_text(format!(
        "{r}\n(this run wrote no reclaim hook, so no cleanup ran; if an earlier run left the \
         target armed and could not disarm — row R-ARMED — the orchard_guide.md §9.1 manual removal still applies)"
    ))
}

                                                                                               
/// failure came at or after the hook write, so the hook (and possibly the premount script + a
/// rebuilt initrd) may be on the target, and the disarm always runs — a `BeforeInstall` refusal
                                                                                              
                                                                                                     
/// `reclaim_abort_text` appends the standing note.
pub(crate) fn append_disarm_outcome(
    ops: &mut dyn OrchestrationOps,
    e: crate::deploy::reclaim::ReclaimRefusal,
    reclaim_completed: bool,
) -> ReclaimAbort {
    let detail = match crate::deploy::reclaim::ceremony::disarm_reachable(ops) {
        Ok(()) => format!(
            "{e}\n(disarmed: the hook and premount script are removed and the initrd rebuilt; \
             a re-run is admitted)"
        ),
        Err(de) => format!(
            "{e}\n(disarm did not verify: {} — the target may still be armed; row R-ARMED, \
             manual removal per orchard_guide.md §9.1)",
            de.text
        ),
    };
                                                                                                   
                                                                                        
    let completed = if reclaim_completed {
        format!("\n({COMPLETED_RECLAIM_CLAUSE})")
    } else {
        String::new()
    };
    reclaim_abort_text(format!("{detail}{completed}"))
}

/// The §5.11 completion-disarm failure (the ceremony otherwise succeeded — its only call site is
/// past `reboot_and_arbitrate`'s Ok, so the shrink, the repartition and the reboot are done — but
/// the disarm could not verify): the ONLY other consumer of an [`ArmedFailure`] besides
/// [`armed_abort`] — the disarm already ran (and failed), so no second attempt. The wrapper states
                                                                                                  
                                                                                                    
/// refusal texts carry their own. `reclaim_abort_text` appends the standing note.
pub(crate) fn completion_disarm_abort(de: ArmedFailure) -> ReclaimAbort {
                                                                                                
                                                                                              
                                                                                                    
                                                                                                 
    let completed = if de.reclaim_completed {
        format!("\n({COMPLETED_RECLAIM_CLAUSE})")
    } else {
        String::new()
    };
    reclaim_abort_text(format!(
        "{}\n(the target may still be armed — manual removal per orchard_guide.md §9.1){completed}",
        de.text
    ))
}

/// Route an `install_and_arm` failure to its operator outcome — the SINGLE routing site both callers
/// (`deploy_prod`, `reclaim_tail_standalone`) share, so the variant→consequence decision cannot drift
/// between them (R8 M2/M2b were exactly that two-site drift class). `BeforeInstall` wrote no hook this
                                                                                                       
                                                                                                  
/// fail-closed guard: a new `InstallFailure` variant is a compile error here until it is routed. Each
/// arm's consequence is asserted end-to-end by driving the real entry points
/// (`prod_orchestrate_reclaim_tests.rs`), never by re-implementing this match
                                                      
pub(crate) fn route_install_failure(
    ops: &mut dyn OrchestrationOps,
    e: crate::deploy::reclaim::ceremony::InstallFailure,
) -> ReclaimAbort {
    use crate::deploy::reclaim::ceremony::InstallFailure;
    match e {
        InstallFailure::BeforeInstall { exit: _, refusal } => no_disarm_outcome(refusal),
                                                                                                   
                                                                            
        InstallFailure::AfterInstall { exit: _, refusal } => {
            append_disarm_outcome(ops, refusal, false)
        }
    }
}

                                                                                                
                                                                                                     
/// so the hook may be on the target and the disarm must run. `reboot_and_arbitrate` and
/// `disarm_reachable` RETURN [`ArmedFailure`] (never `String`), so a present or future call site
                                                                                                
/// staging/kexec wrap constructs its `ArmedFailure` at the one `reclaim_done` gate. Each call site
/// is still floored by a test that drives its real entry point.
pub(crate) fn armed_abort(ops: &mut dyn OrchestrationOps, e: ArmedFailure) -> ReclaimAbort {
    let reclaim_completed = e.reclaim_completed;
    append_disarm_outcome(
        ops,
                                                                                                      
                                                           
        crate::deploy::reclaim::ReclaimRefusal::new(e.row, e.text),
        reclaim_completed,
    )
}

/// The `.layout.toml`'s declared `firmware = "<token>"` value, or `None` if no (non-comment) firmware
/// line is present. deploy-prod feeds this to [`firmware_deploy_eligible`], which ALLOWLISTS `"seabios"`
/// (MBR) and `"seabios-gpt"` (GPT) and fail-closes on `"uefi"` / an absent / a garbled line (allowlist >
/// blocklist; refuse at preflight, before the destructive kexec). This mirrors the on-box
/// `parse_image_layout`, which likewise REQUIRES the line. UEFI deploys via the signed-USB ceremony.
/// Tolerates surrounding whitespace; ignores comments.
fn layout_firmware_token(layout_text: &str) -> Option<String> {
    layout_text.lines().find_map(|l| {
        let t = l.trim();
        if t.starts_with('#') {
            return None;
        }
        let compact = t.replace(' ', "");
        compact
            .strip_prefix("firmware=\"")?
            .strip_suffix('"')
            .map(str::to_string)
    })
}

/// The deploy-prod firmware ALLOWLIST decision, extracted as a pure predicate so BOTH directions
                                                                                          
/// kexec-takeover ceremony installs a `seabios` (MBR) OR a `seabios-gpt` (GPT) image; it fail-closes on
/// `uefi` (its own signed-USB substrate ceremony) and on an absent/garbled firmware line. An ALLOWLIST,
/// never a blocklist — a future firmware token is refused by default, not silently accepted. The caller
/// prefixes the image path onto the returned message.
fn firmware_deploy_eligible(token: Option<&str>) -> Result<Firmware, String> {
    match token {
        Some("seabios") => Ok(Firmware::Seabios),
        Some("seabios-gpt") => Ok(Firmware::SeabiosGpt),
        other => {
            let got = other
                .map(|t| format!("\"{t}\""))
                .unwrap_or_else(|| "<no firmware line>".to_string());
            Err(format!(
                "declares firmware = {got}, but deploy-prod's kexec-takeover ceremony installs only a \
                 seabios (MBR) or seabios-gpt (GPT) image. Build a --firmware seabios or --firmware \
                 seabios-gpt image: uefi deploys via the signed-USB install ceremony (substrate-gated)."
            ))
        }
    }
}

/// Verify the local artifact set against its build-emitted sidecars (spec step 1): the `.img`,
/// vmlinuz, and initramfs bytes each match their `.sha256` sidecar, and the image's baked
                                                                                                 
/// key mismatch aborts BEFORE anything touches the target.
fn preflight_artifacts(
    ops: &mut dyn OrchestrationOps,
    opts: &DeployProdOpts,
    art: &ImageArtifacts,
) -> Result<(), String> {
    let sidecar_hex = |text: &str, what: &str| -> Result<String, String> {
        prod::parse_sha256sum_output(text)
            .first()
            .map(|(hex, _)| hex.clone())
            .ok_or_else(|| format!("{what} sidecar is not in sha256sum form: {text:?}"))
    };
    let check = |bytes: &[u8], sidecar: &str, what: &str| -> Result<(), String> {
        let expected = sidecar_hex(sidecar, what)?;
        let actual = recipes_image_builder::image::sha256_hex(bytes);
        if actual != expected {
            return Err(format!(
                "{what} does not match its .sha256 sidecar (local corruption or a mixed artifact \
                 set): sidecar {expected}, actual {actual} — aborting"
            ));
        }
        Ok(())
    };
                                                                                                 
                                                        
    {
        let expected = sidecar_hex(&art.img_sha_sidecar, ".img")?;
        let digest = crate::deploy::stage_stream::hash_file_chunked(&art.img_path)?;
        let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        if actual != expected {
            return Err(format!(
                ".img does not match its .sha256 sidecar (local corruption or a mixed artifact \
                 set): sidecar {expected}, actual {actual} — aborting"
            ));
        }
    }
    check(&art.vmlinuz, &art.vmlinuz_sha_sidecar, "vmlinuz")?;
    check(&art.initramfs, &art.initramfs_sha_sidecar, "initramfs")?;

    let baked = art.operator_pubkey_fpr_sidecar.as_deref().ok_or(
        "the image has no .operator-pubkey.fpr sidecar — rebuild with the current `deploy build` \
         (: the baked-pubkey preflight is required for `deploy prod`)",
    )?;
    let ours = ops.local_pubkey_fingerprint(&opts.pubkey)?;
    if baked.trim() != ours.trim() {
        return Err(format!(
            "--pubkey fingerprint {ours} does NOT match the pubkey baked into this image \
             ({baked}) — a box installed from it would not accept your key; aborting \
"
        ));
    }
    Ok(())
}

/// The step-9 reconnect wait: poll the box's dropbear until it answers or the wall-clock deadline,
                                                                                                   
/// this post-kexec path — well after every abort window — so the fail-closed mock asserts are
/// undisturbed. Extracted from `deploy_prod` so it is unit-testable with a mock clock.
fn reconnect_wait(ops: &mut dyn OrchestrationOps, timeout_secs: u64) -> Result<(), String> {
    let start = ops.now_epoch();
                                                                                           
                                                                                                   
                                                                                                  
                                                     
    let deadline = i64::try_from(timeout_secs)
        .ok()
        .and_then(|secs| start.checked_add(secs))
        .ok_or_else(|| {
            format!(
                "--reconnect-timeout-secs {timeout_secs} overflows the wall-clock reconnect \
                 deadline (clock {start}) — use a value under 24h; aborting before the poll"
            )
        })?;
    let mut last_tick = start;
    loop {
        ops.sleep_secs(5);
        if ops
            .ssh_capture(Leg::Reconnect, "echo recipes-box-up")
            .is_ok()
        {
            return Ok(());
        }
        let now = ops.now_epoch();
        if now - last_tick >= 15 {
            ops.say(&format!(
                "still waiting ({}/{timeout_secs}s) — install + reboot + first-boot grow in \
                 progress; no contact expected in the first ~2 min.",
                now - start
            ));
            last_tick = now;
        }
        if now >= deadline {
            return Err(format!(
                "the box did not come up within {timeout_secs}s (wall-clock) — the install may have failed \
                 post-kexec; check the provider's VNC/serial console (greenfield has no SSH \
                 fallback)"
            ));
        }
    }
}

                                                                                                 
/// decision the operator authorizes, `say()`d just before the wipe confirmation. Values a profile
/// supplied (Component 5) are annotated `(profile)` — the set is threaded from the merge (empty until
/// C5 wires it). Pure + testable; the confirmation prompt itself is unchanged.
fn render_pre_wipe_summary(
    ops: &dyn OrchestrationOps,
    art: &ImageArtifacts,
    verity_root: &str,
    stage: &str,
    opts: &DeployProdOpts,
    restore: Option<&RestorePreflight>,
    profile_sourced: &std::collections::HashSet<&str>,
) -> String {
    let annot = |keys: &[&str]| -> &'static str {
        if keys.iter().any(|k| profile_sourced.contains(k)) {
            " (profile)"
        } else {
            ""
        }
    };
    let img_name = art
        .img_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| opts.image.display().to_string());
    let img_sha = art
        .img_sha_sidecar
        .split_whitespace()
        .next()
        .unwrap_or("<unknown>");
                                                                                                    
                                                                                              
                                                     
    let op_fpr = art
        .operator_pubkey_fpr_sidecar
        .as_deref()
        .unwrap_or("<none>")
        .trim();
    let mut s = String::from(
        "\n\u{2500}\u{2500} deploy summary — what you are authorizing \u{2500}\u{2500}\n",
    );
    s.push_str(&format!("  image:        {img_name} (sha256 {img_sha})\n"));
    s.push_str(&format!("  verity root:  {verity_root}\n"));
    s.push_str(&format!(
        "  operator key: {op_fpr}{}\n",
        annot(&["operator_pubkey"])
    ));
    s.push_str(&format!(
        "  target:       {}:{}{}\n",
        opts.ip,
        ops.ssh_port(),
                                                                                                     
        annot(&["port"])
    ));
    s.push_str(&format!("  staging:      {stage}\n"));
    if let Some(r) = restore {
        let floor = opts
            .restore_min_ctr
            .map(|c| format!(", floor {c}"))
            .unwrap_or_default();
        s.push_str(&format!(
            "  restore:      {} (monotonic_ctr {}{})\n",
            r.image_name, r.printed_ctr, floor
        ));
    }
    s
}

/// Find a `known_hosts` line that CONFLICTS with the presented key for `ip`: same host, SAME
                                                                                                   
/// same host is NOT a conflict — `ssh-keyscan <ip>` (no `-t`) writes one line per algorithm, so an
/// IP-only compare would false-fire the advisory on an unchanged host. Hashed (`|1|`) / comment
/// lines are skipped (can't be matched to a plaintext ip). Pure over the file content — the testable
/// core of `ProcessOps::ambient_known_hosts_conflict`.
fn known_hosts_conflict_in(
    content: &str,
    ip: &str,
    presented_type: &str,
    presented_key: &str,
) -> Option<String> {
    if presented_type.is_empty() || presented_key.is_empty() {
        return None;
    }
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('|') {
            continue;
        }
        let mut f = line.split_whitespace();
        let hosts = f.next().unwrap_or("");
        let matches_ip = hosts
            .split(',')
            .any(|h| h == ip || h.starts_with(&format!("[{ip}]")));
        if !matches_ip {
            continue;
        }
        let ktype = f.next().unwrap_or("");
        let key = f.next().unwrap_or("");
                                                                                                     
                                                                                   
        if ktype == presented_type && !key.is_empty() && key != presented_key {
            return Some(line.to_string());
        }
    }
    None
}

                                                                                                  
/// own `~/.ssh/known_hosts` holds a DIFFERENT key of the SAME keytype for `ip` than the provisioning
/// host presented (a panel reinstall, not MITM). Advisory only — never edits known_hosts.
fn maybe_known_hosts_advisory(
    ops: &dyn OrchestrationOps,
    ip: &str,
    presented_type: &str,
    presented_key: &str,
) -> Option<String> {
    let conflicting = ops.ambient_known_hosts_conflict(ip, presented_type, presented_key)?;
    Some(format!(
        "note: your ~/.ssh/known_hosts already holds a DIFFERENT key for {ip}:\n  {conflicting}\n\
         this is the EXPECTED result of the box being (re)installed at this address — NOT a MITM. \
         The ceremony pins its OWN key on a private known_hosts; your ambient file is untouched. \
         After the install completes, clear the stale entry: ssh-keygen -R {ip}"
    ))
}

                                                                                                 
/// that the next plain `ssh` will warn host-key-CHANGED (the INSTALL, not a MITM), and the cleanup.
fn completion_message(ip: &str, runtime_fpr: &str) -> String {
    format!(
        "the installed box's runtime host key is {runtime_fpr}. A plain `ssh {ip}` will warn \
         host-key-CHANGED — that is the INSTALL replacing the provisioning key, NOT a MITM. Clear \
         the stale entry with: ssh-keygen -R {ip}"
    )
}

/// The `deploy prod <ip>` greenfield ceremony (spec "The greenfield flow", steps 1-10). Every
/// gate fails closed before the next step; steps 1-6 write nothing destructive; the first
/// irreversible action is [`OrchestrationOps::fire_kexec`], which demands the [`WipeConfirmed`]
/// token by value.
pub fn deploy_prod(ops: &mut dyn OrchestrationOps, mut opts: DeployProdOpts) -> Result<(), String> {
                                                                                               
                                                                                                 
                                                                                                   
                                                                                                
                                                                                                   
    let total_steps = if opts.known_hosts.is_none() { 9 } else { 8 };
    let mut step_n = 0u32;
    step_n += 1;
    ops.step(step_n, total_steps, "local preflight gates");
    let token = opts.wipe_confirmed.take().ok_or(
        "deploy prod ERASES the target's whole disk; pass --wipe-confirmed to proceed \
",
    )?;
    let ip = prod::validate_target_host(&opts.ip)?;
    let stage_dir = prod::validate_stage_dir(&opts.image_stage_dir)?;
    if opts.host_fingerprint.is_none() && opts.known_hosts.is_none() && !ops.stdin_is_tty() {
        return Err(
            "no --host-fingerprint / --known-hosts and stdin is not a TTY — Leg-A host-key \
             trust cannot be pinned or confirmed; failing closed (never accept-new)"
                .to_string(),
        );
    }

                                                                                                
    step_n += 1;
    ops.step(step_n, total_steps, "image preflight");
    let art = ops.read_image_artifacts(&opts.image)?;
    preflight_artifacts(ops, &opts, &art)?;
                                                                                              
                                                                                                 
    let restore = preflight_restore(ops, &opts)?;
    let layout = art.layout;
    let img_len = art.img_len;
                                                                                                     
                                                                                                  
                                                                                                   
                                                                                                      
                                                                                                 
                     
    let in_bounds =
        |offset: u64, size: u64| offset.checked_add(size).is_some_and(|end| end <= img_len);
    let bounds_ok = in_bounds(layout.boot_offset, layout.boot_size)
        && in_bounds(layout.persist_skeleton_offset, layout.persist_skeleton_size)
        && in_bounds(layout.rootfs_offset, layout.rootfs_size)
        && layout.rootfs_verity_hash_offset <= layout.rootfs_size
        && match (layout.weights_offset, layout.weights_size) {
            (Some(o), Some(s)) => in_bounds(o, s),
            (None, None) => true,
                                                                                             
            _ => false,
        };
    if !bounds_ok {
        return Err(format!(
            "layout sidecar offsets exceed the .img ({img_len} bytes) — mixed or corrupt \
             artifact set; aborting"
        ));
    }
                                                                                                
                                                                                                   
                                                  
    if img_len == 0 || !img_len.is_multiple_of(512) {
        return Err(format!(
            ".img is {img_len} bytes — not a non-zero 512-multiple; corrupt or foreign artifact \
             (the builder emit-asserts alignment); rebuild and retry"
        ));
    }

                                                                                            
    let (runtime_pubkey_line, derived_fpr) = ops.derive_runtime_hostkey(&opts.image)?;
    if let Some(flag) = &opts.runtime_hostkey_fingerprint
        && flag.trim() != derived_fpr.trim()
    {
        return Err(format!(
            "--runtime-hostkey-fingerprint {flag} does not match the fingerprint derived \
             from {}: {derived_fpr} — wrong image or a typo; aborting",
            opts.image.display()
        ));
    }

                                                                                                
                                                                                                 
                                                                     
    let local_root_hash = ops.recompute_root_hash(
        &art.img_path,
        layout.rootfs_offset,
        layout.rootfs_verity_hash_offset,
    )?;

                                                                                                
    cancel_check(ops, None)?;
    if opts.known_hosts.is_none() {
        step_n += 1;
        ops.step(step_n, total_steps, "connect + pin host key");
        let (line, presented) = ops.scan_host_key()?;
        use prod::HostKeyDecision::*;
        match prod::host_key_decision(
            opts.host_fingerprint.as_deref(),
            ops.stdin_is_tty(),
            &presented,
        ) {
            Accept => ops.pin_host_key(Leg::Provisioning, &line)?,
            ConfirmInteractively(fp) => {
                ops.say(&format!(
                    "Leg-A host key for {ip} is UNPINNED. Presented: {fp}\n\
                     Compare against the provider console before trusting."
                ));
                match ops.read_line("type 'yes' to trust this key: ") {
                    Some(ans) if ans.trim() == "yes" => {
                        ops.pin_host_key(Leg::Provisioning, &line)?
                    }
                    _ => {
                        return Err(
                            "operator declined the presented Leg-A host key — aborting".into()
                        );
                    }
                }
            }
            Abort => {
                return Err(format!(
                    "Leg-A host-key MISMATCH: pinned {} but {ip} presented {presented} — \
                     possible MitM or wrong host; aborting",
                    opts.host_fingerprint.as_deref().unwrap_or("<none>")
                ));
            }
            FailClosed => {
                return Err("no Leg-A pin and no TTY to confirm on — failing closed".into());
            }
        }
                                                                                                      
                                                                                                   
                                                                                                         
                                                                                   
        let presented_type = line.split_whitespace().nth(1).unwrap_or("");
        let presented_key = line.split_whitespace().nth(2).unwrap_or("");
        if let Some(advisory) = maybe_known_hosts_advisory(ops, &ip, presented_type, presented_key)
        {
            ops.say(&advisory);
        }
    }
    ops.ssh_capture(Leg::Provisioning, "echo recipes-deploy-connected")?;

                                                                                                
    step_n += 1;
    ops.step(step_n, total_steps, "on-target discovery");
    cancel_check(ops, None)?;
    let root_dev = {
        let fm = ops
            .ssh_capture(Leg::Provisioning, "findmnt -n -o SOURCE / || true")
            .unwrap_or_default();
        match prod::parse_findmnt_source(&fm) {
            Some(d) => d,
            None => {
                let mounts = ops
                    .ssh_capture(Leg::Provisioning, "cat /proc/self/mounts")
                    .unwrap_or_default();
                prod::parse_proc_mounts_root(&mounts).ok_or(
                    "could not discover the target's root partition (findmnt AND \
                     /proc/self/mounts both failed to yield a plain /dev/<partition>) — HARD \
                     ABORT, never a default-device guess. LVM/LUKS/whole-disk \
                     roots are unsupported.",
                )?
            }
        }
    };
                                                                                        
                                                                                  
    let real_stage_raw = ops.ssh_capture(
        Leg::Provisioning,
        &format!("mkdir -p {stage_dir} && realpath {stage_dir}"),
    )?;
    let real_stage = prod::validate_stage_dir(real_stage_raw.trim())
        .map_err(|e| format!("the on-target realpath of --image-stage-dir failed: {e}"))?;
    let stage_dev = {
        let fm = ops
            .ssh_capture(
                Leg::Provisioning,
                &format!("findmnt -n -o SOURCE --target {real_stage} || true"),
            )
            .unwrap_or_default();
        match prod::parse_findmnt_source(&fm) {
            Some(d) => d,
            None => {
                let df = ops.ssh_capture(Leg::Provisioning, &format!("df -P {real_stage}"))?;
                prod::parse_df_source(&df).ok_or_else(|| {
                    format!(
                        "could not resolve the partition holding the stage dir {real_stage}; \
                         aborting"
                    )
                })?
            }
        }
    };
    prod::check_same_partition(&root_dev, &stage_dev)?;
    let lsblk = ops.ssh_capture(Leg::Provisioning, "lsblk -nro NAME,TYPE,MOUNTPOINT,PKNAME")?;
    let disk = prod::parse_lsblk_parent_walk(&lsblk, &root_dev)?;
                                                      
    let df = ops.ssh_capture(Leg::Provisioning, &format!("df -P -k {real_stage}"))?;
    let avail = prod::parse_df_avail_kib(&df)
        .ok_or("unparseable df output for the stage dir; aborting")?
        .saturating_mul(1024);
    let restore_staged_bytes = restore
        .as_ref()
        .map(|r| (r.image_bytes.len() + r.sig_bytes.len()) as u64)
        .unwrap_or(0);
                                                                                                
                                                                         
    let staged_bytes = (art.vmlinuz.len() + art.initramfs.len()) as u64
        + restore_staged_bytes
        + STAGE_HEADROOM_BYTES;
    if avail < staged_bytes {
                                                                                                 
                                                                                                    
        let restore_note = if restore.is_some() {
            " + restore image + .sig"
        } else {
            ""
        };
        return Err(format!(
            "stage partition has {avail} bytes free but staging needs {staged_bytes} \
             (vmlinuz + initramfs{restore_note} + headroom) — aborting"
        ));
    }
                                                                                              
                                                                                          
                                                                                             
                                                                                                
                                                                                   
    let sectors = prod::parse_u64_line(&ops.ssh_capture(
        Leg::Provisioning,
        &format!("cat /sys/class/block/{disk}/size"),
    )?)
    .ok_or_else(|| format!("unparseable /sys/class/block/{disk}/size; aborting"))?;
    let disk_bytes = sectors.saturating_mul(512);
    let restore_len = restore
        .as_ref()
        .map(|r| r.image_bytes.len() as u64)
        .unwrap_or(0);
    let window = crate::deploy::staging_geometry::place_and_check_window(
        &layout,
        &disk,
        disk_bytes,
        img_len,
        restore_len,
    )?;
                                                                                                  
                                                                                                       
                                                                                                 
                                                                                                 
                                                
    let extents = prod::parse_lsblk_partition_extents(
        &ops.ssh_capture(
            Leg::Provisioning,
            &format!("lsblk -nbro NAME,TYPE,START,SIZE /dev/{disk}"),
        )?,
        &disk,
    )?;
                                                                                           
                                                                                                     
                                                                         
    let d1_first =
        crate::deploy::staging_geometry::refuse_if_window_intersects_partition(&window, &extents);
    let reclaim_ro = if crate::deploy::reclaim::consent::ReclaimConfirmed::from_flag(
        opts.reclaim_tail,
    )
    .is_some()
    {
        if let Err(e) = &d1_first {
            ops.say(&format!(
                "D-1 refused (RECORDED, --reclaim-tail): {e}\nrunning the reclaim's read-only \
                 checks…"
            ));
        }
        let inputs = crate::deploy::reclaim::ceremony::SpliceInputs {
            ip: &ip,
            disk: &disk,
            root_dev: &root_dev,
            disk_bytes,
            window: &window,
            img_len,
            staging_reserve: staged_bytes,
            extents: &extents,
            d1: d1_first.clone(),
            timeout_secs: crate::deploy::reclaim::ceremony::effective_timeout(
                opts.reclaim_reboot_timeout_secs,
            ),
        };
        Some(
            crate::deploy::reclaim::ceremony::read_only_half(ops, &inputs)
                .map_err(ReclaimAbort::into_message)?,
        )
    } else {
        d1_first?;
        None
    };
                                                                                               
                                                                                              
                                                                                           
                                                                                        
                             
    let root_df = ops.ssh_capture(Leg::Provisioning, "df -P -k /")?;
    let root_avail = prod::parse_df_avail_kib(&root_df)
        .ok_or("unparseable df output for the old root fs; aborting")?
        .saturating_mul(1024);
    if root_avail < img_len {
        let d8_msg = format!(
            "the old root fs reports {root_avail} bytes free but the staging window needs \
             {img_len} — its live data almost certainly reaches the disk tail; use a bigger \
             disk, a smaller image, or re-provision; aborting BEFORE any action"
        );
                                                                                               
                                                                                                 
                                                                                               
                                                                                              
                                                              
        match reclaim_ro.as_ref() {
            Some(ro) if ro.d8_recorded_not_fatal => {
                ops.say(&format!("D8 (RECORDED, --reclaim-tail): {d8_msg}"));
            }
            _ => return Err(d8_msg),
        }
    }
                                                                                          
                                                                                               
                                                                                              
                                                                                              
    let meminfo = ops.ssh_capture(Leg::Provisioning, "cat /proc/meminfo")?;
    let mem_total = prod::parse_meminfo_memtotal_bytes(&meminfo)
        .ok_or("could not parse MemTotal from the target's /proc/meminfo; aborting")?;
    prod::refuse_if_ram_below_floor(mem_total)?;
                                                                                                 
                                                                                                     
                                                                                                       
                                                                                                
                                                                                              
                                                                                                   
                                                                   
    let static_ceiling = recipes_image_builder::restore_image::RESTORE_ASSEMBLY_CEILING_BYTES;
    let restore_cap =
        static_ceiling.min(mem_total.saturating_sub(prod::RESTORE_CAP_HEADROOM_BYTES));
    if restore_len > restore_cap {
        return Err(format!(
            "the restore image is {restore_len} bytes but the box's restore cap is {restore_cap} \
             (min of the {static_ceiling}-byte static ceiling and MemTotal {mem_total} − the \
             {}-byte headroom); use a target with more RAM or a smaller restore; aborting BEFORE \
             any action",
            prod::RESTORE_CAP_HEADROOM_BYTES
        ));
    }
                                                                               
    let kexec_probe = ops.ssh_capture(Leg::Provisioning, "command -v kexec || echo MISSING")?;
    if kexec_probe.trim().is_empty() || kexec_probe.contains("MISSING") {
        return Err(
            "kexec not found on the target — `apt-get install -y kexec-tools` first; aborting \
             before any change"
                .to_string(),
        );
    }
                                                                                            
    let parsed = prod::parse_u64_line(&ops.ssh_capture(Leg::Provisioning, "date +%s")?)
        .ok_or("unparseable `date +%s` from the target; aborting")?;
                                                                                                   
                                                                                                 
                                                
    let remote_epoch = i64::try_from(parsed).map_err(|_| {
        "target clock `date +%s` reads out of i64 range — the target clock is unreadable; aborting"
    })?;
    let now = ops.now_epoch();
    let skew = remote_epoch
        .checked_sub(now)
        .and_then(i64::checked_abs)
        .ok_or(
            "target clock skew is out of i64 range — the target clock is unreadable; aborting",
        )?;
    if skew >= MAX_CLOCK_SKEW_SECS {
        return Err(format!(
            "target clock is {skew}s off the operator clock (limit {MAX_CLOCK_SKEW_SECS}s) — \
             first-boot certificates would carry wrong dates; fix the target clock; aborting"
        ));
    }
                                                                                                
                                                                                                
                                                                                                     
                                                                                                  
                                                                                             
                                                                                              
    let patch = crate::deploy::stage_stream::sentinel_patch_spec(&art.img_path, &layout, &disk)?;

                                                                                                
    step_n += 1;
    ops.step(step_n, total_steps, "wipe gate");
                                                                                                         
                                                                                                       
                                                                                      
    let profile_sourced: std::collections::HashSet<&str> =
        opts.profile_sourced.iter().map(|s| s.as_str()).collect();
    let summary = render_pre_wipe_summary(
        ops,
        &art,
        &local_root_hash,
        &real_stage,
        &opts,
        restore.as_ref(),
        &profile_sourced,
    );
    let reclaim_decision = reclaim_ro.as_ref().map(|ro| ro.decision);
    let mut summary = summary;
    if let Some(row) = crate::deploy::reclaim::consent::summary_row(reclaim_decision) {
        summary.push_str(&row);                                                    
    }
    ops.say(&summary);
    match crate::deploy::reclaim::consent::advisory_clause(reclaim_decision) {
                                                                                  
                                                                
        Some(clause) => {
            let mut advisory = DESTRUCTIVE_ADVISORY.to_string();
            advisory.push_str(&clause);
            ops.say(&advisory);
        }
        None => ops.say(DESTRUCTIVE_ADVISORY),
    }
    let retype = if ops.stdin_is_tty() {
        ops.read_line(&prod::whole_disk_echo(&disk, &ip))
    } else {
        None
    };
    prod::wipe_gate(ops.stdin_is_tty(), retype.as_deref(), &disk, &ip)?;

                                                                                               
                                                                                            
                                                                                                 
                                                                             
    let mut reclaim_done = false;
    if let Some(ro) = &reclaim_ro
        && let Some(prepared) = &ro.prepared
    {
                                                                                                    
                                                                     
        crate::deploy::reclaim::ceremony::reclaim_cancel_check(ops)
            .map_err(ReclaimAbort::into_message)?;
        crate::deploy::reclaim::ceremony::plan_and_consent(
            ops,
            prepared,
            crate::deploy::reclaim::consent::EntryPoint::Prod,
        )
        .map_err(ReclaimAbort::into_message)?;
                                             
        crate::deploy::reclaim::ceremony::reclaim_cancel_check(ops)
            .map_err(ReclaimAbort::into_message)?;
        if let Err(e) = crate::deploy::reclaim::ceremony::install_and_arm(ops, prepared) {
                                                                                                         
            return Err(route_install_failure(ops, e).into_message());
        }
        let crumbs = match crate::deploy::reclaim::ceremony::reboot_and_arbitrate(
            ops,
            prepared,
            &window,
            &real_stage,
            staged_bytes,
            crate::deploy::reclaim::ceremony::effective_timeout(opts.reclaim_reboot_timeout_secs),
            MAX_CLOCK_SKEW_SECS,
            true,
        ) {
            Ok(c) => c,
            Err(e) => return Err(armed_abort(ops, e).into_message()),
        };
        reclaim_done = true;
        ops.say(&format!(
            "reclaim-tail COMPLETE: the window sits in unpartitioned space and D-1 passes on \
             the re-read extents ({} breadcrumb line(s) fetched); continuing to staging",
            crumbs.len()
        ));
    }

                                                                                                
                                                                                                 
                                                                                                 
                                                                                                      
                                                                                              
                                                                                                  
                                                                                              
                                                                                                   
                                                                                                  
                                                                                                
                                                                                               
                                                                                               
                                                                                                 
                                                                                                  
              
    let stage_result: Result<(), String> = (|| {
        step_n += 1;
        ops.step(step_n, total_steps, "stage + verify artifacts");
        cancel_check(ops, None)?;
        let vml_name = ImageArtifacts::file_name(&art.vmlinuz_path)?;
        let ifs_name = ImageArtifacts::file_name(&art.initramfs_path)?;
        let vml_remote = format!("{real_stage}/{vml_name}");
        let ifs_remote = format!("{real_stage}/{ifs_name}");
                                                                                                   
                                                                                                   
                                                               
        let mut staged: Vec<String> = vec![vml_remote.clone(), ifs_remote.clone()];
        ops.scp_stage(&art.vmlinuz_path, &vml_remote)?;
        ops.scp_stage(&art.initramfs_path, &ifs_remote)?;
                                                                                         
                                                                                                   
                                                                                                        
        ops.say(&format!(
            "streaming the {img_len}-byte image onto the raw tail window of /dev/{disk} at byte \
         {} (O(chunk) RAM both sides)…",
            window.offset
        ));
        let staged_digest =
            ops.stage_raw_window(&art.img_path, patch.as_ref(), &disk, window.offset)?;
        let staged_digest_hex: String = staged_digest.iter().map(|b| format!("{b:02x}")).collect();
                                                                                                       
                                                                                         
        let restore_remote = restore.as_ref().map(|r| {
            (
                format!("{real_stage}/{}", r.image_name),
                format!("{real_stage}/{}", r.sig_name),
            )
        });
        if let (Some(r), Some((img_r, sig_r))) = (&restore, &restore_remote) {
            ops.say(&format!(
                "staging the VERIFIED restore image (monotonic_ctr {}) + its .sig",
                r.printed_ctr
            ));
            ops.scp_image_bytes(&r.image_bytes, img_r)?;
            ops.scp_image_bytes(&r.sig_bytes, sig_r)?;
            staged.push(img_r.clone());
            staged.push(sig_r.clone());
        }
        cancel_check(ops, Some(&staged))?;
                                                                                                     
                                                                                                     
                                                                                                     
                                                                                                     
                                                                                                  
                                                      
        let direct_file_ok = |ops: &mut dyn OrchestrationOps,
                              remote: &str,
                              bytes: &[u8],
                              what: &str|
         -> Result<(), String> {
            let want = recipes_image_builder::image::sha256_hex(bytes);
            let out = ops.ssh_capture(
                Leg::Provisioning,
                &format!("dd if={remote} iflag=direct bs=1M status=none | sha256sum"),
            )?;
            match out.split_whitespace().next() {
                Some(hex) if hex.eq_ignore_ascii_case(&want) => Ok(()),
                Some(hex) => Err(format!(
                    "staged {what} direct-read hash mismatch: local {want}, on-target {hex} — \
                 partial scp, corruption, or window clobber; re-stage; aborting before kexec \
                 (step 5)"
                )),
                None => Err(format!(
                    "on-target direct read returned no digest for {remote}; aborting"
                )),
            }
        };
        direct_file_ok(ops, &vml_remote, &art.vmlinuz, "vmlinuz")?;
        direct_file_ok(ops, &ifs_remote, &art.initramfs, "initramfs")?;
        if let (Some(r), Some((img_r, sig_r))) = (&restore, &restore_remote) {
            direct_file_ok(ops, img_r, &r.image_bytes, "restore image")?;                                
            direct_file_ok(ops, sig_r, &r.sig_bytes, "restore .sig")?;
        }
                                                                                                     
                                                                                             
        let window_out = ops.ssh_capture(
            Leg::Provisioning,
            &format!(
                "dd if=/dev/{disk} iflag=direct,skip_bytes,count_bytes skip={} count={} bs=1M \
             status=none | sha256sum",
                window.offset, window.len
            ),
        )?;
        match window_out.split_whitespace().next() {
            Some(hex) if hex.eq_ignore_ascii_case(&staged_digest_hex) => {}
            Some(hex) => {
                return Err(format!(
                    "staged window direct-readback mismatch: streamed {staged_digest_hex}, on-disk \
                 {hex} — live-Debian writeback/allocation contention or an I/O fault; re-stage \
                 (idempotent, same window); repeated recurrence ⇒ the D8 contention diagnosis \
                 (bigger disk / smaller image / re-provision); aborting before kexec"
                ));
            }
            None => return Err("on-target window readback returned no digest; aborting".into()),
        }

        step_n += 1;
        ops.step(step_n, total_steps, "kexec takeover");
                                                                                                    
                                                                                                      
                                                                                                      
                                                                                                
        let append = prod::build_installer_cmdline(
            &local_root_hash,
            layout.rootfs_verity_hash_offset,
            &window,
            &staged_digest_hex,
            &layout,
                                                                                                 
                                                                                                     
                                                     
            restore_remote
                .as_ref()
                .map(|(img_r, _)| (root_dev.as_str(), img_r.as_str())),
            opts.restore_min_ctr,
        )
                                                                                                 
                                                                                                    
                                                                                                  
                                                                                            
                                                                                                     
                                                                           
          
                                                                                                   
                                                                                               
                                                                                                   
                              
          
                                                                                              
                                                                                                   
                                                                                                 
                                                                                               
                                                                                                 
                                                                                                      
                            
        .map_err(|e| {
            let mut msg = e.to_string();
            if matches!(&e, prod::CmdlineError::Length { .. }) {
                msg.push_str(
                    "\nThe consumer on this path is kexec-tools 2.0.29 `bzImage64_load`, which \
                     REFUSES an over-long append rather than truncating it \
                     (`kexec-bzImage64.c:141-144` returns -1, no token delivered), so the whole \
                     load fails, not any tail token.",
                );
            }
            msg.push_str(&format!(
                "\nTwo residues were already written and this refusal removes neither: the raw \
                 tail window on the target's free-space tail (unpartitioned, inert), and the \
                 staged files (vmlinuz and initramfs, plus the --restore-from image and its .sig \
                 when a restore was requested) under {real_stage} on the target's ROOT partition."
            ));
            msg
        })?;
        let load = build_kexec_load_command(&vml_remote, &ifs_remote, &append)?;
        cancel_check(ops, Some(&staged))?;                                                        
        ops.ssh_capture(Leg::Provisioning, &load)?;
        ops.say(&format!(
            "kexec loaded on {ip}; executing — the target now reboots into the installer. \
             From this point cancellation CANNOT undo anything (kexec may have fired). The target's \
             console is only visible via your provider's VNC from here; typical time to first contact \
             is ~2-4 min."
        ));
                                                                                                      
        ops.fire_kexec(token)?;
        Ok(())
    })();
    if let Err(e) = stage_result {
                                                                                                   
                                                                                                     
                                                                                                 
                                                                                                 
                                                                                                     
                                                                                                   
                                                                                                         
                                                                                                   
                                                                                                      
                                                                                                       
                                                                                                      
                                                                     
        return Err(if reclaim_done {
            armed_abort(
                ops,
                                                                                                   
                                                                                             
                ArmedFailure::completed(
                    crate::deploy::reclaim::rows::POST_FIT,
                    format!("{e}\n({NO_KEXEC_OCCURRED_CLAUSE})"),
                ),
            )
            .into_message()
        } else if reclaim_ro.is_some() {
            reclaim_abort_text(format!(
                "{e}\n({NO_KEXEC_OCCURRED_CLAUSE})\n(reclaim was requested but short-circuited this \
                 run; if a PRIOR run reclaimed this target it may already be permanently altered and \
                 its hook may be installed, the orchard_guide.md §9.1 manual removal applies)"
            ))
            .into_message()
        } else {
            format!("{e}\n({NO_KEXEC_OCCURRED_CLAUSE})")
        });
    }

                                                                                                
    step_n += 1;
    ops.step(step_n, total_steps, "reconnect to the box");
                                                                                                  
                                                                           
    let reconnect_host = ops.known_hosts_host();
    ops.pin_host_key(
        Leg::Reconnect,
        &format!("{reconnect_host} {runtime_pubkey_line}"),
    )?;
    ops.say(&format!(
        "waiting for the installed box at {ip} (install + reboot + first-boot grow; up to \
         {}s)…",
        opts.reconnect_timeout_secs
    ));
                                                                                         
                                                                                               
                                                                                                    
    reconnect_wait(ops, opts.reconnect_timeout_secs)?;

                                                                                                
    step_n += 1;
    ops.step(step_n, total_steps, "crypto-identity verify");
                                                                                                 
    let mounts = ops.ssh_capture(Leg::Reconnect, "cat /proc/mounts")?;
    if !prod::rootfs_verity_ro_ok(&mounts) {
                                                                                                    
                                                                                                     
        let root_row = mounts
            .lines()
            .find(|l| l.split_whitespace().nth(1) == Some("/"))
            .unwrap_or("(no / row in /proc/mounts)");
        return Err(format!(
            "IDENTITY FAIL: the box's / is not an RO squashfs on a dm-verity device — \
             /proc/mounts / row: {root_row}"
        ));
    }
    let cmdline = ops.ssh_capture(Leg::Reconnect, "cat /proc/cmdline")?;
    let box_hash = prod::extract_cmdline_root_hash(&cmdline)
        .ok_or("IDENTITY FAIL: no fb.root-hash= token on the box's /proc/cmdline")?;
    if !prod::verity_identity_ok(&box_hash, &local_root_hash) {
        return Err(format!(
            "IDENTITY FAIL: the box runs verity root hash {box_hash} but the local build is \
             {local_root_hash} — the installed bytes are NOT your build"
        ));
    }
                                                                                                     
                                                                                                        
                                                       
    let box_prefix_out = ops.ssh_capture(
        Leg::Reconnect,
        &format!(
            "head -c {} {} | sha256sum",
            layout.boot_size,
            prod::partition_device_name(&disk, 1)                                        
        ),
    )?;
    let box_prefix = box_prefix_out
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    let local_prefix = local_boot_fs_identity_hash(&art.img_path, &layout, &disk)?;
    if !prod::boot_fs_identity_ok(&box_prefix, &local_prefix) {
        return Err(format!(
            "IDENTITY FAIL: boot-fs prefix mismatch (box {box_prefix}, local {local_prefix}) — \
             the boot chain on disk is not your build"
        ));
    }
                                                                                              
                                                                                                  
                                                                                                     
                                                                                                      
                                                                                                      
                                                                                                
                                                                                                 
                                                                                                
                                                                                                 
                                       
    let live = ops.ssh_capture(
        Leg::Reconnect,
        "wget -q -S -O /dev/null --no-check-certificate https://127.0.0.1:443/ 2>&1 || true",
    )?;
    if !live.contains("303") {
        return Err(format!(
            "the box is up and IDENTITY-VERIFIED but recipes did not answer with the expected \
             redirect (got: {}) — inspect services over ssh",
            live.lines().next().unwrap_or_default()
        ));
    }
    ops.say(&format!(
        "deploy prod COMPLETE: {ip} runs your build (verity root hash {local_root_hash}, \
         boot-fs prefix verified, recipes serving). Identity is conclusive under a fresh, \
         uncompromised provisioning host."
    ));
    ops.say(&completion_message(&ip, &derived_fpr));
    Ok(())
}

#[path = "prod_process_ops.rs"]
mod process_ops;
pub use process_ops::{ProcessOps, install_cancel_handler};

#[cfg(test)]
#[path = "prod_orchestrate_tests.rs"]
mod tests;
