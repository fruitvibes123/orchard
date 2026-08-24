                                                                                   
                                                                                                       
//!
//! The operator-side orchestration that converts a freshly-provisioned Debian VPS into the immutable
//! recipes runtime: preflight → build → scp the `.img` + vmlinuz + initramfs (operator-BUILT in
//! origin; `kexec -l` READS the staged-on-target copies, sha256-verified on-target — staging
//! integrity rests on the install-time TCB, not on locality) → discover the target's root device →
//! kexec into installer mode → the on-box [`initramfs_init` installer] partitions + writes slot A +
//! reboots → reconnect on dropbear → crypto-identity verify (step 10).
//!
//! Module layout of the 4.2 ceremony:
//!   - THIS file (`prod.rs`) — the PURE, host-testable units (cmdline builder, device-discovery
//!     parsers, the wipe token, host-key + identity decisions); unit-tested inline below.
//!   - `prod_orchestrate.rs` — the FFI half: the hardened ssh/scp/kexec argv builders + the
//!     `deploy_prod` flow that sequences steps 1–10 over the `OrchestrationOps` effects seam.
//!   - `prod_e2e.rs` + `tests/deploy_prod_e2e.rs` — the Debian-guest kexec-takeover end-to-end gate
//!     (boots a real Debian image, drives the REAL ceremony to a produced-bytes install).
//!
//! (Separately, `tests/deploy_prod_qemu.rs` gates the on-box `initramfs_init` INSTALLER via a
//! SeaBIOS disk-boot — that is the install mechanism, not this operator ceremony.)

/// The fixed kernel-consumed defense triple on the installer kexec cmdline (so the install window
                                                                                              
/// runtime slot-A APPEND carries its own in `crates/image-builder/src/boot_fs.rs` (which also
/// prepends `ro`). orchard depends on image-builder (`crates/orchard/Cargo.toml:24`), but that copy
/// is `const DEFENSE_TRIPLE` declared without `pub` (`boot_fs.rs:38`), so orchard cannot name it and
/// the spelling is asserted per-side by each crate's tests; do NOT reason "one constant ⇒ no drift"
                                                                   
pub const DEFENSE_TRIPLE: &str =
    "lockdown=integrity ima_appraise=enforce sysctl.kernel.yama.ptrace_scope=2";

/// Kernel consoles for the INSTALLER kexec window — `tty0` (what a hypervisor VNC console shows)
/// and `ttyS0` (a provider serial console, and what the QEMU `-nographic` gates capture). Without
/// them the kexec'd installer is silent BY CONSTRUCTION: a fail-closed refusal (a wrong-disk guard,
/// a `fb.image-sha256` mismatch from staging-window contention) resets the machine with the
/// operator seeing nothing — while `prod_orchestrate.rs`'s own failure text tells them to "check
/// the provider's VNC/serial console". That advice only becomes true with these tokens.
///
/// This closes on the kexec arm what audit **R1 I-1** already closed on the UEFI signed-USB arm
/// (spec `2026-06-24-uefi-signed-usb-installer-design.md` §5: *"required for a headless install so
/// the operator can SEE the §6 fail-closed-halt reason — the runtime cmdline carries these,
/// `build_installer_cmdline` does not"*). Both siblings already carry them: the runtime APPEND via
/// `boot_fs.rs::RUNTIME_CONSOLE` and the UEFI installer via `boot_fs.rs::render_installer_cmdline`
/// — this was the last cmdline family without them, not a deliberate hardening.
///
/// NOT a new exposure: every deployed box already runs `console=tty0 console=ttyS0` for its whole
/// operating life (`RUNTIME_CONSOLE`, all four render paths), on a substrate whose serial port is
/// already substrate-accessible. Console output is explicitly NOT a trust anchor either — a
/// tampered installer controls it too (spec-round-4 F-note) — so this is diagnostics, never
/// install-time integrity evidence.
///
/// Ordering: emitted LAST, after [`DEFENSE_TRIPLE`]. These are OPERABILITY tokens, ordered after the
/// security tokens as defense in depth (the composer refuses over-budget rather than relying on any
/// truncation — see [`build_installer_cmdline`]). `ttyS0` stays last among them → it becomes
/// `/dev/console`.
///
/// Same cross-crate duplication caveat as [`DEFENSE_TRIPLE`]: `boot_fs.rs` holds an independent
                                                             
pub const INSTALLER_CONSOLE: &str = "console=tty0 console=ttyS0";

/// x86-64 `COMMAND_LINE_SIZE` — the kernel's fixed cmdline buffer, INCLUDING its NUL terminator, so
/// the usable payload is `COMMAND_LINE_SIZE - 1` bytes.
///
/// [`build_installer_cmdline`] refuses BEFORE the composed append reaches its consumer (audit
                                                                                               
/// (`kexec -l`) path; the QEMU-gate caller (`install_seabios.rs`) feeds the same composition to
/// `qemu -append`, which imposes no length check (grounded: QEMU 11.1.0
/// `hw/i386/x86-common.c:663-664` only 16-byte-aligns the cmdline and never compares it to the
/// header cmdline_size, publishing it unbounded via fw_cfg), so the composer refuses at the
/// strictest consumer's bound for every caller. Grounded on kexec-tools 2.0.29
/// (Debian 13 trixie `1:2.0.29-2`, the ceremony's pre-kexec host): on the classic `kexec -l` path,
/// `bzImage64_load` sets `command_line_len = strlen(command_line) + 1`
/// (`kexec/arch/x86_64/kexec-bzImage64.c:377`) and calls `do_bzImage64_load` (`:391`), which REFUSES
/// with `return -1` when `command_line_len > setup_header.cmdline_size` (`:141-144`) — it
/// does NOT truncate. The `setup_linux_bootloader_parameters_high` clamp exists
/// (`kexec/arch/i386/x86-linux-setup.c`) but is unreachable past that early return (corrected
/// the earlier "truncates silently" attribution). The box's kernel advertises
/// `cmdline_size = COMMAND_LINE_SIZE - 1` = 2047 (`arch/x86/boot/header.S`), so kexec-tools accepts
/// `strlen + 1 <= 2047`, i.e. `strlen <= COMMAND_LINE_SIZE - 2` = 2046. [`build_installer_cmdline`]
/// therefore refuses at `>= COMMAND_LINE_SIZE - 1` (2047), so an over-long append is caught at the
/// composer for every caller, before any `kexec -l` takeover on the `deploy_prod` path (there the
/// box still runs its prior system — no kexec occurred; the raw tail window and staged files were
/// already written), rather than at the remote `kexec -l` on the armed path.
pub const COMMAND_LINE_SIZE: usize = 2048;

                                                                                          
/// O(chunk) copy buffers + init footprint. The successor of the retired whole-image RAM
/// preflight — image size no longer enters any RAM predicate (that is the whole point of the
/// streaming redesign); a target below THIS floor cannot run the installer at all and is still
/// refused pre-wipe.
pub const INSTALL_MIN_RAM_BYTES: u64 = 256 * 1024 * 1024;

/// Operator-side twin of the box's `RESTORE_CAP_HEADROOM_BYTES` (`initramfs-init/installer.rs` —
/// keep in lockstep): the restore image is read into box RAM at the panic=abort gate, capped at
/// `MemTotal − this`; the ceremony mirrors that formula PRE-staging (spec R2-1) so an over-RAM
/// restore aborts here, not post-kexec.
pub const RESTORE_CAP_HEADROOM_BYTES: u64 = 256 * 1024 * 1024;

                                                                                                  
/// Cross-crate TWIN (plan R1-9) of `initramfs-init`'s `installer_stream::INSTALL_COPY_CHUNK_BYTES`
/// — the box REJECTS a window offset that is not a multiple of ITS value, so drift is fail-closed
/// (ceremonies refuse, bytes never mis-copy); keep the two in lockstep. 8 MiB, page-aligned.
pub const INSTALL_COPY_CHUNK_BYTES: u64 = 8 * 1024 * 1024;

                                                                                                   
/// `.img` length — at absolute byte `offset` on whole-disk `disk`. Composed by the flow's
/// geometry step; serialized as `fb.image-raw=<disk>:<offset>:<len>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawWindowSpec {
    pub disk: String,
    pub offset: u64,
    pub len: u64,
}

/// Whole-disk bare device name check — the REAL TWIN of the box's `install_target::valid_install_to_dev`
/// (`initramfs-init` is a standalone workspace, so the per-class grammar is duplicated, not shared;
/// code-audit R1 LOW-1: a looser structural check was NOT a twin — it accepted names the box's
/// class-whitelist rejects (`loop0`, `nvme0`, `foo`), so a doomed ceremony passed this advisory and
                                                                                                  
/// grammar) ported VERBATIM: charset [a-z0-9] AND an installable whole-disk class shape. Accepted set
/// is now byte-identical to the box's — a cross-crate accept/reject test table locks it.
pub fn is_whole_disk_name(s: &str) -> bool {
                                                                                                  
    if s.is_empty()
        || !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return false;
    }
                                                                                                   
    if let Some(rest) = s.strip_prefix("nvme") {
        return match rest.split_once('n') {
            Some((ctrl, ns)) => {
                !ctrl.is_empty()
                    && ctrl.bytes().all(|b| b.is_ascii_digit())
                    && !ns.is_empty()
                    && ns.bytes().all(|b| b.is_ascii_digit())
            }
            None => false,
        };
    }
                                                               
    if let Some(rest) = s.strip_prefix("mmcblk") {
        return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
    }
                                                                                              
    ["xvd", "sd", "vd", "hd"].into_iter().any(|class| {
        s.strip_prefix(class)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_lowercase()))
    })
}

/// Compose `/dev/<disk><n>` per the Linux partition-naming convention: append the number directly
/// for letter-ending disks (`vda`→`/dev/vda2`, `sda`→`/dev/sda1`) but insert `p` when the disk
/// name ends in a digit (`nvme0n1`→`/dev/nvme0n1p2`, `mmcblk0`→`/dev/mmcblk0p2`) so the partition
/// number isn't fused into the disk's own trailing digits. A FAITHFUL PORT of the box's
/// `fb_verity_rt::partition_device_name` (`crates/fb-verity-rt/src/discover.rs:37-44` in the
/// fruit-basket tree; it moved there from `initramfs-init/src/installer.rs`, forwarding note at that
/// file's `:538-540` — a standalone workspace, not an orchard dependency, so the convention is
/// necessarily duplicated): the
/// deploy side previously hand-rolled `format!("/dev/{disk}2")` (letter-form only), baking a
/// nonexistent `/dev/nvme0n12` into the boot-fs APPEND of a digit-ending root disk — installed
                                                                                              
/// install dd's with the CORRECT convention, so only the baked rootfs-dev drifted).
pub fn partition_device_name(disk: &str, number: u8) -> String {
    let sep = if disk.ends_with(|c: char| c.is_ascii_digit()) {
        "p"
    } else {
        ""
    };
    format!("/dev/{disk}{sep}{number}")
}

/// Parse `MemTotal` (in bytes) from a target's `/proc/meminfo` — the value is reported in kB
/// (`MemTotal:     2048000 kB`). `None` if the line is absent or unparseable, so the caller fails closed
/// rather than wipe a disk without knowing whether the target can hold the image in RAM.
pub fn parse_meminfo_memtotal_bytes(meminfo: &str) -> Option<u64> {
    meminfo.lines().find_map(|l| {
        let kb: u64 = l
            .strip_prefix("MemTotal:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        kb.checked_mul(1024)
    })
}

                                                                                         
/// predicate is deliberately IMAGE-SIZE-INDEPENDENT: the streaming installer's peak RAM is
/// O(chunk), so `image > RAM` deploys are exactly the capability this cycle exists to enable —
/// only a target too small to run the installer AT ALL refuses, still pre-wipe.
pub fn refuse_if_ram_below_floor(mem_total: u64) -> Result<(), String> {
    if mem_total < INSTALL_MIN_RAM_BYTES {
        return Err(format!(
            "the target has {mem_total} bytes of RAM, below the {INSTALL_MIN_RAM_BYTES}-byte \
             installer floor (kernel + initramfs + chunk buffers) — aborting BEFORE any \
             destructive action."
        ));
    }
    Ok(())
}

/// A typed refusal from [`build_installer_cmdline`]. The prose `String` error is retired (the fr44
/// factory closure, decision record 2026-08-18): a shared error channel carrying standing prose
/// rendered facts in contexts where one truth dimension failed. The LENGTH axis is a distinct
/// variant so consumer-specific narration (kexec-tools refuses an over-long append) keys on it at
/// the `deploy_prod` call site instead of wrapping every arm. `Display` is caller-agnostic mechanics
/// only: no caller context, no ceremony state, no `installer cmdline:` site prefix — each caller
/// adds the prefix and any site residue itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmdlineError {
    /// The composed append is over the strictest consumer's budget. `composed` is the byte length;
    /// `restore_requested` selects the hint (the `--restore-from` stage path is the only unbounded
    /// input) versus the composer-bug hint. The length guard is `>= COMMAND_LINE_SIZE - 1`.
    Length {
        composed: usize,
        restore_requested: bool,
    },
    /// A composition-shape refusal (hash shape, whole-disk name, both alignments, the SeaBIOS-family
    /// firmware rule, the weights pairing, the restore device/path, the min-ctr pairing). The
    /// message is the arm's own caller-agnostic mechanics.
    Shape(String),
}

impl std::fmt::Display for CmdlineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CmdlineError::Length {
                composed,
                restore_requested,
            } => write!(
                f,
                "the composed append is {composed} bytes, over the strictest consumer budget of {} \
                 (the strictest consumer accepts strlen + 1 <= the kernel's cmdline_size of {}; \
                 COMMAND_LINE_SIZE = {COMMAND_LINE_SIZE}). {}",
                COMMAND_LINE_SIZE - 2,
                COMMAND_LINE_SIZE - 1,
                if *restore_requested {
                    "The --restore-from stage path is the only unbounded input in this composition \
                     — shorten it."
                } else {
                    "No restore path was supplied, so this is a composer bug rather than operator \
                     input."
                }
            ),
            CmdlineError::Shape(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for CmdlineError {}

                                                                                                 
/// raw-window tokens replace the file source. This is a caller-agnostic pure unit. The strictest
/// consumer is kexec-tools on the `deploy_prod` path (loaded via `kexec -l`), which REFUSES an
/// over-long append rather than truncating it (kexec-tools 2.0.29
/// `kexec-bzImage64.c:141-144` returns -1 when `strlen + 1 > cmdline_size`); the QEMU-gate caller
/// feeds the same composition to `qemu -append`, which imposes no length check (grounded: QEMU
/// 11.1.0 `hw/i386/x86-common.c:663-664` only 16-byte-aligns the cmdline, no comparison to the
/// header cmdline_size), so the composer refuses over-budget at the guard below for every caller,
/// at `>= COMMAND_LINE_SIZE - 1` = 2047
/// (the strictest consumer accepts `strlen <= 2046`). On the `deploy_prod` path this is before the
/// `kexec -l` takeover (the box still runs its prior system — no kexec occurred; the raw tail window
/// and staged files were already written). Token ORDER is retained as defense in depth: the
/// security-required tokens (`fb.firmware`, the verity pair, `fb.image-raw`, `fb.image-sha256`,
/// `fb.image-layout`) come EARLY, matching the runtime composers' ordering, even though no runtime
/// truncation mode exists on this path to lose a tail token to. `fb.firmware` is now
/// ALWAYS emitted (both seabios and seabios-gpt — the raw arm's three-way agreement needs it
/// explicit; the old SeaBIOS-omits-it parity is void, the append changed anyway).
///
                                                                                                
/// 64-hex, the window disk a bare WHOLE-disk name, the offset chunk-aligned, the len 512-aligned
/// non-zero, the restore path whitespace-free, `fb.min-ctr` restore-only — a composition bug
/// refuses HERE for every caller. On the `deploy_prod` path that is before the `kexec -l` takeover
/// (the box still runs its prior system — no kexec occurred; the raw tail window and staged files
/// were already written), never as a post-kexec installer panic.
pub fn build_installer_cmdline(
    root_hash: &str,
    verity_hash_offset: u64,
    window: &RawWindowSpec,
    image_sha256_hex: &str,
    layout: &crate::deploy::prod_orchestrate::LayoutInfo,
    restore_from: Option<(&str, &str)>,
    min_ctr: Option<u64>,
) -> Result<String, CmdlineError> {
    let root_hash = normalized_sha256_hex(root_hash).ok_or_else(|| {
        CmdlineError::Shape(format!(
            "root_hash {root_hash:?} is not a 64-hex sha256 — refusing"
        ))
    })?;
    let image_sha256 = normalized_sha256_hex(image_sha256_hex).ok_or_else(|| {
        CmdlineError::Shape(format!(
            "image sha256 {image_sha256_hex:?} is not a 64-hex sha256 — refusing"
        ))
    })?;
    if !is_whole_disk_name(&window.disk) {
        return Err(CmdlineError::Shape(format!(
            "window disk {:?} is not a bare whole-disk name",
            window.disk
        )));
    }
    if !window.offset.is_multiple_of(INSTALL_COPY_CHUNK_BYTES) {
        return Err(CmdlineError::Shape(format!(
            "window offset {} is not a multiple of the {INSTALL_COPY_CHUNK_BYTES}-byte chunk (the box refuses it)",
            window.offset
        )));
    }
    if window.len == 0 || !window.len.is_multiple_of(512) {
        return Err(CmdlineError::Shape(format!(
            "window len {} is not a non-zero 512-multiple (the exact .img length)",
            window.len
        )));
    }
                                                                                             
                                                                      
    let fw = match layout.firmware {
        crate::deploy::build_image::Firmware::Seabios => "seabios",
        crate::deploy::build_image::Firmware::SeabiosGpt => "seabios-gpt",
        crate::deploy::build_image::Firmware::Uefi => {
            return Err(CmdlineError::Shape(
                "the raw-window composer is SeaBIOS-family only (uefi deploys via the signed-USB \
                 ceremony)"
                    .to_string(),
            ));
        }
    };
                                                                                              
                                                                                                  
    let weights_entry = match (layout.weights_offset, layout.weights_size) {
        (Some(off), Some(size)) => format!(",weights:{off}:{size}"),
        (None, None) => String::new(),
        _ => {
            return Err(CmdlineError::Shape(
                "weights_offset/weights_size must be present together".to_string(),
            ));
        }
    };
    let layout_token = format!(
        "fw:{fw},boot:{}:{},skel:{}:{},rootfs:{}:{}{weights_entry}",
        layout.boot_offset,
        layout.boot_size,
        layout.persist_skeleton_offset,
        layout.persist_skeleton_size,
        layout.rootfs_offset,
        layout.rootfs_size,
    );
                                                                                             
                                                                                              
    let restore_token = match restore_from {
        Some((device, path)) => {
            if device.is_empty()
                || !device
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            {
                return Err(CmdlineError::Shape(format!(
                    "restore device {device:?} is not a bare partition name"
                )));
            }
            validate_stage_dir(path)
                .map_err(|e| CmdlineError::Shape(format!("restore_from: {e}")))?;
            format!(" fb.restore-from=disk:{device}:{path}")
        }
        None => String::new(),
    };
    let min_ctr_token = match min_ctr {
        Some(n) => {
            if restore_from.is_none() {
                return Err(CmdlineError::Shape(
                    "--restore-min-ctr given without --restore-from (the box defines fb.min-ctr \
                     only for the restore variant)"
                        .to_string(),
                ));
            }
            format!(" fb.min-ctr={n}")
        }
        None => String::new(),
    };
    let cmdline = format!(
        "fb.mode=installer fb.firmware={fw} fb.root-hash={root_hash} \
         fb.verity-hash-offset={verity_hash_offset} \
         fb.image-raw={}:{}:{} fb.image-sha256={image_sha256} \
         fb.image-layout={layout_token}{restore_token}{min_ctr_token} {DEFENSE_TRIPLE} \
         {INSTALLER_CONSOLE}",
        window.disk, window.offset, window.len,
    );
                                                                                                    
                                                                                                       
                                                                                                       
                                                                              
      
                                                                                           
                                                                                                
                                                                                                     
                                                                                                   
                                                                                     
                                                                                              
                                                                                               
                                                                             
                                            
                                                                                                   
                                                                                                     
                                                                                                        
                                            
    if cmdline.len() >= COMMAND_LINE_SIZE - 1 {
        return Err(CmdlineError::Length {
            composed: cmdline.len(),
            restore_requested: restore_from.is_some(),
        });
    }
    Ok(cmdline)
}

                                                                                                      
                                                                                                
                                                                                                       
                                                                                                          
                                                                                                         
                                                                                     

                                                                                                 
/// fn that issues `kexec -e`, so no operator-side code path reaches the destructive leg without it.
/// The field is private, there is no `Default`/`From<bool>`, and [`WipeConfirmed::from_flag`] is the
/// ONLY constructor — `Some` iff the operator passed `--wipe-confirmed`. ("Un-bypassable" scopes the
/// OPERATOR CLI: the on-box installer dd's unconditionally once kexec'd — the accurate claim is "no
                                                            
#[derive(Debug)]
pub struct WipeConfirmed(());

impl WipeConfirmed {
    /// `Some` iff `--wipe-confirmed` was passed. No other constructor exists.
    pub fn from_flag(confirmed: bool) -> Option<Self> {
        confirmed.then_some(WipeConfirmed(()))
    }
}

                                                                                              
/// `accept-new` arm by construction — the variants are exhaustive and none of them is "silently
/// trust an unpinned key non-interactively".
#[derive(Debug, PartialEq, Eq)]
pub enum HostKeyDecision {
    /// The pinned fingerprint matches the presented key — proceed.
    Accept,
    /// Pinned fingerprint MISMATCH — hard abort. Never an interactive override: a mismatch
    /// against an explicit pin is the MitM/wrong-host signal, not a typo to talk through.
    Abort,
    /// No pin + interactive TTY: present the key's fingerprint and require explicit operator
    /// confirmation (TOFU confirm — the fallback when greenfield has no published fingerprint).
    ConfirmInteractively(String),
    /// No pin + non-interactive: fail closed (e2e/CI must pass `--host-fingerprint`).
    FailClosed,
}

/// Decide Leg-A trust from `(--host-fingerprint, stdin-is-tty, the presented host key's
/// fingerprint)`. Pure decision — reading the presented fingerprint (ssh-keyscan + `ssh-keygen
/// -lf`) and acting on the variant are the orchestration's FFI (Task 10).
pub fn host_key_decision(
    pinned_fingerprint: Option<&str>,
    is_tty: bool,
    presented: &str,
) -> HostKeyDecision {
    match pinned_fingerprint {
        Some(fp) if fp.trim() == presented.trim() => HostKeyDecision::Accept,
        Some(_) => HostKeyDecision::Abort,
        None if is_tty => HostKeyDecision::ConfirmInteractively(presented.to_string()),
        None => HostKeyDecision::FailClosed,
    }
}

/// Normalize one side of a step-10 identity comparison to canonical lowercase 64-hex (sha256
/// width). `None` on ANY other shape — empty, truncated, non-hex — so a failed FFI read (`""`),
/// a clipped pipe, or an error string can never participate in a "match". Fail-closed: the
/// comparison fns return `false` unless BOTH sides normalize.
fn normalized_sha256_hex(h: &str) -> Option<String> {
    let t = h.trim();
    (t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())).then(|| t.to_ascii_lowercase())
}

                                                                                              
/// hash (read from its `/proc/cmdline` over the authenticated reconnect) must equal the operator's
/// locally-recomputed root hash of the built `.img`'s rootfs. One half of a CONJOINED check — it
/// is meaningful only together with `/` being RO-dm-verity (the orchestration asserts both; either
/// alone proves nothing). Public hashes — plain `==` after normalization, no constant-time needed.
pub fn verity_identity_ok(box_root_hash: &str, local_root_hash: &str) -> bool {
    match (
        normalized_sha256_hex(box_root_hash),
        normalized_sha256_hex(local_root_hash),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

                                                                                       
/// partition's `boot_size`-byte PREFIX (not the padded partition) must equal the operator's hash
/// of the post-`patch_rootfs_dev` boot-fs slice — same bytes the installer dd'd; the only per-box
/// variance is the deterministic rootfs-dev patch, which the local side replays before hashing.
pub fn boot_fs_identity_ok(box_prefix_sha: &str, local_post_patch_prefix_sha: &str) -> bool {
    match (
        normalized_sha256_hex(box_prefix_sha),
        normalized_sha256_hex(local_post_patch_prefix_sha),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// ONE path-segment rule, shared by [`validate_stage_dir`] (per segment) and
/// [`validate_artifact_filename`] (the whole name): non-empty, not `.`/`..`, no leading `-`
/// (option-shaped — the segment interpolates into remote argv positions), bytes in
/// `[A-Za-z0-9._-]`.
fn check_segment(segment: &str) -> Result<(), String> {
    if segment.is_empty() {
        return Err("empty path segment (double or trailing /)".into());
    }
    if segment == "." || segment == ".." {
        return Err("traversal segment".into());
    }
    if segment.starts_with('-') {
        return Err("option-shaped segment (leading '-')".into());
    }
    if !segment
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(
            "segment outside the [A-Za-z0-9._-] whitelist (it interpolates into the kexec \
             --append and target argv)"
                .into(),
        );
    }
    Ok(())
}

                                                                                               
/// interpolates into the kexec `--append` (whitespace-tokenized by the kernel) and into scp/shell
                                                                                               
/// absolute path of `/`-separated segments per [`check_segment`] (`[A-Za-z0-9._-]`, no `.`/`..`,
                                                                                               
/// NUL, metacharacters, traversal, option-shaped segments, and non-ASCII all fail closed.
/// (The on-target `realpath` + the same-partition resolution are the orchestration's FFI — this is
/// the pure pre-flight guard.)
pub fn validate_stage_dir(raw: &str) -> Result<String, String> {
    let err = |msg: &str| Err(format!("--image-stage-dir {raw:?}: {msg}"));
    let Some(rest) = raw.strip_prefix('/') else {
        return err("must be an absolute path");
    };
    if rest.is_empty() {
        return err("must name a directory below / (got the bare root)");
    }
    for segment in rest.split('/') {
        if let Err(e) = check_segment(segment) {
            return err(&e);
        }
    }
    Ok(raw.to_string())
}

                                                                                                 
/// interpolates into the scp destination, the remote `sha256sum`/`rm -f` strings, and (vmlinuz /
/// initramfs / `.img`) the kexec `--append` — so it must be ONE clean [`check_segment`] segment.
/// Closed IN the unit so the safety stops leaning on the `sha256sum`-parse ordering and the
/// shared-stem coincidence that defended it before (a hostile filename aborted pre-kexec only by
/// accident of those siblings).
pub fn validate_artifact_filename(name: &str) -> Result<String, String> {
    check_segment(name)
        .map(|()| name.to_string())
        .map_err(|e| format!("artifact file name {name:?}: {e}"))
}

                                                                                                 
/// the install repartitions every partition on the disk, not just the partition `/` is on.
pub fn whole_disk_echo(disk: &str, ip: &str) -> String {
    format!(
        "ALL partitions on /dev/{disk} (not just /) on {ip} will be ERASED and the disk \
         repartitioned. Retype the target ip (or /dev/{disk}) to proceed:"
    )
}

/// The wipe-gate decision (spec step 5). Non-TTY (e2e/CI): the [`WipeConfirmed`] token — which the
/// caller must already hold to be anywhere near the destructive leg — suffices alone. TTY: the
/// operator must additionally retype the target (the `<ip>`, the `/dev/<disk>`, or the bare disk)
/// after the [`whole_disk_echo`] consequence print; a wrong or absent retype aborts.
pub fn wipe_gate(
    stdin_is_tty: bool,
    retyped_target: Option<&str>,
    discovered_disk: &str,
    ip: &str,
) -> Result<(), String> {
    if !stdin_is_tty {
        return Ok(());
    }
    let retyped = retyped_target
        .ok_or("interactive wipe gate: no retyped target read — aborting before any write")?
        .trim();
    if retyped == ip || retyped == discovered_disk || retyped == format!("/dev/{discovered_disk}") {
        Ok(())
    } else {
        Err(format!(
            "retyped target {retyped:?} matches neither {ip} nor /dev/{discovered_disk} — \
             aborting before any write"
        ))
    }
}

/// Validate + strip a `/dev/<name>` device path to the bare partition name the cmdline grammar wants.
                                                                                                  
/// non-empty ascii-lowercase + digits — so `/dev/sda1`/`/dev/vda1`/`/dev/nvme0n1p1` pass, while
/// `/dev/mapper/...` (LVM), a LUKS mapping, a `..`, uppercase, or a non-`/dev/` source FAIL closed
                                                                                                   
/// this is the defense-in-depth catch).
pub(crate) fn bare_device(source: &str) -> Option<String> {
    let name = source.trim().strip_prefix("/dev/")?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }
    Some(name.to_string())
}

/// Parse `findmnt -n -o SOURCE <mountpoint>` output (a single line, e.g. `/dev/sda1`) into the bare
/// partition name. `None` on any unexpected shape (fail closed → the orchestration surfaces an
/// operator-actionable error rather than feeding a junk device into the install cmdline).
pub fn parse_findmnt_source(output: &str) -> Option<String> {
    bare_device(output.lines().next()?)
}

/// Fallback when `findmnt` is absent (older Debian variants): parse `/proc/self/mounts` for the row
/// whose mount point (field 2) is `/`, returning that row's source device (field 1) as a bare
/// partition name. Same whitelist + fail-closed semantics as [`parse_findmnt_source`].
pub fn parse_proc_mounts_root(mounts: &str) -> Option<String> {
    mounts.lines().find_map(|line| {
        let mut f = line.split_whitespace();
        let source = f.next()?;
        let mountpoint = f.next()?;
        (mountpoint == "/").then(|| bare_device(source))?
    })
}

                                                                                                  
/// device, so the image stage dir MUST resolve to the same partition as `/`. Returns `Err`
/// (operator-actionable) when they differ, so the orchestration aborts at preflight rather than scp
/// the `.img` somewhere the init won't mount. (This scopes where the `.img` is STAGED — the install
/// itself still repartitions the WHOLE disk holding `/`.)
pub fn check_same_partition(root_dev: &str, stage_dev: &str) -> Result<(), String> {
    if root_dev == stage_dev {
        Ok(())
    } else {
        Err(format!(
            "image-stage-dir resolves to /dev/{stage_dev} but / is on /dev/{root_dev}; the installer \
             cmdline grammar binds one source device — stage the .img on the same partition as / \
             (the stage-on-root-partition check; the install still erases the whole disk \
             holding /dev/{root_dev})"
        ))
    }
}

/// One partition's byte extent on the install disk — `[start, end)`, end EXCLUSIVE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionExtent {
    pub name: String,
    pub start: u64,
    pub end: u64,
}

/// Parse `lsblk -nbro NAME,TYPE,START,SIZE /dev/<disk>` into the byte extents of that disk's
                                                                       
///
/// **UNIT ASYMMETRY — empirically confirmed, and the whole reason this has its own test.** Under
/// `-b`, lsblk prints SIZE in BYTES but START in 512-byte SECTORS. Reading both as the same unit
/// puts every partition's start 512× too low, which would make the intersection check pass exactly
/// when it should fail — a guard that is worse than none. START is therefore multiplied here, once,
/// and the golden row in the test pins a real observed pair.
///
/// Fail-closed: unparseable rows, or a disk with no partitions at all, are an ERROR rather than an
/// empty "nothing intersects" result. By the time this runs, `parse_lsblk_parent_walk` has already
/// proven the root sits on a partition of this disk, so zero partitions means the listing is not
/// describing the disk we think it is.
pub fn parse_lsblk_partition_extents(
    lsblk_out: &str,
    disk: &str,
) -> Result<Vec<PartitionExtent>, String> {
    let mut parts = Vec::new();
    for line in lsblk_out.lines() {
                                                                                                 
        let f: Vec<&str> = line.split(' ').collect();
        if f.len() < 4 || f[0].is_empty() {
            continue;
        }
        if f[1] != "part" {
            continue;                                                    
        }
        let start_sectors: u64 = f[2].parse().map_err(|_| {
            format!(
                "unparseable START {:?} for partition {:?} in the target's lsblk listing; aborting",
                f[2], f[0]
            )
        })?;
        let size_bytes: u64 = f[3].parse().map_err(|_| {
            format!(
                "unparseable SIZE {:?} for partition {:?} in the target's lsblk listing; aborting",
                f[3], f[0]
            )
        })?;
        let start = start_sectors.saturating_mul(512);
        parts.push(PartitionExtent {
            name: f[0].to_string(),
            start,
            end: start.saturating_add(size_bytes),
        });
    }
    if parts.is_empty() {
        return Err(format!(
            "no partitions parsed for /dev/{disk} from the target's lsblk listing, but the root \
             filesystem was already resolved to a partition of it — refusing to treat an empty \
             partition set as 'the staging window collides with nothing'; aborting"
        ));
    }
    Ok(parts)
}

/// Walk `lsblk -nro NAME,TYPE,MOUNTPOINT,PKNAME` output from the discovered root partition to its
                                                                                             
/// [`bare_device`] whitelist catches `/dev/mapper/...` NAMES, but a plain-named device atop
/// dm-crypt/LVM/RAID needs the type walk. Whitelist of the ONE supported shape
                                                                                              
/// `TYPE=disk`. Everything else — crypt/lvm/raid layers, a whole-disk fs (no partition for
/// the stage partition), a missing row — fails closed with the named reason.
///
/// lsblk `-r` (raw) prints space-separated fields with EMPTY fields preserved (two adjacent
/// spaces), so rows split on `' '`, not on runs of whitespace.
pub fn parse_lsblk_parent_walk(lsblk_out: &str, root_dev: &str) -> Result<String, String> {
                              
    let mut rows = std::collections::HashMap::new();
    for line in lsblk_out.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f.len() >= 4 && !f[0].is_empty() {
            rows.insert(f[0], (f[1], f[3]));
        }
    }
    let (dev_type, pkname) = rows.get(root_dev).ok_or_else(|| {
        format!("root device {root_dev:?} not present in the target's lsblk listing — aborting")
    })?;
    match *dev_type {
        "part" => {}
        "disk" => {
            return Err(format!(
                "/ is a whole-disk filesystem on /dev/{root_dev} (no partition table) — the deploy \
                 derives the install disk from the root PARTITION's parent, so / must sit on a \
                 partition; aborting"
            ));
        }
        other => {
            return Err(format!(
                "/ sits on a {other:?} block layer (/dev/{root_dev}) — the installer needs a \
                 plain partition directly on a disk (no dm-crypt/LVM/RAID); aborting"
            ));
        }
    }
    if pkname.is_empty() {
        return Err(format!(
            "lsblk reports no parent disk for partition /dev/{root_dev}; aborting"
        ));
    }
    match rows.get(pkname) {
        Some(("disk", _)) => {
                                                                                               
                                                                                                     
                                                                                                     
                                                                                                   
                                                                                              
                                                                                                  
            if !pkname
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
            {
                return Err(format!(
                    "parent disk name {pkname:?} of /dev/{root_dev} carries a character outside \
                     [A-Za-z0-9_-] — refusing to interpolate it into a root-run shell command \
                     (fail-closed)"
                ));
            }
            Ok((*pkname).to_string())
        }
        Some((other, _)) => Err(format!(
            "partition /dev/{root_dev}'s parent /dev/{pkname} is {other:?}, not a plain disk \
             (no dm-crypt/LVM/RAID); aborting"
        )),
        None => Err(format!(
            "parent device {pkname:?} of /dev/{root_dev} missing from the lsblk listing; aborting"
        )),
    }
}

/// Parse `sha256sum <files…>` output into `(hex, path)` pairs. Malformed lines are skipped — the
/// caller fails closed on the artifact it can't FIND a digest for, so a skip can only ever cause
/// an abort, never a false verify.
pub fn parse_sha256sum_output(out: &str) -> Vec<(String, String)> {
    out.lines()
        .filter_map(|line| {
            let (hex, rest) = line.split_at_checked(64)?;
            if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
                                                                                    
            let path = rest
                .strip_prefix("  ")
                .or_else(|| rest.strip_prefix(" *"))?;
            Some((hex.to_ascii_lowercase(), path.trim().to_string()))
        })
        .collect()
}

/// Fallback when `findmnt --target` is absent: parse POSIX `df -P <dir>` output → the source
/// device (field 1 of the first data row) as a bare partition name. Same whitelist + fail-closed
/// semantics as [`parse_findmnt_source`].
pub fn parse_df_source(out: &str) -> Option<String> {
    bare_device(out.lines().nth(1)?.split_whitespace().next()?)
}

/// The `deploy prod <ip>` target-host guard: an IP literal (v4/v6) or a lowercase RFC-1123-ish
/// hostname (`[a-z0-9.-]`, no leading `-`/`.`). It interpolates into `root@<host>` argv and the
/// flock key — reject anything else up front (an option-shaped or metacharacter-bearing string
/// never reaches an ssh argv).
pub fn validate_target_host(host: &str) -> Result<String, String> {
    let h = host.trim();
    if h.parse::<std::net::IpAddr>().is_ok() {
        return Ok(h.to_string());
    }
    let valid_shape = !h.is_empty()
        && !h.starts_with('-')
        && !h.starts_with('.')
        && h.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'));
    if valid_shape {
        Ok(h.to_string())
    } else {
        Err(format!(
            "target {host:?} is neither an IP literal nor a plain lowercase hostname — aborting"
        ))
    }
}

/// Parse POSIX `df -P -k <dir>` output → the Available column (KiB) of the first data row.
pub fn parse_df_avail_kib(out: &str) -> Option<u64> {
    let row = out.lines().nth(1)?;
    row.split_whitespace().nth(3)?.parse().ok()
}

/// Parse a single-value remote read (`cat /sys/class/block/<disk>/size`, `date +%s`): exactly one
/// whitespace-trimmed integer token, else `None` (fail closed on any unexpected shape).
pub fn parse_u64_line(out: &str) -> Option<u64> {
    let t = out.trim();
    (!t.is_empty() && !t.contains(char::is_whitespace))
        .then(|| t.parse().ok())
        .flatten()
}

/// Extract the `fb.root-hash=<value>` token from the box's `/proc/cmdline` (the runtime APPEND
/// grammar `parse_cmdline` consumes). Token-anchored — never matches a substring of another token.
pub fn extract_cmdline_root_hash(cmdline: &str) -> Option<String> {
    cmdline
        .split_whitespace()
        .find_map(|t| t.strip_prefix("fb.root-hash="))
        .map(str::to_string)
}

/// The step-10 "RO-dm-verity `/`" half of the conjoined rootfs-identity check, over the box's
/// `/proc/mounts` (busybox ships no `findmnt`): the `/` row's source must be a device-mapper
                                                                                                 
/// `ro` alone is NOT verity; all three or fail).
pub fn rootfs_verity_ro_ok(proc_mounts: &str) -> bool {
    proc_mounts.lines().any(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[1] != "/" {
            return false;
        }
                                                                                          
                                                                                                        
                                                                                                      
                                                                                                    
                                                          
        let dm_source = f[0] == "/dev/recipes-root"
            || f[0].starts_with("/dev/dm-")
            || f[0].starts_with("/dev/mapper/");
        let squashfs = f[2] == "squashfs";
        let ro = f[3].split(',').any(|o| o == "ro");
        dm_source && squashfs && ro
    })
}

                                                                                            
/// carries kexec's OWN message (e.g. lockdown denied the syscall — nothing was executed, fail SAFE
/// and say so) vs PROCEEDING = anything else, in particular ssh's transport error with no kexec
/// stderr (the dropped connection of a target rebooting into the installer).
///
                                                                                             
/// `kexec -e` and an ssh transport failure BOTH surface exit 255: kexec-tools `my_exec()` prints
/// `kexec failed: <errno>` and `return -1`, and a C `main` returning -1 exits 255
/// (horms/kexec-tools `kexec/kexec.c`), which ssh propagates verbatim; ssh's own transport failure
/// is likewise 255 but authors stderr with no "kexec". The earlier `exit_code != Some(255)` clause,
/// added to exclude ssh's transport 255, ALSO excluded the refused-kexec 255, so a lockdown refusal
                                                                                          
/// reachable `kexec -e` failure, `die("Nothing has been loaded!\n")` → exit 1, carries no "kexec"
/// and is unreachable here (the ceremony's prior `kexec -l` load succeeded); a missing binary
/// (`sh: kexec: not found`, exit 127) carries "kexec", classifies refused/fail-safe, and is already
                                                                                                 
/// cannot reach this classifier and masquerade as "kexec may have fired".
pub fn kexec_refused(success: bool, stderr: &str) -> bool {
    !success && stderr.to_ascii_lowercase().contains("kexec")
}

/// Byte-patch the `fb.rootfs-dev` field baked into a pre-baked boot-fs `extlinux.conf` (the O3
/// operator-side step): locate the fixed-width [`recipes_image_builder::boot_fs::ROOTFS_DEV_SENTINEL`]
/// in the boot-fs bytes (exactly once) and overwrite it LENGTH-PRESERVING with the target's
/// `/dev/<partition>` + ASCII-space padding. Length-preserving so the ext4 data block is unchanged in
/// size — stock ext4 doesn't checksum file DATA, so the filesystem stays valid + mountable; the
/// trailing spaces re-tokenize to just the device when `parse_cmdline` splits the APPEND on whitespace.
///
/// `device` is the slot-A partition path (`/dev/<disk>2`); validated via the same bare-partition
/// whitelist the cmdline grammar uses ([`bare_device`]) and rejected if its `/dev/<name>` form is wider
/// than the field. Fail-closed (operator-actionable `Err`) on a bad device, an absent sentinel, or a
/// non-unique sentinel — never a silent half-patch. (Exercised end-to-end by the Task 13 disk-boot gate,
/// which patches the boot-fs slice before assembling the installed disk.)
pub fn patch_rootfs_dev(boot_fs: &mut [u8], device: &str) -> Result<(), String> {
    use recipes_image_builder::boot_fs::{ROOTFS_DEV_FIELD_WIDTH, ROOTFS_DEV_SENTINEL};
    let bare = bare_device(device)
        .ok_or_else(|| format!("rootfs-dev {device:?} is not a plain /dev/<partition> device"))?;
    let value = format!("/dev/{bare}");
    if value.len() > ROOTFS_DEV_FIELD_WIDTH {
        return Err(format!(
            "rootfs-dev {value:?} is {} bytes, wider than the {ROOTFS_DEV_FIELD_WIDTH}-byte field",
            value.len()
        ));
    }
    let sentinel = ROOTFS_DEV_SENTINEL.as_bytes();
    let positions: Vec<usize> = boot_fs
        .windows(sentinel.len())
        .enumerate()
        .filter_map(|(i, w)| (w == sentinel).then_some(i))
        .collect();
    if positions.len() > 1 {
        return Err(format!(
            "rootfs-dev sentinel occurs {} times in the boot-fs (expected exactly one)",
            positions.len()
        ));
    }
    let start = *positions
        .first()
        .ok_or("rootfs-dev sentinel not found in the boot-fs")?;
                                                                                              
    let field = &mut boot_fs[start..start + ROOTFS_DEV_FIELD_WIDTH];
    field.fill(b' ');
    field[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
#[path = "prod_tests.rs"]
mod tests;
