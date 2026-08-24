                                                                                      
//!
//! Gathers a [`BoxSnapshot`] over the [`super::lifecycle::BoxOps`] transport using ONLY read commands
//! (`fb-update status`, `cat /proc/cmdline`, `cat /etc/recipes/artifact-root.pub`), then (T4) compares it
//! against a local `--image`/`--keys-dir` and classifies an honest exit. ALL box-captured bytes are
//! UNTRUSTED: [`sanitize`] strips them before rendering, and every comparison verdict is computed
//! operator-side on sanitized values (§2.6) — a lying box can misreport itself but can never make
//! `status` claim a COMPARISON verdict the operator-side expected values don't support.

use std::path::{Path, PathBuf};

use recipes_image_builder::firmware::Firmware;
use sha2::{Digest, Sha256};

use super::host_pins::HostPinOpts;
use super::lifecycle::{BoxOps, ConnectError, SshBox};
use super::update::{BoxStatus, parse_status};

/// §2.6 output caps — a compromised box cannot flood the operator terminal. Generous enough for the real
/// §4g block + cmdline + the 64-hex anchor, tight enough to bound a hostile response.
const STATUS_BLOCK_CAP: usize = 64 * 1024;
const CMDLINE_CAP: usize = 8 * 1024;
const ANCHOR_CAP: usize = 4 * 1024;

                                                                                                       
/// is `None`/`false`, never a fabricated value (mirrors G3's `unavailable`-over-crash posture).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxSnapshot {
    /// The full §4g `fb-update status` block, SANITIZED, passed through verbatim under `[box]`.
    pub raw_status_block: Option<String>,
    /// The parsed subset ([`BoxStatus`]) — `None` if `fb-update` is absent OR the block is unparseable.
    pub parsed: Option<BoxStatus>,
    /// The ACTIVE slot's baked `min_delegation_ctr`, parsed DIRECTLY from `raw_status_block` — NOT a
    /// [`BoxStatus`] field. `BoxStatus` carries `minctr_floor`, a DIFFERENT value (the runtime
    /// anti-rollback floor); comparing that against an image's baked `min_delegation_ctr` would spuriously
    /// mismatch a matching image (plan-sanity M1).
    pub min_delegation_ctr: Option<u64>,
    /// The serving verity root hash — `/proc/cmdline` `fb.root-hash` (G5), byte-verbatim. Reported even in
    /// degrade mode (a pre-A/B box still boots with this token).
    pub root_hash: Option<String>,
    /// `/proc/cmdline` `fb.rootfs-dev` (the active-slot PARTUUID, G5).
    pub rootfs_dev: Option<String>,
    /// `/proc/cmdline` `fb.firmware` — `Some("seabios-gpt")`/`Some("uefi")` on those firmwares, `None` on
    /// a plain SeaBIOS/MBR box (which bakes no firmware token, per `boot_fs.rs`).
    pub firmware_cmdline: Option<String>,
    /// sha256 (hashed OPERATOR-side over the fetched bytes) of the box's baked trust anchor
    /// `/etc/recipes/artifact-root.pub` (G4). `None` on a pre-A/B image where the file is absent.
    pub anchor_sha256: Option<String>,
    /// Whether `fb-update` answered (the update engine is present). `false` ⇒ degrade mode (G9).
    pub fb_update_present: bool,
}

/// Escape/replace every byte that is not printable ASCII (plus `\n`/`\t` structure) with U+FFFD, and
/// bound the result to `cap` bytes of input (§2.6). NO raw ANSI/escape (0x1b) ever reaches the operator
/// terminal — a compromised box cannot drive the terminal or flood it. U+FFFD (not silent stripping) so
/// the operator SEES that something was scrubbed.
pub fn sanitize(raw: &[u8], cap: usize) -> String {
    let truncated = raw.len() > cap;
    let mut out = String::with_capacity(raw.len().min(cap));
    for &b in raw.iter().take(cap) {
        match b {
            b'\n' | b'\t' => out.push(b as char),
            0x20..=0x7e => out.push(b as char),
            _ => out.push('\u{fffd}'),
        }
    }
    if truncated {
        out.push_str("\n…[truncated]");
    }
    out
}

/// Hash an anchor's bytes OPERATOR-side with the SAME transform on both sides (sanitize → trim →
/// sha256), so the box `/etc/recipes/artifact-root.pub`, a local keys-dir `artifact-root.pub`, and the
/// committed pin's bare hex all hash identically for the same 32-byte pubkey (they encode it as the same
                                                                                                    
fn anchor_hash(raw: &[u8]) -> String {
    let sanitized = sanitize(raw, ANCHOR_CAP);
    format!("{:x}", Sha256::digest(sanitized.trim().as_bytes()))
}

/// Extract a `key=value` token's value from a space-separated kernel cmdline (`fb.root-hash`, etc.).
/// Byte-verbatim (the box keeps `fb.root-hash` un-normalized, R6-1).
fn cmdline_token(cmdline: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    cmdline
        .split_whitespace()
        .find_map(|t| t.strip_prefix(&needle))
        .map(str::to_string)
}

/// The ACTIVE slot's baked `min_delegation_ctr` from the raw §4g block (the top-level
/// `min_delegation_ctr = <n>` line — read from the active rootfs by `render_status`, DISTINCT from the
/// `minctr_floor` line). `None` if absent or `unavailable` (plan-sanity M1).
fn active_min_delegation_ctr(block: &str) -> Option<u64> {
    block.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k.trim() == "min_delegation_ctr")
            .then(|| v.trim().parse::<u64>().ok())
            .flatten()
    })
}

/// Gather the read-only [`BoxSnapshot`] (§2.2). Runs ONLY read commands and writes nothing box-side
                                                                                                    
/// anchor is hashed OPERATOR-side (`sha2`) over the fetched bytes — no box-side `sha256sum` dependency.
pub fn gather(ops: &mut dyn BoxOps) -> Result<BoxSnapshot, String> {
                                                                                              
    let (fb_ok, fb_out) = ops.run("fb-update status")?;
    let raw_status_block = fb_ok.then(|| sanitize(fb_out.as_bytes(), STATUS_BLOCK_CAP));
    let parsed = raw_status_block
        .as_deref()
        .and_then(|b| parse_status(b).ok());
    let min_delegation_ctr = raw_status_block
        .as_deref()
        .and_then(active_min_delegation_ctr);

                                                               
    let (cl_ok, cl_out) = ops.run("cat /proc/cmdline")?;
    let cmdline = if cl_ok {
        sanitize(cl_out.as_bytes(), CMDLINE_CAP)
    } else {
        String::new()
    };
    let root_hash = cmdline_token(&cmdline, "fb.root-hash");
    let rootfs_dev = cmdline_token(&cmdline, "fb.rootfs-dev");
    let firmware_cmdline = cmdline_token(&cmdline, "fb.firmware");

                                                                                          
    let (an_ok, an_out) = ops.run("cat /etc/recipes/artifact-root.pub")?;
    let anchor_sha256 = an_ok.then(|| anchor_hash(an_out.as_bytes()));

    Ok(BoxSnapshot {
        raw_status_block,
        parsed,
        min_delegation_ctr,
        root_hash,
        rootfs_dev,
        firmware_cmdline,
        anchor_sha256,
        fb_update_present: fb_ok,
    })
}

                                                                                                                                                                                                       

/// One field's comparison verdict (§2.3). `NotComparable` carries a reason so the operator distinguishes
/// "the box lacks this value" from "the `--image` is a different comparison" (firmware-mismatch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Match,
    Mismatch,
    NotComparable(String),
}

/// The honest process-exit class (§2.5), one per outcome so a ceremony script can branch without parsing
/// prose. Distinct non-zero codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusExit {
    Ok,
    Mismatch,
    Degraded,
    PinMismatch,
    Unreachable,
}

impl StatusExit {
    /// The distinct process exit code. Deliberately ABOVE clap's reserved usage-error code (2) and the
    /// generic-failure 1, so a ceremony script's `case $?` can never misread a mistyped invocation (clap
    /// exits 2) as a real MISMATCH (§2.5 — branch without parsing prose).
    pub fn code(self) -> i32 {
        match self {
            StatusExit::Ok => 0,
            StatusExit::Mismatch => 10,
            StatusExit::Degraded => 11,
            StatusExit::PinMismatch => 12,
            StatusExit::Unreachable => 13,
        }
    }
}

/// The `.img` sidecar path with a REPLACED extension (`recipes-image-x.img` → `…-x.layout.toml`).
fn sibling(image: &Path, ext: &str) -> std::path::PathBuf {
    image.with_extension(ext)
}

/// The facts read from a local `.img` for the `--image` comparison (§2.3), read through the SAME readers
/// `orchard update` uses (`verify::parse_layout` + `update::read_root_hash_and_offset`). Kept separate
/// from the pure [`compare_image_facts`] so the comparison logic is unit-testable without a real `.img`
/// (the real read is exercised on produced bytes at T10).
struct LocalImageFacts {
    image_version: u64,
    min_delegation_ctr: u64,
    firmware: Firmware,
    /// The local build's serving verity root hash from the boot-fs `extlinux.conf`; `None` if the boot-fs
    /// read failed (that field then reports `not-comparable`, never a false match).
    root_hash: Option<String>,
}

/// Read the local `.img`'s comparison facts (IO). A read/parse failure surfaces as an `Err` the caller
/// turns into a single `not-comparable` verdict.
fn read_local_image_facts(image: &Path) -> Result<LocalImageFacts, String> {
    let img = std::fs::read(image).map_err(|e| format!("read {}: {e}", image.display()))?;
    let layout_str = std::fs::read_to_string(sibling(image, "layout.toml"))
        .map_err(|e| format!("read {}: {e}", sibling(image, "layout.toml").display()))?;
    let layout = super::verify::parse_layout(&layout_str)?;
    let root_hash =
        super::update::read_root_hash_and_offset(&img, layout.boot_offset, layout.boot_size)
            .map(|(rh, _)| rh)
            .ok();
    Ok(LocalImageFacts {
        image_version: layout.image_version,
        min_delegation_ctr: layout.min_delegation_ctr,
        firmware: layout.firmware,
        root_hash,
    })
}

/// Pure per-field comparison of a box snapshot against local image facts (§2.3). The box's
/// `min_delegation_ctr` comes from `snap.min_delegation_ctr` (the raw §4g block), NOT
/// `BoxStatus.minctr_floor` — a different value that would spuriously mismatch (plan-sanity M1). A
/// firmware DIFFERENCE makes the whole `--image` comparison `not-comparable(firmware-mismatch)` — a
/// cross-firmware image is a DIFFERENT comparison, not a drifted one (§2.3; never a raw `Mismatch`,
/// mirroring `orchard update`'s cross-firmware refusal).
fn compare_image_facts(snap: &BoxSnapshot, local: &LocalImageFacts) -> Vec<(String, Verdict)> {
    let local_fw = local.firmware.as_str();
                                                                                 
    let box_fw = snap
        .parsed
        .as_ref()
        .map(|p| p.firmware.as_str())
        .or(snap.firmware_cmdline.as_deref());
    let firmware_differs = matches!(box_fw, Some(b) if b != local_fw);

    let mut out = vec![(
        "firmware".to_string(),
        match box_fw {
            None => Verdict::NotComparable("box-firmware-unavailable".to_string()),
            Some(b) if b == local_fw => Verdict::Match,
            Some(_) => Verdict::NotComparable("firmware-mismatch".to_string()),
        },
    )];

                                                                                                       
                                                                                       
    let cmp_u64 = |name: &str, local_v: u64, box_v: Option<u64>| -> (String, Verdict) {
        let v = if firmware_differs {
            Verdict::NotComparable("firmware-mismatch".to_string())
        } else {
            match box_v {
                None => Verdict::NotComparable("box-value-unavailable".to_string()),
                Some(b) if b == local_v => Verdict::Match,
                Some(_) => Verdict::Mismatch,
            }
        };
        (name.to_string(), v)
    };
    out.push(cmp_u64(
        "image_version",
        local.image_version,
        snap.parsed.as_ref().map(|p| p.image_version),
    ));
    out.push(cmp_u64(
        "min_delegation_ctr",
        local.min_delegation_ctr,
        snap.min_delegation_ctr,
    ));

    let verity = if firmware_differs {
        Verdict::NotComparable("firmware-mismatch".to_string())
    } else {
        match (local.root_hash.as_deref(), snap.root_hash.as_deref()) {
            (None, _) => Verdict::NotComparable("local-root-hash-unreadable".to_string()),
            (_, None) => Verdict::NotComparable("box-root-hash-unavailable".to_string()),
            (Some(l), Some(b)) if l == b => Verdict::Match,
            _ => Verdict::Mismatch,
        }
    };
    out.push(("verity_root_hash".to_string(), verity));
    out
}

/// Compare the box against a local `--image` (§2.3). A local read/parse failure is a single
/// `not-comparable` verdict (never a crash).
pub fn compare_image(snap: &BoxSnapshot, image: &Path) -> Vec<(String, Verdict)> {
    match read_local_image_facts(image) {
        Ok(facts) => compare_image_facts(snap, &facts),
        Err(e) => vec![("image".to_string(), Verdict::NotComparable(e))],
    }
}

fn verdict_eq(a: &str, b: &str) -> Verdict {
    if a == b {
        Verdict::Match
    } else {
        Verdict::Mismatch
    }
}

/// Extract the bare 64-hex root pubkey from a committed `pinned-artifact-root.toml` (`pubkey =
/// "ed25519:<hex>"`). `None` on any read/parse failure (absent/unparseable) — the pin is optional.
fn read_committed_pin_hex(pin_path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(pin_path).ok()?;
    let value: toml::Value = text.parse().ok()?;
    let pubkey = value.get("pubkey")?.as_str()?;
    pubkey.strip_prefix("ed25519:").map(str::to_string)
}

                                                                                                          
/// keys-dir `artifact-root.pub` and, when present, the committed `pinned-artifact-root.toml` — the ONLY
/// supported confirmation that a root-rotation takeover actually took hold. A divergence between the
/// three (local key set vs committed pin vs box) is reported EXPLICITLY per pair.
pub fn compare_anchor(
    snap: &BoxSnapshot,
    keys_dir: &Path,
    committed_pin: Option<&Path>,
) -> Vec<(String, Verdict)> {
    let box_hash = match &snap.anchor_sha256 {
        Some(h) => h.clone(),
        None => {
            return vec![(
                "anchor".to_string(),
                Verdict::NotComparable("box anchor unavailable (pre-A/B image)".to_string()),
            )];
        }
    };
    let local_hash = match std::fs::read(keys_dir.join("artifact-root.pub")) {
        Ok(b) => anchor_hash(&b),
        Err(e) => {
            return vec![(
                "anchor".to_string(),
                Verdict::NotComparable(format!(
                    "local {}: {e}",
                    keys_dir.join("artifact-root.pub").display()
                )),
            )];
        }
    };
    let mut out = vec![(
        "anchor: local keys-dir vs box".to_string(),
        verdict_eq(&local_hash, &box_hash),
    )];
    if let Some(pin_path) = committed_pin
        && pin_path.exists()
    {
        match read_committed_pin_hex(pin_path) {
            Some(pin_hex) => {
                let pin_hash = anchor_hash(pin_hex.as_bytes());
                out.push((
                    "anchor: committed pin vs box".to_string(),
                    verdict_eq(&pin_hash, &box_hash),
                ));
                out.push((
                    "anchor: local keys-dir vs committed pin".to_string(),
                    verdict_eq(&local_hash, &pin_hash),
                ));
            }
                                                                                                          
                                                                                                            
            None => out.push((
                "anchor: committed pin".to_string(),
                Verdict::NotComparable("committed-pin-unparseable".to_string()),
            )),
        }
    }
    out
}

/// Classify the honest exit (§2.5). `requested` = at least one of `--image`/`--keys-dir` was given.
/// `OK` requires that EVERY requested comparison was PERFORMED and matched; any `NotComparable` on a
/// requested comparison ⇒ `Degraded`, never `OK` (I-1). A pre-A/B or partially-legible box is `Degraded`
/// regardless. A confirmed `Mismatch` is the headline (outranks `Degraded`).
pub fn classify_exit(
    snap: &BoxSnapshot,
    comparisons: &[(String, Verdict)],
    requested: bool,
) -> StatusExit {
                                                                                                   
                                    
    let box_degraded = !snap.fb_update_present || snap.parsed.is_none();
    if requested {
        if comparisons.iter().any(|(_, v)| *v == Verdict::Mismatch) {
            return StatusExit::Mismatch;
        }
        if box_degraded
            || comparisons
                .iter()
                .any(|(_, v)| matches!(v, Verdict::NotComparable(_)))
        {
            return StatusExit::Degraded;
        }
        return StatusExit::Ok;
    }
                                                                                              
    if box_degraded {
        StatusExit::Degraded
    } else {
        StatusExit::Ok
    }
}

                                                                                                                                                                                                                                            

/// The resolved `orchard status` inputs (main.rs builds this from the clap variant + the host-pin /
/// tty / repo-pin resolution).
pub struct StatusArgs {
    pub host: String,
    pub port: u16,
    pub image: Option<PathBuf>,
    /// The operator SSH login identity — REQUIRED (I-6): authenticates every read leg.
    pub ssh_identity: PathBuf,
    pub keys_dir: Option<PathBuf>,
                                                                                                        
    /// `None` when absent / not in a repo.
    pub committed_pin: Option<PathBuf>,
    pub host_fingerprint: Option<String>,
    pub pin_dir: PathBuf,
    pub is_tty: bool,
}

/// Map a connect failure to the honest exit (§2.5).
fn connect_error_exit(e: &ConnectError) -> StatusExit {
    match e {
        ConnectError::PinMismatch(_) => StatusExit::PinMismatch,
        ConnectError::Unreachable(_) => StatusExit::Unreachable,
    }
}

/// Render the operator report (§2.4/§2.5) — verdict-first, sanitized, naming the DEGRADED reason so the
/// operator distinguishes "the box lacks the engine" from "your `--image` can't be compared". Returns
/// the text (testable); the caller prints it.
fn render(
    snap: &BoxSnapshot,
    comparisons: &[(String, Verdict)],
    requested: bool,
    exit: StatusExit,
) -> String {
    let mut s = String::new();
    let verdict = match exit {
        StatusExit::Ok => "OK",
        StatusExit::Mismatch => "MISMATCH",
        StatusExit::Degraded => "DEGRADED",
        StatusExit::PinMismatch => "PIN-MISMATCH",
        StatusExit::Unreachable => "UNREACHABLE",
    };
    s.push_str(&format!("box status: {verdict}\n\n"));

                                                                                                        
    if let Some(block) = &snap.raw_status_block {
        s.push_str("[box]\n");
        s.push_str(block);
        if !block.ends_with('\n') {
            s.push('\n');
        }
    } else {
        s.push_str(
            "[box] pre-A/B image: no update engine (fb-update absent); updates require the GPT \
             migration ceremony.\n",
        );
    }
    s.push('\n');

                                                                                                         
    s.push_str("[serving]\n");
    s.push_str(&format!(
        "  verity_root_hash   = {}\n",
        snap.root_hash.as_deref().unwrap_or("unavailable")
    ));
    s.push_str(&format!(
        "  rootfs_dev         = {}\n",
        snap.rootfs_dev.as_deref().unwrap_or("unavailable")
    ));
    s.push_str(&format!(
        "  firmware           = {}\n",
        snap.firmware_cmdline
            .as_deref()
            .unwrap_or("(none — MBR/SeaBIOS)")
    ));
    s.push_str(&format!(
        "  min_delegation_ctr = {}\n",
        snap.min_delegation_ctr
            .map(|c| c.to_string())
            .unwrap_or_else(|| "unavailable".to_string())
    ));
    s.push_str(&format!(
        "  anchor_sha256      = {}\n",
        snap.anchor_sha256
            .as_deref()
            .unwrap_or("unavailable (pre-A/B image)")
    ));
    s.push('\n');

                                                                                                   
                                                
    if requested {
        s.push_str("[comparison]\n");
        for (field, v) in comparisons {
            let vs = match v {
                Verdict::Match => "match".to_string(),
                Verdict::Mismatch => "MISMATCH".to_string(),
                Verdict::NotComparable(r) => format!("not-comparable({r})"),
            };
            s.push_str(&format!("  {field:<40} {vs}\n"));
        }
        if exit == StatusExit::Degraded {
            if !snap.fb_update_present {
                s.push_str(
                    "  (DEGRADED: the box is pre-A/B — no update engine; --image version/ctr cannot \
                     be compared)\n",
                );
            } else {
                s.push_str(
                    "  (DEGRADED: a requested comparison is not-comparable — see the reason above)\n",
                );
            }
        }
    } else {
        s.push_str("no comparison performed (no --image/--keys-dir)\n");
        if !snap.fb_update_present {
            s.push_str(
                "box runs a pre-A/B image: no update engine; updates require the GPT migration \
                 ceremony\n",
            );
        }
    }
    s
}

/// `orchard status` (§2.1): resolve the host pin FIRST (a mismatch ⇒ PIN-MISMATCH before ANY remote
                                                                                                   
pub fn run(args: &StatusArgs) -> StatusExit {
    let host_pin = HostPinOpts {
        host_fingerprint: args.host_fingerprint.as_deref(),
        is_tty: args.is_tty,
        pin_dir: &args.pin_dir,
    };
    let mut ops = match SshBox::connect(&args.host, args.port, &args.ssh_identity, host_pin) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("orchard status: {e}");
            return connect_error_exit(&e);
        }
    };
    let requested = args.image.is_some() || args.keys_dir.is_some();
    run_over(
        &mut ops,
        args.image.as_deref(),
        args.keys_dir.as_deref(),
        args.committed_pin.as_deref(),
        requested,
    )
}

/// The transport-agnostic core (FakeBox-testable): gather + compare + classify + render. Read-only —
                                                                                            
fn run_over(
    ops: &mut dyn BoxOps,
    image: Option<&Path>,
    keys_dir: Option<&Path>,
    committed_pin: Option<&Path>,
    requested: bool,
) -> StatusExit {
    let snap = match gather(ops) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("orchard status: could not read the box: {e}");
            return StatusExit::Unreachable;
        }
    };
    let mut comparisons = Vec::new();
    if let Some(img) = image {
        comparisons.extend(compare_image(&snap, img));
    }
    if let Some(kd) = keys_dir {
        comparisons.extend(compare_anchor(&snap, kd, committed_pin));
    }
    let exit = classify_exit(&snap, &comparisons, requested);
    print!("{}", render(&snap, &comparisons, requested, exit));
    exit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::lifecycle::FakeBox;

    /// A realistic §4g block (matching fruit-basket `render_status`'s exact key order/shape). `min_ctr`
    /// (the active slot's baked min-delegation-ctr) and `minctr_floor` (the runtime floor) are DISTINCT
    /// so the M1 test can prove `min_delegation_ctr` reads the right line.
    fn status_block(version: u64, min_ctr: u64, minctr_floor: u64) -> String {
        format!(
            "active_slot = a\n\
             active_slot_source = /proc/cmdline fb.rootfs-dev PARTUUID\n\
             firmware = seabios-gpt\n\
             image_version = {version}\n\
             min_delegation_ctr = {min_ctr}\n\
             version_floor = {version}\n\
             minctr_floor = {minctr_floor}\n\
             floor_health = ok\n\
             probation = none\n\
             last_failure = none\n\
             backup_age_secs = 120\n\
             uptime_secs = 3600\n"
        )
    }

    pub(crate) fn cmdline(firmware: Option<&str>) -> String {
        let fw = firmware
            .map(|f| format!(" fb.firmware={f}"))
            .unwrap_or_default();
        format!(
            "ro fb.root-hash=deadbeefcafe0011 fb.rootfs-dev=PARTUUID=1234-5678 \
             fb.verity-hash-offset=8192{fw} lockdown=integrity ima_policy=…"
        )
    }

    pub(crate) const ANCHOR_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn gather_populates_parsed_and_raw_block() {
        let mut fake = FakeBox::new()
            .with_fb_status(&status_block(7, 1_700_000_500, 1_700_000_400))
            .with_file("/proc/cmdline", cmdline(Some("seabios-gpt")).as_bytes())
            .with_file(
                "/etc/recipes/artifact-root.pub",
                format!("{ANCHOR_HEX}\n").as_bytes(),
            );

        let snap = gather(&mut fake).unwrap();
        assert!(snap.fb_update_present);
        let parsed = snap.parsed.as_ref().expect("block parses");
        assert_eq!(parsed.image_version, 7);
        assert_eq!(parsed.firmware, "seabios-gpt");
                                                                 
        assert!(
            snap.raw_status_block
                .as_deref()
                .unwrap()
                .contains("active_slot = a")
        );
                         
        assert_eq!(snap.root_hash.as_deref(), Some("deadbeefcafe0011"));
        assert_eq!(snap.rootfs_dev.as_deref(), Some("PARTUUID=1234-5678"));
        assert_eq!(snap.firmware_cmdline.as_deref(), Some("seabios-gpt"));
                                                              
        let expect = format!("{:x}", Sha256::digest(ANCHOR_HEX.as_bytes()));
        assert_eq!(snap.anchor_sha256.as_deref(), Some(expect.as_str()));
    }

    #[test]
    fn min_delegation_ctr_reads_the_block_line_not_minctr_floor() {
                                                                                              
                                                                                           
        let mut fake = FakeBox::new()
            .with_fb_status(&status_block(7, 1_700_000_500, 1_700_000_400))
            .with_file("/proc/cmdline", cmdline(Some("seabios-gpt")).as_bytes())
            .with_file(
                "/etc/recipes/artifact-root.pub",
                format!("{ANCHOR_HEX}\n").as_bytes(),
            );
        let snap = gather(&mut fake).unwrap();
        assert_eq!(
            snap.min_delegation_ctr,
            Some(1_700_000_500),
            "reads the min_delegation_ctr line"
        );
        assert_eq!(
            snap.parsed.unwrap().minctr_floor,
            1_700_000_400,
            "minctr_floor is the OTHER value"
        );
    }

    #[test]
    fn sanitize_strips_ansi_escapes_and_bounds_length() {
                                                                                    
        let hostile = b"line1\n\x1b[2J\x1b[31mEVIL\x07\xff\ntail";
        let out = sanitize(hostile, 64 * 1024);
        assert!(!out.contains('\x1b'), "no raw ESC survives: {out:?}");
        assert!(!out.contains('\x07'), "no raw BEL survives");
        assert!(out.contains("line1"), "printable text is preserved");
        assert!(
            out.contains('\u{fffd}'),
            "scrubbed bytes are visibly replaced"
        );
                                  
        let flood = vec![b'A'; 200];
        let capped = sanitize(&flood, 10);
        assert!(capped.starts_with("AAAAAAAAAA"));
        assert!(capped.contains("truncated"));
    }

    #[test]
    fn degrade_when_fb_update_absent() {
                                                                                                      
        let mut fake = FakeBox::new()
            .without_fb_update()
            .with_file("/proc/cmdline", cmdline(None).as_bytes());
                                                        
        let snap = gather(&mut fake).unwrap();
        assert!(!snap.fb_update_present);
        assert!(snap.parsed.is_none(), "no §4g parse in degrade mode");
        assert!(snap.raw_status_block.is_none());
        assert!(snap.min_delegation_ctr.is_none());
                                                                              
        assert_eq!(snap.root_hash.as_deref(), Some("deadbeefcafe0011"));
        assert_eq!(snap.firmware_cmdline, None);
                                                                                                            
        assert!(snap.anchor_sha256.is_none());
    }

                                                                                                                                                                                                                   

    fn healthy_snap() -> BoxSnapshot {
        let mut fake = FakeBox::new()
            .with_fb_status(&status_block(7, 1_700_000_500, 1_700_000_400))
            .with_file("/proc/cmdline", cmdline(Some("seabios-gpt")).as_bytes())
            .with_file(
                "/etc/recipes/artifact-root.pub",
                format!("{ANCHOR_HEX}\n").as_bytes(),
            );
        gather(&mut fake).unwrap()
    }

    fn degrade_snap() -> BoxSnapshot {
        let mut fake = FakeBox::new()
            .without_fb_update()
            .with_file("/proc/cmdline", cmdline(None).as_bytes());
        gather(&mut fake).unwrap()
    }

    fn matching_facts() -> LocalImageFacts {
        LocalImageFacts {
            image_version: 7,
            min_delegation_ctr: 1_700_000_500,
            firmware: Firmware::SeabiosGpt,
            root_hash: Some("deadbeefcafe0011".to_string()),
        }
    }

    #[test]
    fn compare_image_matching_is_all_match_and_ok() {
                                                                                    
        let snap = healthy_snap();
        let cmp = compare_image_facts(&snap, &matching_facts());
        assert!(cmp.iter().all(|(_, v)| *v == Verdict::Match), "{cmp:?}");
        assert_eq!(classify_exit(&snap, &cmp, true), StatusExit::Ok);
    }

    #[test]
    fn compare_image_divergent_version_and_root_mismatch() {
                                                                                     
        let facts = LocalImageFacts {
            image_version: 9,
            root_hash: Some("differentroot".to_string()),
            ..matching_facts()
        };
        let snap = healthy_snap();
        let cmp = compare_image_facts(&snap, &facts);
        let by = |n: &str| cmp.iter().find(|(k, _)| k == n).unwrap().1.clone();
        assert_eq!(by("image_version"), Verdict::Mismatch);
        assert_eq!(by("verity_root_hash"), Verdict::Mismatch);
        assert_eq!(by("min_delegation_ctr"), Verdict::Match);
        assert_eq!(classify_exit(&snap, &cmp, true), StatusExit::Mismatch);
    }

    #[test]
    fn firmware_mismatch_is_not_comparable_never_mismatch() {
                                                                                                          
                                                                                                        
        let facts = LocalImageFacts {
            firmware: Firmware::Seabios,
            image_version: 9,
            ..matching_facts()
        };
        let snap = healthy_snap();
        let cmp = compare_image_facts(&snap, &facts);
        assert!(
            cmp.iter()
                .all(|(_, v)| matches!(v, Verdict::NotComparable(_))),
            "cross-firmware ⇒ all not-comparable: {cmp:?}"
        );
        let fw = cmp.iter().find(|(k, _)| k == "firmware").unwrap();
        assert_eq!(
            fw.1,
            Verdict::NotComparable("firmware-mismatch".to_string())
        );
        assert!(
            !cmp.iter().any(|(_, v)| *v == Verdict::Mismatch),
            "no raw MISMATCH cross-firmware"
        );
        assert_eq!(classify_exit(&snap, &cmp, true), StatusExit::Degraded);
    }

    #[test]
    fn classify_exit_taxonomy() {
        let snap = healthy_snap();
        let ok = [("a".to_string(), Verdict::Match)];
        assert_eq!(classify_exit(&snap, &ok, true), StatusExit::Ok);
                                                         
        let mm = [
            ("a".to_string(), Verdict::Mismatch),
            ("b".to_string(), Verdict::NotComparable("x".to_string())),
        ];
        assert_eq!(classify_exit(&snap, &mm, true), StatusExit::Mismatch);
                                                                         
        let nc = [
            ("a".to_string(), Verdict::Match),
            ("b".to_string(), Verdict::NotComparable("x".to_string())),
        ];
        assert_eq!(classify_exit(&snap, &nc, true), StatusExit::Degraded);
                                                                                    
        assert_eq!(classify_exit(&snap, &[], false), StatusExit::Ok);
        assert_eq!(
            classify_exit(&degrade_snap(), &[], false),
            StatusExit::Degraded
        );
        assert_eq!(
            classify_exit(&degrade_snap(), &[], true),
            StatusExit::Degraded
        );
                               
        for pair in [
            (StatusExit::Ok, StatusExit::Mismatch),
            (StatusExit::Mismatch, StatusExit::Degraded),
            (StatusExit::Degraded, StatusExit::PinMismatch),
            (StatusExit::PinMismatch, StatusExit::Unreachable),
        ] {
            assert_ne!(pair.0.code(), pair.1.code());
        }
    }

    #[test]
    fn compare_anchor_agreement_mismatch_and_three_way() {
                                                                                                   
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path();
        std::fs::write(keys.join("artifact-root.pub"), format!("{ANCHOR_HEX}\n")).unwrap();
        let base = healthy_snap();

                                                                                               
        let agree = BoxSnapshot {
            anchor_sha256: Some(anchor_hash(format!("{ANCHOR_HEX}\n").as_bytes())),
            ..base.clone()
        };
        assert_eq!(compare_anchor(&agree, keys, None)[0].1, Verdict::Match);

                                               
        let other_hex = "2".repeat(64);
        let diverge = BoxSnapshot {
            anchor_sha256: Some(anchor_hash(other_hex.as_bytes())),
            ..base.clone()
        };
        assert_eq!(compare_anchor(&diverge, keys, None)[0].1, Verdict::Mismatch);

                                                                                                            
        let pin = dir.path().join("pinned-artifact-root.toml");
        std::fs::write(
            &pin,
            format!("pubkey = \"ed25519:{ANCHOR_HEX}\"\ngenerated_at = \"x\"\n"),
        )
        .unwrap();
        let cmp = compare_anchor(&diverge, keys, Some(&pin));
        let by = |n: &str| cmp.iter().find(|(k, _)| k.contains(n)).unwrap().1.clone();
        assert_eq!(by("local keys-dir vs box"), Verdict::Mismatch);
        assert_eq!(by("committed pin vs box"), Verdict::Mismatch);
        assert_eq!(by("local keys-dir vs committed pin"), Verdict::Match);

                                                                                                               
        let bad_pin = dir.path().join("bad-pin.toml");
        std::fs::write(&bad_pin, "this is not toml\n").unwrap();
        let cmp = compare_anchor(&diverge, keys, Some(&bad_pin));
        assert!(
            cmp.iter()
                .any(|(k, v)| k.contains("committed pin") && matches!(v, Verdict::NotComparable(_))),
            "{cmp:?}"
        );

                                                                    
        let preab = BoxSnapshot {
            anchor_sha256: None,
            ..base
        };
        assert!(matches!(
            compare_anchor(&preab, keys, None)[0].1,
            Verdict::NotComparable(_)
        ));
    }

                                                                                                                                                                                                                                                                       

    #[test]
    fn connect_error_maps_to_the_honest_exit() {
                                                                                   
        assert_eq!(
            connect_error_exit(&ConnectError::PinMismatch("x".to_string())),
            StatusExit::PinMismatch
        );
        assert_eq!(
            connect_error_exit(&ConnectError::Unreachable("x".to_string())),
            StatusExit::Unreachable
        );
    }

    #[test]
    fn status_run_over_is_read_only() {
                                                                                                         
        let mut fake = FakeBox::new()
            .with_fb_status(&status_block(7, 1_700_000_500, 1_700_000_400))
            .with_file("/proc/cmdline", cmdline(Some("seabios-gpt")).as_bytes())
            .with_file(
                "/etc/recipes/artifact-root.pub",
                format!("{ANCHOR_HEX}\n").as_bytes(),
            )
            .with_authorized(&["ssh-ed25519 AAAAOPERATOR operator@host"]);
        let before_files = fake.files.clone();
        let before_auth = fake.authorized_lines();

        let exit = run_over(&mut fake, None, None, None, false);
        assert_eq!(exit, StatusExit::Ok, "a bare run on a healthy box is OK");
        assert!(
            fake.writes.is_empty(),
            "status must write nothing: {:?}",
            fake.writes
        );
        assert_eq!(fake.files, before_files, ": box files unchanged");
        assert_eq!(
            fake.authorized_lines(),
            before_auth,
            "authorized_keys unchanged"
        );
    }

    #[test]
    fn render_bare_run_names_no_comparison_and_degrade() {
                                                                                                    
        let snap = healthy_snap();
        let out = render(&snap, &[], false, StatusExit::Ok);
        assert!(out.contains("no comparison performed"), "{out}");
                                                             
        let out = render(&degrade_snap(), &[], false, StatusExit::Degraded);
        assert!(out.contains("pre-A/B image"), "{out}");
        assert!(
            out.contains("anchor_sha256      = unavailable (pre-A/B image)"),
            "{out}"
        );
    }
}
