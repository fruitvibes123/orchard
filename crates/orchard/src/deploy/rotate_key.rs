//! `orchard rotate-key <host> --new-identity <path>` — operator SSH login-key rotation with a
                                         
//!
//! The verb is INTERACTIVE-ONLY (no scripted `--confirmed` path): the ceremony entry ([`run`], T8) gates
//! on [`super::tty::require_interactive_stdin`] up front, so a passphrase-protected identity can prompt
//! and a piped/scripted invocation fails closed (§3.1, plan-sanity F-8).
//!
//! This module is two layers:
//! - PURE PREFLIGHT (this file, T6): [`derive_line`] (derive-not-trust the pubkey via `ssh-keygen -y`)
//!   and [`content_gate`] (the strict whitelist over the box's current authorized_keys). Neither takes a
//!   [`super::lifecycle::BoxOps`] (plan-sanity I-2) — they are host-testable pure functions.
//! - THE STATE MACHINE (T7) + the CLI wiring (T8), which thread these over the transport.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::host_pins::HostPinOpts;
use super::lifecycle::{AUTHORIZED_KEYS_REMOTE_PATH, BoxOps, ProbeResult, SshBox};
use super::status::sanitize;

/// The box-side operator authorized_keys file (§3.2) — the rotate target (G1).
const TARGET: &str = AUTHORIZED_KEYS_REMOTE_PATH;
/// The SAME-DIRECTORY temp the CAS write stages before the atomic `mv` (same filesystem ⇒ `rename(2)` is
/// atomic; a dotfile so it never looks like an authorized_keys entry if a probe races it). PER-INVOCATION
/// UNIQUE (the PID suffix) so two concurrent `rotate-key` processes never share a temp and clobber each
/// other's staged bytes (audit MEDIUM-2 / INFO-2); within one process the append + cleanup reuse it
/// serially, which is correct.
fn temp_path() -> String {
    format!(
        "/persist/etc/ssh/authorized_keys.d/.rotate-key.{}.tmp",
        std::process::id()
    )
}

/// Why deriving the authorized_keys line from a private key failed.
#[derive(Debug)]
pub enum DeriveError {
    /// `ssh-keygen -y -f` rejected the file — it is not a usable private key (bad format), OR an
    /// encrypted key whose passphrase was wrong/absent. Either way: REFUSE, never a rotation. The string
    /// carries `ssh-keygen`'s own diagnosis so the operator sees which case it is (e.g. "incorrect
    /// passphrase" vs "invalid format").
    NotAPrivateKey(String),
    /// `ssh-keygen` could not be spawned (not installed / IO).
    Io(String),
}

impl std::fmt::Display for DeriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeriveError::NotAPrivateKey(m) => {
                write!(f, "could not derive a pubkey from the identity: {m}")
            }
            DeriveError::Io(m) => write!(f, "ssh-keygen could not be run: {m}"),
        }
    }
}

/// Derive the authorized_keys line from a private key via `ssh-keygen -y -f <identity>` — DERIVE, never
/// trust a separate `--pubkey` operand (§3.1; kills the pubkey/privkey-mixup + proves possession
                                                                                                  
///
/// The private key material never leaves the machine. We INHERIT the operator's tty as the child's stdin
/// so an ENCRYPTED identity's passphrase read lands on the TERMINAL (ssh-keygen's `read_passphrase` reads a
/// tty stdin with echo off): `Command::output()`'s default closed/non-tty stdin would, with `DISPLAY` set,
/// route the read to the GUI askpass helper instead (`!isatty(stdin) && DISPLAY` ⇒ askpass — audit
/// MEDIUM-1); stdout is captured (the derived pubkey line), stderr is captured for the error message. A
/// valid-but-encrypted key PROMPTS then succeeds; a non-key (or wrong passphrase) fails as
/// [`DeriveError::NotAPrivateKey`] (plan-sanity I-1, audit R1 F-3). The ceremony's interactive-only gate
/// (that a tty is present at all) is enforced up front in [`run`] (T8), not here — so this stays a pure,
/// unit-testable derivation for an unencrypted key.
pub fn derive_line(identity: &Path) -> Result<String, DeriveError> {
    let out = Command::new("ssh-keygen")
        .arg("-y")
        .arg("-f")
        .arg(identity)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| DeriveError::Io(format!("ssh-keygen -y -f: {e}")))?
        .wait_with_output()
        .map_err(|e| DeriveError::Io(format!("ssh-keygen -y -f: {e}")))?;
    if !out.status.success() {
        return Err(DeriveError::NotAPrivateKey(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !line.starts_with("ssh-") {
        return Err(DeriveError::NotAPrivateKey(format!(
            "ssh-keygen produced an unexpected line: {}",
            sanitize(line.as_bytes(), 256)
        )));
    }
    Ok(line)
}

/// The strict content-gate outcome over the box's current authorized_keys (§3.2 step 1).
#[derive(Debug, PartialEq, Eq)]
pub enum GateOutcome {
    /// The file is EXACTLY the current key → proceed with the append.
    Proceed,
    /// The file is EXACTLY the new key already → idempotent "already rotated", exit OK (§3.2 step-1 (a)).
    AlreadyRotated,
    /// The file is `current + new` (an interrupted prior run) → resume at the verify step (§3.2 (b)).
    ResumeAtVerify,
    /// ANYTHING else (extra keys, options/comments, empty) → REFUSE with the content shown. The tool never
    /// edits a file it does not FULLY recognize (whitelist-over-blacklist; surfacing beats silently
    /// deleting someone's third key). Carries the SANITIZED file content (§2.6).
    Refuse(String),
}

/// Classify the box's current authorized_keys against the expected `current`/`new` lines (§3.2 step 1).
/// STRICT whitelist: the file must be EXACTLY one of the three recognized shapes, else `Refuse`. Lines are
/// trimmed and blank lines ignored; anything with extra keys, ssh options, or comments is unrecognized.
pub fn content_gate(file: &str, current_line: &str, new_line: &str) -> GateOutcome {
    let lines: Vec<&str> = file
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let cur = current_line.trim();
    let new = new_line.trim();
    match lines.as_slice() {
        [only] if *only == cur => GateOutcome::Proceed,
        [only] if *only == new => GateOutcome::AlreadyRotated,
        [a, b] if *a == cur && *b == new => GateOutcome::ResumeAtVerify,
        _ => GateOutcome::Refuse(sanitize(file.as_bytes(), 4096)),
    }
}

                                                                                                                                                                  

/// Every terminal outcome of the rotation (§3.2), each mapped to a distinct process exit code. In EVERY
/// non-`Success` branch at least one key that is PROVEN to authenticate remains authorized — there is no
/// lockout by construction (§3.2 invariant).
#[derive(Debug, PartialEq, Eq)]
pub enum RotateOutcome {
    /// The old key is deauthorized, the new key authenticates, the file is exactly the new line.
    Success,
    /// The cleanup write landed but the OLD key still authenticates — never claim rotation done (§3.2 s4).
    CleanupIncomplete,
    /// The post-cleanup probe could not CONNECT (box rebooting/unreachable) — "couldn't check"; the
    /// on-disk state is the safe new line, but the tool did not confirm it (§3.2 s4).
    VerifyUnreachable,
    /// The step-3 new-key verify failed — BOTH keys remain authorized, re-run after diagnosing (§3.2 s3).
    VerifyFailed,
    /// A pre-write refusal (unrecognized file, a CAS drift, or a transport failure) — the target is
    /// UNTOUCHED, the current key still authenticates.
    Aborted(String),
    /// Post-cleanup, connected, both keys REFUSED (or a mid-mv cleanup failure) — a loud non-success; the
    /// on-disk state is the proven new line, but the new key did not authenticate (F-5A-R2-3).
    Anomaly(String),
}

impl RotateOutcome {
    /// The distinct process exit code (honest exits — a ceremony script branches without parsing prose).
    /// ABOVE clap's reserved usage-error 2 + the generic 1, so a mistyped invocation (clap exits 2) is
    /// never misread as a real VERIFY-FAILED.
    pub fn code(&self) -> i32 {
        match self {
            RotateOutcome::Success => 0,
            RotateOutcome::VerifyFailed => 10,
            RotateOutcome::CleanupIncomplete => 11,
            RotateOutcome::VerifyUnreachable => 12,
            RotateOutcome::Aborted(_) => 13,
            RotateOutcome::Anomaly(_) => 14,
        }
    }
    pub fn is_success(&self) -> bool {
        matches!(self, RotateOutcome::Success)
    }
}

/// The atomic CAS write primitive (§3.2/§3.4). Authenticates EVERY leg of this write as `edit_identity`
/// (the append uses the CURRENT key; the CLEANUP uses the NEW key — valid since the append authorized it,
/// and REQUIRED because the cleanup `mv` deauthorizes the old key, so a post-`mv` leg under the old key
/// would be dropbear-refused and silently no-op — audit LOW-1). Streams `content` to a PER-INVOCATION temp
/// created `0644 root:root` (bytes via STDIN, never argv), `sync`, re-`cat`s the target and re-asserts the
/// content gate (compare-and-swap — a drift aborts WITHOUT the `mv`, §3.2/S-2), the atomic same-dir `mv`
/// (the SOLE commit point), `sync`. EVERY exit status is CHECKED (never a swallowed non-zero). Returns Err
/// ONLY on a PRE-commit failure — the target is UNTOUCHED, the pre-write key still authenticates; a
/// post-`mv` durability-`sync` failure is NON-fatal (the rename already committed) and only warns.
fn cas_write(
    ops: &mut dyn BoxOps,
    content: &str,
    expect: GateOutcome,
    current_line: &str,
    new_line: &str,
    edit_identity: &Path,
) -> Result<(), String> {
    ops.set_login_identity(edit_identity);
    let temp = temp_path();

                                                                                                          
                                                                                       
                                                                                                              
                                                                                                         
                                                               
    let clean = |b: &str| sanitize(b.as_bytes(), 512);
    let write_cmd = format!("cat > {temp} && chmod 0644 {temp}");
    match ops.run_stdin(&write_cmd, content.as_bytes())? {
        (true, _) => {}
        (false, e) => {
            return Err(format!(
                "writing the temp authorized_keys failed: {}",
                clean(&e)
            ));
        }
    }
    match ops.run("sync")? {
        (true, _) => {}
        (false, e) => return Err(format!("pre-mv sync failed: {}", clean(&e))),
    }

                                                                                                           
                                                                  
    let (cat_ok, current) = ops.run(&format!("cat {TARGET}"))?;
    if !cat_ok {
        return Err(format!(
            "re-reading {TARGET} for the compare-and-swap failed: {}",
            clean(&current)
        ));
    }
    if content_gate(&current, current_line, new_line) != expect {
        return Err(format!(
            "{TARGET} drifted since preflight (a concurrent edit?) — aborting WITHOUT writing; the \
             current key still authenticates"
        ));
    }

                                                            
    match ops.run(&format!("mv {temp} {TARGET}"))? {
        (true, _) => {}
        (false, e) => {
            return Err(format!(
                "atomic mv onto {TARGET} failed: {} (target untouched, current key works)",
                clean(&e)
            ));
        }
    }

                                                                                                   
                                                                                                        
                                                                                                          
    match ops.run("sync")? {
        (true, _) => {}
        (false, e) => eprintln!(
            "orchard rotate-key: warning — the post-write durability sync did not run ({}); the rename \
             committed atomically, so a crash reverts to a prior valid state (no lockout).",
            clean(&e)
        ),
    }
    Ok(())
}

/// Classify the two step-4 final probes (old, new) by the §3.2 precedence (F-5A-R2-3) — the FIRST match
/// wins, so the mixed cases resolve unambiguously and a couldn't-check is NEVER a false SUCCESS.
fn classify_final(old: ProbeResult, new: ProbeResult) -> RotateOutcome {
                                                                                                
    if old == ProbeResult::CouldNotConnect || new == ProbeResult::CouldNotConnect {
        return RotateOutcome::VerifyUnreachable;
    }
                                                                                             
    if old == ProbeResult::Authenticated {
        return RotateOutcome::CleanupIncomplete;
    }
                                                         
    if old == ProbeResult::Refused && new == ProbeResult::Authenticated {
        return RotateOutcome::Success;
    }
                                                                                                   
    RotateOutcome::Anomaly(format!(
        "post-cleanup probes were old={old:?}, new={new:?}: the new key did NOT authenticate after a \
         completed cleanup write. The on-disk state is the new key only, but the tool cannot confirm it \
         works — inspect the box over your existing session before relying on the new key."
    ))
}

/// The never-locked-out state machine (§3.2 steps 1-4). Owns the initial `cat` + content gate (its
/// signature carries no start-phase, so it dispatches internally): `Proceed` runs append→verify→cleanup;
/// `ResumeAtVerify` (an interrupted prior run left both keys) skips the append; `AlreadyRotated` is an
/// idempotent no-op success; `Refuse` aborts untouched. `old_identity` is the CURRENT login key
/// (`--ssh-identity`): it authenticates the step-1 read + the append edits + the step-4 old-key probe.
/// `new_identity` (`--new-identity`) authenticates the step-3 verify probe, the CLEANUP edits (after the
/// append authorizes it — audit LOW-1), and the step-4 new-key probe. Each session offers EXACTLY its
/// key (§3.4 I-3).
pub fn run_state_machine(
    ops: &mut dyn BoxOps,
    current_line: &str,
    new_line: &str,
    new_identity: &Path,
    old_identity: &Path,
) -> RotateOutcome {
                                                                                                          
                                                                                                   
    if current_line.trim() == new_line.trim() {
        return RotateOutcome::Aborted(
            "the new key equals the current key — nothing to rotate".to_string(),
        );
    }

                                                                                     
    ops.set_login_identity(old_identity);
    let file = match ops.run(&format!("cat {TARGET}")) {
        Ok((true, f)) => f,
        Ok((false, _)) => {
            return RotateOutcome::Aborted(format!(
                "cannot read {TARGET} on the box (is the operator login authorized_keys present?)"
            ));
        }
        Err(e) => return RotateOutcome::Aborted(format!("reading {TARGET}: {e}")),
    };
    match content_gate(&file, current_line, new_line) {
        GateOutcome::Refuse(content) => {
            return RotateOutcome::Aborted(format!(
                "the box's authorized_keys is not a shape rotate-key recognizes — refusing to edit it \
                 (surfacing beats silently deleting a key you did not expect). Current content:\n{content}"
            ));
        }
                                                                                                   
                                                                                                             
                                                                                                             
                                                                                                           
                                                                                                           
                                                                               
        GateOutcome::AlreadyRotated => return RotateOutcome::Success,
                                                                                                  
        GateOutcome::ResumeAtVerify => {}
                                                                                                           
                                 
        GateOutcome::Proceed => {
            let both = format!("{}\n{}\n", current_line.trim(), new_line.trim());
            if let Err(e) = cas_write(
                ops,
                &both,
                GateOutcome::Proceed,
                current_line,
                new_line,
                old_identity,
            ) {
                return RotateOutcome::Aborted(e);
            }
        }
    }

                                                                                                        
                                                                                             
    match ops.auth_probe(new_identity) {
        ProbeResult::Authenticated => {}
        ProbeResult::Refused | ProbeResult::CouldNotConnect => return RotateOutcome::VerifyFailed,
    }

                                                                                                             
                                                                                                         
    let new_only = format!("{}\n", new_line.trim());
    if let Err(e) = cas_write(
        ops,
        &new_only,
        GateOutcome::ResumeAtVerify,
        current_line,
        new_line,
        new_identity,
    ) {
        return RotateOutcome::Aborted(e);
    }

                                                                                       
    let old = ops.auth_probe(old_identity);
    let new = ops.auth_probe(new_identity);
    classify_final(old, new)
}

                                                                                                                                                                                                                                                                  

/// The resolved `orchard rotate-key` inputs (main.rs builds this from the clap variant + the host-pin /
/// tty resolution).
pub struct RotateKeyArgs {
    pub host: String,
    pub port: u16,
    /// The NEW login private key — its pubkey is DERIVED (`ssh-keygen -y`), never a `--pubkey` operand.
    pub new_identity: PathBuf,
    /// The CURRENT login private key (`--ssh-identity`) — de-facto REQUIRED (I-6): authenticates the edit
    /// legs AND derives `current_line` for the step-1 gate.
    pub ssh_identity: PathBuf,
    pub host_fingerprint: Option<String>,
    pub pin_dir: PathBuf,
    pub is_tty: bool,
}

/// Derive both authorized lines (REFUSE a non-key `--new-identity`/`--ssh-identity` LOCALLY, before any
/// connection) + the no-op guard. Pure over the two key files — no `BoxOps`, no network (I-2).
fn preflight_lines(ssh_identity: &Path, new_identity: &Path) -> Result<(String, String), String> {
                                                                                                          
    let new_line = derive_line(new_identity).map_err(|e| format!("--new-identity: {e}"))?;
    let current_line = derive_line(ssh_identity).map_err(|e| format!("--ssh-identity: {e}"))?;
    if current_line.trim() == new_line.trim() {
        return Err(
            "--new-identity derives the SAME key as --ssh-identity — nothing to rotate".to_string(),
        );
    }
    Ok((current_line, new_line))
}

/// The operator-facing report (§3.2 step 5): the honest headline + the two STANDING reminders (the baked
/// recovery key is untouched; the restore-from interaction). Pure — returns the text the caller prints.
fn report(outcome: &RotateOutcome) -> String {
    let headline = match outcome {
        RotateOutcome::Success => {
            "SUCCESS — the new key authenticates and the old key is deauthorized.".to_string()
        }
        RotateOutcome::CleanupIncomplete => "CLEANUP-INCOMPLETE — the OLD key still authenticates; \
             the rotation did NOT complete. Edit the file over your existing session to remove it."
            .to_string(),
        RotateOutcome::VerifyUnreachable => "VERIFY-UNREACHABLE — the box could not be re-probed after \
             the cleanup write; the on-disk state is the new key, but the tool did not confirm it. \
             Re-run `orchard status`/`rotate-key` once reachable."
            .to_string(),
        RotateOutcome::VerifyFailed => "VERIFY-FAILED — the new key did NOT authenticate; BOTH keys \
             remain authorized (no lockout). Re-run after diagnosing (manual cleanup: edit the file \
             over your existing session)."
            .to_string(),
        RotateOutcome::Aborted(m) => format!("ABORTED — {m}"),
        RotateOutcome::Anomaly(m) => format!("ANOMALY — {m}"),
    };
    let mut s = format!("orchard rotate-key: {headline}\n\nReminders:\n");
    s.push_str(
        "  - The baked-in RECOVERY key is untouched by this verb; rotating it = an image rebake \
         (runbook: Key rotation).\n",
    );
    s.push_str(
        "  - After any `orchard prod --restore-from` takeover, re-run `rotate-key` if the intended login \
         state differs: the restore authorizes the operator pubkey the ceremony STAGES \
         (`restore-image --operator-pubkey`), and a pre-rotation backup's `/persist/etc` may re-introduce \
         pre-rotation key state.\n",
    );
    s
}

/// `orchard rotate-key` (§3.1). INTERACTIVE-ONLY (F-8): the up-front `require_interactive_stdin` gate fails
/// closed on a piped/scripted run (so a passphrase-protected identity can prompt). Derive-not-trust +
/// no-op guard BEFORE any connection; resolve the host pin FIRST; then the never-locked-out state machine.
pub fn run(args: &RotateKeyArgs) -> RotateOutcome {
                                                                                                     
    if let Err(e) = super::tty::require_interactive_stdin() {
        eprintln!("orchard rotate-key: {e}");
        return RotateOutcome::Aborted(e.to_string());
    }
    let (current_line, new_line) = match preflight_lines(&args.ssh_identity, &args.new_identity) {
        Ok(lines) => lines,
        Err(e) => {
            eprintln!("orchard rotate-key: {e}");
            return RotateOutcome::Aborted(e);
        }
    };
    let host_pin = HostPinOpts {
        host_fingerprint: args.host_fingerprint.as_deref(),
        is_tty: args.is_tty,
        pin_dir: &args.pin_dir,
    };
    let mut ops = match SshBox::connect(&args.host, args.port, &args.ssh_identity, host_pin) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("orchard rotate-key: {e}");
            return RotateOutcome::Aborted(e.to_string());
        }
    };
    let outcome = run_state_machine(
        &mut ops,
        &current_line,
        &new_line,
        &args.new_identity,
        &args.ssh_identity,
    );
    print!("{}", report(&outcome));
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_line_matches_ssh_keygen_and_refuses_non_keys() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
                                                                                                     
        let keygen = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", ""])
            .arg("-f")
            .arg(&key)
            .output()
            .unwrap();
        assert!(
            keygen.status.success(),
            "ssh-keygen keygen: {}",
            String::from_utf8_lossy(&keygen.stderr)
        );

        let line = derive_line(&key).expect("derive an unencrypted key");
        assert!(line.starts_with("ssh-ed25519 "), "{line}");
                                                                                                  
        let direct = Command::new("ssh-keygen")
            .args(["-y", "-f"])
            .arg(&key)
            .output()
            .unwrap();
        assert_eq!(line, String::from_utf8_lossy(&direct.stdout).trim());

                                                                   
        let notkey = dir.path().join("notkey");
        std::fs::write(&notkey, b"this is not a private key\n").unwrap();
        assert!(matches!(
            derive_line(&notkey),
            Err(DeriveError::NotAPrivateKey(_))
        ));
    }

    #[test]
    fn content_gate_covers_the_four_branches() {
        let cur = "ssh-ed25519 AAAACURRENT operator@host";
        let new = "ssh-ed25519 AAAANEW operator@host";

                                               
        assert_eq!(
            content_gate(&format!("{cur}\n"), cur, new),
            GateOutcome::Proceed
        );
                                                            
        assert_eq!(
            content_gate(&format!("{new}\n"), cur, new),
            GateOutcome::AlreadyRotated
        );
                                                                    
        assert_eq!(
            content_gate(&format!("{cur}\n{new}\n"), cur, new),
            GateOutcome::ResumeAtVerify
        );
                                                                           
        let third = "ssh-ed25519 AAAATHIRD other@host";
        assert!(matches!(
            content_gate(&format!("{cur}\n{third}\n"), cur, new),
            GateOutcome::Refuse(_)
        ));
                                                                                      
        assert!(matches!(
            content_gate(&format!("no-pty {cur}\n"), cur, new),
            GateOutcome::Refuse(_)
        ));
                                                          
        assert!(matches!(content_gate("", cur, new), GateOutcome::Refuse(_)));
                                                                                          
        assert!(matches!(
            content_gate(&format!("{new}\n{cur}\n"), cur, new),
            GateOutcome::Refuse(_)
        ));
    }

                                                                                                                                                                 

    use crate::deploy::lifecycle::FakeBox;
    use std::path::PathBuf;

    const CUR: &str = "ssh-ed25519 AAAACURRENTKEY operator@host";
    const NEW: &str = "ssh-ed25519 AAAANEWKEYYYY operator@host";

    /// A FakeBox whose target file holds `target_lines`, with the old/new identities mapped to the
    /// current/new authorized lines so the DEFAULT auth_probe drives the natural (happy) flow.
    fn fixture(target_lines: &[&str]) -> (FakeBox, PathBuf, PathBuf) {
        let old_id = PathBuf::from("/keys/old");
        let new_id = PathBuf::from("/keys/new");
        let fb = FakeBox::new()
            .with_authorized(target_lines)
            .with_identity(&old_id, CUR)
            .with_identity(&new_id, NEW);
        (fb, old_id, new_id)
    }

    #[test]
    fn happy_path_rotates_to_new_only() {
                                                                                                                    
        let (mut fb, old_id, new_id) = fixture(&[CUR]);
        let out = run_state_machine(&mut fb, CUR, NEW, &new_id, &old_id);
        assert_eq!(out, RotateOutcome::Success);
        assert_eq!(
            fb.target_contents().unwrap().trim(),
            NEW,
            "the file is exactly the new line"
        );
        assert_eq!(fb.authorized_lines(), vec![NEW.to_string()]);
    }

    #[test]
    fn cas_miss_aborts_without_writing() {
                                                                                                              
        let (mut fb, old_id, new_id) = fixture(&[CUR]);
        let drifted = format!("{CUR}\nssh-ed25519 AAAATHIRDKEY other@host\n");
        fb.on_nth_cat = Some((TARGET.to_string(), 2, drifted.into_bytes()));
        let out = run_state_machine(&mut fb, CUR, NEW, &new_id, &old_id);
        assert!(matches!(out, RotateOutcome::Aborted(_)), "{out:?}");
                                                                                 
        assert_eq!(fb.target_contents().unwrap().trim(), CUR);
    }

    #[test]
    fn verify_failure_keeps_both_keys() {
                                                                                                            
        let (mut fb, old_id, new_id) = fixture(&[CUR]);
        fb.probe_script.push_back(ProbeResult::Refused);
        let out = run_state_machine(&mut fb, CUR, NEW, &new_id, &old_id);
        assert_eq!(out, RotateOutcome::VerifyFailed);
        let auth = fb.authorized_lines();
        assert!(
            auth.iter().any(|l| l == CUR),
            "old key still authorized (fail-safe)"
        );
        assert!(
            auth.iter().any(|l| l == NEW),
            "new key present (append landed)"
        );
        assert_eq!(auth.len(), 2, "cleanup did NOT run");
    }

    #[test]
    fn verify_unreachable_after_cleanup() {
                                                                                                      
        let (mut fb, old_id, new_id) = fixture(&[CUR]);
        fb.probe_script.extend([
            ProbeResult::Authenticated,
            ProbeResult::CouldNotConnect,
            ProbeResult::CouldNotConnect,
        ]);
        let out = run_state_machine(&mut fb, CUR, NEW, &new_id, &old_id);
        assert_eq!(out, RotateOutcome::VerifyUnreachable);
        assert_eq!(
            fb.target_contents().unwrap().trim(),
            NEW,
            "the safe new line is on disk"
        );
    }

    #[test]
    fn anomaly_when_new_key_refused_post_cleanup() {
                                                                                                                    
        let (mut fb, old_id, new_id) = fixture(&[CUR]);
        fb.probe_script.extend([
            ProbeResult::Authenticated,
            ProbeResult::Refused,
            ProbeResult::Refused,
        ]);
        let out = run_state_machine(&mut fb, CUR, NEW, &new_id, &old_id);
        assert!(matches!(out, RotateOutcome::Anomaly(_)), "{out:?}");
        assert_eq!(
            fb.target_contents().unwrap().trim(),
            NEW,
            "the proven new line is on disk"
        );
    }

    #[test]
    fn cleanup_incomplete_when_old_key_still_authenticates() {
                                                                                                                   
        let (mut fb, old_id, new_id) = fixture(&[CUR]);
        fb.probe_script.extend([
            ProbeResult::Authenticated,                 
            ProbeResult::Authenticated,                                             
            ProbeResult::Authenticated,                        
        ]);
        let out = run_state_machine(&mut fb, CUR, NEW, &new_id, &old_id);
        assert_eq!(out, RotateOutcome::CleanupIncomplete);
    }

    #[test]
    fn resume_from_both_keys_completes_to_new_only() {
                                                                                                              
                                               
        let (mut fb, old_id, new_id) = fixture(&[CUR, NEW]);
        let out = run_state_machine(&mut fb, CUR, NEW, &new_id, &old_id);
        assert_eq!(out, RotateOutcome::Success);
        assert_eq!(fb.target_contents().unwrap().trim(), NEW);
                                                                                                        
        let temp_writes = fb.writes.iter().filter(|w| w.starts_with("cat >")).count();
        let mvs = fb.writes.iter().filter(|w| w.starts_with("mv ")).count();
        assert_eq!(
            temp_writes, 1,
            "resume skips the append: only the cleanup write"
        );
        assert_eq!(mvs, 1, "resume skips the append: only the cleanup mv");
    }

    #[test]
    fn old_key_rerun_on_a_rotated_box_aborts_at_read_no_writes() {
                                                                                                              
                                                                                                           
                                                                                                            
                                                                                                                
        let (mut fb, old_id, new_id) = fixture(&[NEW]);
        let out = run_state_machine(&mut fb, CUR, NEW, &new_id, &old_id);
        assert!(
            matches!(out, RotateOutcome::Aborted(_)),
            "old-key re-run aborts at read: {out:?}"
        );
        assert!(
            fb.writes.is_empty(),
            "no writes on a refused read: {:?}",
            fb.writes
        );
                                                 
        assert_eq!(
            fb.auth_probe(&new_id),
            ProbeResult::Authenticated,
            "new key still works"
        );
    }

    #[test]
    fn unrecognized_content_aborts_without_editing() {
                                                                                                    
        let (mut fb, old_id, new_id) = fixture(&[CUR, "ssh-ed25519 AAAAROGUEKEY intruder@host"]);
        let out = run_state_machine(&mut fb, CUR, NEW, &new_id, &old_id);
        assert!(matches!(out, RotateOutcome::Aborted(_)), "{out:?}");
        assert!(fb.writes.is_empty(), "must not edit an unrecognized file");
    }

    #[test]
    fn outcome_exit_codes_are_distinct() {
        let codes = [
            RotateOutcome::Success.code(),
            RotateOutcome::VerifyFailed.code(),
            RotateOutcome::CleanupIncomplete.code(),
            RotateOutcome::VerifyUnreachable.code(),
            RotateOutcome::Aborted("x".to_string()).code(),
            RotateOutcome::Anomaly("x".to_string()).code(),
        ];
        let mut uniq = codes.to_vec();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(
            uniq.len(),
            codes.len(),
            "each outcome has a distinct exit code"
        );
        assert_eq!(RotateOutcome::Success.code(), 0);
    }

    #[test]
    fn classify_final_covers_all_nine_combos() {
                                                                                                      
        use ProbeResult::{Authenticated, CouldNotConnect, Refused};
                                                                                                   
        assert!(matches!(
            classify_final(Refused, Refused),
            RotateOutcome::Anomaly(_)
        ));
                                                          
        let cases = [
            (
                Authenticated,
                Authenticated,
                RotateOutcome::CleanupIncomplete,
            ),
            (Authenticated, Refused, RotateOutcome::CleanupIncomplete),
            (
                Authenticated,
                CouldNotConnect,
                RotateOutcome::VerifyUnreachable,
            ),
            (Refused, Authenticated, RotateOutcome::Success),
            (Refused, CouldNotConnect, RotateOutcome::VerifyUnreachable),
            (
                CouldNotConnect,
                Authenticated,
                RotateOutcome::VerifyUnreachable,
            ),
            (CouldNotConnect, Refused, RotateOutcome::VerifyUnreachable),
            (
                CouldNotConnect,
                CouldNotConnect,
                RotateOutcome::VerifyUnreachable,
            ),
        ];
        for (old, new, want) in cases {
            assert_eq!(classify_final(old, new), want, "({old:?}, {new:?})");
        }
    }

                                                                                                                                                                                                                                                                       

    #[test]
    fn preflight_refuses_a_non_key_new_identity_before_connecting() {
                                                                                                            
                                                                                                    
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("id");
        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", ""])
            .arg("-f")
            .arg(&good)
            .output()
            .unwrap();
        let notkey = dir.path().join("notkey");
        std::fs::write(&notkey, b"not a key\n").unwrap();

        assert!(
            preflight_lines(&good, &notkey).is_err(),
            "non-key --new-identity refused"
        );

        let good2 = dir.path().join("id2");
        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", ""])
            .arg("-f")
            .arg(&good2)
            .output()
            .unwrap();
        let (cur, new) = preflight_lines(&good, &good2).expect("valid pair derives both lines");
        assert!(cur.starts_with("ssh-ed25519 ") && new.starts_with("ssh-ed25519 "));
        assert_ne!(cur, new);

        assert!(
            preflight_lines(&good, &good).is_err(),
            "no-op (same key) refused"
        );
    }

    #[test]
    fn report_carries_the_outcome_and_the_two_reminders() {
                                                                                        
        let r = report(&RotateOutcome::Success);
        assert!(r.contains("SUCCESS"), "{r}");
        assert!(r.contains("RECOVERY key"), "recovery-key reminder: {r}");
        assert!(r.contains("--restore-from"), "restore-from reminder: {r}");
                                                                                                     
        let (mut fb, old_id, new_id) = fixture(&[CUR]);
        assert_eq!(
            run_state_machine(&mut fb, CUR, NEW, &new_id, &old_id),
            RotateOutcome::Success
        );
    }
}
