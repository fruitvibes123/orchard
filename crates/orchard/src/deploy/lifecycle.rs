//! The shared SSH transport seam for the Phase-5a lifecycle verbs (`orchard status` + `orchard
//! rotate-key`), behind a fakeable [`BoxOps`] trait so all verdict/state-machine logic is host-testable
//! without a live box.
//!
//! - [`SshBox`] — the real, per-invocation-pinned transport: [`SshBox::connect`] resolves the durable
//!   host pin ([`super::host_pins`]) ONCE, captures the box's host-key line into an ephemeral
//!   `known_hosts`, and holds it so EVERY later [`BoxOps::run`]/[`BoxOps::auth_probe`] rides the SAME
//!   pinned key (§3.4 MITM). Mirrors the `orchard update` ceremony's transport shape
//!   ([`super::update::SshUpdateOps`]) + reuses [`super::prod_orchestrate::prod_ssh_args`] so the
//!   hardened posture (`IdentitiesOnly=yes` + `StrictHostKeyChecking=yes` + `BatchMode=yes`, no ambient
//!   config) can't drift.
//! - [`FakeBox`] (`#[cfg(test)]`) — an in-memory box model the two verbs' unit batteries drive.
//!
//! `run`/`run_stdin` return `(exit_ok, captured_stdout)`; captured output is UNTRUSTED and the CALLER
//! sanitizes it (`status::sanitize`) before rendering. `auth_probe` returns the three-way
//! [`ProbeResult`] (auth verdict vs bare connectivity) the rotate-key step-4 precedence needs.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::host_pins::{self, HostPinOpts, PinError, PinOutcome};

/// The box-side operator login authorized_keys file (G1): a baked rootfs symlink
/// `/root/.ssh/authorized_keys` → this path, resolved by dropbear at auth time per connection. The
/// sole legitimate write channel (G2) — `rotate-key`'s target (its write primitive edits this exact
/// path), and `FakeBox`'s default authorization source.
pub(crate) const AUTHORIZED_KEYS_REMOTE_PATH: &str = "/persist/etc/ssh/authorized_keys.d/root";

/// The three-way outcome of an [`BoxOps::auth_probe`]: an authentication verdict is DISTINCT from bare
/// connectivity, so the rotate-key step-4 precedence (§3.2) can tell "the old key is deauthorized"
/// (`Refused`) apart from "the box is rebooting / unreachable" (`CouldNotConnect`) — never conflating a
/// couldn't-check into a false SUCCESS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    /// A session was established AND the offered identity authenticated (`true` ran, exit 0).
    Authenticated,
    /// A session reached the box's sshd, which REFUSED the offered key (publickey denied).
    Refused,
    /// No session was established (timeout, connection refused/reset, DNS, or an ambiguous failure) —
    /// auth was never attempted, so this is "couldn't check", never a verdict.
    CouldNotConnect,
}

/// The side effects the lifecycle verbs drive against the box, behind a trait so the verdict logic
/// (`status`) and the never-locked-out state machine (`rotate-key`) are `FakeBox`-testable. Object-safe
/// (`&mut dyn BoxOps`). All captured stdout is UNTRUSTED — the caller sanitizes before rendering.
pub trait BoxOps {
    /// Run a remote command with no stdin; return `(exit_ok, captured_stdout)`. A non-zero exit is
    /// `Ok((false, …))`, NOT `Err` — `Err` is reserved for a transport failure (spawn/IO).
    fn run(&mut self, remote_cmd: &str) -> Result<(bool, String), String>;
    /// Run a remote command feeding `stdin` to it (key/line bytes travel HERE, never in argv — §3.4);
    /// return `(exit_ok, captured_stdout)`.
    fn run_stdin(&mut self, remote_cmd: &str, stdin: &[u8]) -> Result<(bool, String), String>;
    /// Switch the identity that SUBSEQUENT `run`/`run_stdin` edit legs authenticate with (a fresh ssh
    /// session under a different `-i` key). `rotate-key`'s CLEANUP uses this to edit under the NEW key
    /// after the append: the cleanup `mv` deauthorizes the old key, so a post-`mv` edit leg (the durability
    /// `sync`) under the OLD key would be dropbear-REFUSED and silently no-op (audit LOW-1). `auth_probe`
    /// is UNAFFECTED — it always offers its own `identity` argument regardless of this setting.
    fn set_login_identity(&mut self, identity: &Path);
    /// Open a FRESH session offering EXACTLY `identity` (no agent/default-key fallback — §3.4 I-3, so a
    /// clean `Refused` is a real deauthorization) under the SAME host pin, and classify the outcome.
    fn auth_probe(&mut self, identity: &Path) -> ProbeResult;
}

/// Why [`SshBox::connect`] failed, typed so the caller maps it to the right honest exit (§2.5) — a
/// trust refusal (`PinMismatch`) is distinct from "couldn't reach the box" (`Unreachable`).
#[derive(Debug)]
pub enum ConnectError {
    /// The presented host key ≠ the stored pin, an explicit `--host-fingerprint` mismatch, or a
    /// non-interactive first contact with no fingerprint — a trust refusal (§2.5 PIN-MISMATCH), refused
                                        
    PinMismatch(String),
    /// The box could not be reached (keyscan/connection/IO failure) or the operator declined a
    /// first-contact host key.
    Unreachable(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::PinMismatch(m) | ConnectError::Unreachable(m) => f.write_str(m),
        }
    }
}

/// Map a NON-first-contact [`PinError`] to a [`ConnectError`]: a pin/trust refusal ⇒ `PinMismatch`
                                                                                            
fn pin_error_to_connect_error(e: PinError) -> ConnectError {
    match e {
        PinError::SilentOverrideRefused { .. }
        | PinError::FingerprintMismatch { .. }
        | PinError::NoPinNonInteractive { .. } => ConnectError::PinMismatch(e.to_string()),
        other => ConnectError::Unreachable(other.to_string()),
    }
}

/// The real ssh-backed transport (the produced-bytes boundary — exercised by `make
/// boot-gate-lifecycle`, not the unit batteries). Host-key trust is resolved ONCE at [`connect`] and
/// pinned into `known_hosts` for the session's whole life.
///
/// [`connect`]: SshBox::connect
pub struct SshBox {
    host: String,
    port: u16,
    /// The operator's CURRENT login identity (authenticates every edit/read leg). `auth_probe` overrides
    /// it per-call to probe a DIFFERENT candidate key.
    login_identity: PathBuf,
    /// The ephemeral `known_hosts` holding the box's pinned host-key line — held for the session so
    /// every leg rides the same pin, and so the tempfile is not reaped mid-session.
    known_hosts: tempfile::NamedTempFile,
}

impl SshBox {
    /// Resolve the durable host pin ONCE (non-silent first contact; a key CHANGE is refused), capture the
    /// box's host-key line into an ephemeral `known_hosts`, and return a session-scoped transport. The
    /// pin resolve is the ONLY operator-side write (an interactive first-contact `commit_pin`); a
    /// [`PinError::SilentOverrideRefused`] (or any other pin error) is surfaced verbatim so the caller
                                                                         
    pub fn connect(
        host: &str,
        port: u16,
        ssh_identity: &Path,
        host_pin: HostPinOpts<'_>,
    ) -> Result<SshBox, ConnectError> {
        let (line, presented) =
            scan_and_fingerprint(host, port).map_err(ConnectError::Unreachable)?;
        match host_pins::resolve_host_pin(host, &presented, &host_pin) {
            Ok(PinOutcome::Stable(_)) | Ok(PinOutcome::Bootstrapped(_)) => {}
            Err(PinError::FirstContactNeedsConfirm { presented, .. }) => {
                                                                                                      
                                                                                                    
                if !confirm_first_contact(host, &presented).map_err(ConnectError::Unreachable)? {
                    return Err(ConnectError::Unreachable(
                        "operator declined to trust the box's host key — aborted".to_string(),
                    ));
                }
                host_pins::commit_pin(host, &presented, &host_pin)
                    .map_err(|e| ConnectError::Unreachable(e.to_string()))?;
            }
            Err(e) => return Err(pin_error_to_connect_error(e)),
        }

        let mut kh = tempfile::NamedTempFile::new()
            .map_err(|e| ConnectError::Unreachable(format!("known_hosts temp: {e}")))?;
        {
            use std::io::Write as _;
            writeln!(kh, "{}", line.trim())
                .map_err(|e| ConnectError::Unreachable(format!("write known_hosts: {e}")))?;
        }
        Ok(SshBox {
            host: host.to_string(),
            port,
            login_identity: ssh_identity.to_path_buf(),
            known_hosts: kh,
        })
    }

    /// The hardened ssh argv (pinned known_hosts, `IdentitiesOnly`, `BatchMode`, no ambient config) for
    /// `identity` + the trailing remote command — via the shared [`prod_ssh_args`] builder so the
    /// security posture matches the prod/update transports.
    ///
    /// [`prod_ssh_args`]: super::prod_orchestrate::prod_ssh_args
    fn ssh_command(&self, identity: &Path, remote: &str) -> Command {
        let mut args = super::prod_orchestrate::prod_ssh_args(
            &self.host,
            identity,
            self.known_hosts.path(),
            self.port,
        );
        args.push(remote.to_string());
        let mut cmd = Command::new("ssh");
        cmd.args(args);
        cmd
    }
}

/// §2.6 capture cap: the MOST any single box command's stdout is read into operator memory. Applied AT
/// READ TIME (not just at render) so a compromised box cannot exhaust the operator's tool by flooding a
/// response. Generous for the real §4g block / cmdline / anchor; the per-command render caps in `status`
/// are tighter still.
const SSH_CAPTURE_CAP: usize = 1024 * 1024;

/// Read up to `cap` bytes from `r`; return the (≤ `cap`) bytes + whether MORE was available (overflow).
fn read_capped(r: impl std::io::Read, cap: usize) -> std::io::Result<(Vec<u8>, bool)> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    let n = r.take((cap as u64) + 1).read_to_end(&mut buf)?;
    let overflow = n > cap;
    buf.truncate(cap);
    Ok((buf, overflow))
}

/// Drive a spawned ssh child that has already had its stdin closed: bounded-read stdout (§2.6) — on
/// overflow KILL the child + refuse; else return the real exit status + the captured stdout. `stderr` is
/// discarded to `/dev/null` upstream so it can neither fill a pipe (hanging the wait) nor reach the
/// operator terminal unsanitized.
fn drive_capped(
    mut child: std::process::Child,
    remote_cmd: &str,
) -> Result<(bool, String), String> {
    let stdout = child.stdout.take().ok_or("no ssh stdout")?;
    let (buf, overflow) = read_capped(stdout, SSH_CAPTURE_CAP)
        .map_err(|e| format!("read ssh stdout for {remote_cmd:?}: {e}"))?;
    if overflow {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "the box returned > {SSH_CAPTURE_CAP} bytes for {remote_cmd:?} — refusing (a compromised box \
             must not exhaust the operator's memory)"
        ));
    }
    let status = child
        .wait()
        .map_err(|e| format!("wait ssh {remote_cmd:?}: {e}"))?;
    Ok((status.success(), String::from_utf8_lossy(&buf).into_owned()))
}

impl BoxOps for SshBox {
    fn run(&mut self, remote_cmd: &str) -> Result<(bool, String), String> {
        let id = self.login_identity.clone();
        let child = self
            .ssh_command(&id, remote_cmd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn ssh {remote_cmd:?}: {e}"))?;
        drive_capped(child, remote_cmd)
    }

    fn run_stdin(&mut self, remote_cmd: &str, stdin: &[u8]) -> Result<(bool, String), String> {
        let id = self.login_identity.clone();
        let mut child = self
            .ssh_command(&id, remote_cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn ssh {remote_cmd:?}: {e}"))?;
        {
            use std::io::Write as _;
            let mut si = child.stdin.take().ok_or("no ssh stdin")?;
            si.write_all(stdin)
                .map_err(|e| format!("stream stdin to {remote_cmd:?}: {e}"))?;
                                                                
        }
        drive_capped(child, remote_cmd)
    }

    fn set_login_identity(&mut self, identity: &Path) {
                                                                                                    
                                                                                   
        self.login_identity = identity.to_path_buf();
    }

    fn auth_probe(&mut self, identity: &Path) -> ProbeResult {
                                                                                                         
                                                
        let mut child = match self
            .ssh_command(identity, "true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return ProbeResult::CouldNotConnect,
        };
        let Some(stderr) = child.stderr.take() else {
            return ProbeResult::CouldNotConnect;
        };
        let (err_bytes, _overflow) = read_capped(stderr, 64 * 1024).unwrap_or_default();
        let status = match child.wait() {
            Ok(s) => s,
            Err(_) => return ProbeResult::CouldNotConnect,
        };
        if status.success() {
            return ProbeResult::Authenticated;
        }
        let err = String::from_utf8_lossy(&err_bytes);
                                                                                           
                                                                                                           
                                                                                                          
                                                                          
        if err.contains("Permission denied") || err.contains("publickey") {
            ProbeResult::Refused
        } else {
            ProbeResult::CouldNotConnect
        }
    }
}

/// ssh-keyscan the box's ed25519 host key → `(known_hosts line, SHA256:… fingerprint)`. The line pins
/// `known_hosts`; the fingerprint drives the [`host_pins`] trust decision. Mirrors
/// [`super::update::SshUpdateOps::host_fingerprint`].
fn scan_and_fingerprint(host: &str, port: u16) -> Result<(String, String), String> {
    let out = Command::new("ssh-keyscan")
        .args(["-t", "ed25519", "-p", &port.to_string(), host])
        .output()
        .map_err(|e| format!("ssh-keyscan: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .find(|l| l.contains("ssh-ed25519") && !l.trim_start().starts_with('#'))
        .ok_or("ssh-keyscan returned no ed25519 host key")?
        .to_string();
    let mut f = tempfile::NamedTempFile::new().map_err(|e| format!("keyscan temp: {e}"))?;
    {
        use std::io::Write as _;
        writeln!(f, "{}", line.trim()).map_err(|e| format!("write keyscan: {e}"))?;
    }
    let fpr_out = Command::new("ssh-keygen")
        .args(["-lf", &f.path().display().to_string()])
        .output()
        .map_err(|e| format!("ssh-keygen -lf: {e}"))?;
    let fpr = String::from_utf8_lossy(&fpr_out.stdout)
        .split_whitespace()
        .find(|t| t.starts_with("SHA256:"))
        .map(str::to_string)
        .ok_or("ssh-keygen produced no SHA256 fingerprint")?;
    Ok((line, fpr))
}

/// Prompt the operator to trust a first-contact host key (y/N on stderr/stdin). Reached only on an
/// interactive tty (host_pins gates `FirstContactNeedsConfirm` on `is_tty`).
fn confirm_first_contact(host: &str, presented: &str) -> Result<bool, String> {
    eprint!(
        "FIRST CONTACT with {host}: trust the presented SSH host key {presented}? (this pins it) [y/N] "
    );
    use std::io::Write as _;
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("read host-key confirm: {e}"))?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

                                                                                                                                                                                      
#[cfg(test)]
use std::collections::{HashMap, VecDeque};

/// An in-memory box the lifecycle verbs' unit tests drive. Models the box filesystem (`files`), the
/// authorized_keys file as the SINGLE source of truth for authorization (an `mv` onto the target
/// updates who authenticates — no separate field to desync), a `reachable` toggle, and a `writes` log
                                                                                                 
/// battery force the safety-critical branches (plan-sanity M2): `probe_script` drives `auth_probe`
/// outcomes independent of `authorized`, and `on_nth_cat` drives the CAS-miss (the target drifts
/// between the step-1 `cat` and the pre-`mv` re-`cat`).
#[cfg(test)]
pub(crate) struct FakeBox {
    pub files: HashMap<String, Vec<u8>>,
    pub auth_keys_path: String,
    pub reachable: bool,
    pub fb_update_present: bool,
    pub fb_update_block: String,
    /// Every MUTATING command (`run_stdin` temp write + `mv`) is logged here; reads are NOT — so an
                                                                   
    pub writes: Vec<String>,
    /// Identity path → its derived authorized_keys line (the test supplies the association so `auth_probe`
    /// needn't shell `ssh-keygen`).
    pub identity_lines: HashMap<PathBuf, String>,
    /// Forced `auth_probe` results, popped per call (M2-i): drives VerifyFailed / the F-5A-R2-3 Anomaly
    /// independent of `authorized`.
    pub probe_script: VecDeque<ProbeResult>,
    /// `(path, n, bytes)` — the Nth `cat` of `path` returns `bytes` instead of the file (M2-ii): drives
    /// the CAS-miss.
    pub on_nth_cat: Option<(String, usize, Vec<u8>)>,
    /// The identity whose derived line must be authorized for a `run`/`run_stdin` leg to succeed — models
    /// dropbear's per-connection pubkey auth (audit LOW-2). `None` (the `status` flow) ⇒ unmodeled (a leg
    /// always "connects"); `set_login_identity` sets it for the rotate-key flow.
    edit_identity: Option<PathBuf>,
    cat_counts: HashMap<String, usize>,
}

#[cfg(test)]
impl FakeBox {
    pub fn new() -> Self {
        FakeBox {
            files: HashMap::new(),
            auth_keys_path: AUTHORIZED_KEYS_REMOTE_PATH.to_string(),
            reachable: true,
            fb_update_present: true,
            fb_update_block: String::new(),
            writes: Vec::new(),
            identity_lines: HashMap::new(),
            probe_script: VecDeque::new(),
            on_nth_cat: None,
            edit_identity: None,
            cat_counts: HashMap::new(),
        }
    }
    pub fn with_file(mut self, path: &str, bytes: &[u8]) -> Self {
        self.files.insert(path.to_string(), bytes.to_vec());
        self
    }
    /// Seed the authorized_keys target file from the given lines (trailing-LF, one per line).
    pub fn with_authorized(mut self, lines: &[&str]) -> Self {
        let content = if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        };
        self.files
            .insert(self.auth_keys_path.clone(), content.into_bytes());
        self
    }
    pub fn with_identity(mut self, path: &Path, line: &str) -> Self {
        self.identity_lines
            .insert(path.to_path_buf(), line.to_string());
        self
    }
    /// Model a box whose `fb-update status` succeeds and returns `block` (the §4g wire).
    pub fn with_fb_status(mut self, block: &str) -> Self {
        self.fb_update_present = true;
        self.fb_update_block = block.to_string();
        self
    }
    /// Model a pre-A/B box: `fb-update status` fails not-found (degrade mode, G9).
    pub fn without_fb_update(mut self) -> Self {
        self.fb_update_present = false;
        self
    }
    /// The authorized_keys lines currently on the box (parsed from the target file — the single source of
    /// truth, so an `mv` onto the target updates authorization with no separate field to desync).
    pub fn authorized_lines(&self) -> Vec<String> {
        self.files
            .get(&self.auth_keys_path)
            .map(|b| {
                String::from_utf8_lossy(b)
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }
    /// The raw target-file contents (for asserting the exact post-rotation on-disk state).
    pub fn target_contents(&self) -> Option<String> {
        self.files
            .get(&self.auth_keys_path)
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }
    /// Model dropbear's per-connection pubkey auth (LOW-2): the current edit identity's derived line must
    /// be present in the target file for a `run`/`run_stdin` leg to connect. `None` ⇒ unmodeled (status).
    fn edit_authorized(&self) -> bool {
        match &self.edit_identity {
            None => true,
            Some(id) => match self.identity_lines.get(id) {
                Some(line) => self.authorized_lines().iter().any(|l| l == line),
                None => false,
            },
        }
    }
}

#[cfg(test)]
impl BoxOps for FakeBox {
    fn run(&mut self, remote_cmd: &str) -> Result<(bool, String), String> {
                                                                                                           
                                                                                           
        if !self.edit_authorized() {
            return Ok((false, "dropbear: Permission denied (publickey)".to_string()));
        }
        let cmd = remote_cmd.trim();
        if cmd == "fb-update status" {
            return if self.fb_update_present {
                Ok((true, self.fb_update_block.clone()))
            } else {
                Ok((false, "sh: fb-update: not found".to_string()))
            };
        }
        if let Some(path) = cmd.strip_prefix("cat ") {
            let path = path.trim();
            let n = self.cat_counts.entry(path.to_string()).or_insert(0);
            *n += 1;
            let this_n = *n;
            if let Some((hp, hn, hb)) = &self.on_nth_cat
                && hp == path
                && *hn == this_n
            {
                return Ok((true, String::from_utf8_lossy(hb).into_owned()));
            }
            return match self.files.get(path) {
                Some(b) => Ok((true, String::from_utf8_lossy(b).into_owned())),
                None => Ok((false, String::new())),                                          
            };
        }
        if cmd == "sync" {
            return Ok((true, String::new()));
        }
        if let Some(rest) = cmd.strip_prefix("mv ") {
            let mut parts = rest.split_whitespace();
            let src = parts.next().ok_or("FakeBox: mv missing src")?.to_string();
            let dst = parts.next().ok_or("FakeBox: mv missing dst")?.to_string();
            self.writes.push(cmd.to_string());
            return match self.files.remove(&src) {
                Some(b) => {
                    self.files.insert(dst, b);
                    Ok((true, String::new()))
                }
                None => Ok((false, format!("mv: {src}: No such file"))),
            };
        }
        if let Some(_rest) = cmd.strip_prefix("chmod ") {
                                                                                                        
                                                                                                 
            return Ok((true, String::new()));
        }
        panic!("FakeBox: unmodeled remote command {remote_cmd:?}");
    }

    fn run_stdin(&mut self, remote_cmd: &str, stdin: &[u8]) -> Result<(bool, String), String> {
        if !self.edit_authorized() {
            return Ok((false, "dropbear: Permission denied (publickey)".to_string()));
        }
                                                                                                          
                                                                                                         
                           
        let target = remote_cmd
            .rsplit('>')
            .next()
            .and_then(|t| t.split_whitespace().next())
            .map(|t| t.trim_matches(|c| c == '\'' || c == '"'))
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                format!("FakeBox: run_stdin command has no `> <path>` redirect: {remote_cmd:?}")
            })?
            .to_string();
        self.writes.push(remote_cmd.to_string());
        self.files.insert(target, stdin.to_vec());
        Ok((true, String::new()))
    }

    fn set_login_identity(&mut self, identity: &Path) {
        self.edit_identity = Some(identity.to_path_buf());
    }

    fn auth_probe(&mut self, identity: &Path) -> ProbeResult {
        if let Some(forced) = self.probe_script.pop_front() {
            return forced;
        }
        if !self.reachable {
            return ProbeResult::CouldNotConnect;
        }
        match self.identity_lines.get(identity) {
            Some(line) if self.authorized_lines().iter().any(|l| l == line) => {
                ProbeResult::Authenticated
            }
            _ => ProbeResult::Refused,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn fakebox_roundtrips_and_models_auth() {
        let cur_id = PathBuf::from("/keys/current");
        let current_line = "ssh-ed25519 AAAACURRENT operator@host";
        let mut fake = FakeBox::new()
            .with_file("/etc/recipes/artifact-root.pub", b"abcddeadbeef")
            .with_authorized(&[current_line])
            .with_identity(&cur_id, current_line);

                                                               
        let (ok, out) = fake.run("cat /etc/recipes/artifact-root.pub").unwrap();
        assert!(ok);
        assert_eq!(out, "abcddeadbeef");

                                                                                          
        let (ok, _) = fake.run("cat /nope").unwrap();
        assert!(!ok);

                                                                                             
        assert_eq!(fake.auth_probe(&cur_id), ProbeResult::Authenticated);

                                                                                              
        let unknown = PathBuf::from("/keys/unknown");
        assert_eq!(fake.auth_probe(&unknown), ProbeResult::Refused);

                                                                                            
        fake.reachable = false;
        assert_eq!(fake.auth_probe(&cur_id), ProbeResult::CouldNotConnect);
    }

    #[test]
    fn pin_errors_map_to_the_right_connect_exit() {
                                                                                                          
        let refused = PinError::SilentOverrideRefused {
            host: "box".into(),
            stored: "SHA256:a".into(),
            presented: "SHA256:b".into(),
            pin_path: "/p".into(),
        };
        assert!(matches!(
            pin_error_to_connect_error(refused),
            ConnectError::PinMismatch(_)
        ));
        assert!(matches!(
            pin_error_to_connect_error(PinError::NoPinNonInteractive { host: "box".into() }),
            ConnectError::PinMismatch(_)
        ));
        assert!(matches!(
            pin_error_to_connect_error(PinError::FingerprintMismatch {
                host: "b".into(),
                expected: "x".into(),
                presented: "y".into()
            }),
            ConnectError::PinMismatch(_)
        ));
                                                                 
        assert!(matches!(
            pin_error_to_connect_error(PinError::Io {
                path: "/p".into(),
                source: std::io::Error::other("x")
            }),
            ConnectError::Unreachable(_)
        ));
    }

    #[test]
    fn fakebox_models_per_connection_auth() {
                                                                                                        
                                                                                                       
                                                            
        let old_id = PathBuf::from("/keys/old");
        let new_id = PathBuf::from("/keys/new");
        let old_line = "ssh-ed25519 AAAAOLD op@h";
        let new_line = "ssh-ed25519 AAAANEW op@h";
        let mut fake = FakeBox::new()
            .with_authorized(&[new_line])
            .with_identity(&old_id, old_line)
            .with_identity(&new_id, new_line);

                                                  
        fake.set_login_identity(&old_id);
        let (ok, msg) = fake.run("sync").unwrap();
        assert!(
            !ok && msg.contains("Permission denied"),
            "old key refused: {msg}"
        );

                                                                                 
        fake.files.insert("/tmp/x".to_string(), b"staged".to_vec());
        let target = fake.auth_keys_path.clone();
        let (ok, _) = fake.run(&format!("mv /tmp/x {target}")).unwrap();
        assert!(!ok, "refused mv");
        assert!(
            fake.files.contains_key("/tmp/x"),
            "refused mv did not move the file"
        );

                                
        fake.set_login_identity(&new_id);
        assert!(fake.run("sync").unwrap().0, "new key authenticates");
    }
}
