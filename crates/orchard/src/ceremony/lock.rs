                                                                                            
//! every writing verb — runner-driven or direct — holds the host lock; a concurrent second
//! writing invocation REFUSES naming the holder; READ-ONLY verbs never acquire or block (their
//! torn-read cost is T7's disclosed residual: they print one advisory line when the lock is
//! held).
//!
//! Mechanism = the crate's crash-safe precedent (`acquire_deploy_lock`,
                                                                                               
//! for the process lifetime, kernel-released on death, never unlinked on drop. The file CONTENT
//! (pid + verb + start + token uuid) is DIAGNOSTIC payload for the refusal message, never the
//! lock itself — no stale-pid-file class exists.
//!
                                                                                 
//! puts into child environments as `ORCHARD_LOCK_TOKEN`; a child JOINS (neither re-acquires nor
//! refuses) only when ALL THREE hold: the lock file exists, its uuid equals the env token, and
//! the flock is CURRENTLY HELD (the failed `flock` attempt is the liveness proof). A leaked or
//! stale env token never joins — the env is transport for a capability the held lock attests.
//!
//! The TARGET resource lock stays VERB-OWNED (`prod`'s existing per-target
//! `recipes-deploy-<key>.lock`): `flock` is per open-file-description, so a runner-held target
//! flock would make the runner's own prod CHILD self-refuse on its second open of the same file.
//! The host lock + token join serialize the host; the verb's own target lock keeps guarding the
//! target (one lock per resource, no second namespace).

use std::path::{Path, PathBuf};

use crate::ceremony::classify::VerbClass;
use crate::ceremony::refusal::{Refusal, RefusalId};
use crate::cli::OrchardCmd;

pub const LOCK_TOKEN_ENV: &str = "ORCHARD_LOCK_TOKEN";

/// The runner's own pid, exported into a writing child's env beside `ORCHARD_LOCK_TOKEN`. `prctl`
/// binds the death signal to the child's CREATING THREAD (its parent the runner, by the direct-spawn
/// topology), not to a named pid; this exported pid is the liveness gate, checked on every writing
                                                                                                
/// worker opens a `pidfd` on it and refuses if the runner is already gone or dies through the arming,
/// so a death in the fork-to-prctl window does not run detached, order-independent and reuse-safe
    
/// Absent ⇒ not a runner-driven worker (a direct invocation, or a unit test), so nothing is armed.
                                                                                           
/// against a different parent.
pub const CEREMONY_PPID_ENV: &str = "ORCHARD_CEREMONY_PPID";

/// The lock-base override, for hermetic tests (`ORCHARD_LOCK_DIR`).
pub const LOCK_DIR_ENV: &str = "ORCHARD_LOCK_DIR";

                                                                                    
/// `$TMPDIR` when set, so two shells with different `$TMPDIR` — the exact split this project's own
/// build guidance induces ("`/tmp` is 32G … an operator exports `TMPDIR=/var/tmp`") — would each get
/// a PRIVATE lock and the second writing invocation would be admitted. A literal path is host-global
/// for every same-user invocation regardless of `$TMPDIR`. Residual, documented not closed: a mount
/// namespace (`systemd-run --property=PrivateTmp=`) or a per-account `/tmp` bind still isolates it,
/// and a cross-account first-creator owns the dir 0755 so a second account fails closed with the
/// `LockUnavailable` cure (I-11) — both are the same class as the T7 advisory residual.
const HOST_LOCK_DIR: &str = "/tmp/recipes-ceremony-locks";

                                                                                                    
                                                                                        
/// the same class with a different variable). `ORCHARD_LOCK_DIR` overrides the base so the battery
                                                                                       
                                                                                                     
/// from `acquire_deploy_lock`'s per-TARGET file: this is the ONE host lock.
fn lock_base() -> PathBuf {
    lock_base_from(std::env::var_os(LOCK_DIR_ENV).filter(|v| !v.is_empty()))
}

/// The testable core: the override (already empty-filtered) or the FIXED literal. Reads no env, so
                                                                                           
fn lock_base_from(override_dir: Option<std::ffi::OsString>) -> PathBuf {
    override_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(HOST_LOCK_DIR))
}

fn host_lock_path(base: &Path) -> PathBuf {
    base.join("host.lock")
}

/// The diagnostic sidecar (holder pid/verb/start/token), written by ATOMIC rename so a reader on
                                                                                
/// `host.lock`; the diagnostic lives here, so the two never interfere and a short read is
/// impossible — a reader sees either the previous complete file or the new complete file.
fn holder_info_path(base: &Path) -> PathBuf {
    base.join("host.lock.holder")
}

/// The held (or joined) ceremony lock. Holding = an open fd with the flock; the kernel releases
/// on process death. Joined = a child inside the holder's process tree (no fd of its own).
#[derive(Debug)]
pub struct CeremonyLock {
    /// `Some` when this process holds the flock (fd kept open for the process lifetime).
    holder: Option<std::fs::File>,
    token: String,
    /// The holder-info sidecar to unlink on release (only when we hold): a released lock then
                                                                                      
                                                                                   
    /// blocks on the flock until our fd closes, and we unlink BEFORE the fd drops, so it always
    /// writes a fresh sidecar.
    info_path: Option<PathBuf>,
}

impl CeremonyLock {
    /// The inheritance token the runner exports as `ORCHARD_LOCK_TOKEN` for child invocations.
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn is_holder(&self) -> bool {
        self.holder.is_some()
    }
}

impl Drop for CeremonyLock {
    fn drop(&mut self) {
                                                                                             
                                                                                            
        if let Some(info) = self.info_path.take() {
            std::fs::remove_file(info).ok();
        }
    }
}

fn flock_nb(f: &std::fs::File) -> std::io::Result<bool> {
    let rc = unsafe {
        libc::flock(
            std::os::fd::AsRawFd::as_raw_fd(f),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    };
    if rc == 0 {
        Ok(true)
    } else {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Ok(false)
        } else {
            Err(e)
        }
    }
}

                                                                                         
/// a live process owned by another account), ESRCH = gone. `pid <= 0` addresses a process group or
/// every process, never a single parent, so it is not a live parent here.
fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// The parent-death decision from the runner-ppid env — pure, so a unit arm drives it without
                                                                       
/// `arm_parent_death_kill`; actual signal DELIVERY is proven by the driven arm
                                                                       
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum PdeathAction {
    /// The env is absent/empty: not a runner-driven worker. Arm nothing.
    Skip,
    /// A runner-driven worker: arm PDEATHSIG, then require this pid alive.
    Arm(i32),
    /// The env is present but not a positive pid: fail closed.
    Refuse,
}

#[cfg(target_os = "linux")]
fn pdeath_action(ppid_env: Option<std::ffi::OsString>) -> PdeathAction {
    let Some(v) = ppid_env.filter(|v| !v.is_empty()) else {
        return PdeathAction::Skip;
    };
    match v.to_str().and_then(|s| s.trim().parse::<i32>().ok()) {
        Some(pid) if pid > 0 => PdeathAction::Arm(pid),
        _ => PdeathAction::Refuse,
    }
}

                                                                                                    
/// ceremony FAILS the install (the provider panel recovers) instead of orphaning it while the host
/// lock frees. Called as the first step of `acquire_at`, before the flock, so every writing
                                                                                             
/// not a runner-driven worker ⇒ nothing armed. Present ⇒
/// arm PDEATHSIG for kernel-automatic delivery, gated on a `pidfd_open`/`poll` liveness handle to
/// the runner: a runner already gone, or one that dies through the arming, refuses rather than
/// running detached. The pidfd is a sticky handle to the specific process, so the outcome does not
                                                                                 
/// gate does not verify the named pid IS the creator; prctl binds the creating thread, not the pid.
#[cfg(target_os = "linux")]
fn arm_parent_death_kill() -> Result<(), Refusal> {
    let ppid = match pdeath_action(std::env::var_os(CEREMONY_PPID_ENV)) {
        PdeathAction::Skip => return Ok(()),
        PdeathAction::Refuse => {
            return Err(Refusal::new(
                RefusalId::RunnerLivenessLost,
                format!(
                    "{CEREMONY_PPID_ENV} is set but is not a valid pid; aborting the ceremony worker"
                ),
            ));
        }
        PdeathAction::Arm(ppid) => ppid,
    };
    let detached = "the ceremony runner exited before this worker armed its death signal; aborting \
                    rather than running detached";
    let pidfd = unsafe {
        libc::syscall(
            libc::SYS_pidfd_open,
            ppid as libc::c_long,
            0 as libc::c_long,
        )
    };
    if pidfd < 0 {
        let e = std::io::Error::last_os_error();
        let detail = if e.raw_os_error() == Some(libc::ESRCH) {
            detached.to_string()
        } else {
            format!(
                "cannot open a liveness handle to the ceremony runner ({e}); aborting the ceremony worker"
            )
        };
        return Err(Refusal::new(RefusalId::RunnerLivenessLost, detail));
    }
    let pidfd = pidfd as libc::c_int;
    let rc = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(pidfd) };
        return Err(Refusal::new(
            RefusalId::RunnerLivenessLost,
            format!("cannot arm the parent-death signal ({e}); aborting the ceremony worker"),
        ));
    }
                                                                                             
    let mut pfd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let gone = loop {
        let pr = unsafe { libc::poll(&mut pfd, 1, 0) };
        if pr < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break true;
        }
        break pfd.revents != 0;
    };
    unsafe { libc::close(pidfd) };
    if gone {
        return Err(Refusal::new(RefusalId::RunnerLivenessLost, detached));
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn arm_parent_death_kill() -> Result<(), Refusal> {
    Ok(())
}

#[derive(Debug, Clone, Default)]
struct LockContent {
    pid: String,
    verb: String,
    started: String,
    token: String,
}

fn parse_content(s: &str) -> LockContent {
    let mut c = LockContent::default();
    for line in s.lines() {
        if let Some((k, v)) = line.split_once('=') {
            match k {
                "pid" => c.pid = v.to_string(),
                "verb" => c.verb = v.to_string(),
                "started" => c.started = v.to_string(),
                "token" => c.token = v.to_string(),
                _ => {}
            }
        }
    }
    c
}

impl LockContent {
    /// The holder description for the refusal / advisory — honest "holder unknown" when the
                                                                     
    fn describe(&self) -> String {
        if self.pid.is_empty() && self.verb.is_empty() {
            "holder details unavailable".to_string()
        } else {
            format!(
                "pid {} running `{}` since {}",
                self.pid, self.verb, self.started
            )
        }
    }

    /// Is the named holder still alive? The parsed pid routed through `pid_alive` (the T7 advisory's
                                                                                                      
    fn pid_is_alive(&self) -> bool {
        match self.pid.parse::<i32>() {
            Ok(pid) => pid_alive(pid),
            Err(_) => false,
        }
    }
}

/// Acquire (or join) the host WRITING lock at an explicit state base — the testable core;
/// [`acquire_for`] binds the live env. `env_token` is the inherited `ORCHARD_LOCK_TOKEN`, if any.
pub fn acquire_at(
    base: &Path,
    verb_token: &str,
    env_token: Option<&str>,
) -> Result<CeremonyLock, Refusal> {
                                                                                                 
                                                                                                 
                                                                                               
    arm_parent_death_kill()?;
    let path = host_lock_path(base);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            Refusal::new(
                RefusalId::LockUnavailable,
                format!("create lock dir {}: {e}", dir.display()),
            )
        })?;
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| {
            Refusal::new(
                RefusalId::LockUnavailable,
                format!("open {}: {e}", path.display()),
            )
        })?;
    let got = flock_nb(&f).map_err(|e| {
        Refusal::new(
            RefusalId::LockUnavailable,
            format!("flock {}: {e}", path.display()),
        )
    })?;
    let base = path.parent().unwrap_or(Path::new("."));
    if got {
                                                                                             
        let token: String = {
            use rand::RngCore as _;
            let mut b = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut b);
            hex::encode(b)
        };
                                                                                        
                                                                                  
                                                                                                  
                                                                                                
                                                                                   
        write_holder_info(base, verb_token, &token)?;
        return Ok(CeremonyLock {
            holder: Some(f),
            token,
            info_path: Some(holder_info_path(base)),
        });
    }
                                                                                                  
                                                                          
    let content = read_holder_info(base);
    if let Some(t) = env_token
        && !t.is_empty()
        && t == content.token
    {
        return Ok(CeremonyLock {
            holder: None,
            token: t.to_string(),
            info_path: None,
        });
    }
                                                                                        
                                                             
                                                              
    Err(Refusal::new(
        RefusalId::LockHeld,
        format!(
            "another WRITING orchard invocation holds this host ({}) — one writing invocation \
             per host",
            content.describe()
        ),
    ))
}

/// Write the holder diagnostic atomically: a temp file in the same dir then `rename` (same
                                                                                       
/// caller refuses the acquisition rather than proceeding with a stale sidecar. The tmp is opened
/// `create_new` (`O_EXCL|O_CREAT`), which refuses to follow a pre-planted symlink at the
                                                     
fn write_holder_info(base: &Path, verb_token: &str, token: &str) -> Result<(), Refusal> {
    use std::io::Write as _;
    let body = format!(
        "pid={}\nverb={}\nstarted={}\ntoken={}\n",
        std::process::id(),
        verb_token,
        chrono::Utc::now().to_rfc3339(),
        token
    );
    let dst = holder_info_path(base);
    let tmp = base.join(format!("host.lock.holder.{}.tmp", std::process::id()));
    let unavailable = |e: std::io::Error| {
        Refusal::new(
            RefusalId::LockUnavailable,
            format!("write holder diagnostic {}: {e}", tmp.display()),
        )
    };
                                                                                                  
    std::fs::remove_file(&tmp).ok();
    let write_result = (|| -> std::io::Result<()> {
        let mut fh = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        fh.write_all(body.as_bytes())?;
        fh.sync_all()?;
        std::fs::rename(&tmp, &dst)
    })();
    write_result.map_err(|e| {
        std::fs::remove_file(&tmp).ok();
        unavailable(e)
    })
}

/// Read the holder diagnostic (atomic file; a partial read is impossible because the writer
/// renames a complete file into place). Absent/unparseable ⇒ every field empty ⇒ `describe`
                          
fn read_holder_info(base: &Path) -> LockContent {
    match std::fs::read_to_string(holder_info_path(base)) {
        Ok(s) => parse_content(&s),
        Err(_) => LockContent::default(),
    }
}

                                                                                                 
/// any lock, even briefly, would starve a writer) — it reads the atomic diagnostic sidecar and
/// checks `kill(pid, 0)`. A live holder prints one line; a stale/absent sidecar says nothing.
/// Never blocks, never refuses, never acquires.
fn read_only_advisory(base: &Path) {
    let content = read_holder_info(base);
    if content.pid_is_alive() {
                                                                                           
                                                                   
        crate::ceremony::emit::emit_stderr(&format!(
            "note: a WRITING orchard invocation is live on this host (pid {} running `{}`) — \
             a red result here may be a torn read (T7)\n",
            content.pid, content.verb
        ));
    }
}

/// A one-word verb token for the lock content / refusal message.
fn verb_token_of(cmd: &OrchardCmd) -> &'static str {
    match cmd {
        OrchardCmd::GenerateKeys { .. } => "generate-keys",
        OrchardCmd::Redelegate { .. } => "redelegate",
        OrchardCmd::Update { .. } => "update",
        OrchardCmd::DeployModel { .. } => "deploy-model",
        OrchardCmd::RotateKey { .. } => "rotate-key",
        OrchardCmd::SignBackup { .. } => "sign-backup",
        OrchardCmd::SignInContainer { .. } => "sign-in-container",
        OrchardCmd::SignSb { .. } => "sign-sb",
        OrchardCmd::UpdateCertFingerprints { .. } => "update-cert-fingerprints",
        OrchardCmd::Build { .. } => "build",
        OrchardCmd::RestoreImage { .. } => "restore-image",
        OrchardCmd::BuildInstallerUsb { .. } => "build-installer-usb",
        OrchardCmd::SignInstallerUsb { .. } => "sign-installer-usb",
        OrchardCmd::Dryrun { .. } => "dryrun",
        OrchardCmd::Prod { .. } => "prod",
        OrchardCmd::Run { .. } => "run",
        OrchardCmd::Guide { .. } => "guide",
        OrchardCmd::ReclaimTail { .. } => "reclaim-tail",
        OrchardCmd::RefreshApkLock { .. } => "refresh-apk-lock",
        OrchardCmd::SyncPins { .. } => "sync-pins",
        OrchardCmd::Vendor { .. } => "vendor",
        OrchardCmd::Prime { .. } => "prime",
        OrchardCmd::Admit { .. } => "admit",
        OrchardCmd::Market { .. } => "market",
        OrchardCmd::DeriveRescueOffline { .. } => "derive-rescue-offline",
        OrchardCmd::Status { .. } => "status",
        OrchardCmd::Doctor { .. } => "doctor",
        #[cfg(feature = "ceremony-seed-unclassified-verb")]
        OrchardCmd::CeremonySeedUnclassified => "ceremony-seed",
    }
}

                                                                                     
/// EVERY verb, consulting `verb_class` — a verb cannot bypass it. Writing acquires (or joins via
/// the inherited token); ReadOnly prints the T7 advisory when the lock is held and returns None.
pub fn acquire_for(cmd: &OrchardCmd) -> Result<Option<CeremonyLock>, Refusal> {
                                                                                          
                                                                                                   
                                                                              
                                                   
    if let Some(dir) = std::env::var_os(LOCK_DIR_ENV).filter(|v| !v.is_empty()) {
                                                                                                    
                                                                                                    
                                                                          
        crate::ceremony::emit::emit_stderr(&format!(
            "note: ORCHARD_LOCK_DIR={} overrides the host ceremony lock dir — host serialization \
             holds only across invocations sharing this value\n",
            PathBuf::from(dir).display()
        ));
    }
    let env_token = std::env::var(LOCK_TOKEN_ENV).ok();
    acquire_for_at(cmd, &lock_base(), env_token.as_deref())
}

/// The testable core of [`acquire_for`]: explicit state base + inherited token (no process-env
/// reads, so the totality arm can drive every verb against a fixture base).
pub fn acquire_for_at(
    cmd: &OrchardCmd,
    base: &Path,
    env_token: Option<&str>,
) -> Result<Option<CeremonyLock>, Refusal> {
    match crate::ceremony::classify::verb_class(cmd) {
        VerbClass::Writing => Ok(Some(acquire_at(base, verb_token_of(cmd), env_token)?)),
        VerbClass::ReadOnly => {
            read_only_advisory(base);
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_base_default_is_the_fixed_host_literal() {
                                                                                                     
                                                                                                      
                                                                                                 
                                                                                            
                                                                                                       
                                                                      
        let base = lock_base_from(None);
        assert_eq!(base, PathBuf::from(HOST_LOCK_DIR));
        assert!(
            base.is_absolute(),
            "the host lock dir must be an absolute path"
        );
        assert_eq!(lock_base_from(Some("/x/y".into())), PathBuf::from("/x/y"));
    }

    #[test]
    fn pid_is_alive_reads_eperm_as_alive_and_esrch_as_dead() {
                                                                                                    
                                                                                                       
                                                                                                     
                                             
        let init = LockContent {
            pid: "1".into(),
            ..Default::default()
        };
        assert!(
            init.pid_is_alive(),
            "pid 1 is alive (EPERM for an unprivileged caller must not read as dead)"
        );
        let self_pid = LockContent {
            pid: std::process::id().to_string(),
            ..Default::default()
        };
        assert!(self_pid.pid_is_alive(), "our own pid is alive");
        let gone = LockContent {
            pid: "2147480000".into(),
            ..Default::default()
        };
        assert!(!gone.pid_is_alive(), "an unused high pid is ESRCH → dead");
        let unparseable = LockContent {
            pid: "not-a-pid".into(),
            ..Default::default()
        };
        assert!(!unparseable.pid_is_alive(), "an unparseable pid is dead");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pdeath_action_gates_on_the_runner_ppid_env() {
                                                                                                   
                                                                                                  
                                                                                                 
        assert_eq!(pdeath_action(None), PdeathAction::Skip);
        assert_eq!(pdeath_action(Some("".into())), PdeathAction::Skip);
        assert_eq!(pdeath_action(Some("1234".into())), PdeathAction::Arm(1234));
        assert_eq!(
            pdeath_action(Some("  1234 ".into())),
            PdeathAction::Arm(1234)
        );
        assert_eq!(pdeath_action(Some("0".into())), PdeathAction::Refuse);
        assert_eq!(pdeath_action(Some("-5".into())), PdeathAction::Refuse);
        assert_eq!(
            pdeath_action(Some("not-a-pid".into())),
            PdeathAction::Refuse
        );
    }
}
