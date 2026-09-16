                                                                                   
//!
//! The ceremony's PRE-KEXEC transport connects as the cloud user and `sudo`s the privileged
//! steps, never as `root@`: Infomaniak VPS images ship a `command="…exit 142"` restriction on the
//! first key in `/root/.ssh/authorized_keys`, so `root@` prints a banner and exits 142, and the
//! restriction returns after every reinstall (`cookbook/docs/vps-root-login-behavior.md`). As
//! `debian@` + `sudo` there is nothing to fix, ever.
//!
//! So the probe has two arms. The PRIMARY arm asks the real question — is the target reachable as
//! the cloud user with non-interactive sudo. The DETECTOR arm exists only to give a
//! root@-pointed target the right cure instead of a generic "unreachable": the exit-142 + banner
//! signature is `[MEASURED]` in that doc, and its cure names the transport this ceremony uses.

use super::probes::ProbeResult;

/// The cloud user the pre-kexec legs connect as when nothing else is declared. ONE home with
/// the transport's own default (`deploy::prod_orchestrate::DEFAULT_PROVISIONING_USER`), so the
/// probe can never test a different user than the install leg will use.
pub use crate::deploy::prod_orchestrate::DEFAULT_PROVISIONING_USER as CLOUD_USER;

/// The measured signature of the Infomaniak root-key restriction
/// (`cookbook/docs/vps-root-login-behavior.md`): SSH authenticates, the forced command prints the
/// banner, and the session exits 142.
pub const ROOT_RESTRICTION_EXIT: i32 = 142;
pub const ROOT_RESTRICTION_BANNER: &str = "Please login as the user \"debian\"";

/// One SSH attempt's outcome, as the classification sees it.
#[derive(Debug, Clone, Default)]
pub struct SshAttempt {
    /// `None` = terminated by a signal or never ran.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl SshAttempt {
    pub fn spawn_failed(reason: &str) -> Self {
        SshAttempt {
            code: None,
            stdout: String::new(),
            stderr: reason.to_string(),
        }
    }
}

/// Does this attempt carry the root-restriction signature? Either half is enough: the exit code
/// alone identifies it, and the banner alone survives a wrapper that rewrites the code.
pub fn is_root_restricted(a: &SshAttempt) -> bool {
    a.code == Some(ROOT_RESTRICTION_EXIT)
        || a.stdout.contains(ROOT_RESTRICTION_BANNER)
        || a.stderr.contains(ROOT_RESTRICTION_BANNER)
}

/// Classify the preflight (the pure half; the live probe does the I/O and calls this).
/// `cloud` is the `debian@` + `sudo -n whoami` attempt. `root` is the detector attempt, made only
/// when the primary one failed.
pub fn classify(
    user: &str,
    target: &str,
    cloud: &SshAttempt,
    root: Option<&SshAttempt>,
) -> ProbeResult {
    if cloud.code == Some(0) && cloud.stdout.trim() == "root" {
        return ProbeResult::Met;
    }
    if let Some(r) = root
        && is_root_restricted(r)
    {
        return ProbeResult::Unmet(format!(
            "{target} answers as root@ with the provider's login restriction (exit \
             {ROOT_RESTRICTION_EXIT}), and the {user} leg did not succeed. This ceremony connects \
             as {user}@ and sudos the privileged steps, so the restriction never bites — supply \
             the {user} key path as the profile's `ssh_identity` and make sure {user}@{target} has \
             passwordless sudo (`sudo -n whoami` prints root)"
        ));
    }
                                                                                               
                                                  
    let said = first_meaningful_line(cloud);
    ProbeResult::Unmet(format!(
        "{user}@{target} is not reachable with non-interactive sudo (exit {:?}): {said}",
        cloud.code
    ))
}

fn first_meaningful_line(a: &SshAttempt) -> String {
    a.stderr
        .lines()
        .chain(a.stdout.lines())
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no output")
        .to_string()
}

/// The live probe: run the primary arm as the declared provisioning user, and the detector only
/// if it failed. A `root` provisioning user needs no sudo, so its primary arm asks `whoami`.
pub fn probe(user: &str, target: &str, port: Option<&str>, identity: Option<&str>) -> ProbeResult {
    let remote = if user == crate::deploy::prod_orchestrate::DEFAULT_RECONNECT_USER {
        "whoami"
    } else {
        "sudo -n whoami"
    };
    let cloud = ssh_attempt(&format!("{user}@{target}"), port, identity, remote);
    if cloud.code == Some(0) && cloud.stdout.trim() == "root" {
        return ProbeResult::Met;
    }
    let root = ssh_attempt(&format!("root@{target}"), port, identity, "true");
    classify(user, target, &cloud, Some(&root))
}

fn ssh_attempt(dest: &str, port: Option<&str>, identity: Option<&str>, remote: &str) -> SshAttempt {
    let mut cmd = std::process::Command::new("ssh");
    cmd.args([
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]);
    if let Some(p) = port {
        cmd.args(["-p", p]);
    }
    if let Some(i) = identity {
        cmd.args(["-i", i]);
    }
    cmd.args([dest, remote]);
    match cmd.output() {
        Ok(o) => SshAttempt {
            code: o.status.code(),
            stdout: String::from_utf8_lossy(&o.stdout).to_string(),
            stderr: String::from_utf8_lossy(&o.stderr).to_string(),
        },
        Err(e) => SshAttempt::spawn_failed(&format!("could not run ssh: {e}")),
    }
}
