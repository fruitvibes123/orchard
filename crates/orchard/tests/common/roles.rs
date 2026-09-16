//! The role-process shape: an arm that needs a process-global environment re-execs this test
//! binary once per role and asserts inside the role's own process (delta v3.4 §4.2).

use std::path::{Path, PathBuf};

/// The env var that turns a test binary into one role process.
pub const ROLE_ENV: &str = "ORCHARD_R16_ROLE";
/// What a passing role prints before exiting 0.
pub const ROLE_OK: &str = "R16-ROLE-OK";

/// The role this process was spawned as, or `None` in the dispatching process.
pub fn role() -> Option<String> {
    std::env::var(ROLE_ENV).ok()
}

/// Re-exec this binary once per role, each role in its own process. A role asserts inside its own
/// process and prints [`ROLE_OK`] followed by its name.
pub fn dispatch_roles(test_name: &str, roles: &[&str]) {
    let exe = std::env::current_exe().expect("the test binary's own path");
    for role in roles {
        let out = std::process::Command::new(&exe)
            .args([test_name, "--exact", "--nocapture", "--test-threads=1"])
            .env(ROLE_ENV, role)
            .output()
            .expect("spawn the role");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "role {role} failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains(&format!("{ROLE_OK} {role}")),
            "role {role} exited 0 without reaching its assertions:\n{stdout}"
        );
    }
}

/// Point this process's `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` at `global`/`system`.
///
/// Refuses outside a role process: the two names are process-global, so in a shared test process
                                                                                
pub fn pin_git_config(global: &Path, system: &Path) {
    assert!(
        role().is_some(),
        "pin_git_config outside a role process: {ROLE_ENV} is unset, so this pin would reach \
         every other arm of this binary"
    );
                                                                          
    unsafe {
        std::env::set_var("GIT_CONFIG_GLOBAL", global);
        std::env::set_var("GIT_CONFIG_SYSTEM", system);
    }
}

/// Write two empty config files under `dir` and pin at them, so no host `~/.gitconfig`,
/// `/etc/gitconfig` or inherited `GIT_CONFIG_GLOBAL` reaches a git command of this process.
/// Call before the first git command; returns the two paths.
pub fn pin_empty_git_config(dir: &Path) -> (PathBuf, PathBuf) {
                                                                                                  
                          
    let at = dir.join("role-gitconfig");
    std::fs::create_dir_all(&at).expect("mk role-gitconfig");
    let global = at.join("empty-global.gitconfig");
    let system = at.join("empty-system.gitconfig");
    std::fs::write(&global, "").expect("w empty global");
    std::fs::write(&system, "").expect("w empty system");
    pin_git_config(&global, &system);
    (global, system)
}
