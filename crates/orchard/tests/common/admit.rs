//! One spawn helper for the built binary's `admit`, shared by the declared-space and
//! declared-value suites (delta v3.4 §4.1).

use std::path::Path;

/// Run the built `orchard` binary's `admit` over `repo_root` with `stdin` fed from `input`;
/// returns whether the child exited 0 and its stdout followed by its stderr.
///
/// The child gets an isolated `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME` beside `repo_root`,
/// `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` at empty files, and no `FRUIT_ARTIFACT_STORE` or
/// `ORCHARD_LOCK_TOKEN`, so the host operator's context file, artifact store, lock token, global
/// git config and system git config reach neither the child nor the git commands it spawns.
/// `ORCHARD_LOCK_DIR` is its own directory beside `repo_root`: the ceremony lock is one per host,
/// so two suites spawning `admit` at once would refuse `lock-held`.
pub fn run_admit(repo_root: &Path, profile: &Path, dir: &Path, input: &str) -> (bool, String) {
    use std::io::Write as _;
    let side = repo_root.join("..");
    let home = side.join("home");
    std::fs::create_dir_all(home.join(".config")).expect("mk home");
    let store = side.join("store");
    std::fs::create_dir_all(&store).expect("mk store");
    let lock = side.join("ceremony-lock");
    std::fs::create_dir_all(&lock).expect("mk lock dir");
    let empty_global = side.join("empty-global.gitconfig");
    let empty_system = side.join("empty-system.gitconfig");
    std::fs::write(&empty_global, "").expect("w empty global");
    std::fs::write(&empty_system, "").expect("w empty system");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_orchard"))
        .args([
            "--repo-root".as_ref(),
            repo_root.as_os_str(),
            "--artifact-store".as_ref(),
            store.as_os_str(),
            "admit".as_ref(),
            "--box".as_ref(),
            profile.as_os_str(),
            "--repo-form-dir".as_ref(),
            dir.as_os_str(),
        ])
        .env_remove("FRUIT_ARTIFACT_STORE")
        .env_remove("ORCHARD_LOCK_TOKEN")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", home.join(".state"))
        .env("ORCHARD_LOCK_DIR", &lock)
        .env("GIT_CONFIG_GLOBAL", &empty_global)
        .env("GIT_CONFIG_SYSTEM", &empty_system)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn orchard admit");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}
