                                                                         
//!
                                                                                              
//! true from any directory inside a checkout: it resolves the checkout, builds the real binary
//! once, and `exec`s it with the original argv. `exec` rather than spawn-and-wait so the operator
//! keeps one process — signals, exit codes and the controlling terminal all belong to the real
//! binary, which is what the interview's pty gate and the runner's inherited-stdio regime depend
//! on.
//!
                                                                                                
//! CHECKOUT. It refuses with that requirement named rather than silently doing nothing.

use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};

fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
                                                                                                
                                                                                                
                                                                                          
                                                        
    #[allow(clippy::disallowed_methods)]
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => return die(&format!("cannot read the working directory: {e}")),
    };
    let Some(root) = find_checkout(&cwd) else {
        return die(
            "no orchard checkout above the working directory (looking for a directory holding \
             both `crates/orchard` and a `.git` entry).\n  cure: cd into an orchard checkout and \
             re-run; the shim builds and execs that checkout's binary, so it has no meaning \
             outside one",
        );
    };
                                                                                                  
                                                                                                  
                                            
    let child = std::process::Command::new("cargo")
        .current_dir(&root)
        .args([
            "build",
            "--release",
            "-p",
            "orchard",
            "--message-format=json-render-diagnostics",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn();
    let out = match child.and_then(|c| c.wait_with_output()) {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            return die(&format!(
                "`cargo build --release -p orchard` exited {}",
                o.status
            ));
        }
        Err(e) => return die(&format!("cannot run cargo in {}: {e}", root.display())),
    };
                                                                                
                                                                                             
    let Some(bin) = executable_from_cargo_json(&String::from_utf8_lossy(&out.stdout)) else {
        return die(
            "cargo build reported success but its --message-format=json output named no orchard \
             executable",
        );
    };
    if !bin.is_file() {
        return die(&format!(
            "cargo named {} as the built binary, but it is not there",
            bin.display()
        ));
    }
                                                                                             
                                            
    let e = std::process::Command::new(&bin).args(&argv).exec();
    die(&format!("cannot exec {}: {e}", bin.display()))
}

/// The orchard binary's path from `cargo build --message-format=json` output. Each build line is a
/// JSON object; the `compiler-artifact` for the bin carries `"executable":"<path>"` (null for
/// libs), so the last non-null `executable` is the built binary — wherever the target dir actually
                                                                                                  
fn executable_from_cargo_json(stdout: &str) -> Option<PathBuf> {
    #[derive(serde::Deserialize)]
    struct Artifact {
        executable: Option<String>,
    }
    let mut bin = None;
    for line in stdout.lines() {
        if let Ok(a) = serde_json::from_str::<Artifact>(line)
            && let Some(exe) = a.executable
        {
            bin = Some(PathBuf::from(exe));
        }
    }
    bin
}

/// Walk up from `start` to the first directory holding BOTH `crates/orchard` and a `.git` entry.
/// `.git` is a FILE in a worktree and a directory in a main checkout, so the check is existence,
/// not file-type — a worktree is exactly where this stream develops.
fn find_checkout(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        if d.join("crates/orchard").is_dir() && d.join(".git").exists() {
            return Some(d.to_path_buf());
        }
        dir = d.parent();
    }
    None
}

fn die(msg: &str) -> std::process::ExitCode {
    eprintln!("orchard: {msg}");
    std::process::ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::executable_from_cargo_json;
    use std::path::PathBuf;

    #[test]
    fn reads_the_executable_wherever_the_target_dir_is() {
                                                                                                  
                                                                                                     
        let out = concat!(
            r#"{"reason":"compiler-artifact","target":{"name":"serde"},"executable":null}"#,
            "\n",
            r#"{"reason":"compiler-artifact","target":{"name":"orchard","kind":["bin"]},"executable":"/redirected/build/release/orchard"}"#,
            "\n",
            r#"{"reason":"build-finished","success":true}"#,
            "\n",
        );
        assert_eq!(
            executable_from_cargo_json(out),
            Some(PathBuf::from("/redirected/build/release/orchard")),
        );
    }

    #[test]
    fn none_when_no_artifact_names_an_executable() {
        let out = concat!(
            r#"{"reason":"compiler-artifact","target":{"name":"orchard-lib"},"executable":null}"#,
            "\n",
            r#"{"reason":"build-finished","success":true}"#,
            "\n",
        );
        assert_eq!(executable_from_cargo_json(out), None);
    }
}
