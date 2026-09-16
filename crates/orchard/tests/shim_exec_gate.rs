//! Shim exec-path execution gate.
//!
//! The shim must exec the binary at the path cargo reports, not a literal
//! `target/release/orchard`, so a redirected `CARGO_TARGET_DIR` still runs the freshly built
//! binary. Driven layer: build the shim, run it against a throwaway checkout under a redirected
//! target dir, observe which binary it execs.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/orchard resolves a workspace root two levels up")
        .to_path_buf()
}

fn target_profile_dir() -> PathBuf {
                                                                                      
    let exe = std::env::current_exe().expect("test exe path");
    exe.parent()
        .and_then(Path::parent)
        .expect("test exe under <target>/<profile>/deps")
        .to_path_buf()
}

#[test]
fn shim_execs_the_binary_at_the_redirected_target_dir() {
    let ws = workspace_root();
    let profile = target_profile_dir();

    let status = Command::new(env!("CARGO"))
        .args(["build", "-p", "orchard-shim"])
        .current_dir(&ws)
        .status()
        .expect("run cargo build -p orchard-shim");
    assert!(status.success(), "building orchard-shim failed");
    let shim = profile.join("orchard-shim");
    assert!(shim.is_file(), "orchard-shim not at {}", shim.display());

    let sandbox = std::env::temp_dir().join(format!(
        "orchard-shim-exec-gate-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let root = sandbox.join("checkout");
    let crate_dir = root.join("crates/orchard");
    std::fs::create_dir_all(crate_dir.join("src")).unwrap();
                                                                                     
    std::fs::write(root.join(".git"), b"gitdir: /dev/null\n").unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        b"[workspace]\nmembers = [\"crates/orchard\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    std::fs::write(
        crate_dir.join("Cargo.toml"),
        b"[package]\nname = \"orchard\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"orchard\"\npath = \"src/main.rs\"\n",
    )
    .unwrap();
    std::fs::write(
        crate_dir.join("src/main.rs"),
        b"fn main() { println!(\"{}\", std::env::current_exe().unwrap().display()); }\n",
    )
    .unwrap();

                                                                                            
                       
    let stale_dir = root.join("target/release");
    std::fs::create_dir_all(&stale_dir).unwrap();
    let stale = stale_dir.join("orchard");
    std::fs::write(&stale, b"#!/bin/sh\necho STALE-IN-TREE\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let redir = sandbox.join("redirected-target");
    std::fs::create_dir_all(&redir).unwrap();

    let out = Command::new(&shim)
        .current_dir(&root)
        .env("CARGO_TARGET_DIR", &redir)
        .output()
        .expect("run the shim");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let printed = stdout.trim().to_string();
    let redir_c = std::fs::canonicalize(&redir).unwrap();

    let ok = out.status.success() && Path::new(&printed).starts_with(&redir_c);

    let _ = std::fs::remove_dir_all(&sandbox);

    assert!(
        ok,
        "shim did not exec the binary under the redirected target dir.\n  \
         redirected target: {}\n  execed: {printed}\n  status: {}\n  stderr: {stderr}",
        redir_c.display(),
        out.status
    );
}
