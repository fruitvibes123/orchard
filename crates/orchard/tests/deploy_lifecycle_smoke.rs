                                                                                                         
//!
//! Boots a built seabios-gpt A/B `.img` under QEMU via [`boot_lifecycle_box`] and drives the REAL
//! `orchard status` + rotate-key state machine against the live box over real SSH (dropbear) — the
//! produced-bytes proof `make verify` (seam contract only) can never give. ONE `#[test]` by design (the
//! Makefile's fail-closed guard greps `"test result: ok. 1 passed"`; splitting it fail-closed-blocks the
//! gate). `#[ignore]`d + env-gated: it PANICS if `RECIPES_LIFECYCLE_IMG`/`/dev/kvm` are absent (a boot gate
                                                                                      
//!
//! It drives the internal `status::run` + `rotate_key::run_state_machine` APIs (not the CLI subprocess) so
//! the state machine's real SSH edit legs, dropbear per-connection auth, atomic `mv`, and `0644 root:root`
//! mode are all exercised on produced bytes without a subprocess/tty dance — the same produced-bytes
//! surface, minus the interactive-only CLI gate (which `make verify`'s unit tests already pin).

use std::path::{Path, PathBuf};

use orchard::deploy::dryrun::{DryrunOpts, LiveBox, boot_lifecycle_box};
use orchard::deploy::host_pins::HostPinOpts;
use orchard::deploy::lifecycle::{BoxOps, ProbeResult, SshBox};
use orchard::deploy::rotate_key::{RotateOutcome, derive_line, run_state_machine};
use orchard::deploy::status::{StatusArgs, StatusExit, run as status_run};

fn gate_img() -> PathBuf {
    match std::env::var("RECIPES_LIFECYCLE_IMG") {
        Ok(p) => PathBuf::from(p),
        Err(_) => panic!(
            "boot-gate-lifecycle: set RECIPES_LIFECYCLE_IMG to a built seabios-gpt A/B .img (run via \
             `make boot-gate-lifecycle`). A boot gate must never pass without asserting its produced bytes."
        ),
    }
}

/// The operator private key the `RECIPES_LIFECYCLE_IMG` was BUILT with (`--operator-pubkey <its derived
/// pubkey>`). The box boots from its own baked persist-skeleton (NOT an ephemeral gate key), so the login
/// the gate authenticates + rotates is this key — its `ssh-keygen -y` line is exactly what the skeleton
/// baked, which the strict rotate-key content-gate requires.
fn gate_privkey() -> PathBuf {
    match std::env::var("RECIPES_LIFECYCLE_PRIVKEY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => panic!(
            "boot-gate-lifecycle: set RECIPES_LIFECYCLE_PRIVKEY to the operator private key matching the \
             .img's `--operator-pubkey` (run via `make boot-gate-lifecycle`). A boot gate must never pass \
             without asserting its produced bytes."
        ),
    }
}

/// Two DISTINCT free loopback TCP ports for the qemu host-forwards (ssh→22, https→443), replacing the
/// hardcoded 2222/8443 — qemu's `hostfwd` fails to START if a port is already bound. Bind both at once so
/// they differ, then drop the listeners so qemu can claim them. The TOCTOU window (release → qemu's actual
/// bind) spans the whole Phase-1 installer boot — low-single-digit SECONDS, not microseconds — so a
/// collision is possible-but-unlikely; either way it fails the boot LOUDLY (qemu won't start), never a
/// false green.
fn free_ports() -> (u16, u16) {
    let a = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral ssh port");
    let b = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral https port");
    let (pa, pb) = (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    );
    (pa, pb)
}

/// A fresh `SshBox` connected to the live box under the captured pin (non-interactive first contact via
/// the box's `--host-fingerprint`).
fn connect(live: &LiveBox, pin_dir: &Path, identity: &Path) -> SshBox {
    SshBox::connect(
        &live.host,
        live.ssh_port,
        identity,
        HostPinOpts {
            host_fingerprint: Some(&live.host_fingerprint),
            is_tty: false,
            pin_dir,
        },
    )
    .expect("connect to the live box")
}

fn gen_key(path: &Path) {
    let out = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(path)
        .output()
        .expect("spawn ssh-keygen");
    assert!(
        out.status.success(),
        "ssh-keygen: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

                                                                                                        
/// `/persist/update` dir mtime (or `absent`). Read over a real SSH session.
fn read_only_snapshot(ops: &mut SshBox, auth_keys: &str) -> (String, String, String) {
    let (_, content) = ops.run(&format!("cat {auth_keys}")).unwrap();
    let (_, keys_mtime) = ops.run(&format!("stat -c %Y {auth_keys}")).unwrap();
    let (_, update_mtime) = ops
        .run("stat -c %Y /persist/update 2>/dev/null || echo absent")
        .unwrap();
    (
        content.trim().to_string(),
        keys_mtime.trim().to_string(),
        update_mtime.trim().to_string(),
    )
}

/// A "different" local image: the SAME `.img` bytes (symlinked) beside a `layout.toml` whose
/// `image_version` is bumped — so the verity root still matches (same boot-fs) but the version MISMATCHes,
/// which is enough to drive a produced-bytes `StatusExit::Mismatch`. (A verity-ROOT mismatch specifically
/// would need a genuinely different rootfs; that comparison's LOGIC is unit-pinned by
/// `status::tests::compare_image_divergent_version_and_root_mismatch`, and the gate exercises the verity
/// field on produced bytes in the MATCH/OK case above — accepted audit L-5.)
fn tampered_image(orig: &Path, tmp: &Path) -> PathBuf {
    let other_img = tmp.join("other.img");
    std::os::unix::fs::symlink(orig, &other_img).expect("symlink .img");
    let layout =
        std::fs::read_to_string(orig.with_extension("layout.toml")).expect("read layout.toml");
    let bumped: String = layout
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("image_version") {
                let cur: u64 = l
                    .split('=')
                    .nth(1)
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                format!("image_version = {}", cur.wrapping_add(1))
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(tmp.join("other.layout.toml"), bumped).expect("write tampered layout");
    other_img
}

#[test]
#[ignore = "boot gate: needs RECIPES_LIFECYCLE_IMG (a seabios-gpt A/B .img) + /dev/kvm; run via `make boot-gate-lifecycle`"]
fn lifecycle_verbs_on_produced_bytes() {
    let img = gate_img();
    let privkey = gate_privkey();
                                                                                                      
                                                                                                           
                                                                                                 
                                                                                                          
                                                                                                           
                                                                                       
    let (ssh_port, https_port) = free_ports();
    let opts = DryrunOpts {
        ssh_port,
        https_port,
        ..Default::default()
    };
    let live = boot_lifecycle_box(&img, &privkey, &opts).expect("boot the A/B box");
    let pins = tempfile::tempdir().expect("pin dir");
    let pin_dir = pins.path();

    let status_args = |image: Option<PathBuf>| StatusArgs {
        host: live.host.clone(),
        port: live.ssh_port,
        image,
        ssh_identity: live.operator_privkey.clone(),
        keys_dir: None,
        committed_pin: None,
        host_fingerprint: Some(live.host_fingerprint.clone()),
        pin_dir: pin_dir.to_path_buf(),
        is_tty: false,
    };

                                                                                                                                                                        
    assert_eq!(
        status_run(&status_args(Some(img.clone()))),
        StatusExit::Ok,
        "status --image <the running build> must MATCH → OK"
    );
                                                                                                         
    let other = tampered_image(&img, pins.path());
    assert_eq!(
        status_run(&status_args(Some(other))),
        StatusExit::Mismatch,
        "a different image must report MISMATCH"
    );

                                                                                                                                                                
    {
        let mut ops = connect(&live, pin_dir, &live.operator_privkey);
        let before = read_only_snapshot(&mut ops, &live.authorized_keys_remote);
        assert_ne!(
            status_run(&status_args(None)),
            StatusExit::Unreachable,
            "the bare status run must reach the box"
        );
        let after = read_only_snapshot(&mut ops, &live.authorized_keys_remote);
        assert_eq!(
            before, after,
            "a status run must not modify /persist (authorized_keys + /persist/update)"
        );
    }

                                                                                                                                                                                                   
    let throwaway_dir = tempfile::tempdir().unwrap();
    let throwaway = throwaway_dir.path().join("id");
    gen_key(&throwaway);
    let current_line = derive_line(&live.operator_privkey).expect("derive current");
    let new_line = derive_line(&throwaway).expect("derive new");

                                                           
    {
        let mut ops = connect(&live, pin_dir, &live.operator_privkey);
        let out = run_state_machine(
            &mut ops,
            &current_line,
            &new_line,
            &throwaway,
            &live.operator_privkey,
        );
        assert_eq!(
            out,
            RotateOutcome::Success,
            "rotate to the throwaway key must SUCCEED"
        );
    }
                                                                                                       
    {
        let mut ops = connect(&live, pin_dir, &throwaway);
        let (ok, content) = ops
            .run(&format!("cat {}", live.authorized_keys_remote))
            .unwrap();
        assert!(
            ok && content.trim() == new_line.trim(),
            "file is exactly the new line: {content:?}"
        );
        let (ok, mode) = ops
            .run(&format!(
                "stat -c '%a %U:%G' {}",
                live.authorized_keys_remote
            ))
            .unwrap();
        assert!(
            ok && mode.trim() == "644 root:root",
            "0644 root:root, got {mode:?}"
        );
        assert_eq!(
            ops.auth_probe(&throwaway),
            ProbeResult::Authenticated,
            "new key authenticates"
        );
        assert_eq!(
            ops.auth_probe(&live.operator_privkey),
            ProbeResult::Refused,
            "old key is refused after cleanup"
        );
    }
                                                                                                      
    {
        let mut ops = connect(&live, pin_dir, &throwaway);
        let out = run_state_machine(
            &mut ops,
            &new_line,
            &current_line,
            &live.operator_privkey,
            &throwaway,
        );
        assert_eq!(out, RotateOutcome::Success, "rotate BACK must SUCCEED");
    }
    {
        let mut ops = connect(&live, pin_dir, &live.operator_privkey);
        assert_eq!(
            ops.auth_probe(&live.operator_privkey),
            ProbeResult::Authenticated,
            "the operator key is restored"
        );
    }
}
