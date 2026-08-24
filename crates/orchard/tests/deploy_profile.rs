                                                                                                       
                                                                                                     
//! — the regression backstop the source-line ordering otherwise lacks. None of these need docker /
//! kvm / network: every refusal fires in the early merge block.

use std::path::Path;
use std::process::{Command, Output};

fn orchard() -> Command {
    Command::new(env!("CARGO_BIN_EXE_orchard"))
}

fn write_profile(dir: &Path, body: &str) -> std::path::PathBuf {
    let p = dir.join("box.toml");
    std::fs::write(&p, body).unwrap();
    p
}

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

                                                                                                   
/// with the naming-both-sources message BEFORE any ceremony action — proven by the message AND the
/// ABSENCE of any ceremony-progress output (no lock/build/scan/kexec).
#[test]
fn prod_profile_missing_pubkey_refuses_before_any_action() {
    let dir = tempfile::tempdir().unwrap();
    let profile = write_profile(dir.path(), "ip = \"203.0.113.5\"\nport = 2222\n");
    let out = orchard()
        .args(["prod", "203.0.113.5", "--profile"])
        .arg(&profile)
        .arg("--wipe-confirmed")
        .output()
        .unwrap();
    assert!(!out.status.success(), "must refuse: {}", combined(&out));
    let c = combined(&out);
    assert!(
        c.contains("operator pubkey is required"),
        "names the requirement: {c}"
    );
    assert!(
        c.contains("--pubkey") && c.contains("operator_pubkey"),
        "names BOTH sources: {c}"
    );
                                                                                                  
                                                                                                     
                                              
    for forbidden in [
        "step 1/",
        "deploy prod: built",
        "kexec",
        "waiting for the installed box",
    ] {
        assert!(
            !c.contains(forbidden),
            "refused AFTER an action ({forbidden}): {c}"
        );
    }
}

/// `ssh_identity` gets the same fail-closed treatment (profile supplies the pubkey but not ssh_identity).
#[test]
fn prod_profile_missing_ssh_identity_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let profile = write_profile(
        dir.path(),
        "ip = \"203.0.113.5\"\noperator_pubkey = \"/tmp/op.pub\"\n",
    );
    let out = orchard()
        .args(["prod", "203.0.113.5", "--profile"])
        .arg(&profile)
        .arg("--wipe-confirmed")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let c = combined(&out);
    assert!(
        c.contains("ssh identity is required") && c.contains("ssh_identity"),
        "{c}"
    );
}

/// A destructive key in a profile refuses at load (the whitelist gate), before anything else.
#[test]
fn prod_profile_with_destructive_key_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let profile = write_profile(dir.path(), "ip = \"203.0.113.5\"\nwipe_confirmed = true\n");
    let out = orchard()
        .args(["prod", "203.0.113.5", "--profile"])
        .arg(&profile)
        .arg("--wipe-confirmed")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        combined(&out).contains("destructive intent"),
        "{}",
        combined(&out)
    );
}

/// `build --profile` without a domain refuses fail-closed AND prints the ignored-deploy-only-keys note.
#[test]
fn build_profile_missing_domain_refuses_with_ignored_note() {
    let dir = tempfile::tempdir().unwrap();
    let profile = write_profile(dir.path(), "ip = \"203.0.113.5\"\nport = 2222\n");
    let out = orchard()
        .args(["build", "--profile"])
        .arg(&profile)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let c = combined(&out);
    assert!(c.contains("domain is required"), "{c}");
    assert!(
        c.contains("apply to `prod`") || c.contains("ignored here"),
        "ignored-key note: {c}"
    );
}
