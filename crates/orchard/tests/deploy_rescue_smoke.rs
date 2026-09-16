                                                                                                 
//!
//! Deploy-feature-gated AND env-gated (heavy: needs KVM + a built `.img` whose rootfs bakes a recovery
//! pubkey, plus the matching recovery privkey). Build such an image with:
//!   `orchard build --recovery-pubkey <key.pub> --keys-dir <dir> --domain <d> --allow-dirty`
//! then run:
//!   `RECIPES_RESCUE_IMG=<img> RECIPES_RESCUE_PRIVKEY=<key> cargo test -p orchard --test deploy_rescue_smoke`
//!
//! `rescue_bundle_activates_on_corrupt_persist` proves the rescue contract on a NO-fs /persist (spec
                                                                                                       
//! dropbear — (a) recipes does NOT answer, (c) it's reachable by the baked recovery pubkey, (b) its host
//! key matches the offline `derive-rescue-host-keys --image` precompute (TOFU determinism), and (d) it
//! presents the rescue banner.
//!
//! `rescue_activates_on_rc4_corrupt_persist` is persist-crash-recovery ACCEPTANCE #3b: a REAL ext4
//! `/persist` corrupted to `e2fsck -p` rc=4 (uncorrectable in preen) must ALSO divert to rescue —
//! prepare-persist's `(rc & 0xFC) != 0` branch. Unlike the no-fs case (findfs miss / rc≈8), this
//! exercises the rc=4 path the rc-bitmask gate must get right.

use std::path::Path;
use std::process::Command;

/// The env (a built `.img` with a baked recovery pubkey + the matching recovery privkey) both rescue
                                                                                                          
/// run only via `--ignored` (`make boot-gate`); a missing env there is an operator error, never a silent
/// pass — a boot gate must never report success without asserting the produced bytes.
fn gate_env() -> (String, String) {
    match (
        std::env::var("RECIPES_RESCUE_IMG"),
        std::env::var("RECIPES_RESCUE_PRIVKEY"),
    ) {
        (Ok(img), Ok(privkey)) => (img, privkey),
        _ => panic!(
            "deploy_rescue_smoke gate invoked (--ignored) without RECIPES_RESCUE_IMG + \
             RECIPES_RESCUE_PRIVKEY — set them to a built .img with a baked recovery pubkey (+ the \
             matching privkey, /dev/kvm), or run the gates via `make boot-gate`."
        ),
    }
}

/// Offline precompute (b): the rescue host-key fingerprint derived from the image's baked seed + its
/// dm-verity root hash — the operator's `~/.ssh/known_hosts` value. The booted rescue dropbear must
/// present this exact key (the foundation host-key-derivation crate's TOFU contract under a real boot).
/// `CARGO_BIN_EXE_orchard` is the test-built binary (with the `deploy` feature).
fn expected_rescue_fp(img: &str) -> String {
    let admin = env!("CARGO_BIN_EXE_orchard");
    let out = Command::new(admin)
        .args([
            "derive-rescue-offline",
            "--image",
            img,
            "--print-fingerprint",
        ])
        .output()
        .expect("run derive-rescue-host-keys --image --print-fingerprint");
    assert!(
        out.status.success(),
        "offline derive-rescue-host-keys failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find(|t| t.starts_with("SHA256:"))
        .expect("a SHA256: fingerprint in the offline derive output")
        .to_string()
}

#[test]
#[ignore = "boot gate: needs RECIPES_RESCUE_IMG + RECIPES_RESCUE_PRIVKEY + /dev/kvm; run via `make boot-gate`"]
fn rescue_bundle_activates_on_corrupt_persist() {
    let (img, privkey) = gate_env();
    let expected_fp = expected_rescue_fp(&img);
    orchard::deploy::dryrun::boot_rescue_and_verify(
        Path::new(&img),
        Path::new(&privkey),
        &expected_fp,
                                                     
        &orchard::ceremony::leg_registry::rescue_bundle_opts(),
    )
    .expect("rescue bundle should activate + verify on a corrupt /persist");
                                                                                                  
                                                                                                 
                                                               
    orchard::ceremony::gate_record::emit_leg_pass(
        Path::new(&img),
        "rescue_bundle_activates_on_corrupt_persist",
    )
    .expect("emit this leg's gate-record row");
}

#[test]
#[ignore = "boot gate: needs RECIPES_RESCUE_IMG + RECIPES_RESCUE_PRIVKEY + /dev/kvm; run via `make boot-gate`"]
fn rescue_activates_on_rc4_corrupt_persist() {
                                                                                                 
    let (img, privkey) = gate_env();
    let expected_fp = expected_rescue_fp(&img);
                                                                                                       
                                                                                                          
                                                                                             
                                                                           
    let opts = orchard::ceremony::leg_registry::rescue_rc4_opts();
    orchard::deploy::dryrun::boot_rc4_corrupt_persist_and_verify(
        Path::new(&img),
        Path::new(&privkey),
        &expected_fp,
        &opts,
    )
    .expect("rc=4-corrupt /persist must divert to rescue (prepare-persist e2fsck rc=4 branch)");
                                                                                                  
                                                                                                 
                                                               
    orchard::ceremony::gate_record::emit_leg_pass(
        Path::new(&img),
        "rescue_activates_on_rc4_corrupt_persist",
    )
    .expect("emit this leg's gate-record row");
}
