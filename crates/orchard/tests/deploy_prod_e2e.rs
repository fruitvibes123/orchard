                                                                                              
//!
//! The PRODUCED-BYTES proof for the operator ceremony: it boots the Debian fixture under QEMU, lets
//! cloud-init inject an ephemeral provisioning key, then drives the REAL
//! [`orchard::deploy::prod_orchestrate::deploy_prod`] (hardened ssh/scp/ssh-keyscan/kexec over a
//! forwarded port) to a kexec-takeover install of the box `.img`, and asserts the step-10 crypto
//! identity passed over the derived-fingerprint-pinned reconnect (acceptance #1) plus the two
//! fail-closed negatives (acceptance #2/#4). Since `e19d240` the guest runs HERMETIC and
                                                                                             
//!
//! Deploy-feature-gated AND env-gated (heavy: a nested Debian boot + a full box install + two
//! reboots). SKIPPED unless ALL of these are set:
//!   RECIPES_PROD_IMG           — a box `.img` built with `--operator-pubkey <op.pub>` AND
//!                                `--net "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3"`
//!                                (the QEMU user-net addressing — same image the `deploy_prod_qemu`
//!                                gate uses), with its sidecars + `<stem>.vmlinuz`/`.initramfs` beside it.
//!   RECIPES_PROD_PRIVKEY       — the matching operator private key (its `.pub` is the baked key).
//!   RECIPES_PROD_E2E_DEBIAN_IMG — the Debian kexec fixture built by `prepare_kexec_fixture`
//!                                (`make e2e-kexec-fixture`): kexec-tools pre-installed,
                                                                                                 
//!                                the harness overlays it copy-on-write, never mutating the base.
//! Optional: RECIPES_PROD_E2E_LOGDIR — a dir the console logs survive into (else a tempdir).
//!
                                                                                      
//! RECIPES_PROD_WEIGHTS_PRIVKEY — because it needs the PRODUCTION co-tenant `.img` (seabios-gpt,
//! 1804 MiB, weights volume) while the two legs above run a plain reference box. One env cannot be
//! both, so the reference legs run under `make boot-gate` and the weights leg under
//! `make boot-gate-prod-weights`.
//!
//! All tests are `#[ignore]` (runner-visible skip, NEVER a false green — phase-4 holistic M-α); under
//! `--ignored` a missing env PANICS rather than silent-passing.
//!
//! UNATTENDED-RUN contract: the three tests are parallel-safe (distinct forward ports 2222/2224/2226 +
//! per-test console-log names) and read NO real stdin (the harness pins the ceremony
//! non-interactive — token-only wipe gate + explicit fingerprint pins), so no `--test-threads=1`
//! and no piped-stdin workaround is needed.

use orchard::deploy::dryrun::{ProdWeightsProof, weights_proof_for_manifest};
use orchard::deploy::prod_e2e::{
    DebianE2eOpts, PROD_E2E_GUEST_DISK_BYTES, PROD_INSTALL_RAM_MIB, run_debian_kexec_takeover_e2e,
    run_negative_paths_e2e,
};
use std::path::{Path, PathBuf};

                                                                                                     
/// weights-payload floor. Named here so the gate compares against the pins the image was BUILT from.
const PROD_MANIFEST: &str = "crates/image-builder/prod-cotenant.toml";

/// The payload floor for the PROD profile, resolved from the repo's committed pins at gate time.
/// Panics (this is a `--ignored` gate leg) rather than silently degrading to no floor — a gate must
/// never weaken its own assertion because a lookup failed.
fn prod_weights_proof() -> ProdWeightsProof {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root (crates/orchard → two parents up)");
    weights_proof_for_manifest(repo_root, Path::new(PROD_MANIFEST))
        .expect("the prod co-tenant manifest must resolve a models.toml pin profile")
}

/// Read one required env path. Panics (under `--ignored`) if unset, so a gate never reports success
/// without asserting the produced bytes.
fn get_or_panic(which: &str, key: &str) -> PathBuf {
                                                                                                
                                                                                      
    std::env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "deploy_prod_e2e {which} gate invoked (--ignored) without {key} — see the module \
                 doc-comment for this leg's required env, and run the gates via `make boot-gate` / \
                 `make boot-gate-prod-weights`. A boot gate must never pass without asserting."
            )
        })
}

fn log_dir_for(box_img: &Path) -> PathBuf {
    std::env::var_os("RECIPES_PROD_E2E_LOGDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| box_img.parent().unwrap_or(Path::new(".")).to_path_buf())
}

/// The REFERENCE-box legs' artifacts (acceptance #1 + the negatives): `RECIPES_PROD_IMG` +
/// `RECIPES_PROD_PRIVKEY` + the pinned Debian guest.
fn env_or_panic(which: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let box_img = get_or_panic(which, "RECIPES_PROD_IMG");
    let operator_privkey = get_or_panic(which, "RECIPES_PROD_PRIVKEY");
    let debian_img = get_or_panic(which, "RECIPES_PROD_E2E_DEBIAN_IMG");
    let log_dir = log_dir_for(&box_img);
    (box_img, operator_privkey, debian_img, log_dir)
}

                                                                                                    
///
/// It must: the reference legs run a plain 3-component box, while this leg needs the PRODUCTION
/// co-tenant image (seabios-gpt, 1804 MiB, weights volume). Sharing `RECIPES_PROD_IMG` across all three
/// made them mutually exclusive — one `make boot-gate` invocation could only ever satisfy one kind of
/// leg, and the weights assertions would run against whichever image happened to be exported.
fn weights_env_or_panic() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let which = "ac13-prod-image-over-ram";
    let box_img = get_or_panic(which, "RECIPES_PROD_WEIGHTS_IMG");
    let operator_privkey = get_or_panic(which, "RECIPES_PROD_WEIGHTS_PRIVKEY");
    let debian_img = get_or_panic(which, "RECIPES_PROD_E2E_DEBIAN_IMG");
    let log_dir = log_dir_for(&box_img);
    (box_img, operator_privkey, debian_img, log_dir)
}

/// Acceptance #1 — the happy-path Debian-guest kexec-takeover. Green = the ceremony's `Ok` (its
/// step-10 verity-root-hash + boot-fs-prefix + liveness verdict) AND the harness's independent
/// post-condition probe agree (a fresh operator-key ssh on a harness-built pin asserting the
                                                                                              
#[test]
#[ignore = "boot gate: needs RECIPES_PROD_IMG + RECIPES_PROD_PRIVKEY + RECIPES_PROD_E2E_DEBIAN_IMG + /dev/kvm; run via `make boot-gate`"]
fn debian_guest_kexec_takeover_installs_the_box_and_identity_passes() {
    let (box_img, operator_privkey, debian_img, log_dir) = env_or_panic("happy-path");
    run_debian_kexec_takeover_e2e(
        &box_img,
        &operator_privkey,
        &debian_img,
        &DebianE2eOpts::default(),
        &log_dir,
        None,                                                         
    )
    .expect("the Debian-guest kexec-takeover should install the box + pass step-10 identity");
}

                                                                                                      
/// prod co-tenant image (the Qwen3-VL-2B pair in its weights volume, 1804 MiB) installed onto a
/// Debian guest with **2048 MiB** RAM. RECIPES_PROD_WEIGHTS_IMG must be that image, so the operator's
/// REAL `deploy_prod` (stream the .img onto the raw tail window, sibling re-verify, `iflag=direct`
/// window readback, kexec) installs it without image-sized RAM — precisely what the retired
                                                   
///
/// NOTE the image is SMALLER than the guest (measured: 1804.4 MiB vs 2048.0), so the proof is not the
/// naive `image > RAM` — it is that the image cannot be BUFFERED whole: 1804.4 + the 256 MiB installer
/// minimum = 2060.4 > 2048.0, by only 12.4 MiB. The harness guard fails closed on that plus the
/// weights-payload floor against the pinned profile, so a bench fixture or a resized guest cannot green
/// this leg. The window-sha corroboration remains
                                                                                                    
/// 2226 to keep its hostfwd bind clear of the happy (2222) + negatives (2224) legs.
#[test]
#[ignore = "boot gate: needs RECIPES_PROD_WEIGHTS_IMG (the prod co-tenant .img) + RECIPES_PROD_WEIGHTS_PRIVKEY + RECIPES_PROD_E2E_DEBIAN_IMG + /dev/kvm; run via `make boot-gate-prod-weights`"]
fn deploy_prod_e2e_installs_the_prod_weights_image_unbufferable_in_guest_ram() {
    let (box_img, operator_privkey, debian_img, log_dir) = weights_env_or_panic();
    run_debian_kexec_takeover_e2e(
        &box_img,
        &operator_privkey,
        &debian_img,
        &DebianE2eOpts {
            forward_port: 2226,
                                                                      
            memory_mb: PROD_INSTALL_RAM_MIB,
                                                                                                  
                                                                                                   
                                                   
            weights_proof: Some(prod_weights_proof()),
                                                                                                     
                                                                                                 
                                                                                                 
            guest_disk_bytes: Some(PROD_E2E_GUEST_DISK_BYTES),
                                                                                                          
            guest_boot_timeout: std::time::Duration::from_secs(600),
            reconnect_timeout_secs: 900,
                                                                                                     
                                                                                                
                                                                                               
                                                                                           
            restrict_net: true,
            ..DebianE2eOpts::default()
        },
        &log_dir,
        Some("seabios-gpt"),                                         
    )
    .expect(
        "the streaming ceremony must install the prod weights image (unbufferable in guest RAM)",
    );
}

/// Acceptance #2/#4 — both fail-closed negatives over the real ops: a mismatched `--host-fingerprint`
/// (Leg A) and a wrong `--runtime-hostkey-fingerprint` (Leg B) each abort before any byte is staged,
/// with the guest left untouched on its Debian root.
#[test]
#[ignore = "boot gate: needs RECIPES_PROD_IMG + RECIPES_PROD_PRIVKEY + RECIPES_PROD_E2E_DEBIAN_IMG + /dev/kvm; run via `make boot-gate`"]
fn deploy_prod_e2e_fails_closed_on_bad_host_and_runtime_fingerprints() {
    let (box_img, operator_privkey, debian_img, log_dir) = env_or_panic("negatives");
    run_negative_paths_e2e(
        &box_img,
        &operator_privkey,
        &debian_img,
                                                                                                
                                                                                                 
        &DebianE2eOpts {
            forward_port: 2224,
            ..DebianE2eOpts::default()
        },
        &log_dir,
    )
    .expect("both fail-closed negatives should abort pre-kexec with the guest untouched");
}
