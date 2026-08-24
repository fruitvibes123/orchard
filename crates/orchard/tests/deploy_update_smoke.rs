                                                                                         
//!
//! Env-gated AND `#[ignore]`d (heavy: two built seabios-gpt `.img`s + four greenfield installs + ~a
//! dozen QEMU boots incl. the multi-boot A/B commit + rollback dances; needs /dev/kvm + docker). ONE
//! `#[test]` by design — the Makefile's fail-closed guard greps `"test result: ok. 1 passed"`; splitting
//! into more `#[test]`s without bumping that guard fail-closed-blocks the whole boot gate.
//!
//! It proves on PRODUCED BYTES — the REAL installed box, the REAL `fb-update apply`/`fb-mark-good`, the
//! REAL `SeabiosGptSelector` block-device I/O (raw slot write + re-read verify, e2fsck-gated boot-fs
//! mount, on-disk ADV arm/clear, the udev-free PARTUUID resolve) — the §7 battery: G1 happy E2E (commit,
//! idempotent re-commit, durable-across-clean-reboot); the G5 refusal battery (wrong-key, tampered,
//! below-floor, wrong-firmware, truncated each refuse, box un-promoted, then a valid v2 still applies);
//! G3 bad-root_hash → panic=10 rollback (plus G2 panic mechanism, G6 durability, G9(i) retry); G7
//! unloadable kernel → NOESCAPE fallthrough to v1. (The G4/G8/G9(ii)/S4-M1-produced residuals — each
//! needing a bespoke broken bake — are named in `update_seabios.rs`'s module doc; not silently capped.)
//!
//! Build the TWO seabios-gpt `.img`s (same operator SSH key + net; version 1 installed, version 2
//! streamed) + an artifact key set carrying the UpdateImage delegation, then point the gate at them:
//!   orchard generate-keys --artifact-signing software --output-dir <keys>     # or reuse a deploy set +
//!   orchard redelegate --keys-dir <keys>                                       #   `redelegate` for it
//!   orchard build --firmware seabios-gpt --domain box.test --image-version 1 --keys-dir <keys> \
//!     --operator-pubkey <op.pub> --net "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3" \
//!     --out-dir <v1> --allow-dirty
//!   orchard build ... --image-version 2 ... --out-dir <v2>
//!   RECIPES_UPDATE_V1_IMG=<v1>/<img>.img RECIPES_UPDATE_V2_IMG=<v2>/<img>.img \
//!     RECIPES_UPDATE_PRIVKEY=<op> RECIPES_UPDATE_KEYS_DIR=<keys> \
//!     cargo test -p orchard --test deploy_update_smoke -- --ignored --nocapture
//! (each `.img`'s sibling `<stem>.layout.toml` + `<stem>.vmlinuz` + `<stem>.initramfs` must sit beside
//! it; KVM at /dev/kvm; RECIPES_UPDATE_KEYS_DIR is the artifact key set the .imgs were built with — its
//! root is v1's baked box anchor). Operator-run via `make boot-gate-update`; never a false green.

use std::path::Path;

                                                                                                        
/// and run only via `--ignored` (`make boot-gate-update`); a missing env there is an operator error,
/// never a silent pass — a boot gate must never report success without asserting the produced bytes.
fn gate_env() -> (String, String, String, String, String) {
    match (
        std::env::var("RECIPES_UPDATE_V1_IMG"),
        std::env::var("RECIPES_UPDATE_V2_IMG"),
        std::env::var("RECIPES_UPDATE_V2_UNHEALTHY_IMG"),
        std::env::var("RECIPES_UPDATE_PRIVKEY"),
        std::env::var("RECIPES_UPDATE_KEYS_DIR"),
    ) {
        (Ok(v1), Ok(v2), Ok(unhealthy), Ok(privkey), Ok(keys_dir)) => {
            (v1, v2, unhealthy, privkey, keys_dir)
        }
        _ => panic!(
            "deploy_update_smoke gate invoked (--ignored) without RECIPES_UPDATE_V1_IMG + \
             RECIPES_UPDATE_V2_IMG + RECIPES_UPDATE_V2_UNHEALTHY_IMG + RECIPES_UPDATE_PRIVKEY + \
             RECIPES_UPDATE_KEYS_DIR — set them to three seabios-gpt .imgs (v1 = --image-version 1; v2 = \
             --image-version 2; v2-unhealthy = --image-version 2 --manifest <probe port closed>), all \
             --operator-pubkey + --net, the matching SSH privkey, and the artifact keys-dir the .imgs \
             were baked with (UpdateImage delegation present; /dev/kvm), or run via \
             `make boot-gate-update`. A boot gate must never pass without asserting."
        ),
    }
}

#[test]
#[ignore = "boot gate: needs RECIPES_UPDATE_{V1_IMG,V2_IMG,V2_UNHEALTHY_IMG,PRIVKEY,KEYS_DIR} + /dev/kvm; run via `make boot-gate-update`"]
fn ab_update_cycle_on_produced_bytes() {
    let (v1, v2, unhealthy, privkey, keys_dir) = gate_env();
    orchard::deploy::dryrun::install_update_and_verify(
        Path::new(&v1),
        Path::new(&v2),
        Path::new(&unhealthy),
        Path::new(&privkey),
        Path::new(&keys_dir),
        &orchard::deploy::dryrun::DryrunOpts::default(),
    )
    .expect(
        "the A/B update battery must pass on produced bytes: G1 (apply v2 → BOOTONCE → mark-good \
         commit → durable), the G5 refusal battery (each refuses, box un-promoted, then a valid v2 \
         applies), G3 (bad root_hash → panic=10 rollback → v1, durable, retry-accepts), G7 (unloadable \
         kernel → NOESCAPE → v1), and G4 (unhealthy tenant → fb-mark-good deadline reboot() → v1)",
    );
}
