                                                                                                   
//!
//! The one genuinely-new produced-bytes proof for the GPT arm. The installer's GPT byte-path is already
//! proven by `make boot-gate-seabios-gpt`, and the MBR kexec-orchestration by `deploy_prod_e2e`; this
//! closes the one uncovered cell — GPT × kexec-orchestration — by driving the REAL `deploy_prod` to a
//! kexec-takeover install of a `--firmware seabios-gpt` .img and asserting step-10 identity (the
//! verbatim boot-fs compare) over the derived-fingerprint-pinned reconnect, plus that the booted box's
//! /proc/cmdline carries `fb.firmware=seabios-gpt` (a mis-wired firmware env cannot false-green it).
//!
//! SEPARATE test binary (not folded into `deploy_prod_e2e`) so the proven MBR `make boot-gate` run stays
                                                                                                    
//! independently. Run via `make boot-gate-seabios-gpt-e2e`. `#[ignore]`d (never a false green; a missing
//! env PANICS under `--ignored`).
//!
//! SKIPPED unless ALL of these are set:
//!   RECIPES_SEABIOSGPT_PROD_E2E_IMG     — a `--firmware seabios-gpt` box .img built with
//!                                         --operator-pubkey + --net (QEMU user-net addressing), with its
//!                                         sidecars + <stem>.vmlinuz/.initramfs beside it.
//!   RECIPES_SEABIOSGPT_PROD_E2E_PRIVKEY — the matching operator private key.
//!   RECIPES_PROD_E2E_DEBIAN_IMG         — a pinned Debian generic-cloud qcow2 (shared with the MBR e2e).
//! Optional: RECIPES_PROD_E2E_LOGDIR.

use orchard::deploy::prod_e2e::{DebianE2eOpts, run_debian_kexec_takeover_e2e};
use std::path::PathBuf;

/// The three required artifacts + the log dir. Panics (under `--ignored`) if any env is unset, so the
/// gate never reports success without asserting the produced bytes.
fn env_or_panic() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let get = |k: &str| -> PathBuf {
                                                                                                       
                                                                                       
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                panic!(
                    "deploy_prod_seabios_gpt_e2e gate invoked (--ignored) without {k} — set \
                     RECIPES_SEABIOSGPT_PROD_E2E_IMG (a --firmware seabios-gpt box .img built with \
                     --operator-pubkey + --net), RECIPES_SEABIOSGPT_PROD_E2E_PRIVKEY (matching operator \
                     key), and RECIPES_PROD_E2E_DEBIAN_IMG (a pinned Debian generic-cloud qcow2), with \
                     docker + /dev/kvm; or run via `make boot-gate-seabios-gpt-e2e`. A boot gate must \
                     never pass without asserting."
                )
            })
    };
    let box_img = get("RECIPES_SEABIOSGPT_PROD_E2E_IMG");
    let operator_privkey = get("RECIPES_SEABIOSGPT_PROD_E2E_PRIVKEY");
    let debian_img = get("RECIPES_PROD_E2E_DEBIAN_IMG");
    let log_dir = std::env::var_os("RECIPES_PROD_E2E_LOGDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            box_img
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf()
        });
    (box_img, operator_privkey, debian_img, log_dir)
}

                                                                                                 
/// verity-root-hash + VERBATIM boot-fs-prefix + liveness verdict over the derived-fingerprint-pinned
/// reconnect) AND the harness post-condition probe (harness-recomputed root hash + `fb.firmware=seabios-gpt`).
#[test]
#[ignore = "boot gate: needs RECIPES_SEABIOSGPT_PROD_E2E_IMG + _PRIVKEY + RECIPES_PROD_E2E_DEBIAN_IMG + /dev/kvm; run via `make boot-gate-seabios-gpt-e2e`"]
fn debian_guest_kexec_takeover_installs_the_seabios_gpt_box_and_identity_passes() {
    let (box_img, operator_privkey, debian_img, log_dir) = env_or_panic();
    run_debian_kexec_takeover_e2e(
        &box_img,
        &operator_privkey,
        &debian_img,
        &DebianE2eOpts::default(),
        &log_dir,
        Some("seabios-gpt"),
    )
    .expect(
        "the seabios-gpt Debian-guest kexec-takeover should install the box + pass step-10 identity + \
         carry fb.firmware=seabios-gpt",
    );
}
