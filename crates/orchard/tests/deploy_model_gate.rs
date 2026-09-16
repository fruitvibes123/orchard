                                                                                                    
//! PRODUCED BYTES.
//!
//! `#[ignore]` + env-gated: under the default `cargo test` these report "ignored" (honest); under
//! `--ignored` (via `make boot-gate-hotswap`) a MISSING env PANICS rather than silent-passing — so
//! there is no invocation in which a hotswap gate reports success without asserting the produced
                                              
//!
//! The `.img` is a `--firmware seabios-gpt --weights-anchor runtime --manifest
//! crates/image-builder/hotswap-tenant.toml` build (the models.toml-pinned GGUF baked as the
//! initial model, the signed weights record in the persist skeleton, NO `fb.weights-*` cmdline).
//! Build ceremony (the key snapshot is what arms the below-floor negative):
//!
//!   orchard generate-keys --artifact-signing --out <keys>   # or reuse a set; then:
//!   cp -r <keys> <keys-old>                                 # snapshot the OLDER Weights ctr
//!   sleep 2 && orchard redelegate --purpose weights --keys-dir <keys>   # bump the ctr
//!   cargo run -p orchard -- build --dha-weights-gguf <models.toml-pinned gguf> \
//!     --firmware seabios-gpt --weights-anchor runtime --domain hotswap.test \
//!     --manifest crates/image-builder/hotswap-tenant.toml --keys-dir <keys> \
//!     --operator-pubkey <ssh>.pub --recovery-pubkey <ssh>.pub \
//!     --net "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3" --out-dir <dir> --allow-dirty
//!
//! Run:
//!   RECIPES_HOTSWAP_IMG=<dir>/<img>.img RECIPES_HOTSWAP_PRIVKEY=<ssh-key> \
//!   RECIPES_HOTSWAP_KEYS_DIR=<keys> RECIPES_HOTSWAP_KEYS_OLD_DIR=<keys-old> \
//!   RECIPES_HOTSWAP_PUSH_GGUF=<a DIFFERENT, smaller gguf> \
//!     cargo test -p orchard --test deploy_model_gate -- --ignored   (or `make boot-gate-hotswap`)

use orchard::deploy::dryrun::{DryrunOpts, HotswapGateEnv};
use std::path::PathBuf;

/// The bench VM: Σ (768 MiB, hotswap-tenant.toml) + BOX_RESERVE (256) ≤ 1536 MiB. The INSTALLER
/// phase sizes itself up from the image bytes (the harness does that internally).
fn hotswap_opts() -> DryrunOpts {
    DryrunOpts {
        memory_mb: 1536,
        ..Default::default()
    }
}

fn hotswap_env() -> HotswapGateEnv {
    let var = |name: &str| -> PathBuf {
        match std::env::var_os(name) {
            Some(v) => PathBuf::from(v),
            None => panic!(
                "hotswap boot-gate invoked (--ignored) without {name} — set RECIPES_HOTSWAP_IMG + \
                 RECIPES_HOTSWAP_PRIVKEY + RECIPES_HOTSWAP_KEYS_DIR + RECIPES_HOTSWAP_KEYS_OLD_DIR \
                 + RECIPES_HOTSWAP_PUSH_GGUF (see the module doc for the build ceremony), or run \
                 via `make boot-gate-hotswap`. A boot gate must never pass without asserting the \
                 produced bytes."
            ),
        }
    };
    HotswapGateEnv {
        img: var("RECIPES_HOTSWAP_IMG"),
        operator_privkey: var("RECIPES_HOTSWAP_PRIVKEY"),
        keys_dir: var("RECIPES_HOTSWAP_KEYS_DIR"),
        keys_old_dir: var("RECIPES_HOTSWAP_KEYS_OLD_DIR"),
        push_gguf: var("RECIPES_HOTSWAP_PUSH_GGUF"),
        container_image: std::env::var("RECIPES_HOTSWAP_CONTAINER_IMAGE")
            .unwrap_or_else(|_| "recipes-imgbuild:dev".to_string()),
    }
}

                                                                                                
                                                                                                 
                                                                                                
/// `deploy-model` ceremony commits a different model, uptime-continuous, health-inference-gated) +
                                                                                              
/// Rider 3 (a clean reboot serves the PUSHED model from the persisted record).
#[test]
#[ignore = "boot gate: needs RECIPES_HOTSWAP_* env + /dev/kvm + docker; run via `make boot-gate-hotswap`"]
fn hotswap_box_swaps_models_without_reboot_and_persists() {
    let env = hotswap_env();
    orchard::deploy::dryrun::install_hotswap_and_verify_swaps(&env, &hotswap_opts())
        .expect("the v4 box must run the whole swap battery (2/3a/4/5/6/8/9/11 + Rider 3)");
}

                                                                                                    
                                                                                                   
                                                                                                
/// the engine down, never rescue/brick).
#[test]
#[ignore = "boot gate: needs RECIPES_HOTSWAP_* env + /dev/kvm + docker; run via `make boot-gate-hotswap`"]
fn hotswap_box_degrades_visibly_and_recovers_from_torn_state() {
    let env = hotswap_env();
    orchard::deploy::dryrun::install_hotswap_torn_and_verify_recovery(&env, &hotswap_opts())
        .expect("the v4 box must degrade visibly and recover from the torn state (7/10)");
}

/// Leg 3 — the deterministic crash-injection battery (spec Component B): SIGKILL the swap at each
/// PausePoint on a fresh bench box, assert the point's postcondition (AC-B2..B5), and prove the
/// plain re-push recovers to COMMITTED each time.
#[test]
#[ignore = "boot gate: needs RECIPES_HOTSWAP_* env + /dev/kvm + docker; run via `make boot-gate-hotswap`"]
fn hotswap_box_survives_deterministic_crash_injection_at_every_pause_point() {
    let env = hotswap_env();
    orchard::deploy::dryrun::install_hotswap_crash_injection_and_verify_recovery(
        &env,
        &hotswap_opts(),
    )
    .expect("the v4 box must survive SIGKILL at all four pause points (AC-B2..B5)");
}
