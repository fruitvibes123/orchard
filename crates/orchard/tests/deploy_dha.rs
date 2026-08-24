                                                                                        
//!
//! `#[ignore]` + env-gated (`RECIPES_DHA_IMG` + `RECIPES_DHA_PRIVKEY` + `/dev/kvm`): under the default
//! `cargo test` these report "ignored" (honest); under `--ignored` (via `make boot-gate-dha`) a MISSING
//! env PANICS rather than silent-passing — so there is no invocation in which a dha gate reports success
                                                                            
//!
//! The `.img` is a `--firmware seabios-gpt --manifest crates/image-builder/dha-tenant.toml` build with
//! `RECIPES_DHA_WEIGHTS_GGUF` set (bakes the 5th GPT weights partition). The tenant is the REAL
//! creatine/dha-orchestrator/epa (dha's 2nd supply-chain tenant): the gate proves the BOX mechanism
//! (cgroup Σ-ceiling + precise `work/` delegation + s6-permafailon restart-cap + the RO dm-verity weights
                                                                                                            
//! §2 intake probe (H2/Option-A) + the S-INTAKE-WIRE §7 AC-I1..I11 suite (which GATE on dha's published
//! bins + staged scripts, so this whole gate needs dha's publish before it goes green).
//!
//! Run:
//!   RECIPES_DHA_IMG=<dir>/<img>.img RECIPES_DHA_PRIVKEY=<operator-key> \
//!     cargo test -p orchard --test deploy_dha -- --ignored   (or `make boot-gate-dha`)

use std::path::Path;

/// The dha gate boots the VM at the box's PROD RAM — 2048 MiB (2026-07-24 directive: gate at the prod
/// memory config, NEVER the 3B/1536 scenario). box-init's admission predicate is
/// `Σ + BOX_RESERVE(512 MiB, `box-init/src/cgroup.rs:27`) ≤ MemTotal`; this tenant's Σ is 256 MiB, so
/// 256 + 512 = 768 MiB clears the ~1939 MiB MemTotal of a 2 GiB box with wide margin, keeping the F2
/// ancestor-Σ OOM cgroup-scoped rather than global.
///
                                                                                                       
/// A revision of this cycle briefly pointed the `dha-tenant` pin profile at the production VL pair and
                                                                                                      
/// F2 (`assert_ancestor_sigma_survival`) requires a LIVE creatine, and a 1.03 GiB model under this
/// manifest's 128 MiB `oom_group` engine leaf is an untested regime. This gate's job is BOX MECHANISM;
                                                                                                      
/// against the real production image.
fn dha_opts() -> orchard::deploy::dryrun::DryrunOpts {
    orchard::deploy::dryrun::DryrunOpts {
        memory_mb: 2048,
        ..Default::default()
    }
}

fn dha_env() -> (String, String) {
    let (Ok(img), Ok(privkey)) = (
        std::env::var("RECIPES_DHA_IMG"),
        std::env::var("RECIPES_DHA_PRIVKEY"),
    ) else {
        panic!(
            "dha boot-gate invoked (--ignored) without RECIPES_DHA_IMG + RECIPES_DHA_PRIVKEY — set them \
             to a `--firmware seabios-gpt --manifest crates/image-builder/dha-tenant.toml` .img (built \
             with RECIPES_DHA_WEIGHTS_GGUF set) + its operator private key, or run via `make \
             boot-gate-dha`. A boot gate must never pass without asserting the produced bytes."
        );
    };
    (img, privkey)
}

/// F1–F4 on a CLEAN dha `.img`: the controller is present (F1); a simulated aggregate-Σ breach leaves
/// `dha-orchestrator` supervised-up + the box alive with the OOM cgroup-scoped (F2); the dha uid cannot
/// exceed `cgroup.max.descendants` (F3); a capped longrun killed ≥N×/window goes permanently down via
/// s6-permafailon (F4). One boot, sequential SSH assertions (F4 last — it takes the orchestrator down).
#[test]
#[ignore = "boot gate: needs RECIPES_DHA_IMG + RECIPES_DHA_PRIVKEY + /dev/kvm; run via `make boot-gate-dha`"]
fn dha_box_confines_the_tenant_and_survives_a_runaway() {
    let (img, privkey) = dha_env();
    orchard::deploy::dryrun::install_dha_disk_and_verify(
        Path::new(&img),
        Path::new(&privkey),
        &dha_opts(),
    )
    .expect("the dha box must confine the tenant + survive the ancestor-Σ runaway (F1–F4)");
}

/// F5 on a WEIGHTS-TAMPERED dha `.img`: one offline-corrupted weights block yields dm-verity DEFAULT-mode
/// EIO to a reader while the box BOOTS (no `restart_on_corruption` boot-loop — H-R4-1) and stays up in
/// the normal runtime (NOT rescue). A SEPARATE `.img` staging (corrupt-then-install), hence a separate leg.
#[test]
#[ignore = "boot gate: needs RECIPES_DHA_IMG + RECIPES_DHA_PRIVKEY + /dev/kvm; run via `make boot-gate-dha`"]
fn dha_corrupt_weights_yields_eio_and_the_box_survives() {
    let (img, privkey) = dha_env();
    orchard::deploy::dryrun::install_dha_weights_tamper_and_verify_survival(
        Path::new(&img),
        Path::new(&privkey),
        &dha_opts(),
    )
    .expect(
        "a corrupt weights block must EIO (dm-verity default mode) and the box must stay up (F5)",
    );
}
