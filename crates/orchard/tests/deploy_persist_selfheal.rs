//! Persist trust-file self-heal boot-gate (plan Task 5, Legs C+D) — the produced-bytes proof of the
                                                 
//!
                                                                                       
//! default `cargo test` it reports "ignored" (honest); it runs only under `--ignored` (via
//! `make boot-gate-persist`), where a MISSING env PANICS rather than silently passing — so there is
//! no invocation in which this gate reports success without asserting the produced bytes.
//!
//! Build the `.img` first (a from-pins reference recipes box carrying the persist-selfheal
//! recipes-app + recipes-admin + fb-oneshots), then:
//!   RECIPES_PERSIST_IMG=<dir>/<img>.img cargo test -p orchard --test deploy_persist_selfheal -- --ignored

use std::path::Path;

#[test]
#[ignore = "boot gate: needs RECIPES_PERSIST_IMG + /dev/kvm + host openssl; run via `make boot-gate-persist`"]
fn persist_selfheal_on_produced_bytes() {
    let Ok(img) = std::env::var("RECIPES_PERSIST_IMG") else {
        panic!(
            "persist self-heal gate invoked (--ignored) without RECIPES_PERSIST_IMG — set it to a \
             built reference `.img` (+ /dev/kvm + host openssl), or run via `make boot-gate-persist`. \
             A boot gate must never pass without asserting the produced bytes."
        );
    };
    orchard::deploy::dryrun::boot_persist_selfheal_and_verify(
        Path::new(&img),
        &orchard::deploy::dryrun::DryrunOpts::default(),
    )
    .expect(
        "the persist trust-file self-heal must hold on produced bytes (Leg C full.pem + Leg D ca.crt)",
    );
}
