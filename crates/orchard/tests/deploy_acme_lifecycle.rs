                                                                                                  
//! watcher on a REAL from-pins recipes box.
//!
                                                                                               
//! default `cargo test` it reports "ignored" (honest); it runs only under `--ignored` (via
//! `make boot-gate-acme`), where a MISSING env PANICS rather than silently passing — so there is no
//! invocation in which this gate reports success without asserting the produced bytes.
//!
//! Build the `.img` first (a from-pins REFERENCE recipes box carrying the re-pinned fb-acme +
//! fb-oneshots + the periodic_loop service-manifest):
//!   cargo run -p orchard -- build --domain recipes.test \
//!     --operator-pubkey <key.pub> --recovery-pubkey <key.pub> \
//!     --net 'mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3' --out-dir <dir>
//! then RECIPES_ACME_IMG=<dir>/<img>.img cargo test -p orchard --test deploy_acme_lifecycle -- --ignored.

use std::path::Path;

#[test]
#[ignore = "boot gate: needs RECIPES_ACME_IMG + /dev/kvm + host openssl; run via `make boot-gate-acme`"]
fn acme_cert_lifecycle_on_produced_bytes() {
    let Ok(img) = std::env::var("RECIPES_ACME_IMG") else {
        panic!(
            "acme-lifecycle gate invoked (--ignored) without RECIPES_ACME_IMG — set it to a built \
             reference `.img` (+ /dev/kvm + host openssl), or run via `make boot-gate-acme`. A boot \
             gate must never pass without asserting the produced bytes."
        );
    };
    orchard::deploy::dryrun::boot_acme_lifecycle_and_verify(
        Path::new(&img),
        &orchard::deploy::dryrun::DryrunOpts::default(),
    )
    .expect("the ACME cert lifecycle must hold on produced bytes (watcher /3/8 + renewer)");
}
