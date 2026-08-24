                                                                              
//!
//! Not a gate — it asserts nothing about the box. It PRODUCES the input every other prod-e2e leg now
//! consumes: the operator's pinned Debian genericcloud base with `kexec-tools` pre-installed and
//! cloud-init reset. That is what lets [`orchard::deploy::prod_e2e::DebianE2eOpts::restrict_net`]
//! default to `true`, so a booted box can never place a live Let's Encrypt production order from the
//! operator's IP.
//!
//! `#[ignore]` + panics without its env, like every other operator-run leg in this crate. Run it via
//! `make e2e-kexec-fixture`; it needs outbound network (the one boot in this harness that does).

use std::path::PathBuf;

use orchard::deploy::prod_e2e::prepare_kexec_fixture;

fn env_path_or_panic(key: &str) -> PathBuf {
    let raw = std::env::var(key).unwrap_or_else(|_| {
        panic!(
            "{key} is not set — this leg BUILDS the prod-e2e Debian fixture and needs \
             RECIPES_PROD_E2E_DEBIAN_BASE (the pinned genericcloud qcow2) plus \
             RECIPES_KEXEC_FIXTURE_OUT (where to write it). Run via `make e2e-kexec-fixture`."
        )
    });
    PathBuf::from(raw)
}

#[test]
#[ignore = "fixture builder: needs RECIPES_PROD_E2E_DEBIAN_BASE + RECIPES_KEXEC_FIXTURE_OUT + /dev/kvm + outbound network; run via `make e2e-kexec-fixture`"]
fn builds_the_hermetic_prod_e2e_kexec_fixture() {
    let base = env_path_or_panic("RECIPES_PROD_E2E_DEBIAN_BASE");
    let out = env_path_or_panic("RECIPES_KEXEC_FIXTURE_OUT");

    assert!(
        base.exists(),
        "the pinned Debian base does not exist: {}",
        base.display()
    );

    let sha = prepare_kexec_fixture(&base, &out).expect("the kexec fixture must build");

                                                                                                    
                                                                                                    
                                                                              
    println!("kexec fixture written: {}", out.display());
    println!("kexec fixture sha256:  {sha}");
                                                                                            
                                                                                                        
                                                                                                   
                           
    println!(
        "point RECIPES_PROD_E2E_DEBIAN_IMG at it for `make boot-gate`, \
         `make boot-gate-prod-weights` and `make boot-gate-seabios-gpt-e2e`"
    );

    assert_eq!(sha.len(), 64, "sha256 hex must be 64 chars, got {sha:?}");
    assert!(
        out.metadata().expect("fixture metadata").len() > 0,
        "the fixture must not be empty"
    );
}
