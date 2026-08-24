//! One-time builder for the reclaim-tail gate's DEFAULT-PROVISIONED Debian fixture (D-2 §9).
//!
//! Not a gate — it PRODUCES `debian-12-genericcloud-amd64+kexec+grown.qcow2`: the pinned base
//! with kexec-tools baked in, `cloud-initramfs-growroot` RETAINED, the disk grown to 12 GiB and
//! the root grown to fill it on first boot — the exact shape a default-provisioned VPS has, so
                                                                                    
//! `make e2e-grown-fixture` (needs outbound network for the one prep boot).

use std::path::PathBuf;

use orchard::deploy::prod_e2e::prepare_grown_fixture;

fn env_path_or_panic(key: &str) -> PathBuf {
    let raw = std::env::var(key).unwrap_or_else(|_| {
        panic!(
            "{key} is not set — this leg BUILDS the reclaim gate's grown Debian fixture and \
             needs RECIPES_PROD_E2E_DEBIAN_BASE (the pinned genericcloud qcow2) plus \
             RECIPES_GROWN_FIXTURE_OUT (where to write it). Run via `make e2e-grown-fixture`."
        )
    });
    PathBuf::from(raw)
}

#[test]
#[ignore = "fixture builder: needs RECIPES_PROD_E2E_DEBIAN_BASE + RECIPES_GROWN_FIXTURE_OUT + /dev/kvm + outbound network; run via `make e2e-grown-fixture`"]
fn builds_the_grown_default_provisioned_fixture() {
    let base = env_path_or_panic("RECIPES_PROD_E2E_DEBIAN_BASE");
    let out = env_path_or_panic("RECIPES_GROWN_FIXTURE_OUT");
    assert!(
        base.exists(),
        "the pinned Debian base does not exist: {}",
        base.display()
    );
    let sha = prepare_grown_fixture(&base, &out).expect("the grown fixture must build");
    println!("grown fixture written: {}", out.display());
    println!("grown fixture sha256:  {sha}");
    println!("point RECIPES_RECLAIM_E2E_DEBIAN_IMG at it for `make boot-gate-reclaim`");
    assert_eq!(sha.len(), 64, "sha256 hex must be 64 chars, got {sha:?}");
    assert!(
        out.metadata().expect("fixture metadata").len() > 0,
        "the fixture must not be empty"
    );
}
