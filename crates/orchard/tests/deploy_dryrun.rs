                                                        
//!
//! Deploy-feature-gated (the deploy modules live in the orchard crate) AND
//! env-gated: the boot is heavy (needs KVM + a built `.img`), so it's SKIPPED unless
//! `RECIPES_DRYRUN_IMG` points at a built image. Building an image in-test is ~14min — so the
//! operator-facing `orchard dryrun` (which builds, then boots, then verifies) and this
//! test share the same `boot_and_verify` core, but the test feeds it a PRE-built img.
//!
//! Run it: `RECIPES_DRYRUN_IMG=/tmp/box-out/<image>.img cargo test -p orchard --test deploy_dryrun`
//! (the sibling `<image>.layout.toml` must be present; KVM at /dev/kvm).

use std::path::Path;

/// The runtime contract `deploy dryrun` verifies (spec Phase-3 row): the image boots to a working
/// runtime — dropbear accepts the operator pubkey, recipes answers an HTTP probe, the rootfs is ro.
                                                                                                       
                                                                                                      
                                                                                                     
                                                                                                           
                      
#[test]
#[ignore = "boot gate: needs RECIPES_DRYRUN_IMG + /dev/kvm; run via `make boot-gate`, not `make verify`"]
fn dryrun_boots_to_working_runtime() {
    let Ok(img) = std::env::var("RECIPES_DRYRUN_IMG") else {
        panic!(
            "deploy_dryrun gate invoked (--ignored) without RECIPES_DRYRUN_IMG — set it to a built .img \
             (+ /dev/kvm), or run the gates via `make boot-gate`. A boot gate must never pass without \
             asserting the produced bytes."
        );
    };
                                                                                                          
                                                                                                         
                                                                                                         
                                                                                                 
    use recipes_image_builder::artifact_store::{ArtifactStore, DirStore};
    use recipes_image_builder::pin_manifest::PinManifest;
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");                                  
    let pins = PinManifest::load(&repo_root.join("consume-pins.toml"))
        .expect("load consume-pins.toml for the pinned service-manifest");
    let store_path = std::env::var_os("FRUIT_ARTIFACT_STORE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| repo_root.join("../artifact-store"));
    let pin = pins
        .artifact("service-manifest")
        .expect("the consume-pins service-manifest entry");
    let verified = DirStore::new(&store_path)
        .fetch_verified("service-manifest", &pin.sha256)
        .expect("fetch + sha256-verify the pinned service-manifest");
    let manifest = recipes_image_builder::config::parse_validated_manifest(
        std::str::from_utf8(verified.bytes()).expect("service-manifest is utf-8"),
    )
    .expect("the pinned service-manifest validates");
    let probe = manifest.manifest().probe.clone();
    orchard::deploy::dryrun::boot_and_verify(
        Path::new(&img),
                                                                                                  
                                                                                                 
                                                                         
        &orchard::ceremony::leg_registry::dryrun_runtime_opts()
            .with_http_probe(probe.port, &probe.path),
    )
    .expect("dryrun boot+verify should succeed on a freshly-built image");
                                                                                                  
                                                                                                 
                                                               
    orchard::ceremony::gate_record::emit_leg_pass(
        Path::new(&img),
        "dryrun_boots_to_working_runtime",
    )
    .expect("emit this leg's gate-record row");
}

                                                                                                          
/// Build a toy `.img` from the non-recipes manifest:
///   `orchard build --domain toy.test --manifest crates/image-builder/toy-tenant.toml \
///        --operator-pubkey <k>.pub --recovery-pubkey <k>.pub --net '<...>' --out-dir <dir> --allow-dirty`
/// then point `RECIPES_TOY_DRYRUN_IMG` at it. Verifies the box-init topology + s6 supervision
/// GENERALIZE to a non-recipes tenant: dropbear accepts the operator pubkey, the manifest's `widget`
/// longrun is s6-supervised + UP (via [`ServiceCheck::SupervisedUp`], NOT a recipes-specific HTTP
/// probe), and `/` is a ro squashfs. The `--manifest` de-hardcoding (the f436e5f seam) is thus proven
/// on PRODUCED BYTES, not just at the render level.
                                                                                                       
                                                                                                  
                                                                                                        
                                                                                          
                                                                                                         
                                                                                                       
                           
#[test]
#[ignore = "boot gate: needs RECIPES_TOY_DRYRUN_IMG (a toy `--manifest` .img) + /dev/kvm"]
fn toy_manifest_boots_to_running_services() {
    let Ok(img) = std::env::var("RECIPES_TOY_DRYRUN_IMG") else {
        panic!(
            "toy dryrun gate invoked (--ignored) without RECIPES_TOY_DRYRUN_IMG — set it to a `.img` \
             built with `orchard build --manifest crates/image-builder/toy-tenant.toml`. A boot gate \
             must never pass without asserting the produced bytes."
        );
    };
    let opts = orchard::deploy::dryrun::DryrunOpts {
        service_check: orchard::deploy::dryrun::ServiceCheck::SupervisedUp("widget".to_string()),
        ..Default::default()
    };
    orchard::deploy::dryrun::boot_and_verify(Path::new(&img), &opts)
        .expect("the toy non-recipes manifest should boot to running services (widget supervised)");
}
