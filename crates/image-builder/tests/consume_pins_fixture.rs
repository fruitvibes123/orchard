                                                                                                       
//! carries exactly the 23 consumed artifacts with the right kinds. Catches a hand-edit that breaks the
//! manifest (a malformed sha, a missing kind, an unknown field, a dropped/renamed artifact) before the
//! bake hits it — the manifest is the un-hashed verify-chain root, so a parse-time gate is cheap insurance.
use recipes_image_builder::pin_manifest::{ArtifactKind, PinManifest};

#[test]
fn consume_pins_parses_and_carries_the_expected_artifacts() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../consume-pins.toml");
    let m = PinManifest::load(std::path::Path::new(path)).expect("consume-pins.toml parses");
    assert_eq!(
        m.artifacts.len(),
        24,
        "expected 24 consumed artifacts (15 binary + 4 source + 5 config)"
    );

    for b in [
        "recipes-app",
        "recipes-admin",
        "fb-acme",
        "fb-oneshots",
        "fb-backup",
        "fb-cert-check",
        "fb-update",
        "fb-mark-good",
        "fb-weights",
        "box-init",
        "initramfs-init",
        "creatine-serve",
        "epa",
        "dha-orchestrator",
        "uds-pipe",
    ] {
        assert_eq!(
            m.artifact(b).unwrap().kind,
            ArtifactKind::Binary,
            "{b} must be a binary"
        );
    }
    for s in [
        "rambutan-src",
        "fb-manifest-src",
        "grape-src",
        "dragonfruit-src",
    ] {
        assert_eq!(
            m.artifact(s).unwrap().kind,
            ArtifactKind::Source,
            "{s} must be source"
        );
    }
                                                                                                          
                                                                                                     
    for c in [
        "service-manifest",
        "dha-intake-probe",
        "dha-real-job-probe",
        "dha-ac-i-selftest",
        "dha-epa-config",
    ] {
        assert_eq!(
            m.artifact(c).unwrap().kind,
            ArtifactKind::Config,
            "{c} must be config (typed, not source)"
        );
    }
}

/// The staged-name → store-key → pin chain lock: every `/usr/bin` name the SHIPPED dha manifest
/// stages must, through `bin_store_key`, resolve to a pinned BINARY in the real consume-pins.toml.
/// Closes the class the 2026-07-10 dha bake hit (`Pin(Missing("creatine"))`): the manifest execs
/// `/usr/bin/creatine` while the owning repo publishes `creatine-serve`, and the name→key map had
/// no creatine arm — invisible to every host test (the FakeTools staging path never consults pins;
/// only a REAL bake ran the lookup). With this lock a broken remap fails `make verify` instead.
#[test]
fn every_staged_dha_bin_resolves_to_a_pinned_key() {
    use recipes_image_builder::build::{bin_store_key, staged_usr_bin_names};
    let pins_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../consume-pins.toml");
    let pins =
        PinManifest::load(std::path::Path::new(pins_path)).expect("consume-pins.toml parses");
    let manifest = fb_manifest::parse_and_validate(
        include_str!("../dha-tenant.toml"),
        &recipes_image_builder::config::os_identities(),
    )
    .expect("the shipped dha-tenant.toml validates");
    for name in staged_usr_bin_names(&manifest) {
        let key = bin_store_key(&name);
        let pin = pins.artifact(key).unwrap_or_else(|e| {
            panic!("staged bin {name:?} → store key {key:?} has no consume-pins entry: {e}")
        });
        assert_eq!(
            pin.kind,
            ArtifactKind::Binary,
            "staged bin {name:?} → key {key:?} must pin a BINARY artifact"
        );
    }
}

                                                                                                         
/// each staged key must resolve to a consume-pins entry of the COHERENT kind — an exec-mode target
/// (`0o111` bits set, e.g. `/opt/dha/uds-pipe` 0755) pins a BINARY; a non-exec target (the probe scripts
/// 0644, epa.json 0600) pins a CONFIG. The /opt/dha analogue of the /usr/bin lock above; armable only once
                                                                                                     
/// stayed `#[ignore]`d). A mode/kind mismatch (a config pinned as a binary, or vice versa) fails
/// `make verify` here instead of the bake.
#[test]
fn every_staged_file_resolves_to_a_coherent_kind_pin() {
    let pins_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../consume-pins.toml");
    let pins =
        PinManifest::load(std::path::Path::new(pins_path)).expect("consume-pins.toml parses");
    let manifest = fb_manifest::parse_and_validate(
        include_str!("../dha-tenant.toml"),
        &recipes_image_builder::config::os_identities(),
    )
    .expect("the shipped dha-tenant.toml validates");
    let staged = manifest.manifest().staged_files.as_deref().unwrap_or(&[]);
    assert!(!staged.is_empty(), "the dha tenant stages files");
    for sf in staged {
        let pin = pins.artifact(sf.key.as_str()).unwrap_or_else(|e| {
            panic!(
                "staged file {:?} (key {:?}) has no consume-pins entry: {e}",
                sf.target, sf.key
            )
        });
        let expected = if sf.mode & 0o111 != 0 {
            ArtifactKind::Binary
        } else {
            ArtifactKind::Config
        };
        assert_eq!(
            pin.kind, expected,
            "staged file {:?} (mode {:o}) → key {:?} must pin a {expected:?}",
            sf.target, sf.mode, sf.key
        );
    }
}
