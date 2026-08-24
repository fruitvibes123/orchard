                                                                                                
                                                                                                   
//! pin is theater until we watch a mutated artifact get rejected.
use recipes_image_builder::artifact_store::{ArtifactStore, ArtifactStoreError, DirStore};
use recipes_image_builder::pin_manifest::PinManifest;
use sha2::{Digest, Sha256};

#[test]
fn manifest_plus_store_verifies_a_pinned_input_then_refuses_a_tamper() {
    let tmp = tempfile::tempdir().unwrap();
    let bytes = b"the-pinned-recipes-app-elf";
    let sha = hex::encode(Sha256::digest(bytes));
    std::fs::write(tmp.path().join("recipes-app"), bytes).unwrap();

    let manifest_toml = format!(
        "schema-version = 1\n[artifacts.recipes-app]\nsha256 = \"{sha}\"\nkind = \"binary\"\n"
    );
    let manifest = PinManifest::from_toml_str(&manifest_toml).expect("manifest parses");
    let pin = manifest.artifact("recipes-app").expect("pin present");
    let store = DirStore::new(tmp.path());

                                           
    let v = store
        .fetch_verified("recipes-app", &pin.sha256)
        .expect("verified");
    assert_eq!(v.bytes(), bytes);

                                                                                       
    std::fs::write(tmp.path().join("recipes-app"), b"malicious-replacement").unwrap();
    let err = store
        .fetch_verified("recipes-app", &pin.sha256)
        .unwrap_err();
    assert!(
        matches!(err, ArtifactStoreError::HashMismatch { .. }),
        "tampered artifact MUST be refused, got {err:?}"
    );
}
