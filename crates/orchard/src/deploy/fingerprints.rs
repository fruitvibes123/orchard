//! `orchard update-cert-fingerprints` — recompute pinned cert
                                                                                   
//!
//! Reads the existing `crates/image-builder/pinned-cert-fingerprints.toml`,
//! recomputes the entries for the cert paths the operator passed (preserving
//! the others — a leaf rotation leaves the CA pin untouched), and rewrites it
//! through the same renderer `generate-keys` uses. The operator commits the diff.

use std::path::{Path, PathBuf};

use crate::deploy::keys::{
    DeployKeyError, FingerprintEntry, fingerprint_entry_from_cert_pem, now_rfc3339, read_pem,
    render_fingerprints_toml, write_file_mode,
};

/// Which cert sections to recompute. The CLI requires at least one.
#[derive(Default)]
pub struct CertFingerprintUpdate {
    pub image_signing: Option<PathBuf>,
    pub signing_ca: Option<PathBuf>,
    pub ima: Option<PathBuf>,
}

impl CertFingerprintUpdate {
    pub fn is_empty(&self) -> bool {
        self.image_signing.is_none() && self.signing_ca.is_none() && self.ima.is_none()
    }
}

/// Deserialized form of the existing pinned-cert-fingerprints TOML.
#[derive(serde::Deserialize)]
struct FingerprintsDoc {
    image_signing: FingerprintEntry,
    signing_ca: FingerprintEntry,
    ima: FingerprintEntry,
}

/// Recompute + rewrite the fingerprints for the provided certs, preserving the
/// rest. Errors if no cert was given, the TOML is missing/malformed, or a cert
/// isn't a parseable ECDSA-P256 X.509.
pub fn update_cert_fingerprints(
    toml_path: &Path,
    update: &CertFingerprintUpdate,
) -> Result<(), DeployKeyError> {
    if update.is_empty() {
        return Err(DeployKeyError::Import(
            "update-cert-fingerprints: pass at least one of --image-signing / --signing-ca / --ima"
                .into(),
        ));
    }
    let existing = std::fs::read_to_string(toml_path).map_err(|source| DeployKeyError::Io {
        path: toml_path.display().to_string(),
        source,
    })?;
    let mut doc: FingerprintsDoc = toml::from_str(&existing).map_err(|e| {
        DeployKeyError::Import(format!(
            "parsing existing pinned-cert-fingerprints.toml: {e}"
        ))
    })?;

    if let Some(p) = &update.image_signing {
        doc.image_signing = entry_for(p)?;
    }
    if let Some(p) = &update.signing_ca {
        doc.signing_ca = entry_for(p)?;
    }
    if let Some(p) = &update.ima {
        doc.ima = entry_for(p)?;
    }

    let body = render_fingerprints_toml(&doc.image_signing, &doc.signing_ca, &doc.ima);
    write_file_mode(toml_path, body.as_bytes(), 0o644)
}

fn entry_for(cert_path: &Path) -> Result<FingerprintEntry, DeployKeyError> {
    let pem = read_pem(cert_path)?;
    fingerprint_entry_from_cert_pem(&pem)
}

/// Write the committed git-diff record of the operator's artifact-signing ROOT
                                                                   
///
/// **Deliberately a SEPARATE file from `pinned-cert-fingerprints.toml`** (C2):
/// that file pins cert-DER sha256 *fingerprints*; this pins an *ed25519 pubkey* —
/// a different trust scheme, so co-mingling would be a category error and would
/// entangle the cert renderer (whose `update-cert-fingerprints` re-render would
/// clobber an extra key). Being a separate file makes "preserved across cert
/// rotations" true by construction. The OPERATIVE pin the preflight verifies
/// against is `artifact-root.pub` in the keys dir; this committed copy is the
/// record a `git diff` flags if a build host swaps the root.
pub fn set_artifact_root_pin(pin_path: &Path, root_pub: &[u8; 32]) -> Result<(), DeployKeyError> {
    let body = format!(
        "# Operator artifact-signing ROOT pubkey pin (ed25519). Written by\n\
         # `orchard generate-keys --artifact-signing …`; COMMIT the diff.\n\
         # A change here you did not make = a swapped signing root .\n \
         pubkey = \"ed25519:{}\"\n\
         generated_at = \"{}\"\n",
        hex::encode(root_pub),
        now_rfc3339(),
    );
    write_file_mode(pin_path, body.as_bytes(), 0o644)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::keys::{GenMode, GenerateKeysOpts, generate_keys};

    /// Generate a key set under `dir`, returning its keys dir + fingerprints path.
    fn gen_set(dir: &Path) -> (PathBuf, PathBuf) {
        let keys = dir.join("keys");
        let fp = dir.join("pinned-cert-fingerprints.toml");
        generate_keys(&GenerateKeysOpts {
            output_dir: keys.clone(),
            subject_ou: None,
            force: false,
            mode: GenMode::Generate,
            regenerate_master_key: false,
            fingerprints_path: fp.clone(),
        })
        .unwrap();
        (keys, fp)
    }

    fn fp_value(toml: &str, section: &str) -> String {
                                                                  
        let doc: toml::Value = toml::from_str(toml).unwrap();
        doc[section]["fingerprint"].as_str().unwrap().to_string()
    }

    #[test]
    fn rotating_ima_updates_only_that_pin() {
        let a = tempfile::tempdir().unwrap();
        let (_keys_a, fp_a) = gen_set(a.path());
        let before = std::fs::read_to_string(&fp_a).unwrap();
        let is_before = fp_value(&before, "image_signing");
        let ca_before = fp_value(&before, "signing_ca");
        let ima_before = fp_value(&before, "ima");

                                                                                    
        let b = tempfile::tempdir().unwrap();
        let (keys_b, _fp_b) = gen_set(b.path());

        update_cert_fingerprints(
            &fp_a,
            &CertFingerprintUpdate {
                ima: Some(keys_b.join("ima.crt")),
                ..Default::default()
            },
        )
        .unwrap();

        let after = std::fs::read_to_string(&fp_a).unwrap();
        assert_eq!(
            fp_value(&after, "image_signing"),
            is_before,
            "image_signing preserved"
        );
        assert_eq!(
            fp_value(&after, "signing_ca"),
            ca_before,
            "signing_ca preserved"
        );
        assert_ne!(
            fp_value(&after, "ima"),
            ima_before,
            "ima fingerprint rotated"
        );
    }

    #[test]
    fn artifact_root_pin_is_written_and_survives_cert_updates() {
        let dir = tempfile::tempdir().unwrap();
        let (keys, fp) = gen_set(dir.path());                                        
        let pin = dir.path().join("pinned-artifact-root.toml");

        let root_pub = [0xAB; 32];
        set_artifact_root_pin(&pin, &root_pub).unwrap();
        let body = std::fs::read_to_string(&pin).unwrap();
        assert!(
            body.contains(&format!("pubkey = \"ed25519:{}\"", "ab".repeat(32))),
            "pin body: {body}"
        );
        assert!(body.contains("generated_at = "));

                                                                               
                                                                              
        let b = tempfile::tempdir().unwrap();
        let (keys_b, _) = gen_set(b.path());
        update_cert_fingerprints(
            &fp,
            &CertFingerprintUpdate {
                ima: Some(keys_b.join("ima.crt")),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&pin).unwrap(),
            body,
            "artifact-root pin untouched by a cert rotation"
        );
        let _ = keys;                                       
    }

    #[test]
    fn artifact_root_pin_overwrites_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let pin = dir.path().join("pinned-artifact-root.toml");
        set_artifact_root_pin(&pin, &[0x11; 32]).unwrap();
        set_artifact_root_pin(&pin, &[0x22; 32]).unwrap();
        let body = std::fs::read_to_string(&pin).unwrap();
        assert!(body.contains(&format!("ed25519:{}", "22".repeat(32))));
        assert!(!body.contains(&format!("ed25519:{}", "11".repeat(32))));
    }

    #[test]
    fn empty_update_is_rejected() {
        let a = tempfile::tempdir().unwrap();
        let (_k, fp) = gen_set(a.path());
        let err = update_cert_fingerprints(&fp, &CertFingerprintUpdate::default()).unwrap_err();
        assert!(matches!(err, DeployKeyError::Import(_)));
    }

    #[test]
    fn non_cert_path_is_rejected() {
        let a = tempfile::tempdir().unwrap();
        let (keys, fp) = gen_set(a.path());
                                                                                   
        let err = update_cert_fingerprints(
            &fp,
            &CertFingerprintUpdate {
                image_signing: Some(keys.join("image-signing.key")),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, DeployKeyError::Import(_)));
    }

    #[test]
    fn missing_toml_is_io_error() {
        let a = tempfile::tempdir().unwrap();
        let (keys, _fp) = gen_set(a.path());
        let err = update_cert_fingerprints(
            &a.path().join("does-not-exist.toml"),
            &CertFingerprintUpdate {
                ima: Some(keys.join("ima.crt")),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, DeployKeyError::Io { .. }));
    }
}
