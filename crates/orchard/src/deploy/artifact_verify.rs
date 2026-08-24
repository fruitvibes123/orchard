                                                                                   
//! the prod orchestration calls BEFORE any network contact: if a root pin is in
//! force, every box-consumed artifact MUST carry a `.sig` that verifies against it
//! (+ the recomputed hash + the matching purpose), else the deploy aborts.
//!
//! The pin is the OPERATOR-HELD copy (`artifact-root.pub` / `--artifact-pin`),
                                                                                
                                                                               
//! at-rest tampering/swap of the artifacts; the off-build-host depth is
//! hardware-rung-only.
//!
                                                                               
//! means "signing not adopted" → a loud SKIP; a pin that is PRESENT BUT UNREADABLE
//! /malformed is an ABORT, never a skip — see [`read_root_pin`].

use super::artifact_sign::{sig_sidecar_path, streaming_sha256};
use dragonfruit::{BundleFile, Purpose, verify_bundle};
use std::path::Path;

/// Load the preflight root pin, fail-closed. `override_pin` (the `--artifact-pin`
/// off-host value) wins if present. Otherwise read `<keys_dir>/artifact-root.pub`:
/// - path GENUINELY ABSENT → `Ok(None)` (signing not adopted; caller emits a skip);
/// - path PRESENT (any inode, incl. a dangling symlink) but unreadable/NOT 64-hex →
///   `Err` (ABORT — never silently downgraded to "not adopted", which would let an
///   attacker disable verify by corrupting/dangling the pin).
///
                                                                                  
/// wrongly read as "absent → skip". We `lstat` (symlink_metadata) FIRST: if the path
/// exists as an inode of any kind, a subsequent read failure is an ABORT, not a skip.
/// Only a genuinely-absent path (lstat NotFound) is the un-adopted floor.
pub fn read_root_pin(
    keys_dir: &Path,
    override_pin: Option<[u8; 32]>,
) -> Result<Option<[u8; 32]>, String> {
    if let Some(p) = override_pin {
        return Ok(Some(p));
    }
    let pin_path = keys_dir.join("artifact-root.pub");

                                                                                      
    match std::fs::symlink_metadata(&pin_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),                    
        Err(e) => {
            return Err(format!(
                "artifact root pin path unstattable at {} ({e}) — refusing to deploy \
                 (a load-bearing trust anchor must not be skipped on an ambiguous error)",
                pin_path.display()
            ));
        }
        Ok(_) => {}                                                                     
    }

    let s = std::fs::read_to_string(&pin_path).map_err(|e| {
        format!(
            "artifact root pin present but unreadable at {} ({e}) — refusing to deploy \
             (a present-but-unreadable pin, e.g. a dangling symlink, must NOT be \
             treated as 'signing not adopted')",
            pin_path.display()
        )
    })?;
    decode_pin(s.trim()).map(Some).map_err(|m| {
        format!(
            "artifact root pin at {} is malformed: {m}",
            pin_path.display()
        )
    })
}

/// Decode a 64-hex-char ed25519 pin (no `ed25519:` prefix — that prefix lives only
/// in the committed `pinned-artifact-root.toml` record, not in `artifact-root.pub`).
fn decode_pin(hex_str: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(hex_str).map_err(|_| "not valid hex".to_string())?;
    <[u8; 32]>::try_from(raw).map_err(|_| "not 32 bytes (64 hex chars)".to_string())
}

/// Same fail-closed verify as [`verify_artifact`], returning the accepted
/// [`dragonfruit::VerifiedArtifact`] so callers can surface delegation evidence —
/// the restore preflight prints `monotonic_ctr()` as the operator's future
                                                                                     
/// is a thin delegate of this fn.
pub fn verify_artifact_returning(
    pin: &[u8; 32],
    purpose: Purpose,
    artifact: &Path,
) -> Result<dragonfruit::VerifiedArtifact, String> {
    let sig_path = sig_sidecar_path(artifact);
    let raw = std::fs::read(&sig_path)
        .map_err(|_| format!("artifact signature missing: {}", sig_path.display()))?;
    let bf = BundleFile::from_bytes(&raw)
        .map_err(|e| format!("malformed bundle {}: {e}", sig_path.display()))?;
    let hash = streaming_sha256(artifact).map_err(|e| e.to_string())?;
                                                                              
                                                                                   
                                                                                     
                                                                            
    verify_bundle(&bf.as_bundle(), pin, now_unix(), &hash, purpose)
        .map_err(|e| format!("artifact verify FAILED for {}: {e}", artifact.display()))
}

/// Verify `<artifact>.sig` against `pin` for `purpose`, fail-closed. Error strings
/// are operator-facing. Recomputes the artifact hash (streaming) and rejects on any
/// mismatch — a chain that verifies internally proves nothing about the bytes in
                                           
pub fn verify_artifact(pin: &[u8; 32], purpose: Purpose, artifact: &Path) -> Result<(), String> {
    verify_artifact_returning(pin, purpose, artifact).map(|_| ())
}

/// Preflight the box-consumed triple. `pin = None` (un-adopted) → a single loud
/// SKIP message (the box stays posture-agnostic). `Some` → all three are REQUIRED;
/// the FIRST failure aborts (returned `Err`).
pub fn preflight_verify_triple(
    pin: Option<&[u8; 32]>,
    img: &Path,
    vmlinuz: &Path,
    initramfs: &Path,
) -> Result<String, String> {
    let Some(pin) = pin else {
        return Ok(
            "artifact signing not adopted (no artifact-root.pub / --artifact-pin) — \
             preflight signature verify SKIPPED"
                .to_string(),
        );
    };
    verify_artifact(pin, Purpose::Img, img)?;
    verify_artifact(pin, Purpose::KexecVmlinuz, vmlinuz)?;
    verify_artifact(pin, Purpose::KexecInitramfs, initramfs)?;
    Ok(
        "artifact signatures verified against the operator pin (img + vmlinuz + initramfs)"
            .to_string(),
    )
}

fn now_unix() -> u64 {
    super::artifact_keys::unix_now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::artifact_keys::{Custody, generate_artifact_keys, load_artifact_keys};
    use crate::deploy::artifact_sign::{sign_bytes, sign_file, test_authority};

    /// A keys dir with an artifact set + a signed `r.img`; returns (dir, pin, img path).
    fn signed_img() -> (tempfile::TempDir, [u8; 32], std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Raw).unwrap();
        let set = load_artifact_keys(&keys).unwrap();
        let root_pub = set.root_pub;
        let auth = test_authority(set);
        let img = dir.path().join("r.img");
        std::fs::write(&img, b"image bytes").unwrap();
        sign_file(&auth, Purpose::Img, &img).unwrap();
        (dir, root_pub, img)
    }

    #[test]
    fn valid_bundle_passes() {
        let (_d, pin, img) = signed_img();
        verify_artifact(&pin, Purpose::Img, &img).unwrap();
    }

    #[test]
    fn verify_artifact_returning_surfaces_the_delegation_ctr() {
                                                                                               
                                                                                           
                                                                        
        let clock = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };
        let t0 = clock();
        let (_d, pin, img) = signed_img();
        let t1 = clock();
        let v = verify_artifact_returning(&pin, Purpose::Img, &img).expect("verifies");
        assert!(
            (t0..=t1).contains(&v.monotonic_ctr()),
            "ctr {} outside the keygen window {t0}..={t1}",
            v.monotonic_ctr()
        );
        assert_eq!(v.purpose(), Purpose::Img);
                                                                                  
        verify_artifact(&pin, Purpose::Img, &img).expect("delegate verifies");
    }

    #[test]
    fn missing_sig_aborts() {
        let (_d, pin, img) = signed_img();
        std::fs::remove_file(sig_sidecar_path(&img)).unwrap();
        let e = verify_artifact(&pin, Purpose::Img, &img).unwrap_err();
        assert!(e.contains("missing"), "{e}");
    }

    #[test]
    fn tampered_artifact_aborts() {
        let (_d, pin, img) = signed_img();
        std::fs::write(&img, b"image bytEs").unwrap();                    
        let e = verify_artifact(&pin, Purpose::Img, &img).unwrap_err();
        assert!(e.contains("verify FAILED"), "{e}");
    }

    #[test]
    fn wrong_purpose_sidecar_aborts() {
                                                                
        let (d, pin, img) = signed_img();
        let auth = test_authority(load_artifact_keys(&d.path().join("keys")).unwrap());
        let backup_sig = sign_bytes(&auth, Purpose::Backup, b"image bytes").unwrap();
        std::fs::write(sig_sidecar_path(&img), backup_sig).unwrap();
                                                                                
                                                                                 
        let e = verify_artifact(&pin, Purpose::Img, &img).unwrap_err();
        assert!(e.contains("purpose"), "{e}");
    }

    #[test]
    fn wrong_root_pin_aborts() {
        let (_d, _pin, img) = signed_img();
        let e = verify_artifact(&[0x42; 32], Purpose::Img, &img).unwrap_err();
        assert!(e.contains("verify FAILED"), "{e}");
    }

                                                     

    #[test]
    fn absent_pin_is_skip_not_abort() {
        let dir = tempfile::tempdir().unwrap();
                                                                  
        assert_eq!(read_root_pin(dir.path(), None).unwrap(), None);
        let msg = preflight_verify_triple(
            None,
            Path::new("/none/img"),
            Path::new("/none/vmlinuz"),
            Path::new("/none/initramfs"),
        )
        .unwrap();
        assert!(msg.contains("SKIPPED"), "{msg}");
    }

    #[test]
    fn present_but_malformed_pin_aborts_not_skips() {
                                                                                         
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("artifact-root.pub"), "not-hex-garbage\n").unwrap();
        let e = read_root_pin(dir.path(), None).unwrap_err();
        assert!(e.contains("malformed"), "{e}");

                                       
        std::fs::write(dir.path().join("artifact-root.pub"), "abcd\n").unwrap();
        assert!(read_root_pin(dir.path(), None).is_err());
    }

    #[test]
    fn dangling_symlink_pin_aborts_not_skips() {
                                                                                   
                                                                              
        let dir = tempfile::tempdir().unwrap();
        let pin = dir.path().join("artifact-root.pub");
        std::os::unix::fs::symlink(dir.path().join("nonexistent-target"), &pin).unwrap();
        let e = read_root_pin(dir.path(), None).unwrap_err();
        assert!(e.contains("unreadable"), "{e}");
    }

    #[test]
    fn valid_pin_loads_and_override_wins() {
        let (d, pin, _img) = signed_img();
        let loaded = read_root_pin(&d.path().join("keys"), None)
            .unwrap()
            .unwrap();
        assert_eq!(loaded, pin);
                                                         
        let over = [0x07; 32];
        assert_eq!(
            read_root_pin(&d.path().join("keys"), Some(over)).unwrap(),
            Some(over)
        );
    }

    #[test]
    fn triple_with_pin_requires_all_three() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Raw).unwrap();
        let set = load_artifact_keys(&keys).unwrap();
        let pin = set.root_pub;
        let auth = test_authority(set);
        let mk = |name: &str, purpose: Purpose| {
            let p = dir.path().join(name);
            std::fs::write(&p, name.as_bytes()).unwrap();
            sign_file(&auth, purpose, &p).unwrap();
            p
        };
        let img = mk("r.img", Purpose::Img);
        let vmlinuz = mk("r.vmlinuz", Purpose::KexecVmlinuz);
        let initramfs = mk("r.initramfs", Purpose::KexecInitramfs);

                                       
        assert!(preflight_verify_triple(Some(&pin), &img, &vmlinuz, &initramfs).is_ok());
                                 
        std::fs::remove_file(sig_sidecar_path(&vmlinuz)).unwrap();
        assert!(preflight_verify_triple(Some(&pin), &img, &vmlinuz, &initramfs).is_err());
    }
}
