//! `orchard redelegate` — mint the update-path delegations (`UpdateImage` /
//! `RootHash`) over an EXISTING artifact root (os-update A/B v1 T3, component C-F).
//!
//! Every key set minted before the update path (incl. the live box's) lacks the two
//! update-path delegations, so `orchard update`'s signing AND `orchard build`'s baked
//! `min_delegation_ctr` read fail closed — redelegate-before-build (R4-1). The box
//! pins only the ROOT pubkey (baked `artifact-root.pub`), so a fresh delegation
//! signed by the existing root verifies WITHOUT a rebake — the box trust anchor is
//! untouched. This is the "future re-delegation ceremony" the root key file was
//! reserved for ([`super::artifact_keys::ArtifactKeySet`]'s doc); the root seed is
//! loaded ONLY for the mint (both at-rest custody classes, plan-review S3 — the
//! docker rung's wrapped blob unwraps in host MEMORY only, `Zeroizing`, never onto
//! the host FS) and dropped before any file is written; the key files themselves are
//! never rewritten.
//!
//! Re-running redelegate SUPERSEDES the on-disk bundle with a fresh issuance ctr
//! (`monotonic_ctr = unix_now()`, second-granularity ⇒ NON-DECREASING across runs —
//! a same-second re-run ties, which never reopens the downgrade window; plan-review
//! S5). A host clock that would REGRESS the ctr below the existing bundle's is
//! refused fail-closed: the box-side floors (baked `min_delegation_ctr`, the
//! `/persist` minctr floor) treat the ctr as forward-only.

use super::artifact_keys::{
    DELEGATION_BUNDLE_LEN, delegation_bundle_name, delegation_window_end, load_root_seed,
    load_worker_seed, mint_delegation_bundle, read_root_pub, unix_now,
};
use super::keys::{DeployKeyError, set_mode};
use dragonfruit::{DELEGATION_LEN, Delegation, Purpose};
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};

/// One minted delegation: its purpose, where the bundle landed, and the issuance
/// `monotonic_ctr` (the value `orchard build` bakes as `min_delegation_ctr`).
#[derive(Debug)]
pub struct Minted {
    pub purpose: Purpose,
    pub path: PathBuf,
    pub monotonic_ctr: u64,
}

/// Mint fresh delegation bundle(s) for `purposes` over the EXISTING root+worker in
/// `keys_dir`. `passphrase` unwraps a docker-rung (wrapped) key set — `None` on the
/// software rung; a wrapped set with `None` surfaces as
/// [`DeployKeyError::Passphrase`] so the CLI can prompt once and retry. Fail-closed
/// throughout: absent root/worker ⇒ `NotFound`; a root key that does not match the
/// public pin ⇒ `Unloadable` (never mint delegations chaining to an untrusted
/// root); a clock-regressed issuance ctr vs an existing bundle ⇒ refuse. Writes are
/// per-bundle atomic (tempfile in `keys_dir` + rename — same-fs, never EXDEV).
pub fn redelegate(
    keys_dir: &Path,
    purposes: &[Purpose],
    window_days: u64,
    passphrase: Option<&[u8]>,
) -> Result<Vec<Minted>, DeployKeyError> {
                                                                               
                                                             
    let root_seed = load_root_seed(keys_dir, passphrase)?;
    let root = SigningKey::from_bytes(&root_seed);
    drop(root_seed);

                                                                              
                                                                                    
                                                                        
                                                                                    
                                               
    let pin = read_root_pub(keys_dir)?;
    if root.verifying_key().to_bytes() != pin {
        return Err(DeployKeyError::Unloadable {
            path: keys_dir.join("artifact-root.key").display().to_string(),
            reason: "loaded root key does not match artifact-root.pub (the box trust \
                     anchor) — a corrupt / wrong / mis-detected root file; refusing to \
                     mint delegations that would chain to an untrusted root"
                .into(),
        });
    }

                                                                             
                                                                           
    let worker_seed = load_worker_seed(keys_dir, passphrase)?;
    let worker_pubkey = SigningKey::from_bytes(&worker_seed)
        .verifying_key()
        .to_bytes();
    drop(worker_seed);

    let now = unix_now();
    let not_after = delegation_window_end(now, window_days)?;

                                                                                   
                               
    let mut planned = Vec::with_capacity(purposes.len());
    for &purpose in purposes {
        let dest = keys_dir.join(delegation_bundle_name(purpose));
                                                                             
                                                                                      
                                                                      
        if let Some(prev) = existing_bundle_ctr(&dest)?
            && now < prev
        {
            return Err(DeployKeyError::Import(format!(
                "refusing to redelegate {}: the existing bundle's monotonic_ctr \
                 ({prev}) is AHEAD of this host's clock ({now}) — a regressed \
                 issuance ctr would read as a rollback to the box-side floors; \
                 fix the host clock (or investigate the existing bundle) and re-run",
                delegation_bundle_name(purpose),
            )));
        }
        let bundle = mint_delegation_bundle(&root, worker_pubkey, purpose, now, not_after, now);
        planned.push((purpose, dest, bundle));
    }
    drop(root);

                                                                                      
                                                                                      
                                                                               
                                                                              
    let mut minted = Vec::with_capacity(planned.len());
    for (purpose, dest, bundle) in planned {
        let tmp = tempfile::Builder::new()
            .prefix(".recipes-redelegate-")
            .tempfile_in(keys_dir)
            .map_err(|e| DeployKeyError::Io {
                path: keys_dir.display().to_string(),
                source: e,
            })?;
        std::fs::write(tmp.path(), &bundle).map_err(|e| DeployKeyError::Io {
            path: tmp.path().display().to_string(),
            source: e,
        })?;
        set_mode(tmp.path(), 0o644)?;
        tmp.persist(&dest).map_err(|e| DeployKeyError::Io {
            path: dest.display().to_string(),
            source: e.error,
        })?;
        minted.push(Minted {
            purpose,
            path: dest,
            monotonic_ctr: now,
        });
    }
    Ok(minted)
}

/// The existing bundle's `monotonic_ctr`, if a bundle is present at `dest`.
/// Present-but-malformed is LOUD ([`DeployKeyError::Unloadable`]) — a broken key
/// set surfaces, never silently overwritten; the operator removes the corrupt
/// bundle deliberately and re-runs.
fn existing_bundle_ctr(dest: &Path) -> Result<Option<u64>, DeployKeyError> {
    let raw = match std::fs::read(dest) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(DeployKeyError::Io {
                path: dest.display().to_string(),
                source: e,
            });
        }
    };
    if raw.len() != DELEGATION_BUNDLE_LEN {
        return Err(DeployKeyError::Unloadable {
            path: dest.display().to_string(),
            reason: format!(
                "existing delegation bundle is {} bytes, expected {DELEGATION_BUNDLE_LEN} — \
                 remove it deliberately if it is known-bad, then re-run",
                raw.len()
            ),
        });
    }
    let d = Delegation::from_canonical(&raw[..DELEGATION_LEN]).map_err(|e| {
        DeployKeyError::Unloadable {
            path: dest.display().to_string(),
            reason: format!("existing delegation bundle does not parse: {e:?}"),
        }
    })?;
    Ok(Some(d.monotonic_ctr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::artifact_keys::{
        Custody, generate_artifact_keys, load_artifact_keys, load_artifact_keys_with,
    };
    use crate::deploy::artifact_sign::sign_bytes;
    use dragonfruit::{BundleFile, verify_bundle};
    use sha2::{Digest, Sha256};

    const UPDATE_PATH_BUNDLES: [&str; 2] = [
        "artifact-delegation-update-image.bundle",
        "artifact-delegation-root-hash.bundle",
    ];

    /// A key set reduced to the legacy pre-update-path shape (the live box's):
    /// mint the full six-delegation set, then drop the two update-path bundles.
    fn legacy_set(keys: &Path) {
        generate_artifact_keys(keys, 365, false, Custody::Raw).unwrap();
        for name in UPDATE_PATH_BUNDLES {
            std::fs::remove_file(keys.join(name)).unwrap();
        }
    }

    #[test]
    fn redelegate_produces_box_acceptable_updateimage() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        legacy_set(&keys);
                                                                                
        assert!(matches!(
            load_artifact_keys(&keys),
            Err(DeployKeyError::MissingDelegation { .. })
        ));
                                                                                
                                   
        let untouched = [
            "artifact-root.key",
            "artifact-worker.key",
            "artifact-root.pub",
            "artifact-delegation-img.bundle",
        ];
        let before: Vec<Vec<u8>> = untouched
            .iter()
            .map(|n| std::fs::read(keys.join(n)).unwrap())
            .collect();

        let minted =
            redelegate(&keys, &[Purpose::UpdateImage, Purpose::RootHash], 365, None).unwrap();
        assert_eq!(minted.len(), 2);
        assert_eq!(minted[0].purpose, Purpose::UpdateImage);

                                                                                 
        let auth = crate::deploy::artifact_sign::test_authority(
            load_artifact_keys(&keys).expect("redelegated set must load"),
        );
        let artifact = b"update image bytes";
        let sig = sign_bytes(&auth, Purpose::UpdateImage, artifact).unwrap();

                                                                                      
                                                                                   
                                                                             
                                                                                     
                                                                                    
                                                                                 
                                                  
        let pin = read_root_pub(&keys).unwrap();
        let bf = BundleFile::from_bytes(&sig).unwrap();
        let hash: [u8; 32] = Sha256::digest(artifact).into();
        let v = verify_bundle(
            &bf.as_bundle(),
            &pin,
            unix_now(),
            &hash,
            Purpose::UpdateImage,
        )
        .expect("box-side verify must accept the redelegated UpdateImage bundle");
        assert_eq!(v.monotonic_ctr(), minted[0].monotonic_ctr);
        assert!(
            v.monotonic_ctr() >= minted[0].monotonic_ctr,
            "quince ctr floor"
        );

                                                                                 
        for (name, before) in untouched.iter().zip(before) {
            assert_eq!(
                std::fs::read(keys.join(name)).unwrap(),
                before,
                "{name} must be byte-untouched by redelegate"
            );
        }
        assert!(keys.join(UPDATE_PATH_BUNDLES[1]).exists());
    }

    #[test]
    fn redelegate_twice_is_non_decreasing() {
                                                                                        
                                                                               
                                                                         
                                                  
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Raw).unwrap();

        let a = redelegate(&keys, &[Purpose::UpdateImage], 365, None).unwrap();
        let b = redelegate(&keys, &[Purpose::UpdateImage], 365, None).unwrap();
        assert!(
            b[0].monotonic_ctr >= a[0].monotonic_ctr,
            "issuance ctr regressed: {} then {}",
            a[0].monotonic_ctr,
            b[0].monotonic_ctr
        );
                                                      
        assert_eq!(
            existing_bundle_ctr(&keys.join(UPDATE_PATH_BUNDLES[0])).unwrap(),
            Some(b[0].monotonic_ctr)
        );
    }

    #[test]
    fn redelegate_refuses_a_clock_regressed_ctr() {
                                                                                   
                                                                                   
                                                          
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Raw).unwrap();

        let root = SigningKey::from_bytes(&load_root_seed(&keys, None).unwrap());
        let worker_pub = SigningKey::from_bytes(&load_worker_seed(&keys, None).unwrap())
            .verifying_key()
            .to_bytes();
        let future = unix_now() + 10_000;
        let dest = keys.join(UPDATE_PATH_BUNDLES[0]);
        let crafted = mint_delegation_bundle(
            &root,
            worker_pub,
            Purpose::UpdateImage,
            future,
            future + 86_400,
            future,
        );
        std::fs::write(&dest, &crafted).unwrap();

        let err = redelegate(&keys, &[Purpose::UpdateImage], 365, None).unwrap_err();
        assert!(
            err.to_string().contains("AHEAD"),
            "want the clock-regression refusal, got: {err}"
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            crafted,
            "a refused redelegate must leave the existing bundle untouched"
        );
    }

    #[test]
    fn redelegate_handles_both_custody_classes() {
                                                                             
                                                                                  
                                                                      
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Wrapped { passphrase: b"pw" }).unwrap();
        for name in UPDATE_PATH_BUNDLES {
            std::fs::remove_file(keys.join(name)).unwrap();
        }

        assert!(matches!(
            redelegate(&keys, &[Purpose::UpdateImage], 365, None),
            Err(DeployKeyError::Passphrase { .. })
        ));
        assert!(matches!(
            redelegate(&keys, &[Purpose::UpdateImage], 365, Some(b"wrong")),
            Err(DeployKeyError::Passphrase { .. })
        ));

                                                                                    
                                                                             
        let minted = redelegate(
            &keys,
            &[Purpose::UpdateImage, Purpose::RootHash],
            365,
            Some(b"pw"),
        )
        .unwrap();
        let auth = crate::deploy::artifact_sign::test_authority(
            load_artifact_keys_with(&keys, Some(b"pw")).unwrap(),
        );
        let sig = sign_bytes(&auth, Purpose::UpdateImage, b"payload").unwrap();
        let bf = BundleFile::from_bytes(&sig).unwrap();
        let v = verify_bundle(
            &bf.as_bundle(),
            &read_root_pub(&keys).unwrap(),
            unix_now(),
            &Sha256::digest(b"payload").into(),
            Purpose::UpdateImage,
        )
        .expect("wrapped-custody redelegate must chain to the pinned root");
        assert_eq!(v.monotonic_ctr(), minted[0].monotonic_ctr);
    }

    #[test]
    fn redelegate_refuses_wrong_or_absent_root() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Raw).unwrap();

                                                                                       
        std::fs::remove_file(keys.join("artifact-root.key")).unwrap();
        assert!(matches!(
            redelegate(&keys, &[Purpose::UpdateImage], 365, None),
            Err(DeployKeyError::NotFound { .. })
        ));

                                                                             
                                                                                        
                                        
        std::fs::write(keys.join("artifact-root.key"), [7u8; 32]).unwrap();
        let err = redelegate(&keys, &[Purpose::UpdateImage], 365, None).unwrap_err();
        assert!(
            matches!(err, DeployKeyError::Unloadable { .. }),
            "want Unloadable, got {err:?}"
        );
        assert!(err.to_string().contains("does not match"), "{err}");
    }
}
