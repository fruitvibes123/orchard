                                                                              
//! (multi-GB) artifact, a worker-signed ATTESTATION bound to the purpose's
//! delegation, emitted as the fixed 254-byte `<artifact>.sig` sidecar
//! (`dragonfruit::BundleFile`). The box NEVER signs (the CRUX) — this is operator
//! host code in the standalone `orchard` crate, never linked into the box image
//! (post-split there is no `deploy` Cargo feature; the boundary is the `crux-orchard`
//! Makefile gate).

use super::artifact_keys::{ArtifactKeySet, load_artifact_keys};
use super::keys::DeployKeyError;
use dragonfruit::{Attestation, BundleFile, Purpose, sign_attestation};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

/// SHA-256 of a file in 1 MiB chunks — never holds the whole artifact in memory
/// (the `.img` is gigabytes; the streaming read is the point).
pub fn streaming_sha256(path: &Path) -> Result<[u8; 32], DeployKeyError> {
    let mut f = std::fs::File::open(path).map_err(|source| DeployKeyError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(|source| DeployKeyError::Io {
            path: path.display().to_string(),
            source,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Build the 254-byte bundle for `artifact_hash` under `purpose`: select the
/// matching pre-signed delegation, build + worker-sign the attestation that binds
/// the hash to it. Fail-closed (no unwrap/expect) — a missing purpose delegation
/// is a malformed key set, not a panic.
fn bundle_for(
    set: &ArtifactKeySet,
    purpose: Purpose,
    artifact_hash: [u8; 32],
) -> Result<BundleFile, DeployKeyError> {
    let (_, deleg_bytes, root_sig) = set
        .delegations
        .iter()
        .find(|(p, _, _)| *p == purpose)
        .ok_or_else(|| {
            DeployKeyError::Import(format!(
                "artifact key set has no delegation for purpose {purpose:?}"
            ))
        })?;
    let delegation_id: [u8; 32] = Sha256::digest(deleg_bytes).into();
    let att = Attestation {
        artifact_hash,
        purpose,
        delegation_id,
    };
    let worker_sig = sign_attestation(&set.worker, &att);
    Ok(BundleFile {
        delegation_bytes: *deleg_bytes,
        root_sig: *root_sig,
        attestation_bytes: att.to_canonical(),
        worker_sig,
    })
}

/// The HOST-rung signing-capability witness (spec Component E): operator-ARTIFACT-signing
/// (`sign_bytes`/`sign_file` over delegated purposes) requires one, and the private field
/// confines construction to this module and its descendants (rustc field-privacy scope) —
/// the one descendant is the `#[cfg(test)]` `tests` module, which mints only via
/// [`test_authority`], never the struct literal — so a direct `load_artifact_keys →
/// sign_bytes` anywhere else in the crate is a COMPILE error. Exactly two PRODUCTION
/// construction sites exist: [`plan_signing`]'s Host arm and [`sign_in_container_leaf`].
/// Deliberately
/// NO constructing derives or impls — no `Default`, no `Deserialize`, no public
/// `From`/`new` (the `compile_fail` probes below pin each; adding one turns a probe
/// green-compile → doctest FAILURE, so the guard self-tests).
///
/// ```compile_fail
/// // struct-literal construction outside the module fails (private field):
/// fn probe(set: orchard::deploy::artifact_keys::ArtifactKeySet) {
///     let _ = orchard::deploy::artifact_sign::HostSignAuthority { set: Box::new(set) };
/// }
/// ```
/// ```compile_fail
/// // no Default:
/// let _ = orchard::deploy::artifact_sign::HostSignAuthority::default();
/// ```
/// ```compile_fail
/// // no public From/new:
/// fn probe(set: orchard::deploy::artifact_keys::ArtifactKeySet) {
///     let _: orchard::deploy::artifact_sign::HostSignAuthority = set.into();
/// }
/// ```
/// ```compile_fail
/// // a raw key set no longer signs — sign_bytes takes the witness (AC-E1):
/// fn probe(set: &orchard::deploy::artifact_keys::ArtifactKeySet) {
///     let _ = orchard::deploy::artifact_sign::sign_bytes(set, dragonfruit::Purpose::Backup, b"x");
/// }
/// ```
pub struct HostSignAuthority {
    set: Box<ArtifactKeySet>,
}

/// Sign in-memory bytes (tests + small payloads): returns the 254-byte bundle.
/// Requires the [`HostSignAuthority`] witness — the compile-time proof the caller came
/// through [`plan_signing`]'s Host arm or the in-container leaf (spec AC-E1).
pub fn sign_bytes(
    auth: &HostSignAuthority,
    purpose: Purpose,
    artifact: &[u8],
) -> Result<Vec<u8>, DeployKeyError> {
    let hash: [u8; 32] = Sha256::digest(artifact).into();
    Ok(bundle_for(&auth.set, purpose, hash)?.to_bytes().to_vec())
}

/// Sign the file at `path` → write `<path>.sig` (254 bytes) beside it; returns the
/// sidecar path. Streams the hash (no whole-file read). Requires the
/// [`HostSignAuthority`] witness (spec AC-E1) — see [`sign_bytes`].
pub fn sign_file(
    auth: &HostSignAuthority,
    purpose: Purpose,
    path: &Path,
) -> Result<PathBuf, DeployKeyError> {
    let hash = streaming_sha256(path)?;
    let bundle = bundle_for(&auth.set, purpose, hash)?;
    let sig_path = sig_sidecar_path(path);
    std::fs::write(&sig_path, bundle.to_bytes()).map_err(|source| DeployKeyError::Io {
        path: sig_path.display().to_string(),
        source,
    })?;
    Ok(sig_path)
}

/// The docker rung's in-container signing leaf (spec E(2)) — moved from `main.rs` so
/// its authority construction is module-private, not a `pub(crate)` crack. The TTY
/// passphrase read and the dumpable assert stay in the `main.rs` handler (process/UI
/// concerns); this fn unwraps, constructs the witness INTERNALLY, and signs each
/// target. It legitimately cannot use `plan_signing`: it holds an in-container
/// passphrase and MUST unwrap, which `plan_signing` never does.
pub fn sign_in_container_leaf(
    keys_dir: &Path,
    passphrase: &[u8],
    targets: &[(PathBuf, Purpose)],
) -> Result<Vec<PathBuf>, DeployKeyError> {
    let set = super::artifact_keys::load_artifact_keys_with(keys_dir, Some(passphrase))?;
    let auth = HostSignAuthority { set: Box::new(set) };
    let mut out = Vec::with_capacity(targets.len());
    for (path, purpose) in targets {
        out.push(sign_file(&auth, *purpose, path)?);
    }
    Ok(out)
}

/// Test-only witness constructor (spec E; audit R4 I-A: ≈8 direct cfg-test callers keep
/// their raw-set fixtures through this — the production crate has no path to it).
#[cfg(test)]
pub(crate) fn test_authority(set: ArtifactKeySet) -> HostSignAuthority {
    HostSignAuthority { set: Box::new(set) }
}

/// The rung-detection outcome for a build-time sign ([`plan_signing`]).
pub enum SignPlan {
    /// Software rung: raw seeds on the host → sign the outputs on the host. Carries the
    /// [`HostSignAuthority`] witness (which boxes the ~280 B set internally — this enum
    /// is a short-lived once-per-build local, so a single alloc keeps
    /// `Docker`/`UnsignedFloor` cheap).
    Host(HostSignAuthority),
    /// Docker rung: the worker key is a wrapped blob → sign IN the pinned container.
    Docker,
    /// No signing rung is configured (no keys, no committed pin) → the legitimate
    /// UNSIGNED floor; the build proceeds unsigned.
    UnsignedFloor,
}

/// Decide how a build-time sign should proceed WITHOUT signing or spawning docker
/// (§6). PURE + total so the fail-closed matrix is unit-testable. The rung is
/// DETECTED from the worker `.key`'s custody (via the Task 6 taxonomy, no
/// passphrase — the host never unwraps) plus the committed pin:
/// - a RAW worker seed ⇒ [`SignPlan::Host`] (software rung);
/// - a WRAPPED worker blob ⇒ [`SignPlan::Docker`] (`Passphrase` = a wrapped blob
///   detected with no host passphrase — the docker rung signs in-container,
                 
/// - genuinely-absent keys ⇒ consult the committed pin — the DURABLE "a rung was
                                                                                   
///   ⇒ `Err` (a rung was adopted, keys are missing — never build UNSIGNED,
                                                                                 
/// - present-but-unloadable (a corrupt blob, an incomplete set, an io error) ⇒
///   `Err` (ABORT, F-7 — never the silent unsigned fallthrough).
pub fn plan_signing(keys_dir: &Path, pin_path: &Path) -> Result<SignPlan, DeployKeyError> {
    match load_artifact_keys(keys_dir) {
        Ok(set) => Ok(SignPlan::Host(HostSignAuthority { set: Box::new(set) })),
        Err(DeployKeyError::Passphrase { .. }) => Ok(SignPlan::Docker),
        Err(DeployKeyError::NotFound { .. }) => {
                                                                                       
                                                                                   
            if std::fs::symlink_metadata(pin_path).is_ok() {
                Err(DeployKeyError::Import(format!(
                    "a signing rung was adopted (committed pin {} present) but the artifact \
                     keys are absent from {} — refusing to build UNSIGNED; restore the keys \
                     or remove the pin",
                    pin_path.display(),
                    keys_dir.display()
                )))
            } else {
                Ok(SignPlan::UnsignedFloor)
            }
        }
        Err(e) => Err(e),
    }
}

/// Sign the three box-consumed build outputs (`.img` / vmlinuz / initramfs) with the
/// artifact key set in `keys_dir`, returning the `.sig` sidecar paths. Rung-aware +
/// fail-CLOSED (§6): the software rung signs on the host; the docker rung routes the
/// whole triple into the pinned container under ONE invocation (one passphrase entry,
/// via [`super::artifact_keys::docker_sign_artifacts`]). Returns `Ok(None)` ONLY at
/// the un-adopted floor (no keys AND no committed `pin_path`); a rung adopted with the
/// keys absent, a present-but-unloadable key set, or any docker-sign failure is a hard
                                                                               
/// signing hook both `deploy build` AND `deploy prod`'s inline build call, so their
                                                                                
/// standalone `orchard` crate, never linked into the box image.
pub fn sign_build_outputs(
    keys_dir: &Path,
    pin_path: &Path,
    img: &Path,
    vmlinuz: &Path,
    initramfs: &Path,
) -> Result<Option<Vec<PathBuf>>, DeployKeyError> {
    match plan_signing(keys_dir, pin_path)? {
        SignPlan::Host(auth) => {
            let mut sigs = Vec::with_capacity(3);
            for (path, purpose) in [
                (img, Purpose::Img),
                (vmlinuz, Purpose::KexecVmlinuz),
                (initramfs, Purpose::KexecInitramfs),
            ] {
                sigs.push(sign_file(&auth, purpose, path)?);
            }
            Ok(Some(sigs))
        }
        SignPlan::Docker => super::artifact_keys::docker_sign_artifacts(
            keys_dir,
            &[
                (Purpose::Img, img),
                (Purpose::KexecVmlinuz, vmlinuz),
                (Purpose::KexecInitramfs, initramfs),
            ],
        )
        .map(Some),
        SignPlan::UnsignedFloor => Ok(None),
    }
}

/// Docker-rung signing for an IN-MEMORY manifest (the weights record, the model push,
/// the update push): write the canonical bytes into a per-invocation scratch dir,
/// tightened to 0700, run ONE `docker_sign_artifacts` invocation (operator types the
/// passphrase in-container; the host never buffers it or unwraps the seed), read the
/// 254-byte bundle back. `tempfile`'s `tempdir()` honors the umask (0755 under the
/// default umask 022, NOT 0700), so the mode is set explicitly — mirroring
/// `generate_artifact_keys`' staging-dir hardening (audit R1 L-1), even though these
/// bytes are PUBLIC (verity/hash/size manifest metadata; no key material or passphrase
/// ever lands here). Dropped on return. `pub` (not `pub(crate)`) solely so the attended
/// `docker_sign_gate` integration test can exercise the real round-trip; production
/// callers are the three routed ceremonies.
pub fn docker_sign_manifest_bytes(
    keys_dir: &Path,
    purpose: Purpose,
    manifest: &[u8],
    name: &str,
) -> Result<Vec<u8>, String> {
    let scratch = tempfile::Builder::new()
        .prefix("orchard-sign-")
        .tempdir()
        .map_err(|e| format!("docker sign: create scratch dir: {e}"))?;
                                                                                        
                                                                                 
                                                                                          
    super::keys::set_mode(scratch.path(), 0o700)
        .map_err(|e| format!("docker sign: tighten scratch dir to 0700: {e}"))?;
    let path = scratch.path().join(name);
    std::fs::write(&path, manifest)
        .map_err(|e| format!("docker sign: write {}: {e}", path.display()))?;
    let sigs = super::artifact_keys::docker_sign_artifacts(keys_dir, &[(purpose, path.as_path())])
        .map_err(|e| e.to_string())?;
    let sig_path = sigs
        .into_iter()
        .next()
        .ok_or("docker sign: no sidecar produced")?;
    let sig = std::fs::read(&sig_path)
        .map_err(|e| format!("docker sign: read {}: {e}", sig_path.display()))?;
    if sig.len() != 254 {
        return Err(format!(
            "docker sign: sidecar is {} bytes, want 254",
            sig.len()
        ));
    }
    Ok(sig)
}

/// The `sign-backup` ceremony routing (spec E(1)) — extracted from the main.rs handler
/// so the routing decision is unit-testable. Backup signing is an EXPLICIT sign
/// request: there is no unsigned floor — absent keys (with or without a committed
/// pin) and unloadable keys are hard errors, exactly the pre-routing posture (§6/F-7).
pub fn sign_backup_routed(
    keys_dir: &Path,
    pin_path: &Path,
    file: &Path,
) -> Result<PathBuf, String> {
    match plan_signing(keys_dir, pin_path).map_err(|e| {
        format!(
            "sign-backup: cannot load the artifact key set in {} \
             (run `orchard generate-keys --artifact-signing …`): {e}",
            keys_dir.display()
        )
    })? {
        SignPlan::Host(set) => sign_file(&set, Purpose::Backup, file).map_err(|e| e.to_string()),
        SignPlan::Docker => {
            super::artifact_keys::docker_sign_artifacts(keys_dir, &[(Purpose::Backup, file)])
                .map_err(|e| e.to_string())?
                .into_iter()
                .next()
                .ok_or_else(|| "sign-backup: docker sign produced no sidecar".to_string())
        }
        SignPlan::UnsignedFloor => Err(format!(
            "sign-backup: no artifact key set in {} and no committed \
             pinned-artifact-root.toml (run `orchard generate-keys --artifact-signing …`) — \
             sign-backup has no unsigned floor",
            keys_dir.display()
        )),
    }
}

/// `<path>` → `<path>.sig` (append, not replace-extension, so `r.img` → `r.img.sig`
/// and `r.initramfs` → `r.initramfs.sig`).
pub fn sig_sidecar_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".sig");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::artifact_keys::{
        Custody, generate_artifact_keys, load_artifact_keys, unix_now,
    };
    use dragonfruit::{BundleFile, verify_bundle};

    fn key_set(dir: &Path) -> ArtifactKeySet {
        generate_artifact_keys(dir, 365, false, Custody::Raw).unwrap();
        load_artifact_keys(dir).unwrap()
    }

    #[test]
    fn existing_4_delegation_set_gives_actionable_signing_error() {
                                                                                       
                                                                                     
                                                                                     
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Raw).unwrap();
                                                   
        for name in [
            "artifact-delegation-update-image.bundle",
            "artifact-delegation-root-hash.bundle",
        ] {
            std::fs::remove_file(keys.join(name)).unwrap();
        }
        let err = match plan_signing(&keys, &dir.path().join("no-pin")) {
            Err(e) => e,
            Ok(_) => panic!("plan_signing must fail closed on a 4-delegation set"),
        };
        assert!(
            matches!(err, DeployKeyError::MissingDelegation { .. }),
            "want MissingDelegation, got {err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("orchard redelegate"), "not actionable: {msg}");
        assert!(
            msg.contains("update-image"),
            "doesn't name the missing purpose: {msg}"
        );
    }

    #[test]
    fn streaming_hash_matches_oneshot_across_chunk_boundary() {
        let dir = tempfile::tempdir().unwrap();
                                                              
        let big = vec![0xA5u8; (1 << 20) + 12_345];
        let p = dir.path().join("big.bin");
        std::fs::write(&p, &big).unwrap();
        let streamed = streaming_sha256(&p).unwrap();
        let oneshot: [u8; 32] = Sha256::digest(&big).into();
        assert_eq!(streamed, oneshot);
    }

    #[test]
    fn sign_file_emits_a_verifiable_254_byte_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let set = key_set(&dir.path().join("keys"));
        let root_pub = set.root_pub;
        let auth = test_authority(set);
        let art = dir.path().join("toy.img");
        std::fs::write(&art, b"toy image bytes").unwrap();

        let sig_path = sign_file(&auth, Purpose::Img, &art).unwrap();
        assert_eq!(sig_path, dir.path().join("toy.img.sig"));
        let raw = std::fs::read(&sig_path).unwrap();
        assert_eq!(raw.len(), dragonfruit::BUNDLE_FILE_LEN);

        let bf = BundleFile::from_bytes(&raw).unwrap();
        let hash = streaming_sha256(&art).unwrap();
        assert!(verify_bundle(&bf.as_bundle(), &root_pub, unix_now(), &hash, Purpose::Img).is_ok());
    }

    #[test]
    fn each_purpose_embeds_its_own_delegation() {
        let dir = tempfile::tempdir().unwrap();
        let set = key_set(&dir.path().join("keys"));
        let root_pub = set.root_pub;
        let auth = test_authority(set);
        for purpose in [
            Purpose::Img,
            Purpose::KexecVmlinuz,
            Purpose::KexecInitramfs,
            Purpose::Backup,
        ] {
            let sig = sign_bytes(&auth, purpose, b"payload").unwrap();
            let bf = BundleFile::from_bytes(&sig).unwrap();
            let att = dragonfruit::Attestation::from_canonical(&bf.attestation_bytes).unwrap();
            assert_eq!(att.purpose, purpose);
                                                                      
            let v = verify_bundle(
                &bf.as_bundle(),
                &root_pub,
                unix_now(),
                &Sha256::digest(b"payload").into(),
                purpose,
            )
            .unwrap();
            assert_eq!(v.purpose(), purpose);
        }
    }

    #[test]
    fn sign_build_outputs_signs_triple_or_noops_without_keys() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
                                                                                         
        let pin = dir.path().join("pinned-artifact-root.toml");
        let mk = |name: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, name.as_bytes()).unwrap();
            p
        };
        let img = mk("r.img");
        let vmlinuz = mk("r.vmlinuz");
        let initramfs = mk("r.initramfs");

                                                                                         
        assert!(
            sign_build_outputs(&keys, &pin, &img, &vmlinuz, &initramfs)
                .unwrap()
                .is_none()
        );
        assert!(!sig_sidecar_path(&img).exists());

                                                                                        
        generate_artifact_keys(&keys, 365, false, Custody::Raw).unwrap();
        let set = load_artifact_keys(&keys).unwrap();
        let sigs = sign_build_outputs(&keys, &pin, &img, &vmlinuz, &initramfs)
            .unwrap()
            .expect("Some when key set present");
        assert_eq!(sigs.len(), 3);
        for (path, purpose) in [
            (&img, Purpose::Img),
            (&vmlinuz, Purpose::KexecVmlinuz),
            (&initramfs, Purpose::KexecInitramfs),
        ] {
            let bf =
                BundleFile::from_bytes(&std::fs::read(sig_sidecar_path(path)).unwrap()).unwrap();
            let hash = streaming_sha256(path).unwrap();
            let v =
                verify_bundle(&bf.as_bundle(), &set.root_pub, unix_now(), &hash, purpose).unwrap();
            assert_eq!(v.purpose(), purpose);
        }
    }

    #[test]
    fn sign_backup_with_no_rung_is_a_hard_actionable_error() {
                                                                                              
                                                                                            
        let dir = tempfile::tempdir().unwrap();
        let err = sign_backup_routed(
            &dir.path().join("no-keys"),
            &dir.path().join("no-pin"),
            &dir.path().join("backup.tar"),
        )
        .unwrap_err();
        assert!(err.contains("generate-keys"), "not actionable: {err}");
        assert!(
            err.contains("no unsigned floor") || err.contains("cannot load"),
            "{err}"
        );
    }

    #[test]
    fn sign_backup_wrapped_custody_routes_to_docker() {
                                                                                          
                                                                                          
                                                                                         
                                                                     
        use crate::deploy::artifact_keys::{Custody, generate_artifact_keys};
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Wrapped { passphrase: b"pw" }).unwrap();
        assert!(matches!(
            plan_signing(&keys, &dir.path().join("no-pin")),
            Ok(SignPlan::Docker)
        ));
    }

    #[test]
    fn sidecar_path_appends_not_replaces() {
        assert_eq!(
            sig_sidecar_path(Path::new("/x/r.initramfs")),
            PathBuf::from("/x/r.initramfs.sig")
        );
        assert_eq!(
            sig_sidecar_path(Path::new("/x/r.img")),
            PathBuf::from("/x/r.img.sig")
        );
    }

                                                                                    

    fn wrapped_keys(dir: &Path) {
        generate_artifact_keys(dir, 365, false, Custody::Wrapped { passphrase: b"pw" }).unwrap();
    }

    #[test]
    fn plan_signing_raw_keys_routes_to_host_sign() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Raw).unwrap();
        let pin = dir.path().join("pinned-artifact-root.toml");                                     
        assert!(matches!(plan_signing(&keys, &pin), Ok(SignPlan::Host(_))));
    }

    #[test]
    fn plan_signing_wrapped_keys_routes_to_docker() {
                                                                                         
                                                                 
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        wrapped_keys(&keys);
        let pin = dir.path().join("pinned-artifact-root.toml");
        assert!(matches!(plan_signing(&keys, &pin), Ok(SignPlan::Docker)));
    }

    #[test]
    fn plan_signing_absent_keys_no_pin_is_the_unsigned_floor() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");                  
        let pin = dir.path().join("pinned-artifact-root.toml");                   
        assert!(matches!(
            plan_signing(&keys, &pin),
            Ok(SignPlan::UnsignedFloor)
        ));
    }

    #[test]
    fn plan_signing_rung_adopted_but_keys_absent_aborts() {
                                                                                     
                                                                                      
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");                         
        let pin = dir.path().join("pinned-artifact-root.toml");
        std::fs::write(&pin, "pubkey = \"ed25519:00\"\n").unwrap();
        assert!(plan_signing(&keys, &pin).is_err());
    }

    #[test]
    fn plan_signing_corrupt_worker_key_aborts_even_without_a_pin() {
                                                                        
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(
            keys.join("artifact-worker.key"),
            b"neither a v1 blob nor 32 bytes",
        )
        .unwrap();
        let pin = dir.path().join("pinned-artifact-root.toml");          
        assert!(plan_signing(&keys, &pin).is_err());
    }

    #[test]
    fn sign_build_outputs_no_rung_builds_unsigned_but_adopted_rung_aborts() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let pin = dir.path().join("pinned-artifact-root.toml");
        let mk = |name: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, name.as_bytes()).unwrap();
            p
        };
        let (img, vmlinuz, initramfs) = (mk("r.img"), mk("r.vmlinuz"), mk("r.initramfs"));
                                                                                      
        assert!(
            sign_build_outputs(&keys, &pin, &img, &vmlinuz, &initramfs)
                .unwrap()
                .is_none()
        );
        assert!(!sig_sidecar_path(&img).exists());
                                                                                         
        std::fs::write(&pin, "pubkey = \"ed25519:00\"\n").unwrap();
        assert!(sign_build_outputs(&keys, &pin, &img, &vmlinuz, &initramfs).is_err());
        assert!(!sig_sidecar_path(&img).exists());
    }
}
