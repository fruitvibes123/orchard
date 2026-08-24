                                                                                
//! mints the ed25519 root+worker pair + the six purpose-bound delegations in
//! ONE pass. The root pubkey hex (`artifact-root.pub`) is THE operator pin;
                                                                         
//!
//! On the software/docker rungs everything here lives on the operator host — the
                                                                                
//! described as closing build-host compromise. The hardware rungs reuse the same
//! bundle contract but sign on-device (C3/C4) and feed bundles in instead.
//!
                                                                                  
//! a worker authorized for every artifact kind needs SIX delegations over the
//! same worker pubkey — minted here as `artifact-delegation-{img,vmlinuz,
//! initramfs,backup,update-image,root-hash}.bundle`. `monotonic_ctr` = the shared
//! issuance-second (one ceremony; the update path ENFORCES it: the box's minctr
//! floor + `orchard build`'s baked `min_delegation_ctr` both read it — A/B v1).

use super::keys::{DeployKeyError, set_mode, write_file_mode};
use dragonfruit::{DELEGATION_LEN, Delegation, Purpose, sign_delegation};
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// One bundle = `delegation[59] ‖ root_sig[64]`.
pub(crate) const DELEGATION_BUNDLE_LEN: usize = DELEGATION_LEN + 64;

/// Files the ceremony writes (key files 0600, public files 0644).
pub const ARTIFACT_FILES: [&str; 10] = [
    "artifact-root.key",
    "artifact-worker.key",
    "artifact-root.pub",
    "artifact-delegation-img.bundle",
    "artifact-delegation-vmlinuz.bundle",
    "artifact-delegation-initramfs.bundle",
    "artifact-delegation-backup.bundle",
    "artifact-delegation-update-image.bundle",
    "artifact-delegation-root-hash.bundle",
    "artifact-delegation-weights.bundle",
];

                                                                                     
/// pair, os-update A/B v1 T2, + the hotswap-model `Weights` purpose, hotswap v4).
/// Extending this list makes every PRE-existing key set hard-fail its next load —
/// that is intended (fail-closed; `orchard build` bakes the UpdateImage delegation ctr
/// as `min_delegation_ctr`, R4-1) and surfaced as the actionable
/// [`DeployKeyError::MissingDelegation`], never a raw file-not-found (S2):
/// `orchard redelegate` mints the missing delegation over the pre-existing root.
const ALL_PURPOSES: [Purpose; 7] = [
    Purpose::Img,
    Purpose::KexecVmlinuz,
    Purpose::KexecInitramfs,
    Purpose::Backup,
    Purpose::UpdateImage,
    Purpose::RootHash,
    Purpose::Weights,
];

/// The signing material the sign/preflight paths need: the public pin, the
/// worker signing key, and the six stored (purpose-bound) delegation bundles.
/// The ROOT key is intentionally NOT loaded — artifact signing uses only the
/// worker + the pre-signed delegations; the root file exists solely for a future
/// re-delegation ceremony.
pub struct ArtifactKeySet {
    pub root_pub: [u8; 32],
    pub worker: SigningKey,
    /// `(purpose, delegation_bytes[59], root_sig[64])`, ceremony order.
    pub delegations: Vec<(Purpose, [u8; DELEGATION_LEN], [u8; 64])>,
}

                                                                                   
/// (`artifact-root.pub`) and the delegation bundles are public and ALWAYS unwrapped;
/// only the two `.key` SEED files differ:
/// - [`Custody::Raw`] — the software rung: the 32-byte seed in the clear.
/// - [`Custody::Wrapped`] — the docker rung: an Argon2id→XChaCha20-Poly1305 keywrap
///   blob (`HOST_TARGET` params, AAD-bound to the key role). The in-container keygen
///   leg reads the passphrase and wraps, so the UNWRAPPED seed never touches the host FS
                                                      
pub enum Custody<'a> {
    Raw,
    Wrapped { passphrase: &'a [u8] },
}

/// The at-rest encoding of a 32-byte seed under the chosen custody: RAW bytes (software)
/// or a keywrap blob (docker — Argon2id→XChaCha20-Poly1305 at `HOST_TARGET`, AAD-bound
/// to `role`). Returns `Zeroizing` (the raw seed is secret; the blob is ciphertext but
/// zeroizing it is harmless and keeps the return type uniform).
fn seed_at_rest(
    seed: &Zeroizing<[u8; 32]>,
    role: super::keywrap::KeyRole,
    custody: &Custody<'_>,
) -> Result<Zeroizing<Vec<u8>>, DeployKeyError> {
    match custody {
        Custody::Raw => Ok(Zeroizing::new(seed.to_vec())),
        Custody::Wrapped { passphrase } => Ok(Zeroizing::new(
            super::keywrap::wrap_seed(seed, passphrase, role, super::keywrap::HOST_TARGET)
                .map_err(|e| DeployKeyError::Import(format!("wrap {role:?} seed: {e}")))?,
        )),
    }
}

/// The on-disk slug for a purpose's delegation bundle filename.
pub(crate) fn purpose_slug(p: Purpose) -> &'static str {
    match p {
        Purpose::Img => "img",
        Purpose::KexecVmlinuz => "vmlinuz",
        Purpose::KexecInitramfs => "initramfs",
        Purpose::Backup => "backup",
                                                                                           
                                                                                          
                                                                                          
                                                                           
        Purpose::UpdateImage => "update-image",
        Purpose::RootHash => "root-hash",
                                                                               
        Purpose::Weights => "weights",
    }
}

pub(crate) fn delegation_bundle_name(p: Purpose) -> String {
    format!("artifact-delegation-{}.bundle", purpose_slug(p))
}

/// Build one delegation bundle (`delegation[59] ‖ root_sig[64]`) over `worker_pubkey`
/// for `purpose`. THE single mint primitive — the keygen ceremony and `orchard
/// redelegate` both go through it, so the bundle shape cannot drift between them.
pub(crate) fn mint_delegation_bundle(
    root: &SigningKey,
    worker_pubkey: [u8; 32],
    purpose: Purpose,
    not_before: u64,
    not_after: u64,
    monotonic_ctr: u64,
) -> Vec<u8> {
    let d = Delegation {
        worker_pubkey,
        purpose,
        not_before,
        not_after,
        monotonic_ctr,
    };
    let mut bundle = Vec::with_capacity(DELEGATION_BUNDLE_LEN);
    bundle.extend_from_slice(&d.to_canonical());
    bundle.extend_from_slice(&sign_delegation(root, &d));
    bundle
}

                                                                                      
/// checked window end `now + window_days·86400` — no silent saturate-to-never-expire.
/// Shared by the keygen ceremony and `orchard redelegate`.
pub(crate) fn delegation_window_end(now: u64, window_days: u64) -> Result<u64, DeployKeyError> {
                                                                                      
                                                              
    if !(1..=MAX_WINDOW_DAYS).contains(&window_days) {
        return Err(DeployKeyError::Import(format!(
            "delegation window {window_days} days out of range (must be 1..={MAX_WINDOW_DAYS}): \
             0 mints a born-invalid delegation, an absurd value would never expire"
        )));
    }
    window_days
        .checked_mul(86_400)
        .and_then(|secs| now.checked_add(secs))
        .ok_or_else(|| DeployKeyError::Import("delegation window overflows u64".into()))
}

fn io_err(path: &Path, source: std::io::Error) -> DeployKeyError {
    DeployKeyError::Io {
        path: path.display().to_string(),
        source,
    }
}

                                                                          
const PIN_FILE: &str = "artifact-root.pub";

/// Max delegation window accepted at mint (~100 years). Whitelist the sane range
                                                                              
/// delegation, an absurd value would silently never expire.
const MAX_WINDOW_DAYS: u64 = 36_525;

/// Run the artifact-signing ceremony into `keys_dir` — the ed25519 root+worker pair,
/// the six delegation bundles, and the public pin. `custody` selects the at-rest
/// encoding of the two SEED files: RAW (software rung) or passphrase-WRAPPED (docker
/// rung — [`Custody`]); the pin + bundles are public and always unwrapped. Refuses to
/// overwrite an existing artifact key set unless `force`. `window_days` is the
/// delegations' validity window (now → now + window_days, `1..=MAX_WINDOW_DAYS`).
///
                                                                                       
/// (0700) — NOT a sibling of it (a parent-sibling tempdir breaks the docker rung's `/keys`
/// BIND MOUNT with a cross-device EXDEV rename; see the impl comment) — and renamed into
/// `keys_dir` only after every write succeeds. An interrupted ceremony leaves `keys_dir`
/// EMPTY (the staging dir + its partial writes are wiped on drop), never a partial set;
/// the pin is renamed LAST so even a torn rename phase never leaves a pin that out-runs
/// its delegations.
pub fn generate_artifact_keys(
    keys_dir: &Path,
    window_days: u64,
    force: bool,
    custody: Custody<'_>,
) -> Result<(), DeployKeyError> {
                                                                                 
                                                                         
    let now = unix_now();
    let not_after = delegation_window_end(now, window_days)?;
    for name in ARTIFACT_FILES {
        if keys_dir.join(name).exists() && !force {
            return Err(DeployKeyError::Exists(
                name.to_string(),
                keys_dir.display().to_string(),
            ));
        }
    }

                                                                             
    let mut root_seed = Zeroizing::new([0u8; 32]);
    let mut worker_seed = Zeroizing::new([0u8; 32]);
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(root_seed.as_mut());
        rand::rngs::OsRng.fill_bytes(worker_seed.as_mut());
    }
    let root = SigningKey::from_bytes(&root_seed);
    let worker = SigningKey::from_bytes(&worker_seed);
    let worker_pubkey = worker.verifying_key().to_bytes();

                                                                                            
                                                                                            
                                                                                        
                                                                                       
                                                                                         
                                                                                         
                                                                                         
                                                                             
    std::fs::create_dir_all(keys_dir).map_err(|e| io_err(keys_dir, e))?;
    set_mode(keys_dir, 0o700)?;
    let staging = tempfile::Builder::new()
        .prefix(".recipes-artifact-keys-")
        .tempdir_in(keys_dir)
        .map_err(|e| io_err(keys_dir, e))?;
                                                                                     
                                                                     
    set_mode(staging.path(), 0o700)?;

    let pin_line = format!("{}\n", hex::encode(root.verifying_key().to_bytes()));
                                                                                           
                                                                                           
    let root_at_rest = seed_at_rest(&root_seed, super::keywrap::KeyRole::Root, &custody)?;
    let worker_at_rest = seed_at_rest(&worker_seed, super::keywrap::KeyRole::Worker, &custody)?;
    write_file_mode(
        &staging.path().join("artifact-root.key"),
        &root_at_rest,
        0o600,
    )?;
    write_file_mode(
        &staging.path().join("artifact-worker.key"),
        &worker_at_rest,
        0o600,
    )?;
    write_file_mode(&staging.path().join(PIN_FILE), pin_line.as_bytes(), 0o644)?;
    for purpose in ALL_PURPOSES {
        write_file_mode(
            &staging.path().join(delegation_bundle_name(purpose)),
            &mint_delegation_bundle(&root, worker_pubkey, purpose, now, not_after, now),
            0o644,
        )?;
    }

                                                                                       
                                                                                         
                                                         
    for name in ARTIFACT_FILES.iter().filter(|n| **n != PIN_FILE) {
        let dest = keys_dir.join(name);
        std::fs::rename(staging.path().join(name), &dest).map_err(|e| io_err(&dest, e))?;
    }
    let pin_dest = keys_dir.join(PIN_FILE);
    std::fs::rename(staging.path().join(PIN_FILE), &pin_dest).map_err(|e| io_err(&pin_dest, e))?;
    Ok(())
}

/// Read `purpose`'s delegation `monotonic_ctr` from `keys_dir`. PUBLIC-only: it reads the
/// delegation BUNDLE (never the worker/root seed), so a docker-rung (wrapped) key set needs no
/// passphrase. Fail-closed tri-state:
/// - `Ok(Some(ctr))` — the bundle is present and parses;
/// - `Err(MissingDelegation)` — a signing rung WAS adopted (the public pin `artifact-root.pub` is
///   present) but this purpose's bundle is absent (a legacy pre-purpose set) → the actionable
                                                                                  
/// - `Ok(None)` — NO artifact key material at all (no pin) → the unsigned dev floor; the caller
///   decides what that floor means for its purpose.
pub fn read_delegation_ctr(
    keys_dir: &Path,
    purpose: Purpose,
) -> Result<Option<u64>, DeployKeyError> {
    let bundle = keys_dir.join(delegation_bundle_name(purpose));
    match std::fs::read(&bundle) {
        Ok(raw) => {
            if raw.len() != DELEGATION_BUNDLE_LEN {
                return Err(DeployKeyError::Import(format!(
                    "{} delegation bundle is {} bytes, expected {DELEGATION_BUNDLE_LEN}",
                    purpose_slug(purpose),
                    raw.len()
                )));
            }
            let d = Delegation::from_canonical(&raw[..DELEGATION_LEN]).map_err(|e| {
                DeployKeyError::Unloadable {
                    path: bundle.display().to_string(),
                    reason: format!("{} delegation parse: {e:?}", purpose_slug(purpose)),
                }
            })?;
            Ok(Some(d.monotonic_ctr))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                                                                                    
                                                                                                        
            if keys_dir.join(PIN_FILE).exists() {
                Err(DeployKeyError::MissingDelegation {
                    purpose: purpose_slug(purpose).to_string(),
                })
            } else {
                Ok(None)
            }
        }
        Err(e) => Err(io_err(&bundle, e)),
    }
}

/// Read the `UpdateImage` delegation's `monotonic_ctr` — the value `orchard build` bakes as the
/// image's `min_delegation_ctr` (os-update A/B v1 §4i, T6). Thin wrapper over
/// [`read_delegation_ctr`]; existing callers keep this name.
pub fn read_updateimage_ctr(keys_dir: &Path) -> Result<Option<u64>, DeployKeyError> {
    read_delegation_ctr(keys_dir, Purpose::UpdateImage)
}

                                                                                     
/// delegation bundle — always-unwrapped metadata — so the Docker arm (which loads no
/// key set) sources it identically to the Host arm.
pub fn read_weights_ctr(keys_dir: &Path) -> Result<Option<u64>, DeployKeyError> {
    read_delegation_ctr(keys_dir, Purpose::Weights)
}

/// Read + parse the PUBLIC root-pin file (`artifact-root.pub`) → the 32-byte root
/// pubkey. Public bytes: NO secret, NO passphrase — so the docker rung's host-side pin
/// write reads the root pubkey through this even though the `.key` files are wrapped
                                                                                 
pub fn read_root_pub(keys_dir: &Path) -> Result<[u8; 32], DeployKeyError> {
    let path = keys_dir.join(PIN_FILE);
    let pin_hex = String::from_utf8(std::fs::read(&path).map_err(|e| io_err(&path, e))?)
        .map_err(|e| DeployKeyError::Import(format!("artifact-root.pub not utf8: {e}")))?;
    hex::decode(pin_hex.trim())
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| DeployKeyError::Import("artifact-root.pub is not 64 hex chars".into()))
}

/// Load the worker signing seed from `keys_dir/artifact-worker.key`, unwrapping
/// the docker rung's passphrase-wrapped blob when present (Task 6). The on-disk
/// format is SELF-DETECTING: a valid v1 [`super::keywrap`] blob ⇒ unwrap with
/// `passphrase`; a raw 32-byte seed ⇒ the software rung (no passphrase). Fails
/// CLOSED with a precise taxonomy so no caller ever confuses "absent" (skip-vs-abort
/// is the caller's call) with "present but unloadable" (ALWAYS abort — never a
/// silent unsigned fallthrough, F-6):
/// - genuinely absent (lstat NotFound) ⇒ [`DeployKeyError::NotFound`];
/// - wrapped, no passphrase / wrong passphrase ⇒ [`DeployKeyError::Passphrase`];
/// - wrapped-but-otherwise-unopenable, or bytes that are neither a v1 blob nor a
///   32-byte raw seed ⇒ [`DeployKeyError::Unloadable`].
///
/// `symlink_metadata` (lstat) FIRST — mirroring `artifact_verify::read_root_pin`
                                                                                
/// wrongly read as "absent → skip"; lstat calls only a GENUINELY-absent path
/// NotFound, so a broken key link becomes a hard read error, never a skip.
pub fn load_worker_seed(
    keys_dir: &Path,
    passphrase: Option<&[u8]>,
) -> Result<Zeroizing<[u8; 32]>, DeployKeyError> {
    load_seed_file(
        &keys_dir.join("artifact-worker.key"),
        super::keywrap::KeyRole::Worker,
        passphrase,
    )
}

/// Load the ROOT signing seed from `keys_dir/artifact-root.key` — the input of the
/// `orchard redelegate` ceremony (plan-review S3), and its ONLY consumer: every other
/// loader intentionally carries just `root_pub` ([`ArtifactKeySet`] — "the root file
/// exists solely for a future re-delegation ceremony"; this IS that ceremony). Same
/// self-detecting custody classes + absent-vs-unloadable taxonomy as
/// [`load_worker_seed`]; the keywrap AAD binds [`super::keywrap::KeyRole::Root`], so a
/// worker blob renamed over the root file fails the unwrap rather than mis-loading.
pub fn load_root_seed(
    keys_dir: &Path,
    passphrase: Option<&[u8]>,
) -> Result<Zeroizing<[u8; 32]>, DeployKeyError> {
    load_seed_file(
        &keys_dir.join("artifact-root.key"),
        super::keywrap::KeyRole::Root,
        passphrase,
    )
}

/// The shared seed-file loader behind [`load_worker_seed`] / [`load_root_seed`]:
/// self-detecting at-rest custody (a valid v1 keywrap blob ⇒ unwrap with `passphrase`
/// under `role`'s AAD; exactly 32 raw bytes ⇒ the software rung) with the fail-closed
/// absent-vs-unloadable taxonomy documented on [`load_worker_seed`].
fn load_seed_file(
    path: &Path,
    role: super::keywrap::KeyRole,
    passphrase: Option<&[u8]>,
) -> Result<Zeroizing<[u8; 32]>, DeployKeyError> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(DeployKeyError::NotFound {
                path: path.display().to_string(),
            });
        }
        Err(e) => return Err(io_err(path, e)),
        Ok(_) => {}
    }
                                                                                   
                                                                           
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|e| io_err(path, e))?);

                                                                                 
                                                                                    
    if super::keywrap::decode_blob(&bytes[..]).is_ok() {
        let pw = passphrase.ok_or_else(|| DeployKeyError::Passphrase {
            path: path.display().to_string(),
        })?;
        return match super::keywrap::unwrap_seed(&bytes[..], pw, role) {
            Ok(seed) => Ok(seed),
                                                                                        
                                                                                
            Err(super::keywrap::WrapError::Aead) => Err(DeployKeyError::Passphrase {
                path: path.display().to_string(),
            }),
                                                                                       
                                                                                     
            Err(e) => Err(DeployKeyError::Unloadable {
                path: path.display().to_string(),
                reason: e.to_string(),
            }),
        };
    }
    match <[u8; 32]>::try_from(&bytes[..]) {
        Ok(seed) => Ok(Zeroizing::new(seed)),
        Err(_) => Err(DeployKeyError::Unloadable {
            path: path.display().to_string(),
            reason: format!(
                "not a keywrap v1 blob and not a 32-byte raw seed ({} bytes)",
                bytes.len()
            ),
        }),
    }
}

/// Load the signing material (worker key + the six delegation bundles + the pin)
/// on the HOST/software path (no passphrase). Used by the software-rung sign step
/// (C2 Task 6) and — for the pin only — the preflight. A WRAPPED (docker-rung)
/// worker key here correctly surfaces as [`DeployKeyError::Passphrase`] (the docker
/// rung signs IN-container via [`docker_sign_artifacts`], never loading the full set
/// on the host); see [`load_artifact_keys_with`] for the in-container unwrap path.
pub fn load_artifact_keys(keys_dir: &Path) -> Result<ArtifactKeySet, DeployKeyError> {
    load_artifact_keys_with(keys_dir, None)
}

/// Load the signing material, optionally supplying the docker-rung passphrase to
/// unwrap the worker seed (Task 8). `None` is the host/software path (a wrapped key
/// here is correctly [`DeployKeyError::Passphrase`] — the docker rung signs
/// IN-container); `Some(pw)` is the in-container `sign-in-container` leg, where the
/// worker `.key` is a passphrase-wrapped blob. The worker seed is loaded FIRST via
/// the unwrap-aware loader, which drives the absent-vs-unloadable taxonomy — a
/// genuinely-absent set surfaces as NotFound (the caller decides skip-vs-abort), a
/// present-but-unloadable/wrong-passphrase key as Unloadable/Passphrase (ALWAYS
/// abort, never a silent unsigned fallthrough).
pub fn load_artifact_keys_with(
    keys_dir: &Path,
    passphrase: Option<&[u8]>,
) -> Result<ArtifactKeySet, DeployKeyError> {
    let worker_seed = load_worker_seed(keys_dir, passphrase)?;
    let worker = SigningKey::from_bytes(&worker_seed);

    let root_pub = read_root_pub(keys_dir)?;

    let mut delegations = Vec::with_capacity(ALL_PURPOSES.len());
    for purpose in ALL_PURPOSES {
        let p = keys_dir.join(delegation_bundle_name(purpose));
        let raw = match std::fs::read(&p) {
            Ok(raw) => raw,
                                                                               
                                                                                     
                                                                          
                                                                           
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(DeployKeyError::MissingDelegation {
                    purpose: purpose_slug(purpose).to_string(),
                });
            }
            Err(e) => return Err(io_err(&p, e)),
        };
        if raw.len() != DELEGATION_BUNDLE_LEN {
            return Err(DeployKeyError::Import(format!(
                "delegation bundle for {purpose:?} is {} bytes, expected {DELEGATION_BUNDLE_LEN}",
                raw.len()
            )));
        }
        let mut bytes = [0u8; DELEGATION_LEN];
        let mut sig = [0u8; 64];
        bytes.copy_from_slice(&raw[..DELEGATION_LEN]);
        sig.copy_from_slice(&raw[DELEGATION_LEN..]);
        delegations.push((purpose, bytes, sig));
    }

                                                                                        
                                                                                           
                                                                                      
                                                                                            
                                                                                            
                                                                                        
                                                                                               
                                                                                             
                                                                                            
                                                                        
    let worker_pub = worker.verifying_key().to_bytes();
    for (purpose, bytes, _) in &delegations {
        let deleg = Delegation::from_canonical(bytes).map_err(|e| DeployKeyError::Unloadable {
            path: keys_dir
                .join(delegation_bundle_name(*purpose))
                .display()
                .to_string(),
            reason: format!("delegation parse: {e:?}"),
        })?;
        if deleg.worker_pubkey != worker_pub {
            return Err(DeployKeyError::Unloadable {
                path: keys_dir.join("artifact-worker.key").display().to_string(),
                reason: format!(
                    "loaded worker key does not authorize the {purpose:?} delegation \
                     (pubkey mismatch) — a corrupt / wrong / mis-detected key file; refusing \
                     to mis-sign"
                ),
            });
        }
    }

    Ok(ArtifactKeySet {
        root_pub,
        worker,
        delegations,
    })
}

/// The `software` menu rung: mint the artifact key set + write the committed
                                                                                
pub fn provision_software_rung(
    keys_dir: &Path,
    pin_path: &Path,
    window_days: u64,
    force: bool,
) -> Result<[u8; 32], DeployKeyError> {
    generate_artifact_keys(keys_dir, window_days, force, Custody::Raw)?;
    let set = load_artifact_keys(keys_dir)?;
    super::fingerprints::set_artifact_root_pin(pin_path, &set.root_pub)?;
    Ok(set.root_pub)
}

/// The pinned imgbuild container's MUTABLE tag — never a `docker run` target
                                                                             
/// via [`resolve_image_id`] and runs by that id.
pub const IMGBUILD_TAG: &str = "recipes-imgbuild:dev";

/// The in-container mount point of the operator keys dir. SINGLE source of truth so
/// the `docker run -v <host>:<this>` mount target and the in-container
/// `sign-in-container --keys-dir` default cannot drift apart (L-2): the host route
/// never passes `--keys-dir`, so the in-container load relies on this default equalling
/// the mount target — coupled by construction via this one const.
pub const IN_CONTAINER_KEYS_DIR: &str = "/keys";

/// The in-container mount point of the writable outputs dir. SINGLE source of truth so
/// `docker_sign_argv`'s `-v <host>:<this>` mount and `plan_container_sign`'s
/// `<this>/<filename>` artifact paths cannot drift apart.
pub const IN_CONTAINER_OUT_DIR: &str = "/out";

/// Resolve a mutable tag to its concrete, content-addressed image id
                                                                               
                                                                   
/// `docker run` in the operation uses the returned id verbatim, never
/// re-dereferencing the tag, closing the intra-operation tag-substitution
/// window. Fail-closed: an absent/uninspectable image is a refusal, never an
                                     
pub fn resolve_image_id(tag: &str) -> Result<String, DeployKeyError> {
    let out = std::process::Command::new("docker")
        .args(["image", "inspect", "--format", "{{.Id}}", tag])
        .output()
        .map_err(|e| {
            DeployKeyError::Import(format!(
                "docker rung: cannot spawn `docker image inspect {tag}`: {e}"
            ))
        })?;
    if !out.status.success() {
        return Err(DeployKeyError::Import(format!(
            "docker rung: image {tag} is absent/uninspectable (docker exited {}) — \
             build the pinned container first; refusing to run in an unresolved \
             environment",
            out.status
        )));
    }
    parse_image_id_output(&String::from_utf8_lossy(&out.stdout), tag)
}

/// The strict parse of `docker image inspect --format '{{.Id}}'` output:
/// exactly `sha256:` + 64 hex chars (whitelist the one sane shape; anything
/// else — empty, a tag echoed back, truncation — is a refusal).
fn parse_image_id_output(stdout: &str, tag: &str) -> Result<String, DeployKeyError> {
    let id = stdout.trim();
    let hexpart = id.strip_prefix("sha256:").unwrap_or("");
    if hexpart.len() != 64 || !hexpart.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DeployKeyError::Import(format!(
            "docker rung: resolving {tag} returned {id:?}, not a sha256:<64-hex> \
             image id — refusing"
        )));
    }
    Ok(id.to_string())
}

/// Reject a run target that is not a RESOLVED image id. Both container argvs
/// call this, so no call site can slip the mutable tag (or anything else)
/// back in as the `docker run` target — run-by-id is structural, not
                         
fn require_resolved_image_id(image_id: &str) -> Result<(), DeployKeyError> {
    if !image_id.starts_with("sha256:") {
        return Err(DeployKeyError::Import(format!(
            "docker rung: run target {image_id:?} is not a resolved image id \
             (sha256:…) — a mutable tag is never a run target; call \
             resolve_image_id first"
        )));
    }
    Ok(())
}

/// Reject a host mount path that is not a CLEAN absolute path: it must be absolute AND
/// carry no `..` (ParentDir) component. `is_absolute()` alone is not enough — a `..`
/// survives into the `-v host:container` spec and docker resolves it, so
/// `sign-backup /a/b/../../etc/x` would bind-mount `/etc` writable, widening the mount
/// beyond the artifact's own directory (L-3, eroding the F-15 narrowed-mount defense).
/// Whitelist the clean shape, fail-closed. (The `:`-in-path check stays separate — it is
/// a string-level guard on the `-v` field separator, not a path-component property.)
fn reject_unclean_mount_path(what: &str, path: &Path) -> Result<(), DeployKeyError> {
    if !path.is_absolute() {
        return Err(DeployKeyError::Import(format!(
            "docker rung: {what} {path:?} must be an absolute path \
             (a relative name becomes a docker named volume, not a host bind mount)"
        )));
    }
    if path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(DeployKeyError::Import(format!(
            "docker rung: {what} {path:?} contains a `..` component — refusing (a `..` \
             survives docker's mount resolution and can widen the bind mount beyond the \
             intended directory)"
        )));
    }
    Ok(())
}

/// The `--user` value for the seed-handling containers: the INVOKING host user's
/// `uid:gid`, so the container writes host-OWNED outputs (the wrapped keys, the public
/// pin, the `.sig` sidecars) that the non-root operator can read and manage.
///
/// Load-bearing (produced-bytes gate, Task 9 Step 3): the container defaults to running
/// as ROOT, so its outputs are root-owned — a non-root operator then CANNOT read the
/// `0600` wrapped `.key`, so the host-side rung DETECTION (which reads the wrapped key's
/// public header, §6.1) fails with `Permission denied` and the whole sign aborts. Running
/// as the invoking user fixes ownership AND is least-privilege (the seed-handling process
/// is non-root in-container; the isolation namespaces are unchanged — still a fresh
/// `--rm` container from the pinned image). For this non-root build to work the argv sets
/// an EXPLICIT in-container `CARGO_HOME` under the ephemeral `CARGO_TARGET_DIR` (the
/// build_tools_host.rs pattern) — the current `FROM alpine` image sets none of its own, so
/// a non-root uid's `$HOME` is the unwritable `/` and cargo could not create its registry
/// cache (M-R3-1; do NOT rely on a base image's inherited world-writable `CARGO_HOME`).
///
/// FALLBACK (documented for a future UID-agnostic need — e.g. a multi-operator or
/// shared-store setup where baking the invoker's identity into the container is wrong):
/// keep the container as root and run a SECOND, root, `--rm` helper container afterward to
/// `chown -R <uid>:<gid>` the keys/outputs dirs back to the operator. That trades this
/// one-flag fix for an extra container per operation; `--user` is preferred while the
/// rung is single-operator.
fn docker_run_user() -> String {
                                                                                           
                                                                                               
                                                                                 
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    format!("{uid}:{gid}")
}

                                                                                    
/// at-rest isolation — the in-container leg reads the operator passphrase and WRAPS the
/// seeds (Argon2id→XChaCha20-Poly1305), so ONLY the ciphertext blob lands on the
                                                                          
/// Mints the artifact keys inside the pinned imgbuild container: repo mounted RO at
/// `/src` (cwd `-w /src`), the keys dir mounted RW at `/keys`, an in-container
/// target dir. The in-container leg is **`--artifact-signing docker --artifact-keys-only`**
/// — it mints + WRAPS the artifact key set to `/keys` and writes NOTHING to the RO repo
/// (no cert bootstrap, no committed pin); the HOST writes the committed pin from the
                                                                                              
/// it is golden-testable; fails closed on a `:`-bearing path (breaks docker `-v`)
                                       
///
                                                                                 
                                                                                
                                                                         
/// `--ulimit core=0` belt-and-suspenders beside the main() prctl guard — keygen
/// holds fresh root+worker seeds + the passphrase, the same core-dump surface as
                                               
pub fn docker_keygen_argv(
    image_id: &str,
    keys_dir: &Path,
    window_days: u64,
    force: bool,
) -> Result<Vec<String>, DeployKeyError> {
    require_resolved_image_id(image_id)?;
    let repo = std::env::current_dir().map_err(|e| {
        DeployKeyError::Import(format!(
            "docker rung: cannot resolve the current dir for the /src repo mount: {e}"
        ))
    })?;
                                                                                          
                                                                                          
                                                                                         
                                
    reject_unclean_mount_path("--output-dir", keys_dir)?;
    let keys_s = keys_dir.display().to_string();
    let repo_s = repo.display().to_string();
                                                                                     
                                                                                   
    for (what, p) in [("keys dir", &keys_s), ("repo path", &repo_s)] {
        if p.contains(':') {
            return Err(DeployKeyError::Import(format!(
                "docker rung: {what} {p:?} contains ':' — breaks docker -v mount parsing"
            )));
        }
    }
    let mut v = vec![
        "docker".into(),
        "run".into(),
        "--rm".into(),
                                                                             
                                                                                      
        "-it".into(),
                                                                                        
                                                                                              
                                                                                             
        "--user".into(),
        docker_run_user(),
                                                                          
                                                                  
        "--ulimit".into(),
        "core=0".into(),
        "-v".into(),
        format!("{keys_s}:{IN_CONTAINER_KEYS_DIR}"),
        "-v".into(),
        format!("{repo_s}:/src:ro"),
        "-w".into(),
        "/src".into(),
        "-e".into(),
        "CARGO_TARGET_DIR=/tmp/kg-target".into(),
                                                                                             
                                                                                      
                                                                                      
                                                                                           
                                                                                            
        "-e".into(),
        "CARGO_HOME=/tmp/kg-target/cargo-home".into(),
                                                                      
        image_id.into(),
        "cargo".into(),
        "run".into(),
        "--release".into(),
        "--manifest-path".into(),
        "/src/Cargo.toml".into(),
        "-p".into(),
        "orchard".into(),
        "--bin".into(),
        "orchard".into(),
        "--".into(),
        "generate-keys".into(),
        "--output-dir".into(),
        IN_CONTAINER_KEYS_DIR.into(),
                                                                                      
                                                                                            
        "--artifact-signing".into(),
        "docker".into(),
        "--artifact-keys-only".into(),
        "--delegation-window-days".into(),
        window_days.to_string(),
    ];
    if force {
        v.push("--force".into());
    }
    Ok(v)
}

                                                                           
/// RESOLVED `image_id` with the keys-dir mounted **read-only** at `/keys`
/// (F-3 — sign never writes keys) and the outputs dir — NARROWED to the dir
                                                                                
/// at `/out` for the `.sig` sidecars. Inherits `docker_keygen_argv`'s
                                                                          
/// (the signer is `cargo run` from host source — the image pins the toolchain,
                                                                              
/// host `target/`), `--bin orchard`. `-it` inherits the operator's TTY so the
/// in-container process reads the passphrase itself with echo off (the host
/// never buffers it, F-4); `--rm` destroys the container on exit; `--ulimit
/// core=0` is belt-and-suspenders beside the main() prctl guard.
///
/// `in_container_sign_args` is the in-container orchard subcommand tail
/// (e.g. `sign-in-container --purpose img --artifact /out/r.img`).
pub fn docker_sign_argv(
    image_id: &str,
    keys_dir: &Path,
    outputs_dir: &Path,
    in_container_sign_args: &[String],
) -> Result<Vec<String>, DeployKeyError> {
    require_resolved_image_id(image_id)?;
    let repo = std::env::current_dir().map_err(|e| {
        DeployKeyError::Import(format!(
            "docker rung: cannot resolve the current dir for the /src repo mount: {e}"
        ))
    })?;
    reject_unclean_mount_path("keys dir", keys_dir)?;
    reject_unclean_mount_path("outputs dir", outputs_dir)?;
    let keys_s = keys_dir.display().to_string();
    let out_s = outputs_dir.display().to_string();
    let repo_s = repo.display().to_string();
    for (what, p) in [
        ("keys dir", &keys_s),
        ("outputs dir", &out_s),
        ("repo path", &repo_s),
    ] {
        if p.contains(':') {
            return Err(DeployKeyError::Import(format!(
                "docker rung: {what} {p:?} contains ':' — breaks docker -v mount parsing"
            )));
        }
    }
    let mut v = vec![
        "docker".into(),
        "run".into(),
        "--rm".into(),
        "-it".into(),
                                                                                   
                                                      
        "--user".into(),
        docker_run_user(),
        "--ulimit".into(),
        "core=0".into(),
        "-v".into(),
        format!("{keys_s}:{IN_CONTAINER_KEYS_DIR}:ro"),
        "-v".into(),
        format!("{out_s}:{IN_CONTAINER_OUT_DIR}"),
        "-v".into(),
        format!("{repo_s}:/src:ro"),
        "-w".into(),
        "/src".into(),
        "-e".into(),
        "CARGO_TARGET_DIR=/tmp/sign-target".into(),
                                                                                            
                                                                                      
        "-e".into(),
        "CARGO_HOME=/tmp/sign-target/cargo-home".into(),
        image_id.into(),
        "cargo".into(),
        "run".into(),
        "--release".into(),
        "--manifest-path".into(),
        "/src/Cargo.toml".into(),
        "-p".into(),
        "orchard".into(),
        "--bin".into(),
        "orchard".into(),
        "--".into(),
    ];
    v.extend(in_container_sign_args.iter().cloned());
    Ok(v)
}

/// Map an artifact purpose to its `sign-in-container` CLI flag. Fail-closed on a
/// purpose with no flag, so a bad routing surfaces as an error, not a
/// silently-unsigned artifact. After debt-burndown C+D the only flag-less purpose
/// is RootHash — which IS minted (§2f/`purpose_slug`); it refuses here for lack of
/// a docker-sign flag (nothing signs raw root hashes through this path).
fn sign_in_container_flag(purpose: Purpose) -> Result<&'static str, DeployKeyError> {
    Ok(match purpose {
        Purpose::Img => "--img",
        Purpose::KexecVmlinuz => "--vmlinuz",
        Purpose::KexecInitramfs => "--initramfs",
        Purpose::Backup => "--backup",
        Purpose::Weights => "--weights",
        Purpose::UpdateImage => "--update-image",
        other => {
            return Err(DeployKeyError::Import(format!(
                "docker rung: purpose {other:?} has no sign-in-container flag"
            )));
        }
    })
}

/// The `sign-in-container` flag→purpose pairing — the SINGLE list the clap handler
/// iterates (spec AC-C4/AC-D3: the handler's hardcoded tuple was a second, unguarded
/// update site; extracting it makes the coverage a non-docker unit test).
pub fn sign_in_container_pairs(
    img: Option<PathBuf>,
    vmlinuz: Option<PathBuf>,
    initramfs: Option<PathBuf>,
    backup: Option<PathBuf>,
    weights: Option<PathBuf>,
    update_image: Option<PathBuf>,
) -> Vec<(PathBuf, Purpose)> {
    [
        (img, Purpose::Img),
        (vmlinuz, Purpose::KexecVmlinuz),
        (initramfs, Purpose::KexecInitramfs),
        (backup, Purpose::Backup),
        (weights, Purpose::Weights),
        (update_image, Purpose::UpdateImage),
    ]
    .into_iter()
    .filter_map(|(p, purpose)| p.map(|p| (p, purpose)))
    .collect()
}

/// Plan a ONE-invocation in-container sign of `artifacts` (so the operator enters
/// the passphrase ONCE for the whole set): every artifact must share one parent dir
/// — the single writable `/out` mount — and is named to the in-container signer by
/// its `/out/<filename>` path. Returns `(outputs_dir, sign-in-container argv tail)`.
/// PURE (no docker) so the mount + path translation is golden-testable; the spawn is
/// [`docker_sign_artifacts`]. Fail-closed: empty set, a non-sibling artifact, a
/// nameless/parentless path, or an unminted purpose is an `Err`.
fn plan_container_sign(
    artifacts: &[(Purpose, &Path)],
) -> Result<(PathBuf, Vec<String>), DeployKeyError> {
    let first = artifacts
        .first()
        .ok_or_else(|| DeployKeyError::Import("docker rung: no artifact to sign".into()))?
        .1;
    let outputs_dir = first
        .parent()
        .ok_or_else(|| {
            DeployKeyError::Import(format!(
                "docker rung: artifact {first:?} has no parent dir for the /out mount"
            ))
        })?
        .to_path_buf();
    let mut tail = vec!["sign-in-container".to_string()];
    for &(purpose, path) in artifacts {
                                                                                         
                                                                          
        if path.parent().unwrap_or_else(|| Path::new("")) != outputs_dir {
            return Err(DeployKeyError::Import(format!(
                "docker rung: artifacts must share one directory for the /out mount \
                 ({path:?} is not under {outputs_dir:?})"
            )));
        }
        let name = path.file_name().ok_or_else(|| {
            DeployKeyError::Import(format!("docker rung: artifact {path:?} has no file name"))
        })?;
        tail.push(sign_in_container_flag(purpose)?.to_string());
        tail.push(format!("{IN_CONTAINER_OUT_DIR}/{}", name.to_string_lossy()));
    }
    Ok((outputs_dir, tail))
}

/// Sign already-built `artifacts` IN the pinned container under ONE invocation (one
/// passphrase entry, §6): resolve the `:dev` tag to a concrete image id (§4), build
/// the sign argv, spawn `docker` with the operator's TTY inherited (the in-container
/// process reads the passphrase itself, echo off — the host NEVER buffers it,
/// §5/F-4), and return the `.sig` sidecar paths. Fail-CLOSED: a non-sibling artifact
/// set, an absent/unresolvable image, a spawn failure, or a non-zero container exit
                                                                               
/// operator-host orchestration; the box never signs.
pub fn docker_sign_artifacts(
    keys_dir: &Path,
    artifacts: &[(Purpose, &Path)],
) -> Result<Vec<PathBuf>, DeployKeyError> {
    let (outputs_dir, tail) = plan_container_sign(artifacts)?;
                                                                                      
    let image_id = resolve_image_id(IMGBUILD_TAG)?;
    eprintln!("resolved {IMGBUILD_TAG} → {image_id} (this sign runs by that id)");
    let argv = docker_sign_argv(&image_id, keys_dir, &outputs_dir, &tail)?;
    eprintln!("artifact sign in the pinned container: {}", argv.join(" "));
                                                                                 
                                                                                         
    let status = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .status()
        .map_err(|e| {
            DeployKeyError::Import(format!("docker rung: cannot spawn `{}`: {e}", argv[0]))
        })?;
    if !status.success() {
        return Err(DeployKeyError::Import(format!(
            "docker rung: in-container sign exited {status} — refusing to treat a sign \
             failure as UNSIGNED"
        )));
    }
    Ok(artifacts
        .iter()
        .map(|(_, p)| super::artifact_sign::sig_sidecar_path(p))
        .collect())
}

/// Seconds since the unix epoch (ceremony issuance time + the delegation window
/// base). Panics only if the system clock is before 1970 (an unbootable box).
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::keywrap::{self, KeyRole};
    use dragonfruit::{Attestation, Bundle, sign_attestation, verify_bundle_over_bytes};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn weights_has_a_sign_in_container_flag() {
        assert_eq!(
            sign_in_container_flag(Purpose::Weights).unwrap(),
            "--weights"
        );
    }

    #[test]
    fn update_image_has_a_sign_in_container_flag() {
        assert_eq!(
            sign_in_container_flag(Purpose::UpdateImage).unwrap(),
            "--update-image"
        );
    }

    #[test]
    fn sign_in_container_pairs_covers_every_flagged_purpose() {
                                                                                                
                                                                                         
                                                                                            
        let p = |s: &str| Some(PathBuf::from(s));
        let pairs = sign_in_container_pairs(p("i"), p("v"), p("n"), p("b"), p("w"), p("u"));
        let purposes: Vec<Purpose> = pairs.iter().map(|(_, p)| *p).collect();
        assert!(purposes.contains(&Purpose::Weights));
        assert!(purposes.contains(&Purpose::UpdateImage));
        for (_, purpose) in &pairs {
            assert!(
                sign_in_container_flag(*purpose).is_ok(),
                "{purpose:?} has no flag"
            );
        }
        assert!(
            sign_in_container_flag(Purpose::RootHash).is_err(),
            "RootHash must still refuse"
        );
    }

    fn modes(dir: &Path) -> Vec<(&'static str, u32)> {
        ARTIFACT_FILES
            .iter()
            .map(|name| {
                let m = std::fs::metadata(dir.join(name))
                    .unwrap_or_else(|_| panic!("{name} missing"))
                    .permissions()
                    .mode()
                    & 0o777;
                (*name, m)
            })
            .collect()
    }

    #[test]
    fn ceremony_writes_the_key_set_with_correct_modes() {
        let dir = tempfile::tempdir().unwrap();
        generate_artifact_keys(dir.path(), 365, false, Custody::Raw).unwrap();
        for (name, mode) in modes(dir.path()) {
            let want = if name.ends_with(".key") { 0o600 } else { 0o644 };
            assert_eq!(mode, want, "{name} mode");
        }
                                       
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn read_updateimage_ctr_is_fail_closed_tri_state() {
                                                                                                      
                                                                                  
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Raw).unwrap();
        let ctr = read_updateimage_ctr(&keys)
            .unwrap()
            .expect("fresh set has the delegation");
                                                                                                        
        let raw = std::fs::read(keys.join("artifact-delegation-update-image.bundle")).unwrap();
        let d = Delegation::from_canonical(&raw[..DELEGATION_LEN]).unwrap();
        assert_eq!(ctr, d.monotonic_ctr);

                                                                                                        
                                                         
        std::fs::remove_file(keys.join("artifact-delegation-update-image.bundle")).unwrap();
        let err = read_updateimage_ctr(&keys).unwrap_err();
        assert!(
            matches!(err, DeployKeyError::MissingDelegation { .. }),
            "want MissingDelegation, got {err:?}"
        );
        assert!(err.to_string().contains("orchard redelegate"), "{err}");

                                                                                                     
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(read_updateimage_ctr(&empty).unwrap(), None);
    }

    #[test]
    fn read_weights_ctr_is_fail_closed_tri_state() {
                                                                                                  
                                                                                               
                                                              
                                                                                  
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Raw).unwrap();
        let bundle = keys.join(delegation_bundle_name(Purpose::Weights));
        let ctr = read_weights_ctr(&keys)
            .unwrap()
            .expect("fresh set has the delegation");
        let raw = std::fs::read(&bundle).unwrap();
        let d = Delegation::from_canonical(&raw[..DELEGATION_LEN]).unwrap();
        assert_eq!(ctr, d.monotonic_ctr);

                                                                                                 
        std::fs::write(&bundle, &raw[..DELEGATION_BUNDLE_LEN / 2]).unwrap();
        let err = read_weights_ctr(&keys).unwrap_err();
        assert!(
            matches!(err, DeployKeyError::Import(_)),
            "want Import on a truncated bundle, got {err:?}"
        );

                                                                                             
        std::fs::remove_file(&bundle).unwrap();
        let err = read_weights_ctr(&keys).unwrap_err();
        assert!(
            matches!(err, DeployKeyError::MissingDelegation { .. }),
            "want MissingDelegation, got {err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("orchard redelegate"), "{msg}");
        assert!(msg.contains("weights"), "must name the purpose: {msg}");

                                                                                 
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(read_weights_ctr(&empty).unwrap(), None);
    }

    #[test]
    fn wrapped_custody_bake_routes_docker_and_reads_ctr_from_the_public_bundle() {
                                                                                             
                                                                                              
                                                                                  
        use crate::deploy::artifact_sign::{SignPlan, plan_signing};
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Wrapped { passphrase: b"pw" }).unwrap();
        let plan = plan_signing(&keys, &dir.path().join("no-pin")).unwrap();
        assert!(matches!(plan, SignPlan::Docker));
        assert!(
            read_weights_ctr(&keys).unwrap().is_some(),
            "the public bundle must yield the ctr with no passphrase"
        );
    }

    #[test]
    fn pin_file_is_the_root_pubkey_hex() {
        let dir = tempfile::tempdir().unwrap();
        generate_artifact_keys(dir.path(), 365, false, Custody::Raw).unwrap();
        let set = load_artifact_keys(dir.path()).unwrap();
        let pin = std::fs::read_to_string(dir.path().join("artifact-root.pub")).unwrap();
        assert_eq!(pin.trim(), hex::encode(set.root_pub));
        assert_eq!(set.root_pub.len(), 32);
    }

    #[test]
    fn existing_set_requires_force() {
        let dir = tempfile::tempdir().unwrap();
        generate_artifact_keys(dir.path(), 365, false, Custody::Raw).unwrap();
        assert!(matches!(
            generate_artifact_keys(dir.path(), 365, false, Custody::Raw),
            Err(DeployKeyError::Exists(..))
        ));
                                       
        generate_artifact_keys(dir.path(), 365, true, Custody::Raw).unwrap();
    }

    #[test]
    fn generate_keys_mints_updateimage_and_roothash() {
                                                                                                     
                                                                                                  
                     
        let dir = tempfile::tempdir().unwrap();
        generate_artifact_keys(dir.path(), 365, false, Custody::Raw).unwrap();
        let set = load_artifact_keys(dir.path()).unwrap();
        for purpose in [Purpose::UpdateImage, Purpose::RootHash, Purpose::Weights] {
            assert!(
                set.delegations.iter().any(|(p, _, _)| *p == purpose),
                "{purpose:?} delegation missing from a fresh set"
            );
        }
        assert_eq!(
            ARTIFACT_FILES.len(),
            10,
            "root+worker keys, pin, seven delegation bundles"
        );
        for name in [
            "artifact-delegation-update-image.bundle",
            "artifact-delegation-root-hash.bundle",
            "artifact-delegation-weights.bundle",
        ] {
            assert!(dir.path().join(name).exists(), "{name} not written");
        }
    }

    #[test]
    fn minted_delegations_chain_to_a_verifiable_bundle() {
                                                                                   
                                                                                 
                                                                                   
        let dir = tempfile::tempdir().unwrap();
        generate_artifact_keys(dir.path(), 365, false, Custody::Raw).unwrap();
        let set = load_artifact_keys(dir.path()).unwrap();
        let artifact = b"toy artifact bytes";
        let artifact_hash: [u8; 32] = Sha256::digest(artifact).into();
        let now = unix_now();

        for (purpose, deleg_bytes, root_sig) in &set.delegations {
            let delegation_id: [u8; 32] = Sha256::digest(deleg_bytes).into();
            let att = Attestation {
                artifact_hash,
                purpose: *purpose,
                delegation_id,
            };
            let att_bytes = att.to_canonical();
            let worker_sig = sign_attestation(&set.worker, &att);
            let bundle = Bundle {
                delegation_bytes: deleg_bytes,
                root_sig,
                attestation_bytes: &att_bytes,
                worker_sig: &worker_sig,
            };
            let v = verify_bundle_over_bytes(&bundle, &set.root_pub, now, artifact, *purpose);
            assert!(v.is_ok(), "purpose {purpose:?} must chain+verify: {v:?}");
            assert_eq!(v.unwrap().purpose(), *purpose);
        }
    }

    #[test]
    fn provision_software_rung_mints_keys_and_writes_the_pin() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let pin = dir.path().join("pinned-artifact-root.toml");
        let root_pub = provision_software_rung(&keys, &pin, 365, false).unwrap();

                                                      
        for name in ARTIFACT_FILES {
            assert!(keys.join(name).exists(), "{name} missing");
        }
                                                                     
        let body = std::fs::read_to_string(&pin).unwrap();
        assert!(body.contains(&format!("ed25519:{}", hex::encode(root_pub))));
    }

    /// A well-formed resolved image id for argv tests (the prefix guard is
    /// what the builders enforce; the full 64-hex shape is enforced at
    /// `parse_image_id_output`, the production source of ids).
    const TEST_IMAGE_ID: &str = "sha256:deadbeef";

    #[test]
    fn docker_argv_mounts_keys_rw_repo_ro_and_mints_keys_only() {
        let argv = docker_keygen_argv(TEST_IMAGE_ID, Path::new("/k"), 365, false).unwrap();
        assert_eq!(argv[0], "docker");
                                       
        assert!(
            argv.iter().any(|a| a == "/k:/keys"),
            "keys RW mount: {argv:?}"
        );
                                                                     
        assert!(
            argv.iter().any(|a| a.ends_with(":/src:ro")),
            "repo RO mount: {argv:?}"
        );
        let joined = argv.join(" ");
        assert!(
            joined.contains("-w /src"),
            "in-container cwd = /src: {joined}"
        );
                                                                           
                                                                                                
        assert!(joined.contains("--bin orchard"), "bin name: {joined}");
        assert!(
            !joined.contains("--bin admin "),
            "must not use the wrong bin name"
        );
                                                                                                 
        assert!(joined.contains(
            "generate-keys --output-dir /keys --artifact-signing docker --artifact-keys-only"
        ));
        assert!(joined.contains("--delegation-window-days 365"));
        assert!(!joined.contains("--force"));
                                      
        assert!(
            docker_keygen_argv(TEST_IMAGE_ID, Path::new("/k"), 1, true)
                .unwrap()
                .contains(&"--force".to_string())
        );
    }

    #[test]
    fn keygen_argv_carries_it_ulimit_and_runs_by_resolved_id() {
                                                                                      
        let argv = docker_keygen_argv(TEST_IMAGE_ID, Path::new("/abs/keys"), 90, false).unwrap();
        assert!(argv.contains(&"-it".to_string()), "-it pty: {argv:?}");
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--ulimit" && w[1] == "core=0"),
            "--ulimit core=0: {argv:?}"
        );
        assert!(
            argv.contains(&TEST_IMAGE_ID.to_string()),
            "run by resolved id: {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a.contains("recipes-imgbuild")),
            "the mutable tag must never be a run target: {argv:?}"
        );
                                                                
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "-v" && w[1] == "/abs/keys:/keys"),
            "keys RW mount: {argv:?}"
        );
    }

    #[test]
    fn docker_argv_rejects_relative_keys_path() {
                                                                                    
                                      
        assert!(matches!(
            docker_keygen_argv(TEST_IMAGE_ID, Path::new("relative/keys"), 365, false),
            Err(DeployKeyError::Import(_))
        ));
    }

    #[test]
    fn docker_argv_bin_name_matches_a_real_bin_target() {
                                                                                 
                                                                             
                                                                                       
        let argv = docker_keygen_argv(TEST_IMAGE_ID, Path::new("/k"), 365, false).unwrap();
        let bin_pos = argv
            .iter()
            .position(|a| a == "--bin")
            .expect("argv has --bin");
        let bin_name = &argv[bin_pos + 1];
        let manifest = include_str!("../../Cargo.toml");
        assert!(
            manifest.contains(&format!("name = \"{bin_name}\"")),
            "docker argv --bin {bin_name} must match a [[bin]] target in Cargo.toml"
        );
    }

    #[test]
    fn docker_argv_rejects_colon_bearing_keys_path() {
                                                                                           
        assert!(matches!(
            docker_keygen_argv(TEST_IMAGE_ID, Path::new("/k:evil"), 365, false),
            Err(DeployKeyError::Import(_))
        ));
    }

    #[test]
    fn argvs_reject_a_mutable_tag_as_run_target() {
                                                                                   
                                                                               
        assert!(matches!(
            docker_keygen_argv(IMGBUILD_TAG, Path::new("/k"), 365, false),
            Err(DeployKeyError::Import(_))
        ));
        assert!(matches!(
            docker_sign_argv(IMGBUILD_TAG, Path::new("/k"), Path::new("/o"), &[]),
            Err(DeployKeyError::Import(_))
        ));
    }

    #[test]
    fn parse_image_id_output_whitelists_the_sha256_shape() {
        let good = format!("sha256:{}\n", "ab".repeat(32));                             
        assert_eq!(
            parse_image_id_output(&good, "recipes-imgbuild:dev").unwrap(),
            good.trim()
        );
                                                                  
        for bad in [
            "",                                                                          
            "\n",                                         
            "recipes-imgbuild:dev",                          
            "sha256:",                                 
            "sha256:deadbeef",                       
            "sha256:zz",                           
            "sha256:AB.repeat-nonsense",        
        ] {
            assert!(
                parse_image_id_output(bad, "recipes-imgbuild:dev").is_err(),
                "must refuse {bad:?}"
            );
        }
                                                 
        let junk = format!("sha256:{}x", "ab".repeat(32));
        assert!(parse_image_id_output(&junk, "t").is_err());
    }

    #[test]
    fn sign_argv_runs_by_resolved_id_ro_keys_and_ulimit() {
        let argv = docker_sign_argv(
            "sha256:deadbeef",
            Path::new("/abs/keys"),
            Path::new("/abs/out"),
            &[
                "sign-in-container".into(),
                "--img".into(),
                "/out/r.img".into(),
            ],
        )
        .unwrap();
        assert_eq!(argv[0], "docker");
        assert!(argv.contains(&"sha256:deadbeef".to_string()));                           
        assert!(!argv.iter().any(|a| a.contains("recipes-imgbuild")));                                         
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "-v" && w[1] == "/abs/keys:/keys:ro"),
            "keys RO: {argv:?}"
        );                 
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "-v" && w[1].starts_with("/abs/out:")),
            "outputs mount: {argv:?}"
        );                                 
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--ulimit" && w[1] == "core=0"),
            "--ulimit core=0: {argv:?}"
        );
        assert!(argv.contains(&"-it".to_string()));
        assert!(argv.contains(&"--rm".to_string()));
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "-e" && w[1].starts_with("CARGO_TARGET_DIR=")),
            "CARGO_TARGET_DIR (RO /src cannot host target/): {argv:?}"
        );
                                                               
        let dashdash = argv.iter().position(|a| a == "--").expect("has --");
        assert_eq!(
            &argv[dashdash + 1..],
            ["sign-in-container", "--img", "/out/r.img"]
        );
    }

    #[test]
    fn sign_argv_rejects_colon_or_relative_paths() {
        assert!(
            docker_sign_argv(
                "sha256:x",
                Path::new("rel/keys"),
                Path::new("/abs/out"),
                &[]
            )
            .is_err()
        );
        assert!(
            docker_sign_argv(
                "sha256:x",
                Path::new("/abs/k:ey"),
                Path::new("/abs/out"),
                &[]
            )
            .is_err()
        );
        assert!(
            docker_sign_argv(
                "sha256:x",
                Path::new("/abs/keys"),
                Path::new("out/rel"),
                &[]
            )
            .is_err()
        );
        assert!(
            docker_sign_argv(
                "sha256:x",
                Path::new("/abs/keys"),
                Path::new("/abs/o:ut"),
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn docker_host_side_pin_write_after_keysonly_mint() {
                                                                                            
                                                                                             
                                                                                    
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let pin = dir.path().join("pinned-artifact-root.toml");
        generate_artifact_keys(&keys, 365, false, Custody::Raw).unwrap();                            
        assert!(!pin.exists(), "keys-only mint must NOT write the pin");
        let set = load_artifact_keys(&keys).unwrap();
        super::super::fingerprints::set_artifact_root_pin(&pin, &set.root_pub).unwrap();        
        let body = std::fs::read_to_string(&pin).unwrap();
        assert!(body.contains(&format!("ed25519:{}", hex::encode(set.root_pub))));
    }

    #[test]
    fn rejects_out_of_range_window() {
                                                                              
                                                    
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            generate_artifact_keys(&dir.path().join("z"), 0, false, Custody::Raw),
            Err(DeployKeyError::Import(_))
        ));
        assert!(matches!(
            generate_artifact_keys(
                &dir.path().join("big"),
                MAX_WINDOW_DAYS + 1,
                false,
                Custody::Raw
            ),
            Err(DeployKeyError::Import(_))
        ));
        generate_artifact_keys(&dir.path().join("ok"), MAX_WINDOW_DAYS, false, Custody::Raw)
            .unwrap();
                                                                                     
        assert!(!dir.path().join("z").join("artifact-root.pub").exists());
    }

    #[test]
    fn delegation_window_is_honored() {
        let dir = tempfile::tempdir().unwrap();
        generate_artifact_keys(dir.path(), 1, false, Custody::Raw).unwrap();
        let set = load_artifact_keys(dir.path()).unwrap();
        let (_, deleg_bytes, _) = &set.delegations[0];
        let d = Delegation::from_canonical(deleg_bytes).unwrap();
        assert_eq!(d.not_after - d.not_before, 86_400, "1-day window");
        assert_eq!(d.worker_pubkey, set.worker.verifying_key().to_bytes());
    }

                                                                                            

    fn write_worker_file(dir: &Path, bytes: &[u8]) {
        std::fs::write(dir.join("artifact-worker.key"), bytes).unwrap();
    }

    #[test]
    fn load_worker_seed_reads_a_raw_software_key() {
        let dir = tempfile::tempdir().unwrap();
        write_worker_file(dir.path(), &[9u8; 32]);
        let got = load_worker_seed(dir.path(), None).unwrap();
        assert_eq!(&*got, &[9u8; 32]);
    }

    #[test]
    fn load_worker_seed_unwraps_a_wrapped_docker_key() {
        let dir = tempfile::tempdir().unwrap();
        let blob =
            keywrap::wrap_seed(&[9u8; 32], b"pw", KeyRole::Worker, keywrap::HOST_TARGET).unwrap();
        write_worker_file(dir.path(), &blob);
        let got = load_worker_seed(dir.path(), Some(b"pw")).unwrap();
        assert_eq!(&*got, &[9u8; 32]);
    }

    #[test]
    fn present_but_unwrappable_key_is_unloadable_not_absent() {
        let dir = tempfile::tempdir().unwrap();
        let blob = keywrap::wrap_seed(&[9u8; 32], b"right", KeyRole::Worker, keywrap::HOST_TARGET)
            .unwrap();
        write_worker_file(dir.path(), &blob);
                                                                                               
        let err = load_worker_seed(dir.path(), Some(b"wrong")).unwrap_err();
        assert!(matches!(
            err,
            DeployKeyError::Unloadable { .. } | DeployKeyError::Passphrase { .. }
        ));
    }

    #[test]
    fn genuinely_absent_worker_key_is_notfound() {
        let dir = tempfile::tempdir().unwrap();                   
        let err = load_worker_seed(dir.path(), None).unwrap_err();
        assert!(matches!(err, DeployKeyError::NotFound { .. }));                            
    }

                                                                            

    #[test]
    fn wrapped_custody_writes_an_unwrappable_worker_blob() {
        let dir = tempfile::tempdir().unwrap();
        generate_artifact_keys(
            dir.path(),
            365,
            false,
            Custody::Wrapped { passphrase: b"pw" },
        )
        .unwrap();
                                                                               
        let raw = std::fs::read(dir.path().join("artifact-worker.key")).unwrap();
        assert_ne!(
            raw.len(),
            32,
            "wrapped worker key must not be a raw 32-byte seed"
        );
        assert!(
            keywrap::decode_blob(&raw).is_ok(),
            "worker key must be a v1 keywrap blob"
        );
                                                                                  
        let seed = load_worker_seed(dir.path(), Some(b"pw")).unwrap();
        assert_eq!(seed.len(), 32);
        assert!(
            load_worker_seed(dir.path(), None).is_err(),
            "wrapped key needs a passphrase"
        );
        let root_raw = std::fs::read(dir.path().join("artifact-root.key")).unwrap();
        assert!(
            keywrap::decode_blob(&root_raw).is_ok(),
            "root key must be wrapped too"
        );
                                                                                            
        assert_eq!(read_root_pub(dir.path()).unwrap().len(), 32);
        for name in ARTIFACT_FILES.iter().filter(|n| n.ends_with(".bundle")) {
            assert!(
                dir.path().join(name).exists(),
                "{name} (public bundle) present"
            );
        }
    }

    #[test]
    fn raw_custody_writes_a_raw_worker_seed() {
        let dir = tempfile::tempdir().unwrap();
        generate_artifact_keys(dir.path(), 365, false, Custody::Raw).unwrap();
        let raw = std::fs::read(dir.path().join("artifact-worker.key")).unwrap();
        assert_eq!(
            raw.len(),
            32,
            "software rung worker key is a raw 32-byte seed"
        );
        assert!(
            load_worker_seed(dir.path(), None).is_ok(),
            "raw seed loads with no passphrase"
        );
    }

    #[test]
    fn wrapped_worker_key_never_contains_the_plaintext_seed() {
                                                                                          
        let dir = tempfile::tempdir().unwrap();
        generate_artifact_keys(
            dir.path(),
            365,
            false,
            Custody::Wrapped { passphrase: b"pw" },
        )
        .unwrap();
        let seed = load_worker_seed(dir.path(), Some(b"pw")).unwrap();
        let raw = std::fs::read(dir.path().join("artifact-worker.key")).unwrap();
        assert!(
            !raw.windows(32).any(|w| w == &seed[..]),
            "plaintext seed leaked into the wrapped key"
        );
    }

    #[test]
    fn wrapped_root_key_is_root_role_bound_and_never_leaks_its_seed() {
                                                                                          
                                                                                         
        let dir = tempfile::tempdir().unwrap();
        generate_artifact_keys(
            dir.path(),
            365,
            false,
            Custody::Wrapped { passphrase: b"pw" },
        )
        .unwrap();
        let root_blob = std::fs::read(dir.path().join("artifact-root.key")).unwrap();
                                                             
        let root_seed = keywrap::unwrap_seed(&root_blob, b"pw", KeyRole::Root).unwrap();
        assert_eq!(root_seed.len(), 32);
                                                                                             
        assert!(
            keywrap::unwrap_seed(&root_blob, b"pw", KeyRole::Worker).is_err(),
            "root blob must not open in a worker context (AAD role bind)"
        );
        assert!(
            keywrap::unwrap_seed(&root_blob, b"wrong", KeyRole::Root).is_err(),
            "wrong passphrase fails closed"
        );
                                                                                  
        assert!(
            !root_blob.windows(32).any(|w| w == &root_seed[..]),
            "plaintext root seed leaked into the root key file"
        );
    }

                                                                                 
                                           

    #[test]
    fn plan_container_sign_maps_the_triple_to_one_out_mount() {
        let out = Path::new("/abs/out");
        let img = out.join("r.img");
        let vmlinuz = out.join("r.vmlinuz");
        let initramfs = out.join("r.initramfs");
        let (mount, tail) = plan_container_sign(&[
            (Purpose::Img, &img),
            (Purpose::KexecVmlinuz, &vmlinuz),
            (Purpose::KexecInitramfs, &initramfs),
        ])
        .unwrap();
        assert_eq!(mount, out);                                      
        assert_eq!(
            tail.iter().map(String::as_str).collect::<Vec<_>>(),
            [
                "sign-in-container",
                "--img",
                "/out/r.img",
                "--vmlinuz",
                "/out/r.vmlinuz",
                "--initramfs",
                "/out/r.initramfs",
            ]
        );
    }

    #[test]
    fn plan_container_sign_backup_uses_its_own_dir() {
        let f = PathBuf::from("/backups/box.tar.gz");
        let (mount, tail) = plan_container_sign(&[(Purpose::Backup, &f)]).unwrap();
        assert_eq!(mount, Path::new("/backups"));                                          
        assert_eq!(
            tail.iter().map(String::as_str).collect::<Vec<_>>(),
            ["sign-in-container", "--backup", "/out/box.tar.gz"]
        );
    }

    #[test]
    fn plan_container_sign_refuses_non_sibling_artifacts() {
                                                                                    
                                             
        let img = PathBuf::from("/a/r.img");
        let vmlinuz = PathBuf::from("/b/r.vmlinuz");
        assert!(
            plan_container_sign(&[(Purpose::Img, &img), (Purpose::KexecVmlinuz, &vmlinuz),])
                .is_err()
        );
    }

    #[test]
    fn plan_container_sign_refuses_empty_and_unminted_purpose() {
        assert!(plan_container_sign(&[]).is_err(), "no artifact = err");
                                                                                         
                                                                            
        let p = PathBuf::from("/o/x.bin");
        assert!(plan_container_sign(&[(Purpose::RootHash, &p)]).is_err());
    }

    #[test]
    fn load_artifact_keys_with_unwraps_a_wrapped_set() {
                                                                                     
                                                                                
        let dir = tempfile::tempdir().unwrap();
        generate_artifact_keys(
            dir.path(),
            365,
            false,
            Custody::Wrapped { passphrase: b"pw" },
        )
        .unwrap();
                                                                                          
        assert!(load_artifact_keys(dir.path()).is_err());
                                                                           
        let set = load_artifact_keys_with(dir.path(), Some(b"pw")).unwrap();
        assert_eq!(set.delegations.len(), ALL_PURPOSES.len());
        assert_eq!(set.root_pub, read_root_pub(dir.path()).unwrap());
                                           
        assert!(load_artifact_keys_with(dir.path(), Some(b"nope")).is_err());
    }

    #[test]
    fn worker_key_truncated_to_32_bytes_aborts_not_mis_signs() {
                                                                                            
                                                                                            
                                                                                            
                                                                                           
        let dir = tempfile::tempdir().unwrap();
        generate_artifact_keys(
            dir.path(),
            365,
            false,
            Custody::Wrapped { passphrase: b"pw" },
        )
        .unwrap();
        let worker = dir.path().join("artifact-worker.key");
        let blob = std::fs::read(&worker).unwrap();
        assert!(blob.len() > 32, "a real wrapped blob is >32 bytes");
        std::fs::write(&worker, &blob[..32]).unwrap();                                
                                                                                       
                                                                                           
                                                                               
                                                                                             
        assert!(
            matches!(
                load_artifact_keys(dir.path()),
                Err(DeployKeyError::Unloadable { .. })
            ),
            "a 32-byte-corrupted wrapped key must be Unloadable (refusing to silently mis-sign)"
        );
    }

    #[test]
    fn mount_paths_with_dotdot_are_rejected() {
                                                                                            
                                                                                         
        assert!(
            docker_keygen_argv(TEST_IMAGE_ID, Path::new("/a/b/../../etc"), 365, false).is_err(),
            "keygen must reject a `..`-bearing keys dir"
        );
        assert!(
            docker_sign_argv(
                TEST_IMAGE_ID,
                Path::new("/abs/keys"),
                Path::new("/a/b/../../etc"),
                &[]
            )
            .is_err(),
            "sign must reject a `..`-bearing outputs dir"
        );
        assert!(
            docker_sign_argv(
                TEST_IMAGE_ID,
                Path::new("/a/../k"),
                Path::new("/abs/out"),
                &[]
            )
            .is_err(),
            "sign must reject a `..`-bearing keys dir"
        );
    }

    #[test]
    fn container_mount_targets_use_the_shared_consts() {
                                                                                             
                                                                                         
        let sign = docker_sign_argv(
            TEST_IMAGE_ID,
            Path::new("/abs/keys"),
            Path::new("/abs/out"),
            &[],
        )
        .unwrap();
        assert!(
            sign.iter()
                .any(|a| a == &format!("/abs/keys:{IN_CONTAINER_KEYS_DIR}:ro")),
            "keys mount uses IN_CONTAINER_KEYS_DIR: {sign:?}"
        );
        assert!(
            sign.iter()
                .any(|a| a == &format!("/abs/out:{IN_CONTAINER_OUT_DIR}")),
            "out mount uses IN_CONTAINER_OUT_DIR: {sign:?}"
        );
        let keygen = docker_keygen_argv(TEST_IMAGE_ID, Path::new("/abs/keys"), 365, false).unwrap();
        assert!(
            keygen
                .iter()
                .any(|a| a == &format!("/abs/keys:{IN_CONTAINER_KEYS_DIR}")),
            "keygen keys mount uses IN_CONTAINER_KEYS_DIR: {keygen:?}"
        );
    }

    #[test]
    fn container_argvs_carry_no_passphrase_env_or_secret() {
                                                                                              
                                                                                              
                                                                                          
                                                                                               
                                                                                                
        let sign = docker_sign_argv(
            TEST_IMAGE_ID,
            Path::new("/abs/keys"),
            Path::new("/abs/out"),
            &[
                "sign-in-container".into(),
                "--img".into(),
                "/out/r.img".into(),
            ],
        )
        .unwrap();
        let keygen = docker_keygen_argv(TEST_IMAGE_ID, Path::new("/abs/keys"), 365, false).unwrap();
        for argv in [&sign, &keygen] {
            for (i, a) in argv.iter().enumerate() {
                if a == "-e" {
                    let val = &argv[i + 1];
                    assert!(
                        val.starts_with("CARGO_TARGET_DIR=") || val.starts_with("CARGO_HOME="),
                        "the only -e env vars may be CARGO_TARGET_DIR / CARGO_HOME (no \
                         passphrase/secret), got: {val}"
                    );
                }
            }
        }
    }

    #[test]
    fn seed_container_argvs_run_as_the_invoking_host_user() {
                                                                                         
                                                                                           
                                                                                          
                                                   
        let want = docker_run_user();
        assert!(want.contains(':'), "user value is uid:gid: {want:?}");
        for argv in [
            docker_keygen_argv(TEST_IMAGE_ID, Path::new("/abs/keys"), 365, false).unwrap(),
            docker_sign_argv(
                TEST_IMAGE_ID,
                Path::new("/abs/keys"),
                Path::new("/abs/out"),
                &[],
            )
            .unwrap(),
        ] {
            assert!(
                argv.windows(2).any(|w| w[0] == "--user" && w[1] == want),
                "argv must run `--user {want}`: {argv:?}"
            );
        }
    }
}
