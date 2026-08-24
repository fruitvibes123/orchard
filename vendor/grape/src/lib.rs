//! Deterministic, operator-owned derivation of the rescue dropbear ed25519 host key.
//!
                                                                                    
                                                                                     
                                                                                 
//! (validated musl-clean in Phase 0.5).
//!
//! Two stages, both pure + deterministic (no randomness):
//! - **build time** (`derive_seed`): HKDF-SHA256 over `(public_text ‖ master_key)`,
//!   salt `rescue-host-key-seed-derivation-v1`, info `rescue-host-key-seed` → 32-byte
//!   seed baked into the read-only rootfs.
//! - **runtime** (`derive_host_key`): HKDF-SHA256 over `seed`, info = the dm-verity
//!   root hash (boot-stable nonce), salt `rescue-host-key-derivation-v1` → ed25519
//!   seed → dropbear binary host-key wire bytes.
//!
//! API shape: the path-taking `derive_seed` / `derive_host_key` are the operator-facing
//! form pinned by the spec's Crate-extraction subsection; the `seed_from_inputs` /
//! `host_key_from_seed` byte cores carry the crypto and are what tests + in-memory
//! reusers call (no filesystem coupling). Salts are version-tagged `-v1` (F-mini-17):
//! a construction change bumps to `-v2` so v1/v2 outputs never silently collide.

use std::path::Path;

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Build-time HKDF salt (domain separation), version-tagged per F-mini-17.
const SEED_SALT: &[u8] = b"rescue-host-key-seed-derivation-v1";
/// Build-time HKDF info (output-context label).
const SEED_INFO: &[u8] = b"rescue-host-key-seed";
/// Runtime HKDF salt (domain separation), version-tagged per F-mini-17.
const HOST_KEY_SALT: &[u8] = b"rescue-host-key-derivation-v1";
/// Build-time HKDF salt for the kernel GCC `-frandom-seed` — domain-separated from the rescue seed,
                                                                                               
const KERNEL_FRANDOM_SALT: &[u8] = b"recipes-kernel-frandom-seed-derivation-v1";
/// Output-context label for the kernel `-frandom-seed` derivation.
const KERNEL_FRANDOM_INFO: &[u8] = b"kernel-frandom-seed";
/// SSH/dropbear ed25519 algorithm name (RFC 8709 / RFC 4251 §5).
const SSH_ED25519_NAME: &[u8] = b"ssh-ed25519";

/// Opaque wrapper around dropbear's binary host-key wire-format bytes;
/// `AsRef<[u8]>` for write-to-file consumption.
#[derive(Clone, PartialEq, Eq)]
pub struct DropbearHostKeyBytes(Vec<u8>);

impl AsRef<[u8]> for DropbearHostKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for DropbearHostKeyBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                                                           
        write!(f, "DropbearHostKeyBytes({} bytes)", self.0.len())
    }
}

/// Public IKM components for the build-time seed derivation. Construct via
/// [`PublicInputs::new`], which validates the hex-char counts: the values feed a
/// pipe-separated ASCII IKM, so a malformed field would silently shift the IKM.
pub struct PublicInputs {
    git_sha_hex: String,
    alpine_version: String,
    image_signing_crt_sha256_hex: String,
}

impl PublicInputs {
    /// `git_sha_hex`: 40 ASCII hex chars. `image_signing_crt_sha256_hex`: 64 ASCII hex
    /// (sha256 over the cert DER — equals the `pinned-cert-fingerprints.toml` value sans
    /// the `sha256:` prefix, per F-mini-11). `alpine_version`: non-empty, no `|` (e.g. "3.21.0").
    pub fn new(
        git_sha_hex: impl Into<String>,
        alpine_version: impl Into<String>,
        image_signing_crt_sha256_hex: impl Into<String>,
    ) -> Result<Self, DeriveError> {
        let git_sha_hex = git_sha_hex.into();
        let alpine_version = alpine_version.into();
        let image_signing_crt_sha256_hex = image_signing_crt_sha256_hex.into();
        validate_hex(&git_sha_hex, 40, "git_sha_hex")?;
        validate_hex(
            &image_signing_crt_sha256_hex,
            64,
            "image_signing_crt_sha256_hex",
        )?;
        if alpine_version.is_empty() {
            return Err(DeriveError::PublicInput("alpine_version is empty".into()));
        }
        if alpine_version.contains('|') {
            return Err(DeriveError::PublicInput(
                "alpine_version contains the '|' IKM separator".into(),
            ));
        }
        Ok(Self {
            git_sha_hex,
            alpine_version,
            image_signing_crt_sha256_hex,
        })
    }

                                                                            
    fn ikm_public_text(&self) -> String {
        format!(
            "{}|{}|{}",
            self.git_sha_hex, self.alpine_version, self.image_signing_crt_sha256_hex
        )
    }
}

fn validate_hex(s: &str, expected_len: usize, field: &str) -> Result<(), DeriveError> {
    if s.len() != expected_len {
        return Err(DeriveError::PublicInput(format!(
            "{field}: expected {expected_len} hex chars, got {}",
            s.len()
        )));
    }
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DeriveError::PublicInput(format!(
            "{field}: non-hex character present"
        )));
    }
    Ok(())
}

                                                                                      
#[derive(Debug, thiserror::Error)]
pub enum DeriveError {
    #[error("seed/key file missing or wrong size: {0}")]
    FileRead(#[source] std::io::Error),
    #[error("HKDF derivation failed: {0}")]
    Hkdf(hkdf::InvalidLength),
    #[error("invalid public input: {0}")]
    PublicInput(String),
    #[error("write failed: {0}")]
    Write(#[source] std::io::Error),
}

                                                                                   

                                                                                      
pub fn seed_from_inputs(
    master_key: &[u8; 32],
    public_inputs: &PublicInputs,
) -> Result<[u8; 32], DeriveError> {
                                                                                
    let mut ikm = public_inputs.ikm_public_text().into_bytes();
    ikm.extend_from_slice(master_key);
    let hk = Hkdf::<Sha256>::new(Some(SEED_SALT), &ikm);
    let mut seed = [0u8; 32];
    let expanded = hk.expand(SEED_INFO, &mut seed).map_err(DeriveError::Hkdf);
    ikm.zeroize();                                                            
    expanded?;
    Ok(seed)
}

/// Runtime HKDF expand: seed (IKM) + verity_root_hash (info/nonce) → the 32-byte ed25519
/// seed. The single source of the runtime derivation, shared by [`host_key_from_seed`] +
/// [`ed25519_public_from_seed`] so the dropbear private-key bytes and the SSH public key
/// can NEVER diverge. Caller zeroizes the returned seed.
fn expand_ed25519_seed(seed: &[u8; 32], nonce: &[u8; 32]) -> Result<[u8; 32], DeriveError> {
    let hk = Hkdf::<Sha256>::new(Some(HOST_KEY_SALT), seed);
    let mut ed25519_seed = [0u8; 32];
    hk.expand(nonce, &mut ed25519_seed)
        .map_err(DeriveError::Hkdf)?;
    Ok(ed25519_seed)
}

                                                                                    
/// `nonce` is the dm-verity root hash (SHA-256 → 32 bytes; strict width per F-mini-1).
pub fn host_key_from_seed(
    seed: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<DropbearHostKeyBytes, DeriveError> {
    let mut ed25519_seed = expand_ed25519_seed(seed, nonce)?;
    let signing_key = SigningKey::from_bytes(&ed25519_seed);
    let public = signing_key.verifying_key().to_bytes();

                                                                           
                                                                                       
    let mut out = Vec::with_capacity(4 + SSH_ED25519_NAME.len() + 4 + 64);
    out.extend_from_slice(&(SSH_ED25519_NAME.len() as u32).to_be_bytes());
    out.extend_from_slice(SSH_ED25519_NAME);
    out.extend_from_slice(&64u32.to_be_bytes());
    out.extend_from_slice(&ed25519_seed);
    out.extend_from_slice(&public);
    ed25519_seed.zeroize();                                                            
    Ok(DropbearHostKeyBytes(out))
}

/// Derive the ed25519 PUBLIC key (32 bytes) for `(seed, nonce)` — the SSH/known_hosts
/// public half of the SAME key [`host_key_from_seed`] produces (shares
/// [`expand_ed25519_seed`], so they never diverge). For the operator-side offline TOFU
/// precompute (`recipes-admin derive-rescue-host-keys --image …`): the operator formats
/// this into the `ssh-ed25519 AAAA…` pubkey + the SHA-256 fingerprint for known_hosts.
pub fn ed25519_public_from_seed(
    seed: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<[u8; 32], DeriveError> {
    let mut ed25519_seed = expand_ed25519_seed(seed, nonce)?;
    let signing_key = SigningKey::from_bytes(&ed25519_seed);
    let public = signing_key.verifying_key().to_bytes();
    ed25519_seed.zeroize();
    Ok(public)
}

/// Build-time: derive the kernel's GCC `-frandom-seed` from the operator master key, domain-separated
/// from the rescue seed (distinct salt + info). Bound to the build via `git_sha_hex` (info suffix).
/// The 32-byte output — returned lowercase-hex, a command-safe seed string — flips `latent_entropy`
/// to its `deterministic_seed` path (reproducible for the key holder, unpredictable without the
                                                                                                
pub fn kernel_frandom_seed_hex(
    master_key: &[u8; 32],
    git_sha_hex: &str,
) -> Result<String, DeriveError> {
    let hk = Hkdf::<Sha256>::new(Some(KERNEL_FRANDOM_SALT), master_key);
    let mut info = KERNEL_FRANDOM_INFO.to_vec();
    info.push(b':');
    info.extend_from_slice(git_sha_hex.as_bytes());
    let mut seed = [0u8; 32];
    hk.expand(&info, &mut seed).map_err(DeriveError::Hkdf)?;
    let hex = seed.iter().map(|b| format!("{b:02x}")).collect::<String>();
    seed.zeroize();
    Ok(hex)
}

/// Build-time path-taking: read the operator master key + derive the kernel `-frandom-seed` (hex).
/// Mirrors [`derive_seed`].
pub fn derive_kernel_frandom_seed_hex(
    master_key_path: &Path,
    git_sha_hex: &str,
) -> Result<String, DeriveError> {
    let mut master = read_exact_32(master_key_path)?;
    let out = kernel_frandom_seed_hex(&master, git_sha_hex);
    master.zeroize();
    out
}

                                                                      

/// Build-time: read the operator-secret `rescue-seed-master.key` and derive the seed.
pub fn derive_seed(
    master_key_path: &Path,
    public_inputs: &PublicInputs,
) -> Result<[u8; 32], DeriveError> {
    let mut master_key = read_exact_32(master_key_path)?;
    let result = seed_from_inputs(&master_key, public_inputs);
    master_key.zeroize();                                            
    result
}

/// Runtime: read the baked-in seed file and derive the dropbear host-key bytes.
pub fn derive_host_key(
    seed_path: &Path,
    nonce: &[u8; 32],
) -> Result<DropbearHostKeyBytes, DeriveError> {
    let mut seed = read_exact_32(seed_path)?;
    let result = host_key_from_seed(&seed, nonce);
    seed.zeroize();
    result
}

fn read_exact_32(path: &Path) -> Result<[u8; 32], DeriveError> {
    let bytes = std::fs::read(path).map_err(DeriveError::FileRead)?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        DeriveError::FileRead(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected 32 bytes, got {}", v.len()),
        ))
    })
}
