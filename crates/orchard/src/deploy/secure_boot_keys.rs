//! `orchard generate-keys --secure-boot` — the Secure Boot key family
                                       
//!
//! Mints the operator-enrolled PK → KEK → db hierarchy: PK self-signed (the platform
//! root the firmware trusts for KEK updates), KEK signed by PK (authorizes db
//! updates), db signed by KEK (the image-signing leaf — `deploy sign-sb` signs the
//! rambutan loader + the kernel PE with it, and the firmware verifies both at boot).
//! The X.509 chain mirrors the variable-update authority hierarchy; enrollment
                                                                                     
//! no MOK (we own db).
//!
                                                                                      
//! accept RSA-2048/3072 + SHA-256 for db; EC support is spotty. So this family is RSA —
//! deliberately SEPARATE from the operator's ed25519 artifact keys and the ECDSA-P256
//! IMA/EVM leaves. RSA-3072/SHA-256 is the default; `--sb-rsa 2048` is the documented
//! downgrade for firmware that rejects 3072. Keygen = RustCrypto `rsa` (rcgen/ring
//! signs the certs with the generated keys but cannot generate RSA itself).
//!
                                                                                      
//! dir (`<keys_dir>/secure-boot/`, keys 0600 / certs 0644) — the buildable-now floor:
//! it weakens only the operator's own exposure, never the box's verified chain. The
//! hardware rungs (`one-signer`/`two-signers` — db key on the air-gapped signer,
//! round-trip signing) route to [`SecureBootKeyError::HardwareRungNotYetAvailable`],
//! mirroring the artifact-signer ceremony menu (C4 forward-debt).
//!
//! The PK/KEK/db cert sha256 fingerprints are pinned into a committed
                                                                                               
//! cross-checks the firmware-enrolled exact PK/KEK/db set against what the repo pinned; same
//! posture as `pinned-cert-fingerprints.toml`).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_RSA_SHA256,
};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

                                                                                     
                                                                                   
/// verification ignores time-validity anyway — §12 ledger item 5 — but tools and
/// humans read these fields.)
const THIRTY_YEARS_SECS: u64 = 60 * 60 * 24 * 365 * 30;

/// The six files of the SB family, under `<keys_dir>/secure-boot/`.
pub const SECURE_BOOT_FILES: [&str; 6] =
    ["PK.key", "PK.crt", "KEK.key", "KEK.crt", "db.key", "db.crt"];

                                                                                     
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootRung {
    /// Keys on the operator host (the buildable-now floor).
    Software,
    /// db key on the air-gapped signer (one device).
    OneSigner,
    /// Split custody across two signer devices.
    TwoSigners,
}

impl SecureBootRung {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "software" => Some(Self::Software),
            "one-signer" => Some(Self::OneSigner),
            "two-signers" => Some(Self::TwoSigners),
            _ => None,
        }
    }
}

                                                
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbRsaBits {
    /// The default: RSA-3072/SHA-256.
    Rsa3072,
    /// The documented downgrade for firmware that rejects 3072.
    Rsa2048,
}

impl SbRsaBits {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "3072" => Some(Self::Rsa3072),
            "2048" => Some(Self::Rsa2048),
            _ => None,
        }
    }
    fn bits(self) -> usize {
        match self {
            Self::Rsa3072 => 3072,
            Self::Rsa2048 => 2048,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecureBootKeyError {
    #[error("{0} already exists in {1} (pass --force to overwrite the SB family)")]
    Exists(String, String),
    #[error(
        "the '{0}' Secure Boot custody rung routes the db key to the air-gapped \
         signer (PIPELINE hardware); \
         not yet available — use --secure-boot software (the documented floor)"
    )]
    HardwareRungNotYetAvailable(&'static str),
    #[error("RSA/certificate generation failed: {0}")]
    Crypto(String),
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

fn crypto<E: std::fmt::Display>(e: E) -> SecureBootKeyError {
    SecureBootKeyError::Crypto(e.to_string())
}

fn io_at(path: &Path) -> impl Fn(std::io::Error) -> SecureBootKeyError + '_ {
    move |source| SecureBootKeyError::Io {
        path: path.display().to_string(),
        source,
    }
}

pub struct SecureBootKeysOpts {
    /// The operator keys dir (the family lands in `<keys_dir>/secure-boot/`).
    pub keys_dir: PathBuf,
    /// The committed PK/KEK/db fingerprint anchor (`crates/image-builder/pinned-secure-boot-db.toml`).
    pub db_fingerprint_path: PathBuf,
    pub rung: SecureBootRung,
    pub bits: SbRsaBits,
    pub force: bool,
                                                                                         
    /// tag, same as the main key set).
    pub subject_ou: Option<String>,
}

/// Mint the PK/KEK/db family (the `software` rung). Refuses if any of the six files
/// exists (unless `force`); writes atomically (tempdir + rename — all six or none,
                                                                                            
pub fn generate_secure_boot_keys(opts: &SecureBootKeysOpts) -> Result<(), SecureBootKeyError> {
    match opts.rung {
        SecureBootRung::Software => {}
        SecureBootRung::OneSigner => {
            return Err(SecureBootKeyError::HardwareRungNotYetAvailable(
                "one-signer",
            ));
        }
        SecureBootRung::TwoSigners => {
            return Err(SecureBootKeyError::HardwareRungNotYetAvailable(
                "two-signers",
            ));
        }
    }

    let sb_dir = opts.keys_dir.join("secure-boot");
    if !opts.force {
        for name in SECURE_BOOT_FILES {
            let dest = sb_dir.join(name);
            if dest.exists() {
                return Err(SecureBootKeyError::Exists(
                    name.to_string(),
                    sb_dir.display().to_string(),
                ));
            }
        }
    }

                                                                                       
    let pk_kp = rsa_keypair(opts.bits)?;
    let kek_kp = rsa_keypair(opts.bits)?;
    let db_kp = rsa_keypair(opts.bits)?;

                                                                           
    let pk_cert = ca_params("recipes-sb-pk", opts.subject_ou.as_deref())?
        .self_signed(&pk_kp.rcgen)
        .map_err(crypto)?;
                                                                                 
    let kek_cert = ca_params("recipes-sb-kek", opts.subject_ou.as_deref())?
        .signed_by(&kek_kp.rcgen, &pk_cert, &pk_kp.rcgen)
        .map_err(crypto)?;
                                                                                     
                                                                                 
    let db_cert = db_leaf_params("recipes-sb-db", opts.subject_ou.as_deref())?
        .signed_by(&db_kp.rcgen, &kek_cert, &kek_kp.rcgen)
        .map_err(crypto)?;

                                                                                                      
                                                                                                       
                                                                                             
    let pk_fingerprint_hex = format!("{:x}", Sha256::digest(pk_cert.der()));
    let kek_fingerprint_hex = format!("{:x}", Sha256::digest(kek_cert.der()));
    let db_fingerprint_hex = format!("{:x}", Sha256::digest(db_cert.der()));

                                                                                   
    let parent = opts.keys_dir.as_path();
    std::fs::create_dir_all(parent).map_err(io_at(parent))?;
    let tmp = tempfile::Builder::new()
        .prefix(".secure-boot-keys.")
        .tempdir_in(parent)
        .map_err(io_at(parent))?;
    let (pk_pem, kek_pem, db_pem) = (pk_cert.pem(), kek_cert.pem(), db_cert.pem());
    let files: [(&str, &[u8], u32); 6] = [
        ("PK.key", pk_kp.pem.as_bytes(), 0o600),
        ("PK.crt", pk_pem.as_bytes(), 0o644),
        ("KEK.key", kek_kp.pem.as_bytes(), 0o600),
        ("KEK.crt", kek_pem.as_bytes(), 0o644),
        ("db.key", db_kp.pem.as_bytes(), 0o600),
        ("db.crt", db_pem.as_bytes(), 0o644),
    ];
    for (name, bytes, mode) in files {
        write_file_mode(&tmp.path().join(name), bytes, mode)?;
    }
    if opts.force && sb_dir.exists() {
        std::fs::remove_dir_all(&sb_dir).map_err(io_at(&sb_dir))?;
    }
                                                                                                  
                                                                                                        
                                                                                                  
                                                                                                   
    std::fs::rename(tmp.path(), &sb_dir).map_err(io_at(&sb_dir))?;
    drop(tmp);
    set_mode(&sb_dir, 0o700)?;

    write_sb_fingerprints(
        &opts.db_fingerprint_path,
        &db_fingerprint_hex,
        &kek_fingerprint_hex,
        &pk_fingerprint_hex,
    )?;
    Ok(())
}

/// An RSA keypair as both the zeroizing PKCS#8 PEM (what gets written / what sbsign
/// consumes) and the rcgen handle (what signs the X.509 certs).
struct RsaPair {
    pem: Zeroizing<String>,
    rcgen: KeyPair,
}

fn rsa_keypair(bits: SbRsaBits) -> Result<RsaPair, SecureBootKeyError> {
    let mut rng = rsa::rand_core::OsRng;
    let key = rsa::RsaPrivateKey::new(&mut rng, bits.bits()).map_err(crypto)?;
    let pem: Zeroizing<String> = key.to_pkcs8_pem(LineEnding::LF).map_err(crypto)?;
                                                                                 
                                                                   
    let rcgen = KeyPair::from_pem_and_sign_algo(&pem, &PKCS_RSA_SHA256).map_err(crypto)?;
    Ok(RsaPair { pem, rcgen })
}

fn dn(cn: &str, ou: Option<&str>) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    if let Some(ou) = ou {
        dn.push(DnType::OrganizationalUnitName, ou);
    }
    dn
}

fn validity() -> (SystemTime, SystemTime) {
    let now = SystemTime::now();
    (now, now + Duration::from_secs(THIRTY_YEARS_SECS))
}

fn ca_params(cn: &str, ou: Option<&str>) -> Result<CertificateParams, SecureBootKeyError> {
    let mut p = CertificateParams::default();
    p.distinguished_name = dn(cn, ou);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let (nb, na) = validity();
    p.not_before = nb.into();
    p.not_after = na.into();
    Ok(p)
}

fn db_leaf_params(cn: &str, ou: Option<&str>) -> Result<CertificateParams, SecureBootKeyError> {
    let mut p = CertificateParams::default();
    p.distinguished_name = dn(cn, ou);
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
                                                                                 
                                                                                    
                                
    p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
    let (nb, na) = validity();
    p.not_before = nb.into();
    p.not_after = na.into();
    Ok(p)
}

/// The committed enrollment anchor (mirrors `pinned-cert-fingerprints.toml`). Records the WHOLE enrolled
/// set — PK + KEK + db (sha256 of each cert DER) — so the §7.2/§10.2 exact-set cross-check (the
                                                                                                    
/// `[db]` is written FIRST so `sign_sb::check_db_fingerprint`'s first-`fingerprint=` scan still reads
/// the db value; do not reorder.
fn write_sb_fingerprints(
    path: &Path,
    db_hex: &str,
    kek_hex: &str,
    pk_hex: &str,
) -> Result<(), SecureBootKeyError> {
    let now = httpdate_like_utc();
    let body = format!(
        "# Secure Boot enrolled-cert fingerprints (sha256 of each cert DER).\n\
         # Written by `orchard generate-keys --secure-boot`; commit to the repo.\n\
         # The enrollment ceremony  + the §10.2 exact-set re-key check cross-check the\n \
         # firmware-enrolled PK/KEK/db against THESE values; `deploy sign-sb` refuses a db.crt that\n\
         # does not match `[db]`. `[db]` MUST stay first (the sign-sb reader scans for the first\n\
         # `fingerprint =` line).\n\
         [db]\n\
         fingerprint = \"sha256:{db_hex}\"\n\
         generated_at = \"{now}\"\n\
         \n\
         [kek]\n\
         fingerprint = \"sha256:{kek_hex}\"\n\
         \n\
         [pk]\n\
         fingerprint = \"sha256:{pk_hex}\"\n"
    );
    write_file_mode(path, body.as_bytes(), 0o644)
}

/// UTC `YYYY-MM-DDTHH:MM:SSZ` without a chrono dep (mirrors keys.rs's stamp shape).
fn httpdate_like_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let (h, m, s) = ((secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);
                                                                             
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn write_file_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<(), SecureBootKeyError> {
    std::fs::write(path, bytes).map_err(io_at(path))?;
    set_mode(path, mode)
}

fn set_mode(path: &Path, mode: u32) -> Result<(), SecureBootKeyError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(io_at(path))
}

#[cfg(test)]
#[path = "secure_boot_keys_tests.rs"]
mod tests;
