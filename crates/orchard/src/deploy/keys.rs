//! `orchard generate-keys` — the operator key-bootstrap ceremony
                                                                     
//!
//! Produces the 7-file operator key set as a 2-cert CA→leaf hierarchy plus the
//! rescue-seed master key, all ECDSA-P256. **Pure-Rust (`rcgen`)** rather than
//! the spec's literal `openssl` CLI shell-outs — per
                                                                            
//! for examination) and because the CA→leaf chain + keyUsage extensions are
//! then verifiable in CI. `rcgen`/`rand` are already in-image for the
//! device-pairing CA, so this adds no image weight.
//!
//! **Trust-anchor shapes (load-bearing — the box's `.ima`/`.evm` link gate is
//! `restrict_link_by_digsig`, which requires each leaf to be signed by a key
//! already trusted, i.e. the CA on `.builtin_trusted_keys`):**
//! - `signing-ca.crt`: self-signed ROOT, `CA:TRUE` + `keyCertSign` → embedded in
//!   `CONFIG_SYSTEM_TRUSTED_KEYS` → `.builtin_trusted_keys`; vouches for the leaves.
//! - `ima.crt`: CA-SIGNED leaf, `CA:FALSE` + `digitalSignature` ONLY — the shape
//!   `restrict_link_by_digsig` REQUIRES: it rejects a leaf missing digitalSignature
//!   (`restrict.c:186`) or carrying CA (`:189`) / keyCertSign (`:192`), so that shape is a hard
//!   kernel-gate requirement here, not just X.509 hygiene. (The sibling gate `restrict_link_by_ca`,
//!   `:143-145`, is the inverse — requires CA+keyCertSign — guarding the trust-anchor/MOK path,
//!   off the box's `.ima`/`.evm` path.)
//! - `image-signing.crt`: self-signed leaf, `digitalSignature` — for the operator-sovereign ed25519
//!   `.img` signature (forward-debt: the signer is un-wired; the cert is currently consumed only as the
                                                                                                          

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

                                                                      
const TEN_YEARS_SECS: u64 = 60 * 60 * 24 * 365 * 10;

/// The operator-secret master key is exactly 32 bytes (the rescue-host-key IKM).
const MASTER_KEY_LEN: usize = 32;

/// The prime256v1 (NIST P-256) named-curve OID. The ONLY curve the spec + the
                                                                                   
const PRIME256V1_OID: &str = "1.2.840.10045.3.1.7";

                                                                                
pub const SIGNING_FILES: [&str; 6] = [
    "image-signing.key",
    "image-signing.crt",
    "signing-ca.key",
    "signing-ca.crt",
    "ima.key",
    "ima.crt",
];
pub const MASTER_KEY_FILE: &str = "rescue-seed-master.key";

#[derive(Debug, thiserror::Error)]
pub enum DeployKeyError {
    #[error("{0} already exists in {1} (pass --force to overwrite)")]
    Exists(String, String),
    #[error(
        "token-backed signing (--signing-key-token) is a PIPELINE-phase feature \
         (the air-gapped signer device); \
         not implemented in the foundation build"
    )]
    TokenUnsupported,
    #[error("certificate/key generation failed: {0}")]
    Crypto(String),
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("imported key set is invalid: {0}")]
    Import(String),
    #[error(
        "the `{0}` rung provisions a hardware signer via the 1C device ceremony \
         (component C4, hardware-gated) — not available in this host-only build. \
         Software rungs: --artifact-signing software | docker"
    )]
    HardwareRungNotYetAvailable(String),
    /// A required key file is genuinely absent (lstat NotFound) — the caller
    /// decides skip-vs-abort (an un-adopted rung is a legitimate floor). Distinct
    /// from [`DeployKeyError::Unloadable`]: absent is not the same as broken.
    #[error("required key file not found: {path}")]
    NotFound { path: String },
    /// A key file is PRESENT but cannot be loaded (a corrupt wrapped blob, bytes
    /// that are neither a v1 blob nor a 32-byte raw seed, a dangling symlink). A
    /// hard error — NEVER a silent skip-to-unsigned (F-6 fail-closed).
    #[error("key at {path} is present but cannot be loaded: {reason}")]
    Unloadable { path: String, reason: String },
    /// A key is passphrase-wrapped (docker rung) but the passphrase is missing or
    /// wrong. A hard error, distinguished from [`DeployKeyError::Unloadable`] so the
    /// operator sees "re-enter the passphrase", not "the file is corrupt".
    #[error(
        "key at {path} is passphrase-wrapped (docker rung) but the passphrase is missing or wrong"
    )]
    Passphrase { path: String },
    /// The key set predates one of the update-path purposes (a legacy 4-delegation
    /// set — e.g. the live box's). Still fail-closed — every sign/build path aborts —
    /// but actionable by construction (plan-review S2): extending `ALL_PURPOSES` makes
    /// EVERY pre-existing set hard-fail its next ORDINARY build, so the error must
    /// name the one-command fix, never read as a raw file-not-found. `purpose` is the
    /// bundle-file slug (e.g. `update-image`).
    #[error(
        "artifact key set has no {purpose} delegation (a key set minted before the \
         update path): run `orchard redelegate` to mint the missing UpdateImage/RootHash \
         delegations over the EXISTING root — no rebake, the box trust anchor is unchanged"
    )]
    MissingDelegation { purpose: String },
}

/// True iff a full cert key set (the 6 [`SIGNING_FILES`]) already exists in `dir`.
/// Lets `--artifact-signing` run as a standalone artifact-key add over an existing
/// set (no cert regen, no `--force` demanded) vs a fresh full bootstrap.
pub fn signing_set_exists(dir: &Path) -> bool {
    SIGNING_FILES.iter().all(|f| dir.join(f).exists())
}

fn crypto<E: std::fmt::Display>(e: E) -> DeployKeyError {
    DeployKeyError::Crypto(e.to_string())
}

fn io_at(path: &Path) -> impl Fn(std::io::Error) -> DeployKeyError + '_ {
    move |source| DeployKeyError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// How the 6 signing files are sourced.
pub enum GenMode {
    /// Default: generate fresh ECDSA-P256 keypairs + certs.
    Generate,
    /// Import an externally-generated key set; master.key is auto-generated.
    Import(ImportPaths),
    /// `--signing-key-token <slot>` — YubiKey/PIV. Unsupported (pipeline phase).
    Token { slot: String },
}

/// The six file paths an `--import-*` invocation supplies.
pub struct ImportPaths {
    pub image_signing_key: PathBuf,
    pub image_signing_cert: PathBuf,
    pub signing_ca_key: PathBuf,
    pub signing_ca_cert: PathBuf,
    pub ima_key: PathBuf,
    pub ima_cert: PathBuf,
}

pub struct GenerateKeysOpts {
    /// Keys directory (default `~/.config/recipes-deploy/keys`).
    pub output_dir: PathBuf,
                                                                               
    /// CN stays role-fixed; this is the multi-operator audit-trail tag.
    pub subject_ou: Option<String>,
    pub force: bool,
    pub mode: GenMode,
    /// Orthogonal to `mode`: rotate ONLY `rescue-seed-master.key` (F-mini-2).
    pub regenerate_master_key: bool,
    /// `crates/image-builder/pinned-cert-fingerprints.toml` (working-dir contract).
    pub fingerprints_path: PathBuf,
}

                                                                                 
/// key/master files hold secrets, the cert files are public but wiping them is
/// harmless + keeps the type uniform), unix mode.
struct OutFile {
    name: &'static str,
    bytes: Zeroizing<Vec<u8>>,
    mode: u32,
}

/// The full set to commit atomically (7 files + the cert DERs for fingerprints).
struct GeneratedSet {
    files: Vec<OutFile>,
    image_signing_der: Vec<u8>,
    signing_ca_der: Vec<u8>,
    ima_der: Vec<u8>,
}

/// Run the ceremony (the `generate-keys` entry point).
pub fn generate_keys(opts: &GenerateKeysOpts) -> Result<(), DeployKeyError> {
    if opts.regenerate_master_key {
                                                                                  
        return regenerate_master_key(opts);
    }
    let set = match &opts.mode {
        GenMode::Token { .. } => return Err(DeployKeyError::TokenUnsupported),
        GenMode::Generate => generate_set(opts.subject_ou.as_deref())?,
        GenMode::Import(paths) => import_set(paths)?,
    };
    commit_set(opts, set)
}

/// Rotate ONLY `rescue-seed-master.key` (master.key rotation / lost-master recovery).
fn regenerate_master_key(opts: &GenerateKeysOpts) -> Result<(), DeployKeyError> {
    let target = opts.output_dir.join(MASTER_KEY_FILE);
    if target.exists() && !opts.force {
        return Err(DeployKeyError::Exists(
            MASTER_KEY_FILE.to_string(),
            opts.output_dir.display().to_string(),
        ));
    }
    std::fs::create_dir_all(&opts.output_dir).map_err(io_at(&opts.output_dir))?;
    set_mode(&opts.output_dir, 0o700)?;
    write_file_mode(&target, &random_master_key(), 0o600)?;
    Ok(())
}

/// Generate three fresh ECDSA-P256 keypairs + the CA→leaf cert hierarchy.
fn generate_set(subject_ou: Option<&str>) -> Result<GeneratedSet, DeployKeyError> {
                                                               
    let mut ca_kp = ecdsa_keypair()?;
    let ca_cert = ca_params("recipes-signing-ca", subject_ou)?
        .self_signed(&ca_kp)
        .map_err(crypto)?;

                                                                                                  
                                                                                                    
    let mut is_kp = ecdsa_keypair()?;
    let is_cert = leaf_params("recipes-image-signing", subject_ou, &is_kp)?
        .self_signed(&is_kp)
        .map_err(crypto)?;

                                                              
    let mut ima_kp = ecdsa_keypair()?;
    let ima_cert = leaf_params("recipes-ima", subject_ou, &ima_kp)?
        .signed_by(&ima_kp, &ca_cert, &ca_kp)
        .map_err(crypto)?;

                                                                                     
                                                                                      
                                                                                          
                                                                                             
                                                                                        
                                                                                            
                                                                                     
                                                                                   
                                                                                           
                            
    let is_key = pem_file("image-signing.key", is_kp.serialize_pem());
    let ca_key = pem_file("signing-ca.key", ca_kp.serialize_pem());
    let ima_key = pem_file("ima.key", ima_kp.serialize_pem());
    is_kp.zeroize();
    ca_kp.zeroize();
    ima_kp.zeroize();

    Ok(GeneratedSet {
        files: vec![
            is_key,
            crt_file("image-signing.crt", is_cert.pem()),
            ca_key,
            crt_file("signing-ca.crt", ca_cert.pem()),
            ima_key,
            crt_file("ima.crt", ima_cert.pem()),
            OutFile {
                name: MASTER_KEY_FILE,
                bytes: random_master_key(),
                mode: 0o600,
            },
        ],
        image_signing_der: is_cert.der().to_vec(),
        signing_ca_der: ca_cert.der().to_vec(),
        ima_der: ima_cert.der().to_vec(),
    })
}

/// Validate + read an externally-generated 6-file key set; auto-generate master.key.
fn import_set(paths: &ImportPaths) -> Result<GeneratedSet, DeployKeyError> {
    let is_key = read_pem(&paths.image_signing_key)?;
    let is_crt = read_pem(&paths.image_signing_cert)?;
    let ca_key = read_pem(&paths.signing_ca_key)?;
    let ca_crt = read_pem(&paths.signing_ca_cert)?;
    let ima_key = read_pem(&paths.ima_key)?;
    let ima_crt = read_pem(&paths.ima_cert)?;

    let is_der = pem_cert_to_der(&is_crt)?;
    let ca_der = pem_cert_to_der(&ca_crt)?;
    let ima_der = pem_cert_to_der(&ima_crt)?;

                                                                                        
    validate_ca_cert(&ca_der)?;
    validate_leaf_cert(&is_der, None, "image-signing")?;
    validate_leaf_cert(&ima_der, Some(&ca_der), "ima")?;
                                                                       
    check_key_matches_cert(&is_key, &is_der, "image-signing")?;
    check_key_matches_cert(&ca_key, &ca_der, "signing-ca")?;
    check_key_matches_cert(&ima_key, &ima_der, "ima")?;

    Ok(GeneratedSet {
        files: vec![
            pem_file("image-signing.key", is_key),
            crt_file("image-signing.crt", is_crt),
            pem_file("signing-ca.key", ca_key),
            crt_file("signing-ca.crt", ca_crt),
            pem_file("ima.key", ima_key),
            crt_file("ima.crt", ima_crt),
            OutFile {
                name: MASTER_KEY_FILE,
                bytes: random_master_key(),
                mode: 0o600,
            },
        ],
        image_signing_der: is_der,
        signing_ca_der: ca_der,
        ima_der,
    })
}

/// Commit the 7 files atomically: refuse-if-exists (unless force), write all to
/// a sibling tempdir, then rename into the keys dir (0700) only after all
                                                                             
fn commit_set(opts: &GenerateKeysOpts, mut set: GeneratedSet) -> Result<(), DeployKeyError> {
    if !opts.force {
        for f in &set.files {
            let dest = opts.output_dir.join(f.name);
            if dest.exists() {
                return Err(DeployKeyError::Exists(
                    f.name.to_string(),
                    opts.output_dir.display().to_string(),
                ));
            }
        }
    }

                                                                                 
                                                                                   
                                                                               
                                                                                         
    if opts.force {
        let existing = opts.output_dir.join(MASTER_KEY_FILE);
        if let Ok(bytes) = std::fs::read(&existing) {
            let bytes = Zeroizing::new(bytes);
            if bytes.len() == MASTER_KEY_LEN {
                if let Some(f) = set.files.iter_mut().find(|f| f.name == MASTER_KEY_FILE) {
                    f.bytes = bytes;
                }
            } else {
                                                                                       
                                                                                          
                                                             
                eprintln!(
                    "warning: existing {MASTER_KEY_FILE} is {} bytes, not {MASTER_KEY_LEN}; \
                     regenerating it (previously-derived rescue host keys will NOT reproduce)",
                    bytes.len()
                );
            }
        }
    }

    let parent = opts.output_dir.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(io_at(parent))?;
                                                                            
                                                                       
    let staging = tempfile::Builder::new()
        .prefix(".recipes-keys-")
        .tempdir_in(parent)
        .map_err(io_at(parent))?;
                                                                                    
                                                                                    
    set_mode(staging.path(), 0o700)?;
    for f in &set.files {
        write_file_mode(&staging.path().join(f.name), &f.bytes, f.mode)?;
    }

                                                     
    std::fs::create_dir_all(&opts.output_dir).map_err(io_at(&opts.output_dir))?;
    set_mode(&opts.output_dir, 0o700)?;
    for f in &set.files {
        let dest = opts.output_dir.join(f.name);
        std::fs::rename(staging.path().join(f.name), &dest).map_err(io_at(&dest))?;
    }

    write_fingerprints(opts, &set)
}

/// One `[section]` of the pinned-cert-fingerprints TOML.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct FingerprintEntry {
    /// `"sha256:<hex>"` over the cert DER.
    pub fingerprint: String,
    /// ISO-8601 UTC generation timestamp.
    pub generated_at: String,
}

impl FingerprintEntry {
    fn from_cert_der(der: &[u8]) -> Self {
        Self {
            fingerprint: format!("sha256:{}", sha256_hex(der)),
            generated_at: now_rfc3339(),
        }
    }
}

pub(crate) fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Build a [`FingerprintEntry`] from a cert PEM, validating it parses as an
/// ECDSA-P256 X.509 cert (used by `update-cert-fingerprints` on a rotation).
pub(crate) fn fingerprint_entry_from_cert_pem(
    pem: &str,
) -> Result<FingerprintEntry, DeployKeyError> {
    use x509_parser::prelude::FromDer;
    let der = pem_cert_to_der(pem)?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|e| DeployKeyError::Import(format!("cert parse: {e}")))?;
    require_ecdsa_p256(&cert, "cert")?;
                                                                                
                                                                                      
                                                                
    require_currently_valid(&cert, "cert")?;
    Ok(FingerprintEntry::from_cert_der(&der))
}

/// Render the pinned-cert-fingerprints TOML — the SINGLE source of its on-disk
/// shape (both `generate-keys` and `update-cert-fingerprints` go through here).
pub(crate) fn render_fingerprints_toml(
    image_signing: &FingerprintEntry,
    signing_ca: &FingerprintEntry,
    ima: &FingerprintEntry,
) -> String {
    format!(
        "# Operator signing-cert fingerprints (sha256 of the cert DER).\n\
         # Written by `orchard {{generate-keys,update-cert-fingerprints}}`; commit to the repo.\n\
         [image_signing]\nfingerprint = \"{}\"\ngenerated_at = \"{}\"\n\n\
         [signing_ca]\nfingerprint = \"{}\"\ngenerated_at = \"{}\"\n\n\
         [ima]\nfingerprint = \"{}\"\ngenerated_at = \"{}\"\n",
        image_signing.fingerprint,
        image_signing.generated_at,
        signing_ca.fingerprint,
        signing_ca.generated_at,
        ima.fingerprint,
        ima.generated_at,
    )
}

/// Write `crates/image-builder/pinned-cert-fingerprints.toml` (atomic, 0644).
fn write_fingerprints(opts: &GenerateKeysOpts, set: &GeneratedSet) -> Result<(), DeployKeyError> {
    let body = render_fingerprints_toml(
        &FingerprintEntry::from_cert_der(&set.image_signing_der),
        &FingerprintEntry::from_cert_der(&set.signing_ca_der),
        &FingerprintEntry::from_cert_der(&set.ima_der),
    );
    write_file_mode(&opts.fingerprints_path, body.as_bytes(), 0o644)
}

                                

fn ecdsa_keypair() -> Result<KeyPair, DeployKeyError> {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(crypto)
}

fn distinguished_name(cn: &str, ou: Option<&str>) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    if let Some(ou) = ou {
        dn.push(DnType::OrganizationalUnitName, ou);
    }
    dn
}

fn ca_params(cn: &str, ou: Option<&str>) -> Result<CertificateParams, DeployKeyError> {
    let mut p = CertificateParams::new(vec![]).map_err(crypto)?;
    p.distinguished_name = distinguished_name(cn, ou);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    set_validity(&mut p);
    Ok(p)
}

/// The SubjectKeyIdentifier extension (OID 2.5.29.14) for a leaf cert, computed exactly as rcgen's
/// `KeyIdMethod::Sha256` does (RFC 7093 method 1 — truncated SHA-256 over the SPKI), so the keyid
/// value is unchanged from the prior `ExplicitNoCa` certs. BOOT-CRITICAL (QEMU boot-test
/// 2026-05-28): we add the SKID as a CUSTOM extension because rcgen couples its built-in SKID
/// emission with `IsCa::ExplicitNoCa`, which ALSO writes a non-canonical
/// `basicConstraints SEQUENCE{BOOLEAN FALSE}`. The kernel's strict DER x509 parser
/// (`x509_cert_parser.c` basicConstraints handler) rejects that with -EBADMSG — it accepts only an
/// empty SEQUENCE for CA:FALSE — so an ExplicitNoCa leaf never links onto `.ima`/`.evm`. `NoCa`
/// omits basicConstraints (canonical CA:FALSE) but also the SKID, so we re-add it here.
fn skid_extension(key: &KeyPair) -> CustomExtension {
    let digest = Sha256::digest(key.public_key_der());
                                                                                                 
    let mut content = vec![0x04u8, 0x14u8];
    content.extend_from_slice(&digest[..20]);
    let mut ext = CustomExtension::from_oid_content(&[2, 5, 29, 14], content);
    ext.set_criticality(false);                                             
    ext
}

fn leaf_params(
    cn: &str,
    ou: Option<&str>,
    key: &KeyPair,
) -> Result<CertificateParams, DeployKeyError> {
    let mut p = CertificateParams::new(vec![]).map_err(crypto)?;
    p.distinguished_name = distinguished_name(cn, ou);
                                                                                                  
                                                                                           
                                                                          
                                                                                                   
                                                                                                     
                                                                                                 
                                                                                           
    p.is_ca = IsCa::NoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.custom_extensions.push(skid_extension(key));
                                                                                                   
                                                                                                 
                                                                                                   
                                                                                    
    p.use_authority_key_identifier_extension = true;
    set_validity(&mut p);
    Ok(p)
}

fn set_validity(p: &mut CertificateParams) {
    let now = SystemTime::now();
    p.not_before = now.into();
    p.not_after = (now + Duration::from_secs(TEN_YEARS_SECS)).into();
}

                                            

                                                                               
/// not-yet-valid). The kernel rejects out-of-window certs at link/appraise time →
/// boot lockout; an expired image-signing cert → `.img` verify failure. Fail closed.
fn require_currently_valid(
    cert: &x509_parser::certificate::X509Certificate,
    label: &str,
) -> Result<(), DeployKeyError> {
    if !cert.validity().is_valid() {
        return Err(DeployKeyError::Import(format!(
            "{label} cert is expired or not yet valid (NotBefore {}, NotAfter {})",
            cert.validity().not_before,
            cert.validity().not_after
        )));
    }
    Ok(())
}

fn validate_ca_cert(der: &[u8]) -> Result<(), DeployKeyError> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der)
        .map_err(|e| DeployKeyError::Import(format!("signing-ca cert parse: {e}")))?;
    require_ecdsa_p256(&cert, "signing-ca")?;
    require_currently_valid(&cert, "signing-ca")?;
    let bc = cert
        .basic_constraints()
        .map_err(|e| DeployKeyError::Import(format!("signing-ca basicConstraints: {e}")))?;
    if !bc.map(|b| b.value.ca).unwrap_or(false) {
        return Err(DeployKeyError::Import(
            "signing-ca cert is not CA:TRUE".into(),
        ));
    }
    let ku = cert
        .key_usage()
        .map_err(|e| DeployKeyError::Import(format!("signing-ca keyUsage: {e}")))?
        .ok_or_else(|| DeployKeyError::Import("signing-ca has no keyUsage".into()))?;
    if !ku.value.key_cert_sign() {
        return Err(DeployKeyError::Import(
            "signing-ca cert lacks keyCertSign".into(),
        ));
    }
                                                                                   
                                                                                    
                                                                                   
    cert.verify_signature(Some(cert.public_key()))
        .map_err(|e| DeployKeyError::Import(format!("signing-ca self-signature invalid: {e}")))?;
    Ok(())
}

/// Validate a leaf: ECDSA-P256, CA:FALSE, digitalSignature ONLY (no keyCertSign),
/// and — if `issuer_der` is given — its signature chains to that issuer.
fn validate_leaf_cert(
    der: &[u8],
    issuer_der: Option<&[u8]>,
    label: &str,
) -> Result<(), DeployKeyError> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der)
        .map_err(|e| DeployKeyError::Import(format!("{label} cert parse: {e}")))?;
    require_ecdsa_p256(&cert, label)?;
    require_currently_valid(&cert, label)?;

                                                                                    
                                                                                     
    if let Some(bc) = cert
        .basic_constraints()
        .map_err(|e| DeployKeyError::Import(format!("{label} basicConstraints: {e}")))?
        && bc.value.ca
    {
        return Err(DeployKeyError::Import(format!(
            "{label} cert must be CA:FALSE (it is a signing leaf)"
        )));
    }
    if let Some(ku) = cert
        .key_usage()
        .map_err(|e| DeployKeyError::Import(format!("{label} keyUsage: {e}")))?
    {
        if ku.value.key_cert_sign() {
                                                                                           
                                                                                                   
                                                                                                     
                                                                         
            return Err(DeployKeyError::Import(format!(
                "{label} leaf must be digitalSignature-only, not CA-capable (carries keyCertSign)"
            )));
        }
        if !ku.value.digital_signature() {
            return Err(DeployKeyError::Import(format!(
                "{label} leaf must carry digitalSignature"
            )));
        }
    } else {
        return Err(DeployKeyError::Import(format!(
            "{label} leaf has no keyUsage extension"
        )));
    }

                                                                                 
                                                                                         
    match issuer_der {
        Some(issuer_der) => {
            let (_, issuer) = x509_parser::certificate::X509Certificate::from_der(issuer_der)
                .map_err(|e| DeployKeyError::Import(format!("{label} issuer parse: {e}")))?;
            cert.verify_signature(Some(issuer.public_key()))
                .map_err(|e| {
                    DeployKeyError::Import(format!(
                        "{label} leaf does not chain to the signing-CA: {e}"
                    ))
                })?;
        }
        None => {
            cert.verify_signature(Some(cert.public_key()))
                .map_err(|e| {
                    DeployKeyError::Import(format!(
                        "{label} self-signed cert signature invalid: {e}"
                    ))
                })?;
        }
    }
    Ok(())
}

fn require_ecdsa_p256(
    cert: &x509_parser::certificate::X509Certificate,
    label: &str,
) -> Result<(), DeployKeyError> {
                                                                             
    use x509_parser::public_key::PublicKey;
    match cert.public_key().parsed() {
        Ok(PublicKey::EC(ec)) => {
                                                                                         
            let len = ec.data().len();
            if len != 65 && len != 33 {
                return Err(DeployKeyError::Import(format!(
                    "{label} key is EC but not P-256 (point len {len})"
                )));
            }
        }
        Ok(_) => {
            return Err(DeployKeyError::Import(format!(
                "{label} key is not ECDSA (P-256 required)"
            )));
        }
        Err(e) => {
            return Err(DeployKeyError::Import(format!(
                "{label} public key parse: {e}"
            )));
        }
    }
                                                                                   
                                                                                
                                                                                   
                                                                                    
                                                                                      
                                                
    let oid = cert
        .public_key()
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .ok_or_else(|| {
            DeployKeyError::Import(format!("{label} key carries no EC named-curve OID"))
        })?;
    if oid.to_string() != PRIME256V1_OID {
        return Err(DeployKeyError::Import(format!(
            "{label} curve is not P-256 (prime256v1); got {oid}"
        )));
    }
    Ok(())
}

/// Confirm a PEM private key parses (rcgen) and its public half matches the cert.
fn check_key_matches_cert(
    key_pem: &str,
    cert_der: &[u8],
    label: &str,
) -> Result<(), DeployKeyError> {
    use x509_parser::prelude::FromDer;
    let mut kp = KeyPair::from_pem(key_pem)
        .map_err(|e| DeployKeyError::Import(format!("{label} key parse: {e}")))?;
                                                                                       
                                                                                            
                                                                                         
                                                                                            
    let key_spki = kp.public_key_der();
    kp.zeroize();
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .map_err(|e| DeployKeyError::Import(format!("{label} cert parse: {e}")))?;
    if key_spki != cert.public_key().raw {
        return Err(DeployKeyError::Import(format!(
            "{label} private key does not match its certificate"
        )));
    }
    Ok(())
}

                                

fn random_master_key() -> Zeroizing<Vec<u8>> {
    use rand::RngCore;
    let mut buf = [0u8; MASTER_KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let out = Zeroizing::new(buf.to_vec());
    buf.zeroize();                                                               
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn pem_file(name: &'static str, pem: String) -> OutFile {
                                                                                   
                                                                            
    OutFile {
        name,
        bytes: Zeroizing::new(pem.into_bytes()),
        mode: 0o600,
    }
}

fn crt_file(name: &'static str, pem: String) -> OutFile {
    OutFile {
        name,
        bytes: Zeroizing::new(pem.into_bytes()),
        mode: 0o644,
    }
}

pub(crate) fn read_pem(path: &Path) -> Result<String, DeployKeyError> {
    let bytes = std::fs::read(path).map_err(io_at(path))?;
    String::from_utf8(bytes)
        .map_err(|_| DeployKeyError::Import(format!("{} is not UTF-8 PEM", path.display())))
}

pub(crate) fn pem_cert_to_der(pem: &str) -> Result<Vec<u8>, DeployKeyError> {
    let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|e| DeployKeyError::Import(format!("PEM parse: {e}")))?;
    Ok(p.contents)
}

/// Write `contents` to `path` at `mode`, atomically (sibling temp + rename), with
                                                                                 
/// the temp is opened `create_new` + `O_NOFOLLOW` so a planted symlink at the temp
/// path can't redirect the write/chmod through to another file; a stale temp is
/// unlinked-and-retried once (the unlink removes the link, not its target).
pub(crate) fn write_file_mode(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<(), DeployKeyError> {
    use std::io::Write as _;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(io_at(parent))?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("out")
    ));

    let mut f = open_fresh_temp(&tmp, mode)?;
                                                                               
                                               
    set_mode(&tmp, mode)?;
    f.write_all(contents).map_err(io_at(&tmp))?;
    f.sync_all().map_err(io_at(&tmp))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(io_at(path))
}

/// Open `tmp` as a fresh inode at `mode`: `create_new` (fails if it exists, so a
/// pre-planted file/symlink is never opened) + `O_NOFOLLOW` on Unix. On a stale
/// temp (`AlreadyExists`), unlink it and retry once.
fn open_fresh_temp(tmp: &Path, mode: u32) -> Result<std::fs::File, DeployKeyError> {
    fn attempt(tmp: &Path, mode: u32) -> std::io::Result<std::fs::File> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(mode);
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        opts.open(tmp)
    }
    match attempt(tmp, mode) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(tmp).map_err(io_at(tmp))?;
            let f = attempt(tmp, mode).map_err(io_at(tmp))?;
            Ok(f)
        }
        Err(e) => Err(io_at(tmp)(e)),
    }
}

#[cfg(unix)]
pub(crate) fn set_mode(path: &Path, mode: u32) -> Result<(), DeployKeyError> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(io_at(path))
}

#[cfg(not(unix))]
pub(crate) fn set_mode(_path: &Path, _mode: u32) -> Result<(), DeployKeyError> {
    Ok(())
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
