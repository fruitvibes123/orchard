//! `orchard sign-sb` — Authenticode-sign the UEFI boot PEs and splice them
                                                                          
//!
//! `deploy build --firmware uefi` emits the UNSIGNED `.img` plus the unsigned PE sidecars
//! (`<base>.loader.efi`, `<base>.vmlinuz`) and a signing manifest (`<base>.sign-manifest.toml`,
//! paths + SHA-256s). This verb — the SB-rung-only second hop (SB-off rungs never run it):
//!
//! 1. refuses any rung but `software` (hardware rungs route the db key to the air-gapped
//!    signer round-trip — C4 forward-debt, mirroring the artifact-signer menu);
//! 2. refuses a `db.crt` whose DER sha256 differs from the committed
//!    `pinned-secure-boot-db.toml` anchor (sign-with-the-wrong-key fails closed BEFORE
//!    any signature exists);
//! 3. verifies the sidecar PEs against the manifest digests (what gets signed IS what the
//!    build produced);
                                                                                        
//!    DOES embed a wall-clock `signingTime` authenticated attribute (OpenSSL inserts it when
//!    the PKCS#7 carries any auth attrs, which Authenticode requires), so two signings are
//!    NOT byte-identical and signed-PE byte-determinism does NOT hold. Reproducibility rests
//!    on Authenticode-DIGEST equivalence instead: `signingTime` + the certificate table + the
//!    PE checksum all live in regions the Authenticode hash excludes by construction, so the
//!    signed PE's Authenticode digest equals the reproducible unsigned build's. The container
//!    seam test asserts THAT property (not raw byte-identity);
//! 5. splices the signed PEs into the `.img`'s ESP via `mcopy -i img@@<boot_offset>`
                                                                                             
//!    reads them back and byte-compares (splice faithfulness, fail closed);
//! 6. rewrites `<base>.sha256` over the spliced image. The operator-sovereign ed25519
//!    `.img` signature is the documented un-wired forward-debt (gates 4.3) — when the
//!    signer lands, it signs the POST-splice image, i.e. runs after this verb.
//!
//! Signed PE copies are also left beside the image (`<base>.loader.signed.efi`,
//! `<base>.vmlinuz.signed`) — the §7.2 installer-USB ceremony consumes them.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::secure_boot_keys::SecureBootRung;

/// `<base>.sign-manifest.toml` — written by `deploy build --firmware uefi`, consumed here.
#[derive(Serialize, Deserialize)]
pub struct SignManifest {
    pub loader: ManifestEntry,
    pub vmlinuz: ManifestEntry,
}

#[derive(Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Sidecar filename (relative to the `.img`'s directory).
    pub file: String,
    /// SHA-256 of the unsigned PE bytes.
    pub sha256: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SignSbError {
    #[error(
        "the '{0}' Secure Boot custody rung routes the db key to the air-gapped \
         signer (PIPELINE hardware); not yet available — use --secure-boot software"
    )]
    HardwareRungNotYetAvailable(&'static str),
    #[error(
        "db.crt fingerprint mismatch: keys dir has sha256:{actual} but the committed \
         pin ({pin_path}) says {pinned} — refusing to sign with an un-pinned key \
         (re-run `deploy generate-keys --secure-boot software` or fix the pin deliberately)"
    )]
    DbFingerprintMismatch {
        actual: String,
        pinned: String,
        pin_path: String,
    },
    #[error(
        "{file}: sidecar digest mismatch vs the sign manifest (expected {expected}, got {actual}) — the sidecars are not the PEs this build produced"
    )]
    ManifestDigestMismatch {
        file: String,
        expected: String,
        actual: String,
    },
    #[error(
        "ESP splice verification failed for {0}: the read-back bytes differ from the signed PE"
    )]
    SpliceUnfaithful(String),
    #[error("{tool}: {reason}")]
    Tool { tool: &'static str, reason: String },
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parse error in {path}: {msg}")]
    Parse { path: String, msg: String },
}

fn io_at(path: &Path) -> impl Fn(std::io::Error) -> SignSbError + '_ {
    move |source| SignSbError::Io {
        path: path.display().to_string(),
        source,
    }
}

pub struct SignSbOpts {
    /// The built `--firmware uefi` `.img` (its `.layout.toml` / `.loader.efi` / `.vmlinuz` /
    /// `.sign-manifest.toml` siblings are derived from it).
    pub img: PathBuf,
    /// The operator keys dir (db key/cert under `secure-boot/`).
    pub keys_dir: PathBuf,
    pub rung: SecureBootRung,
    /// The pinned build container (sbsign + mtools run in it; the db key bind-mounts RO).
    pub container_image: String,
    /// The committed PK/KEK/db fingerprint anchor (`crates/image-builder/pinned-secure-boot-db.toml`).
    pub db_fingerprint_path: PathBuf,
}

/// The full sign-sb ceremony (the doc-comment's six steps). On success the `.img` carries
/// db-signed boot PEs in its ESP and a fresh `.sha256`.
pub fn sign_sb(opts: &SignSbOpts) -> Result<(), SignSbError> {
    require_software_rung(&opts.rung)?;

    let sb_dir = opts.keys_dir.join("secure-boot");
                                                                                          
                                                                                    
    let db_crt = sb_dir.join("db.crt");
    check_db_fingerprint(&db_crt, &opts.db_fingerprint_path)?;

                                                                   
    let dir = opts.img.parent().unwrap_or(Path::new("."));
    let manifest_path = sibling(&opts.img, "sign-manifest.toml");
    let manifest: SignManifest =
        toml::from_str(&std::fs::read_to_string(&manifest_path).map_err(io_at(&manifest_path))?)
            .map_err(|e| SignSbError::Parse {
                path: manifest_path.display().to_string(),
                msg: e.to_string(),
            })?;
    let loader_path = dir.join(&manifest.loader.file);
    let vmlinuz_path = dir.join(&manifest.vmlinuz.file);
    for (path, entry) in [
        (&loader_path, &manifest.loader),
        (&vmlinuz_path, &manifest.vmlinuz),
    ] {
        let bytes = std::fs::read(path).map_err(io_at(path))?;
        let actual = format!("{:x}", Sha256::digest(&bytes));
        if actual != entry.sha256 {
            return Err(SignSbError::ManifestDigestMismatch {
                file: entry.file.clone(),
                expected: entry.sha256.clone(),
                actual,
            });
        }
    }

                                                                                          
    let layout_path = super::dryrun::layout_sidecar(&opts.img);
    let layout = super::dryrun::parse_layout(&layout_path).map_err(|e| SignSbError::Parse {
        path: layout_path.display().to_string(),
        msg: e.to_string(),
    })?;
    let esp_offset = layout.boot_offset;

                                                                                              
    let work = tempfile::tempdir().map_err(io_at(Path::new("sign-sb workdir")))?;
    std::fs::copy(&loader_path, work.path().join("loader.efi")).map_err(io_at(&loader_path))?;
    std::fs::copy(&vmlinuz_path, work.path().join("vmlinuz")).map_err(io_at(&vmlinuz_path))?;

                                                                                                           
                                                                                                          
                                                                                                       
    let script = format!(
        "set -e; \
         sbsign --key /sb/db.key --cert /sb/db.crt --output /work/loader.signed.efi /work/loader.efi && \
         sbsign --key /sb/db.key --cert /sb/db.crt --output /work/vmlinuz.signed /work/vmlinuz && \
         mcopy -o -i /img.img@@{esp_offset} /work/loader.signed.efi ::/EFI/BOOT/BOOTX64.EFI && \
         mcopy -o -i /img.img@@{esp_offset} /work/vmlinuz.signed ::/vmlinuz && \
         mcopy -i /img.img@@{esp_offset} ::/EFI/BOOT/BOOTX64.EFI /work/readback-loader && \
         mcopy -i /img.img@@{esp_offset} ::/vmlinuz /work/readback-vmlinuz && \
         chmod a+r /work/loader.signed.efi /work/vmlinuz.signed /work/readback-loader /work/readback-vmlinuz"
    );
    let out = Command::new("docker")
        .args(["run", "--rm"])
        .args(["-v", &format!("{}:/sb:ro", sb_dir.display())])
        .args(["-v", &format!("{}:/work", work.path().display())])
        .args(["-v", &format!("{}:/img.img", opts.img.display())])
        .arg(&opts.container_image)
        .args(["sh", "-c", &script])
        .output()
        .map_err(|e| SignSbError::Tool {
            tool: "docker run (sign-sb)",
            reason: format!("spawn: {e}"),
        })?;
    if !out.status.success() {
        return Err(SignSbError::Tool {
            tool: "sbsign/mcopy (sign-sb)",
            reason: format!(
                "exit {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        });
    }

                                                                                       
    for (signed, readback, label) in [
        ("loader.signed.efi", "readback-loader", "BOOTX64.EFI"),
        ("vmlinuz.signed", "readback-vmlinuz", "vmlinuz"),
    ] {
        let s = std::fs::read(work.path().join(signed)).map_err(io_at(work.path()))?;
        let r = std::fs::read(work.path().join(readback)).map_err(io_at(work.path()))?;
        if s != r {
            return Err(SignSbError::SpliceUnfaithful(label.to_string()));
        }
    }

                                                                                       
    for (workname, suffix) in [
        ("loader.signed.efi", "loader.signed.efi"),
        ("vmlinuz.signed", "vmlinuz.signed"),
    ] {
        let dest = sibling(&opts.img, suffix);
        std::fs::copy(work.path().join(workname), &dest).map_err(io_at(&dest))?;
    }

                                                                                      
    let img_bytes = std::fs::read(&opts.img).map_err(io_at(&opts.img))?;
    let base = opts
        .img
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("image");
    let sha_path = opts.img.with_extension("sha256");
    std::fs::write(
        &sha_path,
        format!("{:x}  {base}.img\n", Sha256::digest(&img_bytes)),
    )
    .map_err(io_at(&sha_path))?;

    Ok(())
}

/// SB-rung gate: only the `software` custody rung signs on the host; the hardware rungs route the db
/// key to the air-gapped PIPELINE signer round-trip (C4 forward-debt). Shared by `sign-sb` +
/// `sign-installer-usb` so the rung policy is single-source (fail-closed on every non-software rung).
pub(crate) fn require_software_rung(rung: &SecureBootRung) -> Result<(), SignSbError> {
    match rung {
        SecureBootRung::Software => Ok(()),
        SecureBootRung::OneSigner => Err(SignSbError::HardwareRungNotYetAvailable("one-signer")),
        SecureBootRung::TwoSigners => Err(SignSbError::HardwareRungNotYetAvailable("two-signers")),
    }
}

/// `<base>.img` → `<base>.<suffix>` (sibling sidecar path).
pub fn sibling(img: &Path, suffix: &str) -> PathBuf {
    img.with_extension(suffix)
}

/// Fail closed unless sha256(db.crt DER) equals the committed pin (the enrollment anchor).
pub(crate) fn check_db_fingerprint(db_crt: &Path, pin_path: &Path) -> Result<(), SignSbError> {
    let pem_bytes = std::fs::read(db_crt).map_err(io_at(db_crt))?;
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(&pem_bytes).map_err(|e| SignSbError::Parse {
            path: db_crt.display().to_string(),
            msg: e.to_string(),
        })?;
    let actual = format!("{:x}", Sha256::digest(&pem.contents));
    let pin_body = std::fs::read_to_string(pin_path).map_err(io_at(pin_path))?;
    let pinned = pin_body
        .lines()
        .find_map(|l| l.trim().strip_prefix("fingerprint = \"sha256:"))
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(|| SignSbError::Parse {
            path: pin_path.display().to_string(),
            msg: "no `fingerprint = \"sha256:<hex>\"` line".into(),
        })?;
    if actual != pinned {
        return Err(SignSbError::DbFingerprintMismatch {
            actual,
            pinned: pinned.to_string(),
            pin_path: pin_path.display().to_string(),
        });
    }
    Ok(())
}
