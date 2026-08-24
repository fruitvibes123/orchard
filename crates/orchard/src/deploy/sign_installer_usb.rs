//! `orchard sign-installer-usb` (§9.5 Task 5.3) — Authenticode-sign the installer loader inside a
                                                                                       
//!
//! `deploy build-installer-usb` (Task 5.2) emits `recipes-installer-usb-<label>.{img,sha256}` with an
//! UNSIGNED 2nd rambutan loader baked into the USB's ESP and the ALREADY-`sign-sb`-signed `vmlinuz`
//! alongside it (the runtime kernel is signed once, at `sign-sb` time — it is reused verbatim). This
//! verb — the SB-rung-only second hop (carrying `sign-sb`'s exact rung gate + db-pin check):
//!
//! 1. refuses any rung but `software` ([`super::sign_sb::require_software_rung`] — hardware rungs
//!    route the db key to the air-gapped PIPELINE signer, C4 forward-debt);
//! 2. refuses a `db.crt` whose DER sha256 differs from the committed `pinned-secure-boot-db.toml`
//!    anchor ([`super::sign_sb::check_db_fingerprint`] — sign-with-the-wrong-key fails closed BEFORE
//!    any signature exists);
//! 3. `sbsign`s ONLY the installer loader (the kernel is already db-signed) extracted from the USB
//!    ESP at the fixed [`recipes_image_builder::installer_usb::ESP_PARTITION_OFFSET`], splices the
//!    signed PE back into the ESP, then reads it back and byte-compares (splice faithfulness, fail
//!    closed) — all in one pinned-container run;
//! 4. leaves the signed loader beside the USB and recomputes the USB's OWN `<base>.sha256` over the
//!    spliced image. It does NOT touch the source runtime `.img`'s `.sha256` (that image was already
//!    `sign-sb`-signed and is only `dd`'d, never re-signed).
//!
//! The `sbsign`/`mcopy` container ops (step 3) are gate-proven by the Phase-6 2-stage SB-on OVMF
//! gate (M-α: not host-runnable). The host unit tests cover the two fail-closed refusals (rung +
//! db-pin) — both reached before any container op or USB read.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use super::secure_boot_keys::SecureBootRung;
use super::sign_sb::SignSbError;

pub struct SignInstallerUsbOpts {
    /// The `deploy build-installer-usb` output (`recipes-installer-usb-<label>.img`) whose p1 ESP
    /// carries the unsigned installer loader.
    pub usb_img: PathBuf,
    /// The operator key set dir (db key/cert under `secure-boot/`).
    pub keys_dir: PathBuf,
    pub rung: SecureBootRung,
    /// The pinned build container (`sbsign` + `mtools` run in it; the db key bind-mounts RO).
    pub container_image: String,
    /// The committed PK/KEK/db fingerprint anchor (`crates/image-builder/pinned-secure-boot-db.toml`).
    pub db_fingerprint_path: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum SignInstallerUsbError {
    /// The rung gate + the db-pin check are `sign-sb`'s (single-source); their errors flow through.
    #[error(transparent)]
    SignSb(#[from] SignSbError),
    #[error("ESP splice verification failed: the read-back loader differs from the signed PE")]
    SpliceUnfaithful,
    #[error("{tool}: {reason}")]
    Tool { tool: &'static str, reason: String },
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

fn io_at(path: &Path) -> impl Fn(std::io::Error) -> SignInstallerUsbError + '_ {
    move |source| SignInstallerUsbError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// The full sign-installer-usb ceremony (the doc-comment's four steps). On success the USB `.img`
/// carries a db-signed installer loader in its ESP and a fresh `<base>.sha256`.
pub fn sign_installer_usb(opts: &SignInstallerUsbOpts) -> Result<(), SignInstallerUsbError> {
                                                                                                     
                                                                                                  
    super::sign_sb::require_software_rung(&opts.rung)?;
    let sb_dir = opts.keys_dir.join("secure-boot");
    let db_crt = sb_dir.join("db.crt");
    super::sign_sb::check_db_fingerprint(&db_crt, &opts.db_fingerprint_path)?;

                                                                                                     
    let esp_offset = recipes_image_builder::installer_usb::ESP_PARTITION_OFFSET;

                                                                                                   
                                                                                                    
                                                                                                 
    let work = tempfile::tempdir().map_err(io_at(Path::new("sign-installer-usb workdir")))?;
    let script = format!(
        "set -e; \
         mcopy -i /usb.img@@{esp_offset} ::/EFI/BOOT/BOOTX64.EFI /work/loader.efi && \
         sbsign --key /sb/db.key --cert /sb/db.crt --output /work/loader.signed.efi /work/loader.efi && \
         mcopy -o -i /usb.img@@{esp_offset} /work/loader.signed.efi ::/EFI/BOOT/BOOTX64.EFI && \
         mcopy -i /usb.img@@{esp_offset} ::/EFI/BOOT/BOOTX64.EFI /work/readback && \
         chmod a+r /work/loader.signed.efi /work/readback"
    );
    let out = Command::new("docker")
        .args(["run", "--rm"])
        .args(["-v", &format!("{}:/sb:ro", sb_dir.display())])
        .args(["-v", &format!("{}:/work", work.path().display())])
        .args(["-v", &format!("{}:/usb.img", opts.usb_img.display())])
        .arg(&opts.container_image)
        .args(["sh", "-c", &script])
        .output()
        .map_err(|e| SignInstallerUsbError::Tool {
            tool: "docker run (sign-installer-usb)",
            reason: format!("spawn: {e}"),
        })?;
    if !out.status.success() {
        return Err(SignInstallerUsbError::Tool {
            tool: "sbsign/mcopy (sign-installer-usb)",
            reason: format!(
                "exit {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        });
    }

                                                                                          
    let signed =
        std::fs::read(work.path().join("loader.signed.efi")).map_err(io_at(work.path()))?;
    let readback = std::fs::read(work.path().join("readback")).map_err(io_at(work.path()))?;
    if signed != readback {
        return Err(SignInstallerUsbError::SpliceUnfaithful);
    }

                                                                                                   
                                                                                                    
    let signed_sidecar = opts.usb_img.with_extension("loader.signed.efi");
    std::fs::copy(work.path().join("loader.signed.efi"), &signed_sidecar)
        .map_err(io_at(&signed_sidecar))?;
    let usb_bytes = std::fs::read(&opts.usb_img).map_err(io_at(&opts.usb_img))?;
    let base = opts
        .usb_img
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("recipes-installer-usb");
    let sha_path = opts.usb_img.with_extension("sha256");
    std::fs::write(
        &sha_path,
        format!("{:x}  {base}.img\n", Sha256::digest(&usb_bytes)),
    )
    .map_err(io_at(&sha_path))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_fake_db_crt(sb_dir: &Path) {
        std::fs::create_dir_all(sb_dir).unwrap();
                                                                                                      
                                                                                                      
        std::fs::write(
            sb_dir.join("db.crt"),
            "-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQ=\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
    }

    #[test]
    fn sign_installer_usb_refuses_a_hardware_rung_before_anything_else() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = SignInstallerUsbOpts {
            usb_img: tmp.path().join("recipes-installer-usb-x.img"),
            keys_dir: tmp.path().join("keys"),
            rung: SecureBootRung::OneSigner,
            container_image: "unused-in-this-test".into(),
            db_fingerprint_path: tmp.path().join("pin.toml"),
        };
        let err = sign_installer_usb(&opts).unwrap_err();
        assert!(matches!(
            err,
            SignInstallerUsbError::SignSb(SignSbError::HardwareRungNotYetAvailable("one-signer"))
        ));
    }

    #[test]
    fn sign_installer_usb_refuses_a_db_cert_that_misses_the_pin() {
        let tmp = tempfile::tempdir().unwrap();
        let keys_dir = tmp.path().join("keys");
        write_fake_db_crt(&keys_dir.join("secure-boot"));
                                                                                                   
        let pin = tmp.path().join("pinned-secure-boot-db.toml");
        std::fs::write(
            &pin,
            "fingerprint = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n",
        )
        .unwrap();
        let opts = SignInstallerUsbOpts {
            usb_img: tmp.path().join("recipes-installer-usb-x.img"),                                  
            keys_dir,
            rung: SecureBootRung::Software,
            container_image: "unused-in-this-test".into(),
            db_fingerprint_path: pin,
        };
        let err = sign_installer_usb(&opts).unwrap_err();
        assert!(matches!(
            err,
            SignInstallerUsbError::SignSb(SignSbError::DbFingerprintMismatch { .. })
        ));
    }
}
