//! `orchard build-installer-usb` (§9.5 Task 5.2) — assemble the signed-USB installer image from a
//! built + `sign-sb`-signed runtime `.img`.
//!
//! `deploy build --firmware uefi --secure-boot` + `deploy sign-sb` produce the signed runtime
//! `recipes-image-<label>.img` plus its sidecars (`.layout.toml`, the db-signed `.vmlinuz.signed`,
//! and the digest-gated `.initramfs`). This verb consumes that `--from` image and:
//!
//! 1. reads the signed `.img` (the p2 payload AND the `fb.image-sha256` digest source) + its three
//!    siblings;
//! 2. re-verifies the committed `vendor/` tree against `consume-pins.toml` BEFORE the 2nd rambutan
//!    loader compiles from `vendor/rambutan` — the same source-integrity gate `deploy build` applies;
                                                                              
//! 3. recomputes the box.img dm-verity root hash from the verified rootfs slice (the
//!    [`crate::oneshots_offline`] `offline_public_key` precedent) — the installer cmdline's
//!    DEAD-WEIGHT verity pair, baked for forward-safety, NEVER a placeholder/zero;
//! 4. calls [`recipes_image_builder::installer_usb::build_installer_usb`] (digest → installer cmdline
//!    → 2nd loader → ESP[p1] + ext4 data[p2] → GPT assembly);
//! 5. writes `recipes-installer-usb-<label>.{img,sha256}` beside the `--from` image.
//!
//! The whole USB `.img` is NOT byte-reproducible (the to-be-signed installer-loader PE carries a
//! per-sign `signingTime`), so there is no repro gate over it; the produced-bytes proof is the
//! Phase-6 2-stage SB-on OVMF gate. The installer loader is built `SB_REQUIRED` (the §9 SB-on rung)
//! and db-signed by `deploy sign-installer-usb` (Task 5.3). The container + `veritysetup`
                                                                                                   
//! label derivation + the artifact emission.

use std::path::{Path, PathBuf};

use recipes_image_builder::build_tools_host::HostBuildTools;
use recipes_image_builder::installer_usb::{
    InstallerUsbInputs, build_installer_usb as assemble_installer_usb,
};
use sha2::{Digest, Sha256};

/// Inputs for [`build_installer_usb`] (the `deploy build-installer-usb` CLI arm).
pub struct InstallerUsbCliOpts {
    /// The built + `sign-sb`-signed runtime `.img`; its `.layout.toml` / `.vmlinuz.signed` /
    /// `.initramfs` siblings are derived from it.
    pub from: PathBuf,
    /// Optional `fb.install-to` whole-disk override baked into the installer cmdline; `None` ⇒ the
    /// init auto-selects the single eligible internal disk (fail-closed on 0/>1).
    pub install_to: Option<String>,
    /// The pinned build container (the 2nd loader build + the ESP/ext4 bakes run inside it).
    pub container_image: String,
    /// The recipes repo root (`vendor/` + `consume-pins.toml` + the git HEAD epoch).
    pub repo_root: PathBuf,
}

/// The emitted installer-USB artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallerUsbCliOutputs {
    pub img: PathBuf,
    pub sha256: PathBuf,
}

/// Fail-closed errors. The `veritysetup`/layout + `vendor/` legs are flattened to strings so this
/// public type does not leak the `pub(crate)` `dryrun::DryrunError` into the crate's public surface.
#[derive(Debug, thiserror::Error)]
pub enum InstallerUsbCliError {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("layout/verity: {0}")]
    Layout(String),
    #[error("vendor/ integrity: {0}")]
    Vendor(String),
    #[error("installer-usb build: {0}")]
    Build(#[from] recipes_image_builder::build::BuildError),
    #[error("{0}")]
    Other(String),
}

fn io_at(path: &Path) -> impl Fn(std::io::Error) -> InstallerUsbCliError + '_ {
    move |source| InstallerUsbCliError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Assemble + emit the signed-USB installer image. The container + `veritysetup` orchestration is
/// gate-proven (Phase-6 OVMF gate, M-α); see the module doc-comment for the five steps.
pub fn build_installer_usb(
    opts: &InstallerUsbCliOpts,
) -> Result<InstallerUsbCliOutputs, InstallerUsbCliError> {
                                                                                              
                                                                                               
                                                                                                    
    let signed_img = std::fs::read(&opts.from).map_err(io_at(&opts.from))?;
    let layout_path = opts.from.with_extension("layout.toml");
    let box_layout_toml = std::fs::read(&layout_path).map_err(io_at(&layout_path))?;
    let vmlinuz_path = opts.from.with_extension("vmlinuz.signed");
                                                                                                     
                                                                                                         
                                                                                                      
                                                                                                        
    if !vmlinuz_path.exists() {
        return Err(InstallerUsbCliError::Other(format!(
            "--from must be a sign-sb'd runtime image: the db-signed sidecar {} is missing \
             (run `deploy build --firmware uefi --secure-boot`, then `deploy sign-sb`, first)",
            vmlinuz_path.display()
        )));
    }
    let vmlinuz = std::fs::read(&vmlinuz_path).map_err(io_at(&vmlinuz_path))?;
    let initramfs_path = opts.from.with_extension("initramfs");
    let initramfs = std::fs::read(&initramfs_path).map_err(io_at(&initramfs_path))?;

                                                                                                 
                                                                                                      
    let pins = recipes_image_builder::pin_manifest::PinManifest::load(
        &opts.repo_root.join("consume-pins.toml"),
    )
    .map_err(|e| InstallerUsbCliError::Vendor(format!("load consume-pins.toml: {e}")))?;
    let n_src =
        recipes_image_builder::vendor::verify_vendored_tree(&opts.repo_root.join("vendor"), &pins)
            .map_err(|e| InstallerUsbCliError::Vendor(e.to_string()))?;
    if n_src < 4 {
        return Err(InstallerUsbCliError::Vendor(format!(
            "only {n_src} source drop(s) verified, expected >= 4 (consume-pins truncated?)"
        )));
    }

                                                                                     
                                                                                             
    let layout = super::dryrun::parse_layout(&layout_path)
        .map_err(|e| InstallerUsbCliError::Layout(e.to_string()))?;
    let start = layout.rootfs_offset as usize;
    let data_end = start
        .checked_add(layout.rootfs_verity_hash_offset as usize)
        .ok_or_else(|| InstallerUsbCliError::Layout("verity offset overflows".into()))?;
    let part_end = start
        .checked_add(layout.rootfs_size as usize)
        .ok_or_else(|| InstallerUsbCliError::Layout("rootfs range overflows".into()))?;
    if part_end > signed_img.len() || data_end > part_end {
        return Err(InstallerUsbCliError::Layout(format!(
            "layout offsets exceed image size ({} bytes)",
            signed_img.len()
        )));
    }
    let tmp =
        tempfile::tempdir().map_err(io_at(Path::new("build-installer-usb verity tempdir")))?;
    let data_path = tmp.path().join("rootfs-data");
    let hash_path = tmp.path().join("hash-tree");
    std::fs::write(&data_path, &signed_img[start..data_end]).map_err(io_at(&data_path))?;
    let root_hash = super::dryrun::recompute_verity_root_hash(&data_path, &hash_path)
        .map_err(|e| InstallerUsbCliError::Layout(e.to_string()))?;

                                                                                                
                                                                           
    let source_date_epoch: u64 =
        super::build_image::git_output(&opts.repo_root, &["show", "-s", "--format=%ct", "HEAD"])
            .map_err(|e| InstallerUsbCliError::Other(format!("git HEAD epoch: {e}")))?
            .parse()
            .map_err(|e| InstallerUsbCliError::Other(format!("git commit epoch parse: {e}")))?;

                                                                                                    
    let tools = HostBuildTools::new(opts.container_image.clone(), opts.repo_root.clone());
    let inputs = InstallerUsbInputs {
        signed_img: &signed_img,
        box_layout_toml: &box_layout_toml,
        vmlinuz: &vmlinuz,
        initramfs: &initramfs,
        root_hash: &root_hash,
        verity_offset: layout.rootfs_verity_hash_offset,
        install_to: opts.install_to.as_deref(),
        sb_required: true,                                                
        source_date_epoch,
    };
    let usb = assemble_installer_usb(&tools, &inputs)?;

                                                                                     
    let out_dir = opts.from.parent().unwrap_or(Path::new("."));
    let label = derive_installer_label(&opts.from);
    write_installer_usb_outputs(out_dir, &label, &usb.img).map_err(io_at(out_dir))
}

/// `recipes-image-<label>.img` → `<label>` (the installer-USB artifact label, keeping any `-dirty`
/// taint); a non-`recipes-image-` filename falls back to the whole stem.
fn derive_installer_label(from: &Path) -> String {
    let stem = from
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("installer");
    stem.strip_prefix("recipes-image-")
        .unwrap_or(stem)
        .to_string()
}

/// Write `recipes-installer-usb-<label>.{img,sha256}` to `out_dir`. The `.sha256` is `sha256sum`
/// format (`<hex>  <name>\n`, the name matching the `.img`) — mirrors `image::write_image_outputs`.
fn write_installer_usb_outputs(
    out_dir: &Path,
    label: &str,
    img: &[u8],
) -> std::io::Result<InstallerUsbCliOutputs> {
    std::fs::create_dir_all(out_dir)?;
    let base = format!("recipes-installer-usb-{label}");
    let img_path = out_dir.join(format!("{base}.img"));
    let sha_path = out_dir.join(format!("{base}.sha256"));
    std::fs::write(&img_path, img)?;
    std::fs::write(
        &sha_path,
        format!("{:x}  {base}.img\n", Sha256::digest(img)),
    )?;
    Ok(InstallerUsbCliOutputs {
        img: img_path,
        sha256: sha_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_installer_label_strips_the_recipes_image_prefix() {
        assert_eq!(
            derive_installer_label(Path::new("/out/recipes-image-deadbeef1234.img")),
            "deadbeef1234"
        );
                                                      
        assert_eq!(
            derive_installer_label(Path::new("/out/recipes-image-abc123-dirty.img")),
            "abc123-dirty"
        );
                                                                
        assert_eq!(
            derive_installer_label(Path::new("/out/custom.img")),
            "custom"
        );
    }

    #[test]
    fn write_installer_usb_outputs_writes_img_and_sha256sum_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let img = b"the-assembled-usb-bytes";
        let out = write_installer_usb_outputs(tmp.path(), "deadbeef", img).unwrap();

        assert_eq!(
            out.img,
            tmp.path().join("recipes-installer-usb-deadbeef.img")
        );
        assert_eq!(
            out.sha256,
            tmp.path().join("recipes-installer-usb-deadbeef.sha256")
        );
                                                       
        assert_eq!(std::fs::read(&out.img).unwrap(), img);
                                                                                          
        let expected = format!(
            "{:x}  recipes-installer-usb-deadbeef.img\n",
            Sha256::digest(img)
        );
        assert_eq!(std::fs::read_to_string(&out.sha256).unwrap(), expected);
    }

    #[test]
    fn build_installer_usb_rejects_an_unsigned_from_with_a_clear_error() {
                                                                                                         
                                                                                                  
                                                                                                          
        let tmp = tempfile::tempdir().unwrap();
        let from = tmp.path().join("recipes-image-deadbeef.img");
        std::fs::write(&from, b"box-img-bytes").unwrap();
        std::fs::write(from.with_extension("layout.toml"), b"[layout]\n").unwrap();
                                                                
        let opts = InstallerUsbCliOpts {
            from,
            install_to: None,
            container_image: "unused".into(),
            repo_root: tmp.path().to_path_buf(),
        };
        let err = build_installer_usb(&opts).unwrap_err();
        assert!(
            matches!(&err, InstallerUsbCliError::Other(m) if m.contains("must be a sign-sb'd")),
            "expected a clear sign-sb'd-required error, got {err:?}"
        );
    }
}
