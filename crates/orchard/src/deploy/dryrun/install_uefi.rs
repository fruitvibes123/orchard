//! The UEFI SB-chain install gates (§9.1/9.2/9.3/9.6): install via the INSTALLER_DATA_PARTUUID model, + the ESP-tamper helpers.

use super::assertions::*;
use super::installer_usb::make_blank_target;
use super::qemu::*;
use super::*;

                                                                                              
/// `.img` onto a GPT disk via the REAL on-box installer, then OVMF-boot the INSTALLED disk + assert the
/// services acceptance set. Deltas from the SeaBIOS path:
///   - **No boot-fs `fb.rootfs-dev` byte-patch.** The UEFI rootfs-dev is the build-FIXED slot-A
///     `PARTUUID` baked into the rambutan loader's cmdline const (SB-loader plan L4); `build_gpt`
///     writes that same PARTUUID onto the slot-A GPT entry, so the kernel resolves it at boot
///     (the install is patch-free).
///   - the installer runs with `fb.firmware=uefi` → `commit()`'s GPT partition-table arm (`build_gpt`).
///   - the installed disk boots through **OVMF** ([`boot_installed_uefi_disk`], no `-kernel`), not SeaBIOS.
///
/// The local `vmlinuz`/`initramfs` sidecars are the ONE plain shared kernel pair (the loader design
/// has no `CONFIG_CMDLINE_OVERRIDE`), so the installer-mode `-append` is honored. `ovmf_code`/
/// `ovmf_vars` are the OVMF VARS blob. SB-OFF: the stock `OVMF_VARS` + the plain `OVMF_CODE`. SB-ON
/// (§9.2): pass the `.secboot` `OVMF_CODE` + an ENROLLED VARS built by [`build_enrolled_sb_vars`] from
/// our test PK/KEK/db — the firmware then verifies the loader + (via the loader's `LoadImage`) the
/// kernel against our db. The installer phase is `-kernel`-based and ignores both blobs; only the
/// final [`boot_installed_uefi_disk`] consumes them — so ONE harness serves both rungs.
pub fn install_uefi_disk_and_verify(
    img: &Path,
    operator_privkey: &Path,
    opts: &DryrunOpts,
    ovmf_code: &Path,
    ovmf_vars: &Path,
) -> Result<(), DryrunError> {
    let workdir = tempfile::Builder::new()
        .prefix("recipes-uefi-gate-")
        .tempdir()
        .map_err(DryrunError::io("creating uefi-gate workdir"))?;
    let (disk, log_dir) = install_uefi_disk_onto(img, opts, ovmf_code, ovmf_vars, workdir.path())?;

                                                                                             
                                                                       
    let console = log_dir.join("uefi-boot-console.log");
    let mut guard = boot_installed_uefi_disk(
        &disk,
        opts,
        &console,
        true,
        ovmf_code,
        ovmf_vars,
        StorageKind::Virtio,
    )?;
                                                                                                      
                                                                                                 
                                   
    wait_for_ssh(
        operator_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        &console,
    )?;
    assert_recipes_http(opts, &mut guard)?;                  
    assert_rootfs_ro(operator_privkey, opts.ssh_port)?;                                                 
    sync_persist_over_ssh(operator_privkey, opts.ssh_port)?;
    Ok(())
}

/// Install a `--firmware uefi` `.img` onto a fresh GPT disk via the REAL dd-only installer (shared by
/// [`install_uefi_disk_and_verify`] and [`install_uefi_disk_expect_rejected`]). Returns
/// `(installed_disk, log_dir)`. The boot phase is the CALLER's (positive: assert services; negative:
/// assert no-services + a rejection signal). `wd` is the caller-owned workdir (it must outlive the
/// boot). The installer phase is `-kernel`-based — it ignores `ovmf_code`/`ovmf_vars`, which are
/// validated here only so a missing-blob failure is reported before the install runs.
fn install_uefi_disk_onto(
    img: &Path,
    opts: &DryrunOpts,
    ovmf_code: &Path,
    ovmf_vars: &Path,
    wd: &Path,
) -> Result<(PathBuf, PathBuf), DryrunError> {
    preflight()?;
    for (label, p) in [
        ("RECIPES_OVMF_CODE/_SECBOOT", ovmf_code),
        ("RECIPES_OVMF_VARS (or the enrolled VARS)", ovmf_vars),
    ] {
        if !p.is_file() {
            return Err(DryrunError::HostToolMissing(format!(
                "OVMF blob not found at {} (set {label})",
                p.display()
            )));
        }
    }
    let layout = parse_layout(&layout_sidecar(img))?;
    let vmlinuz = local_artifact(img, "vmlinuz")?;                                                  
    let initramfs = local_artifact(img, "initramfs")?;

    let log_dir = std::env::var_os("RECIPES_PROD_GATE_LOGDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| wd.to_path_buf());
    if log_dir != wd {
        std::fs::create_dir_all(&log_dir).map_err(DryrunError::io("creating gate log dir"))?;
    }

                                                                                                       
                                                                                                        
    let rootfs_data = wd.join("rootfs-data");
    slice(
        img,
        layout.rootfs_offset,
        layout.rootfs_verity_hash_offset,
        &rootfs_data,
    )?;
    let root_hash = recompute_verity_root_hash(&rootfs_data, &wd.join("verity.hash"))?;

                                                                                                   
                                                                                                     
                                                                                                         
    let image = std::fs::read(img).map_err(DryrunError::io(format!("read {}", img.display())))?;

                                                                                                    
                                                                                                        
                                                                                                               
                                                                                              
                                                                                                        
                                                                                                                  
                                                                                                              
                                                                                                        
                                                                                                              
                                                                                                              
                                 
    let source = wd.join("installer-source.img");
    stage_installer_data_disk(&image, &layout_sidecar(img), wd, &source)?;
    let target = make_blank_target(wd, UEFI_GATE_TARGET_BYTES)?;
    let image_sha256 = recipes_image_builder::boot_fs::installer_image_sha256_hex(&image);

                                                                                                          
    run_uefi_installer_phase(
        &vmlinuz,
        &initramfs,
        &source,
        &target,
        &image_sha256,
        &root_hash,
        layout.rootfs_verity_hash_offset,
        opts,
        &log_dir.join("uefi-install-console.log"),
    )?;
    Ok((target, log_dir))
}

/// A generous SPARSE install target for the §9.5 UEFI SB-chain gates — the same 6 GiB blank the §9.5a
/// installer-USB gate uses: the installer commits box.img's boot/slot-A/slot-B GPT layout + grows persist
/// to fill it. Sparse ⇒ ~zero real cost; the runtime box.img is a few hundred MiB, well under this.
const UEFI_GATE_TARGET_BYTES: u64 = 6 * 1024 * 1024 * 1024;

/// Run the §9.5 UEFI installer over `-kernel` for the SB-chain gates (§9.1/9.2/9.3/9.6). The combined
/// installer's UEFI arm resolves the built-in `INSTALLER_DATA_PARTUUID` on `source` (no install-source token),
/// verifies box.img against `image_sha256_hex` (which MUST be the whole-file digest of the box.img staged
/// into `source` — see [`install_uefi_disk_onto`]) before any write, then dd's onto `target` (the single
/// eligible disk `≠ disk_of(source)`). Feeds the production installer cmdline ([`render_installer_cmdline`],
/// which already carries both consoles) and rides the shared [`run_installer_qemu`] core.
#[allow(clippy::too_many_arguments)]
pub(super) fn run_uefi_installer_phase(
    vmlinuz: &Path,
    initramfs: &Path,
    source: &Path,
    target: &Path,
    image_sha256_hex: &str,
    root_hash: &str,
    verity_offset: u64,
    opts: &DryrunOpts,
    console: &Path,
) -> Result<(), DryrunError> {
                                                                                                             
                                                                                                                    
                                                                                                               
    let append = recipes_image_builder::boot_fs::render_installer_cmdline(
        image_sha256_hex,
        root_hash,
        verity_offset,
        None,
    );
                                                                                                              
                                                                                                            
    run_installer_qemu(
        vmlinuz,
        initramfs,
        &[source, target],
        &append,
        opts,
        console,
    )
}

/// Stage the §9.5 install SOURCE disk for the UEFI SB-chain gates: a GPT carrying the ext4
/// `INSTALLER_DATA_PARTUUID` data partition (`/box.img` = `image`, `/box.layout.toml` = `sidecar`), so the
/// combined installer's `BuiltinDataPartuuid` arm resolves + reads it. Mirrors the production
/// `bake_installer_data` + `assemble_usb_image`, but HOST-SIDE (`mke2fs -d`, like [`stage_install_disk`]) so
/// the gates stay self-contained (input = the runtime `.img` only, no externally-built installer USB).
fn stage_installer_data_disk(
    image: &[u8],
    sidecar: &Path,
    wd: &Path,
    disk: &Path,
) -> Result<(), DryrunError> {
    let data = bake_installer_data_host(image, sidecar, wd)?;
    let source = assemble_installer_source_disk(&data)?;
    std::fs::write(disk, &source).map_err(DryrunError::io(format!(
        "write installer source disk {}",
        disk.display()
    )))?;
    Ok(())
}

/// Host-bake the ext4 `INSTALLER_DATA_PARTUUID` data partition: `/box.img` + `/box.layout.toml` at the fs
/// root — the exact names `initramfs_init::installer::{INSTALLER_DATA_IMG_PATH, layout_sidecar_path}` read.
/// `mke2fs -d` mount-free + privilege-free (the installer reads these as root — no ownership constraint),
/// sized like [`stage_install_disk`] (box.img + 64 MiB headroom, whole-MiB ⇒ a 512-multiple for
/// [`assemble_installer_source_disk`]). Returns the raw partition bytes.
fn bake_installer_data_host(
    image: &[u8],
    sidecar: &Path,
    wd: &Path,
) -> Result<Vec<u8>, DryrunError> {
    let stage_err = DryrunError::InstallDiskStage;
    let tree = wd.join("installer-data-tree");
    std::fs::create_dir_all(&tree).map_err(DryrunError::io("create installer-data tree"))?;
    std::fs::write(tree.join("box.img"), image).map_err(DryrunError::io("write staged box.img"))?;
    std::fs::copy(sidecar, tree.join("box.layout.toml"))
        .map_err(DryrunError::io("copy staged box.layout.toml"))?;

    let fs_bytes = round_up_mib(image.len() as u64 + 64 * 1024 * 1024);
    let fs_img = wd.join("installer-data.img");
    File::create(&fs_img)
        .and_then(|f| f.set_len(fs_bytes).map(|_| f))
        .map_err(DryrunError::io("create+size installer-data.img"))?;
    let status = Command::new("mke2fs")
        .args(["-t", "ext4", "-b", "4096", "-F", "-q", "-d"])
        .arg(&tree)
        .arg(&fs_img)
        .status()
        .map_err(|e| stage_err(format!("spawn mke2fs (installer data): {e}")))?;
    if !status.success() {
        return Err(stage_err(format!(
            "mke2fs (installer data) exited {status}"
        )));
    }
    std::fs::read(&fs_img).map_err(DryrunError::io("read baked installer-data.img"))
}

/// Wrap the baked ext4 data partition behind a blank placeholder ESP in a GPT — `assemble_usb_image` stamps
/// the data entry with `INSTALLER_DATA_PARTUUID` (the GUID the init resolves) + the protective MBR/primary/
/// backup GPT. The p1 ESP is DEAD WEIGHT here: the `-kernel` install boots no firmware off the source, so a
/// blank 1 MiB sector-aligned placeholder satisfies `assemble_usb_image`'s sector-multiple precondition. The
/// GPT layout itself is golden-tested in `recipes_image_builder::installer_usb`.
fn assemble_installer_source_disk(data: &[u8]) -> Result<Vec<u8>, DryrunError> {
    let esp = vec![0u8; 1024 * 1024];
    let usb =
        recipes_image_builder::installer_usb::assemble_usb_image(&esp, data).map_err(|e| {
            DryrunError::InstallDiskStage(format!("assemble installer source GPT: {e}"))
        })?;
    Ok(usb.img)
}

/// The §9.3 negative harness: install the `.img`, OVMF-boot it, and assert it does NOT reach services.
                                                                                                        
/// for unsigned-loader / tampered-initrd / SB_REQUIRED-on-SB-OFF.
pub fn install_uefi_disk_expect_rejected(
    img: &Path,
    operator_privkey: &Path,
    opts: &DryrunOpts,
    ovmf_code: &Path,
    ovmf_vars: &Path,
) -> Result<String, DryrunError> {
    let workdir = tempfile::Builder::new()
        .prefix("recipes-uefi-neg-")
        .tempdir()
        .map_err(DryrunError::io("creating uefi-neg workdir"))?;
    let (disk, log_dir) = install_uefi_disk_onto(img, opts, ovmf_code, ovmf_vars, workdir.path())?;
    let console = log_dir.join("uefi-neg-boot-console.log");
    boot_installed_uefi_disk_expect_no_services(
        &disk,
        operator_privkey,
        opts,
        &console,
        ovmf_code,
        ovmf_vars,
    )
}

/// Flip one byte of the ESP's `\initrd` in a built `.img` (the §9.3d tamper). The initrd is NOT
/// PE-signed — only the rambutan loader's baked SHA-256 covers it — so this exercises the loader's
/// OWN integrity gate (it must halt, never StartImage). Reads the ESP offset from the `.layout.toml`,
/// `mcopy`s the initrd out of the FAT, flips a byte, `mcopy`s it back. Fail-closed on any tool error.
pub fn tamper_esp_initrd(img: &Path) -> Result<(), DryrunError> {
    let layout = parse_layout(&layout_sidecar(img))?;
    let esp_offset = layout.boot_offset;
    let work = tempfile::tempdir().map_err(DryrunError::io("tamper workdir"))?;
    let extracted = work.path().join("initrd");
    let run = |args: &[&str]| -> Result<(), DryrunError> {
        let status = Command::new("mcopy")
            .args(args)
            .status()
            .map_err(|e| DryrunError::QemuLaunch(format!("spawn mcopy: {e}")))?;
        if !status.success() {
            return Err(DryrunError::QemuLaunch(format!("mcopy {args:?} failed")));
        }
        Ok(())
    };
    let img_at = format!("{}@@{esp_offset}", img.display());
    let extracted_str = extracted
        .to_str()
        .expect("tempdir path is valid UTF-8 (tempfile uses ASCII names)");
    run(&["-n", "-i", &img_at, "::/initrd", extracted_str])?;
    let mut bytes = std::fs::read(&extracted).map_err(DryrunError::io("read extracted initrd"))?;
                                                                                                      
                                                                                
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&extracted, &bytes).map_err(DryrunError::io("write tampered initrd"))?;
    run(&["-o", "-i", &img_at, extracted_str, "::/initrd"])?;
    Ok(())
}

/// §9.3a: strip the Authenticode signature from the ESP's db-signed loader so it is GENUINELY UNSIGNED —
/// enforcing OVMF must then REFUSE it (an unsigned image has no db match → `EFI_SECURITY_VIOLATION`). The
/// base `.img` is production-signed (the operator `sign-sb`s the loader; §9.2 accept + §9.3b–f + the
/// installer-USB gates need it signed), so §9.3a creates the unsigned scenario LOCALLY on ITS copy — it does
/// NOT swap in the SB-off build (whose loader is the non-SB build, which wouldn't test THIS SB loader's
/// rejection). Mirrors [`tamper_esp_initrd`]'s mcopy-out / mutate / mcopy-back over the ESP FAT; the loader
/// lives at the firmware's auto-enumerated `\EFI\BOOT\BOOTX64.EFI` (the same default
/// [`relocate_esp_loader_off_default`] extracts). Fail-closed on any tool/parse error. Closes the latent
/// §9.3a gap the first combined produced-bytes run surfaced — the gate previously copied a SIGNED loader
/// verbatim, so SB-ON correctly accepted it + the "rejects an unsigned loader" property went UNTESTED.
pub fn unsign_esp_loader(img: &Path) -> Result<(), DryrunError> {
    let layout = parse_layout(&layout_sidecar(img))?;
    let esp_offset = layout.boot_offset;
    let work = tempfile::tempdir().map_err(DryrunError::io("unsign-loader workdir"))?;
    let extracted = work.path().join("loader.efi");
    let run = |args: &[&str]| -> Result<(), DryrunError> {
        let status = Command::new("mcopy")
            .args(args)
            .status()
            .map_err(|e| DryrunError::QemuLaunch(format!("spawn mcopy: {e}")))?;
        if !status.success() {
            return Err(DryrunError::QemuLaunch(format!("mcopy {args:?} failed")));
        }
        Ok(())
    };
    let img_at = format!("{}@@{esp_offset}", img.display());
    let extracted_str = extracted
        .to_str()
        .expect("tempdir path is valid UTF-8 (tempfile uses ASCII names)");
    run(&[
        "-n",
        "-i",
        &img_at,
        "::/EFI/BOOT/BOOTX64.EFI",
        extracted_str,
    ])?;
    let signed = std::fs::read(&extracted).map_err(DryrunError::io("read extracted loader PE"))?;
    let unsigned = strip_authenticode(&signed)?;
    std::fs::write(&extracted, &unsigned).map_err(DryrunError::io("write unsigned loader PE"))?;
    run(&[
        "-o",
        "-i",
        &img_at,
        extracted_str,
        "::/EFI/BOOT/BOOTX64.EFI",
    ])?;
    Ok(())
}

/// Remove a PE/COFF Authenticode signature: zero the Certificate-Table data-directory entry (data dir #4 at
/// `OptionalHeader+144`: a 4-byte file-offset + 4-byte size) and truncate the appended cert blob (it sits at
/// EOF). The PE-offset walk mirrors the signed-PE repro gate's `authenticode_covered_bytes` (DOS `e_lfanew`
/// → `PE\0\0` → COFF(20) → OptionalHeader; PE32+ magic `0x20b`). Fail-closed on a malformed PE OR an
/// ALREADY-UNSIGNED input (`cert_size==0`) — the latter would mean the base `.img`'s loader was never signed,
/// so the §9.3a setup tests nothing and must abort LOUD.
fn strip_authenticode(pe: &[u8]) -> Result<Vec<u8>, DryrunError> {
    let bad = |m: &str| DryrunError::InstallDiskStage(format!("unsign loader PE: {m}"));
    let u32le = |off: usize| -> Result<usize, DryrunError> {
        pe.get(off..off + 4)
            .map(|b| {
                u32::from_le_bytes(b.try_into().expect("get(off..off+4) is exactly 4 bytes"))
                    as usize
            })
            .ok_or_else(|| bad("truncated before a u32 field"))
    };
    let pe_off = u32le(0x3c)?;
    if pe.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return Err(bad("no PE signature at e_lfanew"));
    }
    let opt = pe_off + 24;                                                    
    let magic = pe
        .get(opt..opt + 2)
        .ok_or_else(|| bad("truncated OptionalHeader"))?;
    if u16::from_le_bytes(
        magic
            .try_into()
            .expect("get(opt..opt+2) is exactly 2 bytes"),
    ) != 0x20b
    {
        return Err(bad("not PE32+ (x86_64-unknown-uefi)"));
    }
    let security_dir = opt + 144;                                   
    let cert_off = u32le(security_dir)?;
    let cert_size = u32le(security_dir + 4)?;
    if cert_size == 0 {
        return Err(bad(
            "loader carries no cert table — the base .img loader must be signed for §9.3a to test rejection",
        ));
    }
    let mut out = pe
        .get(..cert_off)
        .ok_or_else(|| bad("cert-table file offset runs past EOF"))?
        .to_vec();                                                     
    out[security_dir..security_dir + 8].fill(0);                                        
    Ok(out)
}

/// Overwrite the ESP's `\vmlinuz` with the UNSIGNED build sidecar (the §9.3b kernel swap). The loader is
/// db-signed (the firmware runs it), but its `LoadImage(\vmlinuz)` makes the platform re-verify the
/// SWAPPED kernel against db — and an unsigned PE has no signature for db to match, so the firmware
/// returns `EFI_SECURITY_VIOLATION` and the loader halts (`rambutan: LoadImage(vmlinuz) refused`). This
                                                                                                   
/// re-verifies even a memory load"): the loader never `StartImage`s a platform-rejected kernel. Splices
/// the unsigned `.vmlinuz` sidecar into the `.img`'s ESP via host `mcopy`; fail-closed on any tool error.
pub fn replace_esp_vmlinuz_unsigned(img: &Path) -> Result<(), DryrunError> {
    let unsigned = local_artifact(img, "vmlinuz")?;                                          
    mcopy_into_esp(img, &unsigned, "::/vmlinuz")
}

/// Sign the kernel with a FRESH throwaway key that is NOT enrolled in db, then splice it over the ESP's
/// `\vmlinuz` (the §9.3c swap). Distinct from §9.3b: here the kernel IS validly Authenticode-signed, just
/// by a cert the firmware does not trust — so `LoadImage` must STILL refuse it (a signed-but-untrusted
/// image is `EFI_SECURITY_VIOLATION` under EDK2 `DxeImageVerificationLib`, not merely an unsigned one).
/// Proves db membership — not "is signed at all" — is the gate. openssl mints the wrong key + cert and
/// `sbsign` signs in the pinned container (sbsign is not a host tool — same container as `sign-sb`), then
/// `mcopy` splices into the ESP. Fail-closed on any tool error.
pub fn wrongkey_sign_vmlinuz_into_esp(
    img: &Path,
    container_image: &str,
) -> Result<(), DryrunError> {
    let layout = parse_layout(&layout_sidecar(img))?;
    let esp_offset = layout.boot_offset;
    let unsigned = local_artifact(img, "vmlinuz")?;                                                      
    let work = tempfile::tempdir().map_err(DryrunError::io("wrongkey workdir"))?;
    std::fs::copy(&unsigned, work.path().join("vmlinuz.unsigned"))
        .map_err(DryrunError::io("stage unsigned vmlinuz for wrong-key sign"))?;
                                                                                                     
                                                                                                    
                                                                                                      
                                                                                     
    let script = format!(
        "set -e; \
         openssl req -x509 -newkey rsa:2048 -keyout /work/wrong.key -out /work/wrong.crt -days 3650 \
           -nodes -subj '/CN=recipes-wrong-key-NOT-in-db' 2>/dev/null && \
         sbsign --key /work/wrong.key --cert /work/wrong.crt --output /work/vmlinuz.wrong \
           /work/vmlinuz.unsigned && \
         mcopy -o -i /img.img@@{esp_offset} /work/vmlinuz.wrong ::/vmlinuz"
    );
    let out = Command::new("docker")
        .args(["run", "--rm"])
        .args(["-v", &format!("{}:/work", work.path().display())])
        .args(["-v", &format!("{}:/img.img", img.display())])
        .arg(container_image)
        .args(["sh", "-c", &script])
        .output()
        .map_err(|e| DryrunError::QemuLaunch(format!("spawn docker (wrong-key sign): {e}")))?;
    if !out.status.success() {
        return Err(DryrunError::QemuLaunch(format!(
            "wrong-key sbsign/mcopy failed (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// `mcopy` a local file into the ESP of a built `.img` at `esp_dest` (e.g. `::/vmlinuz`), reading the ESP
/// offset from the `.layout.toml`. Host-side (mtools), `-o` overwrite. Shared by the §9.3b/c kernel
/// swaps; fail-closed on any tool error.
fn mcopy_into_esp(img: &Path, src: &Path, esp_dest: &str) -> Result<(), DryrunError> {
    let layout = parse_layout(&layout_sidecar(img))?;
    let img_at = format!("{}@@{}", img.display(), layout.boot_offset);
    let src_str = src
        .to_str()
        .ok_or_else(|| DryrunError::QemuLaunch(format!("non-UTF-8 path {}", src.display())))?;
    let status = Command::new("mcopy")
        .args(["-o", "-i", &img_at, src_str, esp_dest])
        .status()
        .map_err(|e| DryrunError::QemuLaunch(format!("spawn mcopy: {e}")))?;
    if !status.success() {
        return Err(DryrunError::QemuLaunch(format!(
            "mcopy {} -> {esp_dest} (ESP @ {}) failed",
            src.display(),
            layout.boot_offset
        )));
    }
    Ok(())
}

/// The §9.3e relocated-loader path, in the two spellings the tooling needs: the mtools `::/`-form for
/// `mcopy`/`mdel` and the UEFI `\`-form baked into the injected `Boot0001` device path. They MUST name
/// the same file — [`relocate_esp_loader_off_default`] writes the mtools form, the var fixture reads the
/// UEFI form.
const RELOCATED_LOADER_MTOOLS: &str = "::/EFI/rambutan/loader.efi";
const RELOCATED_LOADER_UEFI: &str = "\\EFI\\rambutan\\loader.efi";

/// Move the signed loader OFF the default removable path (the §9.3e anti-vacuity step). Copies the ESP's
/// `\EFI\BOOT\BOOTX64.EFI` to [`RELOCATED_LOADER_MTOOLS`], then DELETES the default path. After this the
/// firmware's auto-enumerated `\EFI\BOOT\BOOTX64.EFI` route is GONE, so the only way to reach the loader
/// (and thus services) is the injected `Boot0001` — a relocate/inject failure can't be masked by a silent
/// default-path boot with empty LoadOptions. Host mtools; fail-closed on any tool error.
pub fn relocate_esp_loader_off_default(img: &Path) -> Result<(), DryrunError> {
    let layout = parse_layout(&layout_sidecar(img))?;
    let img_at = format!("{}@@{}", img.display(), layout.boot_offset);
    let work = tempfile::tempdir().map_err(DryrunError::io("relocate-loader workdir"))?;
    let staged = work.path().join("loader.efi");
    let staged_str = staged
        .to_str()
        .expect("tempdir path is valid UTF-8 (tempfile uses ASCII names)");
    let mtool = |tool: &str, args: &[&str]| -> Result<(), DryrunError> {
        let status = Command::new(tool)
            .args(args)
            .status()
            .map_err(|e| DryrunError::QemuLaunch(format!("spawn {tool}: {e}")))?;
        if !status.success() {
            return Err(DryrunError::QemuLaunch(format!("{tool} {args:?} failed")));
        }
        Ok(())
    };
                                                                                                            
    mtool(
        "mcopy",
        &["-n", "-i", &img_at, "::/EFI/BOOT/BOOTX64.EFI", staged_str],
    )?;
    mtool("mmd", &["-i", &img_at, "::/EFI/rambutan"])?;
    mtool(
        "mcopy",
        &["-o", "-i", &img_at, staged_str, RELOCATED_LOADER_MTOOLS],
    )?;
    mtool("mdel", &["-i", &img_at, "::/EFI/BOOT/BOOTX64.EFI"])?;
    Ok(())
}

/// Author a `Boot0001` load option carrying attacker OptionalData on top of an enrolled VARS (the §9.3e
/// injection). `Boot0001` points at the relocated loader ([`RELOCATED_LOADER_UEFI`]) and stuffs
/// OptionalData with `injected_cmdline` (UCS-2); `BootOrder=[0001]`. Shells the committed
/// `uefi-inject-boot-option.py` fixture — the narrowest tool for the one thing `virt-fw-vars` can't do
/// (set a `Boot####` OptionalData), driven by the same `virt.firmware` lib the enrolled-VARS fixture
/// already needs. Fail-closed on any tool error.
pub fn build_injected_boot_vars(
    enrolled_vars: &Path,
    out_vars: &Path,
    injected_cmdline: &str,
) -> Result<(), DryrunError> {
    const SCRIPT: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
                                                                                    
        "/../image-builder/uefi-inject-boot-option.py"
    );
    let out = Command::new("python3")
        .arg(SCRIPT)
        .arg(enrolled_vars)
        .arg(out_vars)
        .arg(RELOCATED_LOADER_UEFI)
        .arg(injected_cmdline)
        .output()
        .map_err(|e| DryrunError::QemuLaunch(format!("spawn python3 (inject-boot-option): {e}")))?;
    if !out.status.success() {
        return Err(DryrunError::QemuLaunch(format!(
            "uefi-inject-boot-option.py failed (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// §9.3e — install the `.img`, boot under enforcing OVMF + the INJECTED VARS, and on reaching services
/// return the booted `/proc/cmdline`. Services-up is the anti-vacuity proof: the default loader path was
/// deleted ([`relocate_esp_loader_off_default`]), so the only route to a running box is the injected
/// `Boot0001` — i.e. the loader DID run with attacker LoadOptions, and the caller asserts the kernel
                                                                                                  
pub fn install_uefi_disk_capture_cmdline(
    img: &Path,
    operator_privkey: &Path,
    opts: &DryrunOpts,
    ovmf_code: &Path,
    ovmf_vars: &Path,
) -> Result<String, DryrunError> {
    let workdir = tempfile::Builder::new()
        .prefix("recipes-uefi-inject-")
        .tempdir()
        .map_err(DryrunError::io("creating uefi-inject workdir"))?;
    let (disk, log_dir) = install_uefi_disk_onto(img, opts, ovmf_code, ovmf_vars, workdir.path())?;
    let console = log_dir.join("uefi-inject-boot-console.log");
    let mut guard = boot_installed_uefi_disk(
        &disk,
        opts,
        &console,
        true,
        ovmf_code,
        ovmf_vars,
        StorageKind::Virtio,
    )?;
                                                                                                                   
    wait_for_ssh(
        operator_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        &console,
    )?;
    let output = Command::new("ssh")
        .args(ssh_base_args(operator_privkey, opts.ssh_port))
        .arg("cat /proc/cmdline")
        .output()
        .map_err(|e| DryrunError::BootFailed(format!("ssh cat /proc/cmdline: {e}")))?;
    if !output.status.success() {
        return Err(DryrunError::BootFailed(format!(
            "ssh cat /proc/cmdline exited {}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// §9.6 — install + boot under OVMF, and on reaching SERVICES return the dropbear host key's `SHA256:…`
/// fingerprint. The caller compares it to the OFFLINE `derive-rescue-host-keys --image` precompute: a
/// match proves the cmdline-delivered `fb.root-hash` fed box-init's host-key derivation (the
/// `services-keys-stage` oneshot HKDFs `seed + verity-root-hash` → the SAME identity the operator can
/// precompute), i.e. the box's IDENTITY is cryptographically bound to the exact rootfs the cmdline named
/// — the bug-#7 regression gate. Services-up here = the operator pubkey already authenticated; this adds
/// the identity binding on top.
pub fn install_uefi_disk_capture_identity(
    img: &Path,
    operator_privkey: &Path,
    opts: &DryrunOpts,
    ovmf_code: &Path,
    ovmf_vars: &Path,
) -> Result<String, DryrunError> {
    let workdir = tempfile::Builder::new()
        .prefix("recipes-uefi-ident-")
        .tempdir()
        .map_err(DryrunError::io("creating uefi-ident workdir"))?;
    let (disk, log_dir) = install_uefi_disk_onto(img, opts, ovmf_code, ovmf_vars, workdir.path())?;
    let console = log_dir.join("uefi-ident-boot-console.log");
    let mut guard = boot_installed_uefi_disk(
        &disk,
        opts,
        &console,
        true,
        ovmf_code,
        ovmf_vars,
        StorageKind::Virtio,
    )?;
                                                                                               
    wait_for_ssh(
        operator_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        &console,
    )?;
                                                                                                      
                                                          
    rescue_host_key_fingerprint(opts.ssh_port).ok_or_else(|| {
        DryrunError::BootFailed(format!(
            "the UEFI box presented no ed25519 services host key; console tail:\n{}",
            console_tail(&console)
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installer_source_disk_advertises_the_data_partuuid() {
                                                                                                            
                                                                                                        
                                                                                                        
                                                                                                  
                                                                                                         
                                                                                                         
        let data = vec![0u8; 4096 * 64];                           
        let disk = assemble_installer_source_disk(&data).expect("assemble installer source disk");
        let needle = recipes_image_builder::gpt::guid_to_mixed_endian(
            recipes_image_builder::boot_fs::INSTALLER_DATA_PARTUUID,
        )
        .expect("INSTALLER_DATA_PARTUUID is a valid GUID");
        assert!(
            disk.windows(needle.len()).any(|w| w == needle.as_slice()),
            "the source disk GPT must stamp INSTALLER_DATA_PARTUUID so the installer resolves the data partition"
        );
    }

    #[test]
    fn strip_authenticode_removes_the_cert_table_and_fails_closed_on_unsigned() {
                                                                                                       
                                                                                                       
                                                                                                     
        let pe_off = 0x80usize;
        let opt = pe_off + 24;
        let security_dir = opt + 144;                                   
        let cert_off = 0x200usize;
        let cert_size = 16usize;
        let mut pe = vec![0u8; cert_off + cert_size];
        pe[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());            
        pe[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        pe[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());               
        pe[security_dir..security_dir + 4].copy_from_slice(&(cert_off as u32).to_le_bytes());
        pe[security_dir + 4..security_dir + 8].copy_from_slice(&(cert_size as u32).to_le_bytes());
        pe[cert_off..].fill(0xAB);                                  

        let out = strip_authenticode(&pe).expect("strip a valid signed PE");
        assert_eq!(
            out.len(),
            cert_off,
            "the appended cert blob is truncated away"
        );
        assert!(
            out[security_dir..security_dir + 8].iter().all(|&b| b == 0),
            "the Certificate-Table data-dir entry is zeroed (the PE is now unsigned)"
        );
                                                                                                 
        assert!(
            strip_authenticode(&out).is_err(),
            "an already-unsigned loader must abort §9.3a loud, not silently test nothing"
        );
    }
}
