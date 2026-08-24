//! The bare-metal USB-reproduction harness (sgdisk-style GPT + component dd, USB-booted through OVMF).

use super::assertions::*;
use super::qemu::*;
use super::*;

                                                                                              
                                                                                                     
                                                                                                       
                                                                                                         
                                                                                         
                                                                                                      
                                                                                                         
                                                                                                      
                                                 
                                                                                              

/// The four fixed partition PARTUUIDs + the disk GUID. **CANONICAL SOURCE: `crates/initramfs-init/
/// src/installer.rs`** — `SLOT_A_PARTUUID`/`SLOT_B_PARTUUID` consts + `build_gpt`'s derived ESP/persist
/// GUIDs + disk GUID + the `BOOT_SIZE_BYTES`/`SLOT_SIZE_BYTES`-derived LBAs below. These are HAND-MIRRORED
/// here AND in `install-usb.sh` (the `sgdisk` args). Audit R1 F-2: there is no automated guard tying the
/// three copies to the canonical source — they agree today (verified) but a future change to the
/// installer's sizes/GUIDs would silently desync the mirrors. The proper single-source-of-truth fix
/// (export the installer constants via a shared crate / generate the flash script from them) is
/// installer/builder-tool-phase work; until then, **any change in installer.rs must be mirrored in BOTH
/// this block and `install-usb.sh`'s sgdisk args + dd sizes.**
const SB_DISK_GUID: &str = "d91aff31-df15-4b91-9478-2ff7512c006e";
const SB_PARTUUID_ESP: &str = "e9abb6ab-76cf-4b2e-aa9a-f53e2ae152dd";
const SB_PARTUUID_SLOT_A: &str = "04c92659-e47a-485b-b840-fe5561eaa0da";
const SB_PARTUUID_SLOT_B: &str = "a5dff702-a9ff-41a1-9243-30e6136aba95";
const SB_PARTUUID_PERSIST: &str = "95f6532c-6953-4b27-8f85-2ba29fb4b91e";

/// Fixed start LBAs (512-byte sectors) — mirror of installer.rs's `build_gpt` layout (see SB_* above).
const LBA_ESP: u64 = 2048;
const LBA_SLOT_A: u64 = 264192;
/// Slot B start = slot A end; the gap (`LBA_SLOT_B - LBA_SLOT_A`) IS slot A's capacity in sectors.
const LBA_SLOT_B: u64 = 395264;
const LBA_PERSIST: u64 = 526336;
const REPRO_SECTOR: u64 = 512;

/// Slot-A byte capacity, derived from the partition LBAs (no new magic number) = 64 MiB, matching the
/// installer's `SLOT_SIZE_BYTES`. The rootfs component must fit — audit R1 F-1 (the manual copy paths
/// must replicate the installer's `check_image_fits` refusal; a too-large rootfs would otherwise
/// truncate/overrun slot A silently).
const SLOT_A_CAPACITY_BYTES: u64 = (LBA_SLOT_B - LBA_SLOT_A) * REPRO_SECTOR;

/// USB reproduction entry point: assemble the laptop's EXACT disk (sgdisk + component dd), USB-boot it
/// through OVMF (whatever SB posture the OVMF blobs carry), and assert the SAME services contract as the
/// §8 gate. A PASS means the USB/partuuid path works under QEMU → the laptop trouble is more
/// firmware/SB/stick-specific (the pre-Linux "#4" class). A FAIL whose captured console shows the
/// `resolve_partuuid` poll spinning / `/dev/sda` never appearing IS the reproduction we want — an
/// observable loop to fix against. Unlike the installer-based §8 path this is self-contained: the ESP
/// (partition 1) carries rambutan + vmlinuz + initrd, so there is NO `-kernel`, no sidecar, and no
/// fb.root-hash recompute (the cmdline + fb.root-hash are baked into the signed loader). The console log path
/// is printed on success and carried in the boot error on failure.
pub fn usb_repro_uefi_disk_and_observe(
    img: &Path,
    operator_privkey: &Path,
    opts: &DryrunOpts,
    ovmf_code: &Path,
    ovmf_vars: &Path,
) -> Result<(), DryrunError> {
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
    let workdir = tempfile::Builder::new()
        .prefix("recipes-uefi-usb-")
        .tempdir()
        .map_err(DryrunError::io("creating usb-repro workdir"))?;
    let log_dir = std::env::var_os("RECIPES_PROD_GATE_LOGDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workdir.path().to_path_buf());
    if log_dir != workdir.path() {
        std::fs::create_dir_all(&log_dir).map_err(DryrunError::io("creating gate log dir"))?;
    }

    let layout = parse_layout(&layout_sidecar(img))?;
    let disk = assemble_manual_usb_disk(img, &layout, workdir.path())?;

    let console = log_dir.join("uefi-usb-boot-console.log");
    let mut guard = boot_installed_uefi_disk(
        &disk,
        opts,
        &console,
        true,
        ovmf_code,
        ovmf_vars,
        StorageKind::UsbXhci,
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
    eprintln!(
        "USB repro: booted to services over USB/xHCI. console log: {}",
        console.display()
    );
    Ok(())
}

/// Assemble the disk the laptop actually boots: a GPT-partitioned file built with the EXACT `sgdisk`
/// invocation + component `dd` offsets from `install-usb.sh`, so a manual-procedure-vs-installer GPT
/// divergence surfaces HERE rather than hiding behind the dd-only installer the §8/§9 gates use. The
/// three pre-baked components are copied out of `img` (at its `.layout.toml` offsets) into their
/// partition byte-offsets (start-LBA × 512). Returns the assembled disk path under `wd`.
fn assemble_manual_usb_disk(
    img: &Path,
    layout: &Layout,
    wd: &Path,
) -> Result<PathBuf, DryrunError> {
                                                                                                          
    require_host_tool("sgdisk")?;

    let disk = wd.join("usb-repro-disk.img");
                                                                                                        
                                                                                              
    let disk_bytes = LBA_PERSIST * REPRO_SECTOR + layout.persist_skeleton_size + 64 * 1024 * 1024;
    File::create(&disk)
        .and_then(|f| f.set_len(disk_bytes))
        .map_err(DryrunError::io(format!("create+size {}", disk.display())))?;

                                                                                                         
                                                                                                        
                                                   
    let status = Command::new("sgdisk")
        .args(["--zap-all", "-U", SB_DISK_GUID])
        .args(["-n", "1:2048:+262144", "-t", "1:EF00"])
        .args(["-u", &format!("1:{SB_PARTUUID_ESP}")])
        .args(["-n", "2:264192:+131072", "-t", "2:8300"])
        .args(["-u", &format!("2:{SB_PARTUUID_SLOT_A}")])
        .args(["-n", "3:395264:+131072", "-t", "3:8300"])
        .args(["-u", &format!("3:{SB_PARTUUID_SLOT_B}")])
        .args(["-n", "4:526336:0", "-t", "4:8300"])
        .args(["-u", &format!("4:{SB_PARTUUID_PERSIST}")])
        .arg(&disk)
        .status()
        .map_err(|e| DryrunError::QemuLaunch(format!("spawn sgdisk: {e}")))?;
    if !status.success() {
        return Err(DryrunError::InstallDiskStage(format!(
            "sgdisk failed on {} (exit {status})",
            disk.display()
        )));
    }

                                                                                                
                                                                                                    
                                                                                         
    if layout.rootfs_size > SLOT_A_CAPACITY_BYTES {
        return Err(DryrunError::InstallDiskStage(format!(
            "rootfs ({} bytes) exceeds slot-A capacity ({SLOT_A_CAPACITY_BYTES} bytes) — \
             the component would not fit the partition (mirrors installer check_image_fits)",
            layout.rootfs_size
        )));
    }

                                                                                                        
                                                                                                        
                                                            
    let persist_img_offset = layout.boot_offset + layout.boot_size;
    copy_region(
        img,
        layout.boot_offset,
        layout.boot_size,
        &disk,
        LBA_ESP * REPRO_SECTOR,
    )?;
    copy_region(
        img,
        layout.rootfs_offset,
        layout.rootfs_size,
        &disk,
        LBA_SLOT_A * REPRO_SECTOR,
    )?;
    copy_region(
        img,
        persist_img_offset,
        layout.persist_skeleton_size,
        &disk,
        LBA_PERSIST * REPRO_SECTOR,
    )?;
    Ok(disk)
}

/// Copy `len` bytes from `src` at `src_off` into `dst` at `dst_off` WITHOUT truncating `dst` (a
/// pre-sized sparse disk file) — host-side `dd skip=…/seek=… conv=notrunc`.
fn copy_region(
    src: &Path,
    src_off: u64,
    len: u64,
    dst: &Path,
    dst_off: u64,
) -> Result<(), DryrunError> {
    let mut input = File::open(src).map_err(DryrunError::io(format!("open {}", src.display())))?;
    input
        .seek(SeekFrom::Start(src_off))
        .map_err(DryrunError::io(format!(
            "seek {} to {src_off}",
            src.display()
        )))?;
    let mut bounded = std::io::Read::take(input, len);
    let mut output = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dst)
        .map_err(DryrunError::io(format!("open-rw {}", dst.display())))?;
    output
        .seek(SeekFrom::Start(dst_off))
        .map_err(DryrunError::io(format!(
            "seek {} to {dst_off}",
            dst.display()
        )))?;
    let copied = std::io::copy(&mut bounded, &mut output)
        .map_err(DryrunError::io(format!("copy into {}", dst.display())))?;
    if copied != len {
        return Err(DryrunError::SliceShort {
            out: dst.display().to_string(),
            expected: len,
            got: copied,
        });
    }
    output.sync_all().map_err(DryrunError::io("sync dst"))?;
    Ok(())
}

/// Single-tool variant of [`preflight`]'s loop — check one host tool is on PATH (used for the repro-only
/// `sgdisk`, which the shared §8/§9 preflight does not require).
fn require_host_tool(tool: &str) -> Result<(), DryrunError> {
    let found = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !found {
        return Err(DryrunError::HostToolMissing(tool.to_string()));
    }
    Ok(())
}
