//! The §9.5 signed-USB installer gates: install from a signed USB onto a blank target under enforcing Secure Boot.

use super::assertions::*;
use super::qemu::*;
use super::*;

                                                                                              
                                                                                                   
                                                                                                   
                                                                                                   
                                                                                                   
                                                                                                        
                                                                                                        
                                                                                              

/// A blank sparse raw target disk (the installer's `dd` destination). Sparse (`set_len`) so a generous
/// size costs ~nothing; ≥ the box.img the installer commits (its GPT + persist-fill needs the room).
pub(super) fn make_blank_target(wd: &Path, size_bytes: u64) -> Result<PathBuf, DryrunError> {
    let target = wd.join("blank-target.img");
    File::create(&target)
        .and_then(|f| f.set_len(size_bytes))
        .map_err(DryrunError::io(format!(
            "create+size blank target {}",
            target.display()
        )))?;
    Ok(target)
}

/// §9.5 stage 1 — boot the SIGNED installer USB (its ESP's db-signed loader, NOT `-kernel`) under
/// ENFORCING OVMF (the `.secboot` CODE + the enrolled VARS), with a BLANK virtio target attached. The
/// firmware SB-verifies the USB loader; the loader boots the kernel + digest-gated initrd; the init's
/// UEFI installer arm resolves `INSTALLER_DATA_PARTUUID` on the USB, verifies box.img's baked digest,
/// selects the blank virtio target (the single eligible disk: non-removable AND `!= source` — the USB is
/// excluded as the SOURCE, the load-bearing rule; its `removable` status under QEMU is not relied on),
/// commits the GPT + `dd`s, and reboots → `-no-reboot` makes QEMU EXIT. Waits for that exit
/// (a hang → timeout). Returns the console text VERBATIM (success OR a `fb-init FATAL` halt — the
/// caller decides which it wants: §9.5a asserts no-FATAL+services, §9.5b/d assert the FATAL).
#[allow(clippy::too_many_arguments)]
fn run_installer_usb_phase(
    usb_img: &Path,
    targets: &[&Path],
    opts: &DryrunOpts,
    secboot_code: &Path,
    enrolled_vars: &Path,
    console: &Path,
) -> Result<String, DryrunError> {
                                                                                                         
    let vars = console.with_extension("ovmf-vars.fd");
    std::fs::copy(enrolled_vars, &vars).map_err(|e| {
        DryrunError::QemuLaunch(format!(
            "copy enrolled VARS {} -> {}: {e}",
            enrolled_vars.display(),
            vars.display()
        ))
    })?;
    let log = File::create(console)
        .map_err(|e| DryrunError::QemuLaunch(format!("create installer-usb console log: {e}")))?;
    let log_err = log
        .try_clone()
        .map_err(|e| DryrunError::QemuLaunch(format!("clone console handle: {e}")))?;
    let mem = opts.memory_mb.to_string();
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(["-enable-kvm", "-cpu", "host", "-m", &mem, "-machine", "q35"])
                                                                                                    
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,unit=0,readonly=on,file={}",
            secboot_code.display()
        ))
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,unit=1,file={}",
            vars.display()
        ))
                                                                                                           
                                                                                                            
                                                                                   
                                                                                                
                                                                                                            
                                                                                                      
                                                                                            
        .arg("-drive")
        .arg(format!(
            "file={},format=raw,if=none,id=usbinst,readonly=on",
            usb_img.display()
        ))
        .args(["-device", "nec-usb-xhci,id=xhci"])
        .args([
            "-device",
            "usb-storage,bus=xhci.0,drive=usbinst,bootindex=0",
        ]);
                                                                                                           
                                                                                                      
                                                                                                        
                                                      
    for t in targets {
        cmd.arg("-drive")
            .arg(format!("file={},format=raw,if=virtio", t.display()));
    }
                                                                                                  
                                                                                                    
                                                                                                       
    cmd.args(["-nographic", "-no-reboot", "-nic", "none"])
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(log_err);
                                                                                                 
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| DryrunError::QemuLaunch(format!("spawn installer-usb qemu: {e}")))?;

    let deadline = Instant::now() + opts.boot_timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,                                                             
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                return Err(DryrunError::InstallFailed(format!(
                    "waiting on installer-usb qemu: {e}"
                )));
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(DryrunError::InstallFailed(format!(
                "installer-usb did not finish (reboot) within {}s; console tail:\n{}",
                opts.boot_timeout.as_secs(),
                console_tail(console)
            )));
        }
        sleep(Duration::from_secs(2));
    }
    let _ = child.wait();
    Ok(std::fs::read_to_string(console).unwrap_or_default())
}

                                                                                                         
/// target under enforcing SB, and the TARGET (USB detached) then boots runtime services under SB.
/// Stage 1 = [`run_installer_usb_phase`] (assert NO `fb-init FATAL`). Stage 2 = boot the target
/// alone via [`boot_installed_uefi_disk`] (USB gone, so reaching services PROVES the target carries a
/// bootable signed install — the install landed on the target, not the USB).
pub fn install_from_usb_and_verify_target(
    usb_img: &Path,
    operator_privkey: &Path,
    opts: &DryrunOpts,
    secboot_code: &Path,
    enrolled_vars: &Path,
) -> Result<(), DryrunError> {
    preflight()?;
    for (label, p) in [
        ("RECIPES_OVMF_CODE_SECBOOT", secboot_code),
        ("the enrolled VARS", enrolled_vars),
    ] {
        if !p.is_file() {
            return Err(DryrunError::HostToolMissing(format!(
                "OVMF blob not found at {} (set {label})",
                p.display()
            )));
        }
    }
    let workdir = tempfile::Builder::new()
        .prefix("recipes-installer-usb-gate-")
        .tempdir()
        .map_err(DryrunError::io("creating installer-usb gate workdir"))?;
    let log_dir = std::env::var_os("RECIPES_PROD_GATE_LOGDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workdir.path().to_path_buf());
    if log_dir != workdir.path() {
        std::fs::create_dir_all(&log_dir).map_err(DryrunError::io("creating gate log dir"))?;
    }

                                                                                                        
    let target = make_blank_target(workdir.path(), 6 * 1024 * 1024 * 1024)?;

                                                                                        
    let stage1 = log_dir.join("installer-usb-stage1-install-console.log");
    let install_console = run_installer_usb_phase(
        usb_img,
        &[&target],
        opts,
        secboot_code,
        enrolled_vars,
        &stage1,
    )?;
    if let Some(line) = install_console
        .lines()
        .find(|l| l.contains("fb-init FATAL"))
    {
        return Err(DryrunError::InstallFailed(format!(
            "§9.5a stage-1 install aborted: {}\nconsole tail:\n{}",
            line.trim(),
            console_tail(&stage1)
        )));
    }

                                                                                                
    let stage2 = log_dir.join("installer-usb-stage2-target-console.log");
    let mut guard = boot_installed_uefi_disk(
        &target,
        opts,
        &stage2,
        true,
        secboot_code,
        enrolled_vars,
        StorageKind::Virtio,
    )?;
    wait_for_ssh(
        operator_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        &stage2,
    )?;
    assert_recipes_http(opts, &mut guard)?;
    assert_rootfs_ro(operator_privkey, opts.ssh_port)?;
    eprintln!(
        "§9.5a: signed USB → installed onto the blank target → target boots runtime under enforcing \
         SB (dropbear/operator-pubkey/recipes/ro). stage-1 {} | stage-2 {}",
        stage1.display(),
        stage2.display()
    );
    Ok(())
}

/// A blank target is UNTOUCHED iff its first MiB is all-zero — the installer's GPT-commit writes the
/// protective MBR + primary GPT at LBA0 FIRST, so an all-zero head proves no destructive write reached
/// the disk (the §9.5b/§9.5d fail-closed assertion: the installer touched no disk before its halt).
fn target_is_untouched(target: &Path) -> Result<bool, DryrunError> {
    let mut f =
        File::open(target).map_err(DryrunError::io(format!("open {}", target.display())))?;
    let mut head = vec![0u8; 1024 * 1024];
    let n = std::io::Read::read(&mut f, &mut head)
        .map_err(DryrunError::io(format!("read {}", target.display())))?;
    Ok(head[..n].iter().all(|&b| b == 0))
}

/// §9.5b/§9.5d negative — boot the installer USB with `targets` attached and assert it FAIL-CLOSES:
/// a `fb-init FATAL` halt whose message contains `expect_substr` (the digest-mismatch reason for §9.5b,
/// the target-selection reason for §9.5d), and EVERY target left byte-untouched (no destructive write
/// before the halt). The installer's FATAL path reboots → `-no-reboot` → QEMU exits, so
/// [`run_installer_usb_phase`] returns the console. 0 targets = no-eligible; 2 = ambiguous.
pub fn install_from_usb_expect_halt(
    usb_img: &Path,
    targets: &[&Path],
    opts: &DryrunOpts,
    secboot_code: &Path,
    enrolled_vars: &Path,
    expect_substr: &str,
) -> Result<(), DryrunError> {
    preflight()?;
    let workdir = tempfile::Builder::new()
        .prefix("recipes-installer-usb-neg-")
        .tempdir()
        .map_err(DryrunError::io("creating installer-usb neg workdir"))?;
    let log_dir = std::env::var_os("RECIPES_PROD_GATE_LOGDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workdir.path().to_path_buf());
    if log_dir != workdir.path() {
        std::fs::create_dir_all(&log_dir).map_err(DryrunError::io("creating gate log dir"))?;
    }
                                                                                                            
                                                                                                     
                                                                                             
    let slug: String = expect_substr
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(32)
        .collect();
    let console = log_dir.join(format!("installer-usb-halt-{slug}-console.log"));
    let out = run_installer_usb_phase(
        usb_img,
        targets,
        opts,
        secboot_code,
        enrolled_vars,
        &console,
    )?;

                                                                                                       
    let fatal = out
        .lines()
        .find(|l| l.contains("fb-init FATAL"))
        .ok_or_else(|| {
            DryrunError::InstallFailed(format!(
                "expected a fail-closed `fb-init FATAL` halt; none in console:\n{}",
                console_tail(&console)
            ))
        })?;
    if !fatal.contains(expect_substr) {
        return Err(DryrunError::InstallFailed(format!(
            "FATAL halt did not mention {expect_substr:?}: {}\nconsole tail:\n{}",
            fatal.trim(),
            console_tail(&console)
        )));
    }
                                                                                                          
    for t in targets {
        if !target_is_untouched(t)? {
            return Err(DryrunError::InstallFailed(format!(
                "the halt left {} WRITTEN — a fail-closed installer must touch no disk before halting",
                t.display()
            )));
        }
    }
    eprintln!(
        "§9.5 negative: installer FAIL-CLOSED ({expect_substr:?}); {} target(s) byte-untouched. console: {}",
        targets.len(),
        console.display()
    );
    Ok(())
}

/// §9.5b — corrupt the `box.img` on a COPY of the installer USB so its SHA-256 no longer matches the
/// loader-baked `fb.image-sha256`. Reads the USB GPT's 2nd entry (the ext4 data partition; entries at
/// LBA 2, entry 1's `first_lba` at +32 over the 2nd 128-byte entry) to find its start, then flips a
/// byte 32 MiB in — well past the ext4 metadata, inside box.img's data extents (box.img is the bulk of
/// the partition). The ESP / signed loader is UNTOUCHED, so the loader's baked digest is unchanged and
/// the installer's verify-before-write sees a MISMATCH and fail-closes BEFORE any target write.
pub fn tamper_installer_usb_box_img(usb_copy: &Path) -> Result<(), DryrunError> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(usb_copy)
        .map_err(DryrunError::io(format!("open {}", usb_copy.display())))?;
                                                                                                          
    let entry1_first_lba_off = 2 * 512 + 128 + 32;
    let mut lba = [0u8; 8];
    f.seek(SeekFrom::Start(entry1_first_lba_off))
        .map_err(DryrunError::io("seek GPT entry-1 first_lba"))?;
    f.read_exact(&mut lba)
        .map_err(DryrunError::io("read p2 first_lba"))?;
    let p2_off = u64::from_le_bytes(lba) * 512;
    let flip_off = p2_off + 32 * 1024 * 1024;                                                    
    let mut byte = [0u8; 1];
    f.seek(SeekFrom::Start(flip_off))
        .map_err(DryrunError::io("seek box.img byte"))?;
    f.read_exact(&mut byte)
        .map_err(DryrunError::io("read box.img byte"))?;
    byte[0] ^= 0xff;
    f.seek(SeekFrom::Start(flip_off))
        .map_err(DryrunError::io("re-seek box.img byte"))?;
    f.write_all(&byte)
        .map_err(DryrunError::io("flip box.img byte"))?;
    Ok(())
}

/// §9.5c — an UNSIGNED installer USB under ENFORCING SB: the firmware REFUSES the unsigned loader
/// (Authenticode verify vs db fails), so the installer never runs and the target is byte-untouched.
                                                                                                  
/// refusal mechanism is §9.3a's (same rambutan loader, same db) applied to the USB-booted installer
/// loader; a short deadline suffices — the firmware signals the violation within seconds.
pub fn install_from_usb_expect_firmware_refusal(
    unsigned_usb: &Path,
    target: &Path,
    opts: &DryrunOpts,
    secboot_code: &Path,
    enrolled_vars: &Path,
) -> Result<(), DryrunError> {
    preflight()?;
    let workdir = tempfile::Builder::new()
        .prefix("recipes-installer-usb-refusal-")
        .tempdir()
        .map_err(DryrunError::io("creating installer-usb refusal workdir"))?;
    let log_dir = std::env::var_os("RECIPES_PROD_GATE_LOGDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workdir.path().to_path_buf());
    if log_dir != workdir.path() {
        std::fs::create_dir_all(&log_dir).map_err(DryrunError::io("creating gate log dir"))?;
    }
                                                                                                        
                                                                                              
    let short = DryrunOpts {
        boot_timeout: Duration::from_secs(75),
        ..opts.clone()
    };
    let console = log_dir.join("installer-usb-refusal-console.log");
                                                                                                         
                                                                                                         
    let _ = run_installer_usb_phase(
        unsigned_usb,
        &[target],
        &short,
        secboot_code,
        enrolled_vars,
        &console,
    );
    let console_text = std::fs::read_to_string(&console).unwrap_or_default();
    let signalled = console_text.contains("Security Violation")
        || console_text.contains("Image failed")
        || console_text.contains("Access Denied")
        || console_text.contains("access denied")
        || console_text.contains("BdsDxe: failed to load")
        || console_text.contains("ProtocolError");
    if !signalled {
        return Err(DryrunError::InstallFailed(format!(
            "expected a POSITIVE Secure Boot refusal signal for the unsigned installer loader; \
             console tail:\n{}",
            console_tail(&console)
        )));
    }
    if !target_is_untouched(target)? {
        return Err(DryrunError::InstallFailed(
            "the refused boot left the target WRITTEN — a refused installer must touch no disk"
                .into(),
        ));
    }
    eprintln!(
        "§9.5c: unsigned installer loader REFUSED by enforcing SB; target byte-untouched. console: {}",
        console.display()
    );
    Ok(())
}

/// §9.5d (`fb.install-to`) — the installer USB was baked with `fb.install-to=<named>`; with TWO eligible
/// disks attached it installs to EXACTLY the named one. Stage 1 installs cleanly (no FATAL) and leaves
/// the OTHER disk byte-untouched; stage 2 boots the NAMED disk alone → runtime services under SB. The
/// operator's explicit disambiguation — the positive complement to the ambiguous fail-closed halt.
/// `named_target` is attached FIRST (→ `/dev/vda`) so it matches a `fb.install-to=vda`-baked USB.
pub fn install_from_usb_to_named_and_verify(
    usb_img: &Path,
    named_target: &Path,
    other_target: &Path,
    operator_privkey: &Path,
    opts: &DryrunOpts,
    secboot_code: &Path,
    enrolled_vars: &Path,
) -> Result<(), DryrunError> {
    preflight()?;
    let workdir = tempfile::Builder::new()
        .prefix("recipes-installer-usb-named-")
        .tempdir()
        .map_err(DryrunError::io("creating installer-usb named workdir"))?;
    let log_dir = std::env::var_os("RECIPES_PROD_GATE_LOGDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workdir.path().to_path_buf());
    if log_dir != workdir.path() {
        std::fs::create_dir_all(&log_dir).map_err(DryrunError::io("creating gate log dir"))?;
    }
                                                                                                       
    let stage1 = log_dir.join("installer-usb-named-stage1-console.log");
    let console = run_installer_usb_phase(
        usb_img,
        &[named_target, other_target],
        opts,
        secboot_code,
        enrolled_vars,
        &stage1,
    )?;
    if let Some(line) = console.lines().find(|l| l.contains("fb-init FATAL")) {
        return Err(DryrunError::InstallFailed(format!(
            "§9.5d fb.install-to stage-1 aborted (expected a clean install to the named disk): {}\n\
             console tail:\n{}",
            line.trim(),
            console_tail(&stage1)
        )));
    }
                                                                                                  
    if !target_is_untouched(other_target)? {
        return Err(DryrunError::InstallFailed(
            "fb.install-to wrote the NON-named disk — it must install to exactly the named disk"
                .into(),
        ));
    }
                                                                                                    
    let stage2 = log_dir.join("installer-usb-named-stage2-console.log");
    let mut guard = boot_installed_uefi_disk(
        named_target,
        opts,
        &stage2,
        true,
        secboot_code,
        enrolled_vars,
        StorageKind::Virtio,
    )?;
    wait_for_ssh(
        operator_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        &stage2,
    )?;
    assert_recipes_http(opts, &mut guard)?;
    assert_rootfs_ro(operator_privkey, opts.ssh_port)?;
    eprintln!(
        "§9.5d fb.install-to: installed to EXACTLY the named disk (other byte-untouched) → it boots \
         runtime under enforcing SB. stage-1 {} | stage-2 {}",
        stage1.display(),
        stage2.display()
    );
    Ok(())
}
