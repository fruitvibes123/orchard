//! QEMU launch + SSH transport + installed-disk boot/reboot primitives shared across the dryrun harnesses.

use super::assertions::*;
use super::install_seabios::GATE_NO_BOOT_WINDOW;
use super::*;

pub(super) fn ssh_keygen(privkey: &Path) -> Result<(), DryrunError> {
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f"])
        .arg(privkey)
        .status()
        .map_err(|e| DryrunError::KeygenFailed(format!("spawn ssh-keygen: {e}")))?;
    if !status.success() {
        return Err(DryrunError::KeygenFailed(format!(
            "ssh-keygen exited {status}"
        )));
    }
    Ok(())
}

/// QEMU should die with the dryrun process (`PR_SET_PDEATHSIG`) EXCEPT under `--keep-running`, whose
/// whole purpose is to let the VM OUTLIVE this process for manual inspection — pinning its lifetime
/// to the (exiting) parent there would SIGKILL it on return, breaking the flag (R2 L-1).
fn qemu_dies_with_parent(opts: &DryrunOpts) -> bool {
    !opts.keep_running
}

/// The ONE `-netdev user,…` argument every services-box QEMU launcher in this module renders.
/// Appends `restrict=on` iff `opts.restrict_net`, isolating the guest from the host and the internet
/// while leaving the inbound `hostfwd` rules intact — QEMU's user-net `restrict` "does not affect any
/// explicitly set forwarding rules" (QEMU invocation docs / user-networking), so ssh/https hostfwd
/// still work while egress and DNS die. Extracted so the hermetic wiring lives in ONE place with ONE
                                                                                                     
/// `boot_installed_uefi_disk` — the builders that boot the INSTALLED services box where
/// `fb-acme-renew` runs — booted under open NAT for every value of the flag.
///
/// Each `hostfwd` binds the LOOPBACK host address (`tcp:127.0.0.1:…`), so only the host reaches the
/// guest's forwarded dropbear (22) and haproxy (`guest_https_port`) ports, never the whole network
                                                                                     
/// `hostfwd=tcp:127.0.0.1:PORT-…` on `127.0.0.1` (measured, QEMU 11.0.3 via `ss -tln`). The sibling
/// `prod_e2e.rs::debian_user_netdev_arg` binds loopback the same way.
pub(crate) fn user_netdev_arg(opts: &DryrunOpts) -> String {
    format!(
        "user,id=n0,hostfwd=tcp:127.0.0.1:{}-:22,hostfwd=tcp:127.0.0.1:{}-:{}{}",
        opts.ssh_port,
        opts.https_port,
        opts.guest_https_port,
        if opts.restrict_net {
            ",restrict=on"
        } else {
            ""
        }
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn launch_qemu(
    vmlinuz: &Path,
    initramfs: &Path,
    rootfs: &Path,
    persist: &Path,
    root_hash: &str,
    verity_hash_offset: u64,
    opts: &DryrunOpts,
    console: &Path,
) -> Result<QemuGuard, DryrunError> {
                                                                                              
                                                                                                 
                                                                                                      
                                                                                                          
                                                                     
    let append = format!(
        "fb.root-hash={root_hash} fb.verity-hash-offset={verity_hash_offset} \
         fb.rootfs-dev=/dev/vda \
         fb.net=mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3 \
         ro lockdown=integrity ima_appraise=enforce sysctl.kernel.yama.ptrace_scope=2 console=ttyS0"
    );
    let log = File::create(console)
        .map_err(|e| DryrunError::QemuLaunch(format!("create console log: {e}")))?;
    let log_err = log
        .try_clone()
        .map_err(|e| DryrunError::QemuLaunch(format!("clone console log handle: {e}")))?;
    let mem = opts.memory_mb.to_string();
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(["-enable-kvm", "-cpu", "host", "-m", &mem])
        .arg("-kernel")
        .arg(vmlinuz)
        .arg("-initrd")
        .arg(initramfs)
        .arg("-append")
        .arg(&append)
        .arg("-drive")
        .arg(format!("file={},format=raw,if=virtio", rootfs.display()))
        .arg("-drive")
        .arg(format!("file={},format=raw,if=virtio", persist.display()))
        .arg("-netdev")
        .arg(user_netdev_arg(opts))
        .args([
            "-device",
            "virtio-net-pci,netdev=n0",
            "-nographic",
            "-no-reboot",
        ])
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(log_err);
                                                                                                  
                                                                                                       
                                                                                               
                                                                                                
                                                                                                 
                                                                                          
      
                                                                                                     
                                                                                               
                                                                                                    
                                                                     
    if qemu_dies_with_parent(opts) {
                                                                                                  
                                                                                  
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
    }
    let child = cmd
        .spawn()
        .map_err(|e| DryrunError::QemuLaunch(format!("spawn qemu-system-x86_64: {e}")))?;
    Ok(QemuGuard {
        child,
        keep_running: opts.keep_running,
    })
}

/// SSH args for ephemeral-key, pubkey-only auth against the forwarded port. `BatchMode` +
/// `PasswordAuthentication=no` mean a *success* proves dropbear accepted the operator pubkey (no
/// password fallback masks a pubkey rejection).
pub(super) fn ssh_base_args(privkey: &Path, port: u16) -> Vec<String> {
    vec![
        "-i".into(),
        privkey.display().to_string(),
        "-p".into(),
        port.to_string(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "ConnectTimeout=5".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "PasswordAuthentication=no".into(),
        "-o".into(),
        "LogLevel=ERROR".into(),
        "root@127.0.0.1".into(),
    ]
}

pub(crate) fn wait_for_ssh(
    privkey: &Path,
    port: u16,
    timeout: Duration,
    guard: &mut QemuGuard,
    console: &Path,
) -> Result<(), DryrunError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(status)) = guard.child.try_wait() {
            return Err(DryrunError::BootFailed(format!(
                "qemu exited early ({status}) before dropbear came up; console tail:\n{}",
                console_tail(console)
            )));
        }
        let up = Command::new("ssh")
            .args(ssh_base_args(privkey, port))
            .arg("true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if up {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(DryrunError::BootTimeout(format!(
                "dropbear pubkey auth not up within {}s; console tail:\n{}",
                timeout.as_secs(),
                console_tail(console)
            )));
        }
        sleep(Duration::from_secs(2));
    }
}

/// The shared QEMU launch-and-wait core for the `-kernel` installer phases — the SeaBIOS/SeabiosGpt
/// [`run_installer_phase`] and the §9.5 UEFI [`run_uefi_installer_phase`]. Boots `vmlinuz`+`initramfs`
/// with `append`, attaches every disk in `disks` as a virtio drive (SeaBIOS passes one source-and-target
/// disk; UEFI passes the `INSTALLER_DATA_PARTUUID` source + a separate blank target), waits for the
/// installer to reboot (→ `-no-reboot` → QEMU exits) or time out, then fails closed on a `fb-init FATAL`
/// console line. The two callers vary ONLY the cmdline and the disk set; the PDEATHSIG lifetime pin, the
/// wait loop, and the FATAL scan are identical, so they live here once.
pub(super) fn run_installer_qemu(
    vmlinuz: &Path,
    initramfs: &Path,
    disks: &[&Path],
    append: &str,
    opts: &DryrunOpts,
    console: &Path,
) -> Result<(), DryrunError> {
    let log = File::create(console)
        .map_err(|e| DryrunError::QemuLaunch(format!("create installer console log: {e}")))?;
    let log_err = log
        .try_clone()
        .map_err(|e| DryrunError::QemuLaunch(format!("clone console handle: {e}")))?;
    let mem = opts.memory_mb.to_string();
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(["-enable-kvm", "-cpu", "host", "-m", &mem])
        .arg("-kernel")
        .arg(vmlinuz)
        .arg("-initrd")
        .arg(initramfs)
        .arg("-append")
        .arg(append);
                                                                                                    
                                                                                          
    for disk in disks {
        cmd.arg("-drive")
            .arg(format!("file={},format=raw,if=virtio", disk.display()));
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
        .map_err(|e| DryrunError::QemuLaunch(format!("spawn installer qemu: {e}")))?;

                                                                                                   
    let deadline = Instant::now() + opts.boot_timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,                                                             
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                return Err(DryrunError::InstallFailed(format!(
                    "waiting on installer qemu: {e}"
                )));
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(DryrunError::InstallFailed(format!(
                "installer did not finish (reboot) within {}s; console tail:\n{}",
                opts.boot_timeout.as_secs(),
                console_tail(console)
            )));
        }
        sleep(Duration::from_secs(2));
    }
    let _ = child.wait();

                                                                                                  
                                                                                                     
                                                 
    let log_text = std::fs::read_to_string(console).unwrap_or_default();
    if let Some(line) = log_text.lines().find(|l| l.contains("fb-init FATAL")) {
        return Err(DryrunError::InstallFailed(format!(
            "installer aborted: {}\nconsole tail:\n{}",
            line.trim(),
            console_tail(console)
        )));
    }
    Ok(())
}

/// Boot an INSTALLED disk through SeaBIOS (NO `-kernel` — the firmware reads the MBR → mbr.bin → the
/// active partition's VBR → ldlinux → the baked extlinux.conf), with user-net hostfwd for SSH/HTTPS.
/// Returns the RAII guard (killed on Drop unless `keep_running`).
pub(super) fn boot_installed_disk(
    disk: &Path,
    opts: &DryrunOpts,
    console: &Path,
    no_reboot: bool,
) -> Result<QemuGuard, DryrunError> {
    let log = File::create(console)
        .map_err(|e| DryrunError::QemuLaunch(format!("create boot console log: {e}")))?;
    let log_err = log
        .try_clone()
        .map_err(|e| DryrunError::QemuLaunch(format!("clone console handle: {e}")))?;
    let mem = opts.memory_mb.to_string();
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(["-enable-kvm", "-cpu", "host", "-m", &mem])
        .arg("-drive")
        .arg(format!("file={},format=raw,if=virtio", disk.display()))
        .arg("-netdev")
        .arg(user_netdev_arg(opts))
        .args(["-device", "virtio-net-pci,netdev=n0", "-nographic"]);
                                                                                                          
                                                                                                      
                                                                                                      
    if no_reboot {
        cmd.arg("-no-reboot");
    }
    cmd.stdin(Stdio::null()).stdout(log).stderr(log_err);
    if qemu_dies_with_parent(opts) {
                                                                                                     
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
    }
    let child = cmd
        .spawn()
        .map_err(|e| DryrunError::QemuLaunch(format!("spawn disk-boot qemu: {e}")))?;
    Ok(QemuGuard {
        child,
        keep_running: opts.keep_running,
    })
}

/// How the installed disk is presented to the guest kernel. The converged §8/§9 gates use
/// [`StorageKind::Virtio`] (synchronous, instant — what QEMU has always done). [`StorageKind::UsbXhci`]
/// presents the SAME disk as a USB-3 mass-storage device behind an xHCI controller, so the kernel
/// enumerates it ASYNC as `/dev/sda` (a SCSI disk) — the bare-metal-USB axis the laptop boots, which the
/// virtio path is structurally blind to (the partuuid poll + async partition-node materialisation only
/// matter when enumeration is async). OVMF still finds `\EFI\BOOT\BOOTX64.EFI` on the ESP either way.
#[derive(Clone, Copy)]
pub(crate) enum StorageKind {
    Virtio,
    UsbXhci,
}

                                                                                 
/// `/EFI/BOOT/BOOTX64.EFI` (the rambutan loader) off the GPT ESP via the removable-media fallback path;
/// there is NO `-kernel`/`-initrd`/`-append` (the cmdline is a const inside the SIGNED loader, set on
/// the kernel's LoadOptions — the firmware cannot inject a rootfs-dev). Mirrors [`boot_installed_disk`] but adds the q35 machine +
/// the SB-OFF OVMF pflash pair: `OVMF_CODE` readonly at unit 0, a per-boot WRITABLE copy of `OVMF_VARS`
/// at unit 1 (OVMF persists its NVRAM there — a readonly VARS would wedge the firmware). The writable
/// copy lands beside `console` (`<console>.ovmf-vars.fd`) so it survives for diagnosis + is fresh per
/// boot. `ovmf_code`/`ovmf_vars_template` come from `RECIPES_OVMF_CODE`/`_VARS` (the §8 SB-OFF blobs).
pub(super) fn boot_installed_uefi_disk(
    disk: &Path,
    opts: &DryrunOpts,
    console: &Path,
    no_reboot: bool,
    ovmf_code: &Path,
    ovmf_vars_template: &Path,
    storage: StorageKind,
) -> Result<QemuGuard, DryrunError> {
                                                                                                          
                                                                                                         
    let vars = console.with_extension("ovmf-vars.fd");
    std::fs::copy(ovmf_vars_template, &vars).map_err(|e| {
        DryrunError::QemuLaunch(format!(
            "copy OVMF_VARS {} -> {}: {e}",
            ovmf_vars_template.display(),
            vars.display()
        ))
    })?;
    let log = File::create(console)
        .map_err(|e| DryrunError::QemuLaunch(format!("create uefi boot console log: {e}")))?;
    let log_err = log
        .try_clone()
        .map_err(|e| DryrunError::QemuLaunch(format!("clone console handle: {e}")))?;
    let mem = opts.memory_mb.to_string();
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(["-enable-kvm", "-cpu", "host", "-m", &mem, "-machine", "q35"])
                                                                                         
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,unit=0,readonly=on,file={}",
            ovmf_code.display()
        ))
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,unit=1,file={}",
            vars.display()
        ))
                                                                                                   
        ;
    match storage {
                                                                              
        StorageKind::Virtio => {
            cmd.arg("-drive")
                .arg(format!("file={},format=raw,if=virtio", disk.display()));
        }
                                                                                                      
                                                                                                
        StorageKind::UsbXhci => {
            cmd.arg("-drive")
                .arg(format!(
                    "file={},format=raw,if=none,id=usbdisk",
                    disk.display()
                ))
                .args(["-device", "nec-usb-xhci,id=xhci"])
                .args(["-device", "usb-storage,bus=xhci.0,drive=usbdisk"]);
        }
    }
    cmd.arg("-netdev").arg(user_netdev_arg(opts)).args([
        "-device",
        "virtio-net-pci,netdev=n0",
        "-nographic",
    ]);
    if no_reboot {
        cmd.arg("-no-reboot");
    }
    cmd.stdin(Stdio::null()).stdout(log).stderr(log_err);
    if qemu_dies_with_parent(opts) {
                                                                                                     
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
    }
    let child = cmd
        .spawn()
        .map_err(|e| DryrunError::QemuLaunch(format!("spawn uefi disk-boot qemu: {e}")))?;
    Ok(QemuGuard {
        child,
        keep_running: opts.keep_running,
    })
}

/// Build an ENROLLED OVMF VARS from our test PK/KEK/db (SB-loader plan L3 / §9.2): `virt-fw-vars`
/// writes each CERT into its firmware variable atop a COPY of the stock VARS template — deterministic,
/// from OUR certs, NO opaque committed blob. `--no-microsoft` keeps db ours-only (no MS CA). Setting
/// PK takes the firmware out of SetupMode, so the `.secboot` OVMF_CODE then ENFORCES (SecureBoot=1).
/// `sb_keys_dir` is the `<keys>/secure-boot/` dir [`crate::deploy::secure_boot_keys`] writes.
pub fn build_enrolled_sb_vars(
    sb_keys_dir: &Path,
    vars_template: &Path,
    out_vars: &Path,
) -> Result<(), DryrunError> {
    let found = Command::new("sh")
        .arg("-c")
        .arg("command -v virt-fw-vars")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !found {
        return Err(DryrunError::HostToolMissing(
            "virt-fw-vars not found (the SB-ON enrolled-VARS fixture; from the virt-firmware package)"
                .into(),
        ));
    }
                                                                                               
    let owner = "9b5b8e3a-0000-4000-8000-0000005ec0de";
    let pk = sb_keys_dir.join("PK.crt");
    let kek = sb_keys_dir.join("KEK.crt");
    let db = sb_keys_dir.join("db.crt");
    let status = Command::new("virt-fw-vars")
        .arg("-i")
        .arg(vars_template)
        .args(["--set-pk", owner])
        .arg(&pk)
        .args(["--add-kek", owner])
        .arg(&kek)
        .args(["--add-db", owner])
        .arg(&db)
        .arg("--no-microsoft")
        .arg("-o")
        .arg(out_vars)
        .status()
        .map_err(|e| DryrunError::QemuLaunch(format!("spawn virt-fw-vars: {e}")))?;
    if !status.success() {
        return Err(DryrunError::QemuLaunch(
            "virt-fw-vars failed to write the enrolled VARS".into(),
        ));
    }
    Ok(())
}

/// Boot an installed UEFI disk and assert it does NOT reach SSH within `timeout` — the §9.3 negative
/// shape (a refused/halted chain must NOT come up to services). Returns the boot console text for the
                                                                                                        
/// sufficient; the caller asserts the firmware/loader actually SIGNALLED a refusal, not merely hung).
pub(super) fn boot_installed_uefi_disk_expect_no_services(
    disk: &Path,
    operator_privkey: &Path,
    opts: &DryrunOpts,
    console: &Path,
    ovmf_code: &Path,
    ovmf_vars: &Path,
) -> Result<String, DryrunError> {
    let mut guard = boot_installed_uefi_disk(
        disk,
        opts,
        console,
        true,
        ovmf_code,
        ovmf_vars,
        StorageKind::Virtio,
    )?;
                                                                                                  
    match wait_for_ssh(
        operator_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        console,
    ) {
        Ok(()) => Err(DryrunError::QemuLaunch(
            "SB negative gate: the chain REACHED services, but a refused/halted boot must NOT — \
             the firmware/loader failed to reject it"
                .into(),
        )),
                                                                                                
                                                                             
        Err(_) => std::fs::read_to_string(console)
            .map_err(DryrunError::io("read SB-negative boot console")),
    }
}

/// Wait until the box's SSH STOPS responding — i.e. it is rebooting — so the clean-reboot gate does not
/// false-pass on the still-up first-boot SSH. Errors if QEMU EXITS (the clean-reboot gate runs WITHOUT
/// `-no-reboot`, so a guest reboot keeps QEMU alive; an exit here is an unexpected halt) or if SSH never
/// drops within `timeout` (the clean-shutdown leg did not fire).
pub(super) fn wait_for_ssh_down(
    privkey: &Path,
    port: u16,
    timeout: Duration,
    guard: &mut QemuGuard,
    console: &Path,
) -> Result<(), DryrunError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(status)) = guard.child.try_wait() {
            return Err(DryrunError::BootFailed(format!(
                "qemu exited ({status}) during the clean reboot — expected a REBOOT (qemu stays up), not \
                 a halt; console tail:\n{}",
                console_tail(console)
            )));
        }
        let up = Command::new("ssh")
            .args(ssh_base_args(privkey, port))
            .arg("true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !up {
            return Ok(());                                                   
        }
        if Instant::now() >= deadline {
            return Err(DryrunError::BootTimeout(format!(
                "SSH never went down within {}s after `kill -TERM 1` — the .s6-svscan SIGTERM→finish \
                 clean-shutdown leg did not fire; console tail:\n{}",
                timeout.as_secs(),
                console_tail(console)
            )));
        }
        sleep(Duration::from_secs(1));
    }
}

/// M-β (phase-4 holistic): the CLEAN-reboot path — the one in-scope un-run BOOT-1 leg. SIGTERM to PID-1
/// (s6-svscan) runs the `.s6-svscan/SIGTERM`→`finish` handler exec leg (tree-stop → sync/umount/reboot);
/// the box REBOOTS (this boots WITHOUT `-no-reboot`) and must come BACK to SERVICES.
///
                                                                                                         
/// handler → PID-1 panics → (no `panic=` token) HANG → the boot-2 `wait_for_ssh` times out = RED, so the
/// hang WAS the signal. `panic=10` (T4) changes that: a panicking PID-1 now REBOOTS after 10 s, so a
/// misresolved handler would panic → reboot → boot-2 comes back to Services → the timing/liveness check
/// alone reads GREEN — a FALSE green (the finish handler is broken but the gate can't tell a clean reboot
/// from a panic-recovery reboot). The migration closes that: it records the console offset before the
/// SIGTERM and, after boot-2 is healthy, asserts the shutdown→boot-2 window carries NO kernel-panic
/// marker. A clean finish reboots with no panic; a misresolved one prints `Kernel panic - not syncing`
/// (then `Rebooting in 10 seconds`) — so the marker's PRESENCE is the S4-M1 catch that the liveness check
/// can no longer make on its own.
///
/// **`boot_installed_disk` caller inventory under `panic=10`** (why only THIS gate needed migrating — the
/// `no_reboot=true` callers cannot false-green because QEMU EXITS on the guest reboot, so a panic still
/// surfaces as an SSH-down RED, never a recovered-and-healthy pass):
/// - `qemu.rs:566` (here) — `no_reboot=false`, THE rebootable gate → migrated (panic-marker check).
/// - `qemu.rs:629` (`assert_not_bootable`) — `no_reboot=true`; a panic → QEMU exit → the "does not boot"
///   assertion still holds (a panic is not a successful boot).
/// - `install_seabios.rs:132/194/813`, `install_dha.rs:234` — all `no_reboot=true`; a panic → QEMU exit →
///   `wait_for_ssh` times out → RED (no false-green). `installer_usb.rs` boots via its own helper, never
///   this fn.
pub(super) fn clean_reboot_and_verify(
    disk: &Path,
    operator_privkey: &Path,
    opts: &DryrunOpts,
    console: &Path,
) -> Result<(), DryrunError> {
    let mut guard = boot_installed_disk(disk, opts, console, false)?;                              
    wait_for_ssh(
        operator_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        console,
    )?;
    assert_recipes_http(opts, &mut guard)?;
                                                                                                      
                                                                                                          
                                                                                        
    let shutdown_mark = std::fs::metadata(console).map(|m| m.len()).unwrap_or(0);
                                                                                                          
                                                                                              
    let _ = Command::new("ssh")
        .args(ssh_base_args(operator_privkey, opts.ssh_port))
        .arg("kill -s TERM 1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    wait_for_ssh_down(
        operator_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        console,
    )?;
                                                                                                      
                                                                                                            
                                                   
    wait_for_ssh(
        operator_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        console,
    )?;
    assert_recipes_http(opts, &mut guard)?;
                                                                                                    
                                                                                                             
                                                                                                    
                                                                                                     
    assert_no_kernel_panic_since(console, shutdown_mark)?;
    Ok(())
}

/// Assert the console region from `from_offset` onward carries NO kernel-panic marker (S4-M1). Reads the
/// whole console + slices from the byte offset recorded before the clean-shutdown trigger, so a benign
/// earlier occurrence can never mask a real one. `Kernel panic - not syncing` is the unmodified Linux
/// panic banner (printk → `console=ttyS0`); `panic=10` follows it with `Rebooting in 10 seconds`.
fn assert_no_kernel_panic_since(console: &Path, from_offset: u64) -> Result<(), DryrunError> {
    let text = std::fs::read_to_string(console).unwrap_or_default();
    let window = text.get(from_offset as usize..).unwrap_or(&text);
    if let Some(line) = window
        .lines()
        .find(|l| l.contains("Kernel panic") || l.contains("panic - not syncing"))
    {
        return Err(DryrunError::BootTimeout(format!(
            "clean-reboot gate: PID-1 PANICKED during the SIGTERM→finish shutdown and only rebooted via \
             `panic=10` — the `.s6-svscan/finish` handler misresolved (S4-M1 false-green catch). The box \
             came back healthy but the clean-shutdown leg is BROKEN. Panic line:\n  {}\nconsole tail:\n{}",
            line.trim(),
            console_tail(console)
        )));
    }
    Ok(())
}

/// Zero the 440-byte MBR boot-code area (preserving the partition table at 446..512 + the boot
/// signature), reproducing the on-disk state of a mid-commit abort BEFORE `write_mbr_bootcode` (the
/// LAST destructive installer step). The disk then has every partition + component but no stage-1.
pub(super) fn zero_mbr_bootcode(disk: &Path) -> Result<(), DryrunError> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(disk)
        .map_err(DryrunError::io("open disk to zero boot code"))?;
    f.seek(SeekFrom::Start(0))
        .map_err(DryrunError::io("seek to MBR"))?;
    f.write_all(&[0u8; 440])
        .map_err(DryrunError::io("zero MBR boot code"))?;
    f.sync_all().map_err(DryrunError::io("sync zeroed MBR"))
}

/// Bootable-last: assert `disk` does NOT boot to the runtime. Boots it (short window) and confirms SSH
/// never comes up and recipes never answers — a healthy box would within [`GATE_NO_BOOT_WINDOW`], so
/// silence across it proves the disk is not bootable (the bootable-last guarantee). SSH coming up ⇒ the
/// guarantee is violated.
pub(super) fn assert_disk_does_not_boot(
    disk: &Path,
    privkey: &Path,
    opts: &DryrunOpts,
    console: &Path,
) -> Result<(), DryrunError> {
    let mut guard = boot_installed_disk(disk, opts, console, true)?;
    let deadline = Instant::now() + GATE_NO_BOOT_WINDOW;
    loop {
                                                                                                       
                                                                                                
        if let Ok(Some(_)) = guard.child.try_wait() {
            return Ok(());
        }
        let up = Command::new("ssh")
            .args(ssh_base_args(privkey, opts.ssh_port))
            .arg("true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if up {
            return Err(DryrunError::UnexpectedBoot(format!(
                "SSH came up on a disk with a zeroed MBR boot code — the disk became bootable before \
                 write_mbr_bootcode; console tail:\n{}",
                console_tail(console)
            )));
        }
        if Instant::now() >= deadline {
            return Ok(());                                                                              
        }
        sleep(Duration::from_secs(3));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdeathsig_pins_lifetime_off_exactly_under_keep_running() {
                                                                                                  
                                                                                                 
                                                                                                 
        assert!(
            !qemu_dies_with_parent(&DryrunOpts {
                keep_running: true,
                ..DryrunOpts::default()
            }),
            "a --keep-running VM must outlive the process (PDEATHSIG off)"
        );
        assert!(
            qemu_dies_with_parent(&DryrunOpts {
                keep_running: false,
                ..DryrunOpts::default()
            }),
            "a normal dryrun must not orphan QEMU on a signal (PDEATHSIG on)"
        );
    }

    #[test]
    fn every_qemu_launcher_renders_a_network_directive() {
                                                                                               
                                                                                                   
                                                                                                   
                                                                                                    
                                                                                       
                                                                                                      
                                                                    
                                                        
          
                                                                                                
                                                                                                     
                                                                                                      
                                                                 
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/deploy/dryrun");
        let needle = "Command::new(\"qemu-system-x86_64\")";
        let mut spawns = 0;
        for entry in std::fs::read_dir(&dir).expect("read dryrun dir") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            for (idx, _) in src.match_indices(needle) {
                spawns += 1;
                let rest = &src[idx + needle.len()..];
                                                                                                  
                                                                                               
                let end = [
                    rest.find(needle),
                    rest.find("\nfn "),
                    rest.find("\n    fn "),
                ]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(rest.len());
                assert!(
                    rest[..end].contains("user_netdev_arg")
                        || rest[..end].contains("\"-nic\", \"none\""),
                    "a qemu spawn in {} renders no network directive within its launcher",
                    path.display()
                );
            }
        }
        assert!(
            spawns >= 5,
            "expected >= 5 qemu spawns scanned across dryrun/, found {spawns} — the match form drifted"
        );
    }

    #[test]
    fn user_netdev_arg_wires_restrict_on_iff_hermetic() {
                                                                                   
                                                                                                      
                                                                                           
                                                                                                 
                                                                                                    
                                                                                                         
                                                                                                
                                                                                                     
        let hermetic = user_netdev_arg(&DryrunOpts {
            restrict_net: true,
            ..DryrunOpts::default()
        });
        assert!(
            hermetic.contains(",restrict=on"),
            "restrict_net=true must render restrict=on: {hermetic}"
        );
                                                                                              
                                                                                               
        assert!(
            hermetic.contains("hostfwd=tcp:127.0.0.1:") && hermetic.contains("-:22"),
            "the inbound ssh hostfwd must survive restrict=on, bound to loopback: {hermetic}"
        );
        assert!(
            !hermetic.contains("hostfwd=tcp::"),
            "no hostfwd may bind the wildcard address: {hermetic}"
        );
        let open = user_netdev_arg(&DryrunOpts {
            restrict_net: false,
            ..DryrunOpts::default()
        });
        assert!(
            !open.contains("restrict=on"),
            "restrict_net=false must NOT render restrict=on (self-test: proves the arm is live): {open}"
        );
        assert!(
            open.contains("hostfwd=tcp:127.0.0.1:") && open.contains("-:22"),
            "the inbound ssh hostfwd is present, loopback-bound, in the open form too: {open}"
        );
        assert!(
            !open.contains("hostfwd=tcp::"),
            "no hostfwd may bind the wildcard address in the open form either: {open}"
        );
    }

    /// T7 (os-update A/B v1): the S4-M1 panic-marker scan — the pure half of the migrated
    /// `clean_reboot_and_verify` (the produced-bytes half runs a real misresolved-finish bake under
    /// `make boot-gate-update`, T22). A clean-reboot window (no panic) passes; a `panic=10`-recovery
    /// window (the finish handler misresolved) is caught; and a benign pre-shutdown "panic" mention is
    /// NOT mistaken for a real one (the offset slice is load-bearing).
    #[test]
    fn s4_m1_panic_marker_scan_distinguishes_clean_reboot_from_panic_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let console = dir.path().join("console.log");

                                                                                                           
        let clean = "boot-1: recipes serving\n[  12.3] reboot: Restarting system\nboot-2: recipes serving\n";
        std::fs::write(&console, clean).unwrap();
        assert!(assert_no_kernel_panic_since(&console, 0).is_ok());

                                                                                                         
                                                                                   
        let mark = std::fs::metadata(&console).map(|m| m.len()).unwrap_or(0);
        let panicky = "Kernel panic - not syncing: Attempted to kill init!\nRebooting in 10 seconds..\nboot-2: recipes serving\n";
        std::fs::write(&console, format!("{clean}{panicky}")).unwrap();
        let err = assert_no_kernel_panic_since(&console, mark).unwrap_err();
        assert!(
            err.to_string().contains("PANICKED") && err.to_string().contains("S4-M1"),
            "the S4-M1 catch must name the false-green: {err}"
        );

                                                                                                         
                                                                                                  
        let full = std::fs::read_to_string(&console).unwrap();
        assert!(assert_no_kernel_panic_since(&console, full.len() as u64).is_ok());
    }
}
