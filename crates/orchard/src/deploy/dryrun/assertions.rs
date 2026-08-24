//! Runtime-contract assertions over SSH/HTTP — recipes serves, rootfs is RO, the cmdline rootfs-dev/PARTUUID, persist grown.

use super::install_seabios::GATE_ROOTFS_DEV;
use super::qemu::*;
use super::*;

pub(super) fn assert_recipes_http(
    opts: &DryrunOpts,
    guard: &mut QemuGuard,
) -> Result<(), DryrunError> {
                                                                                                      
                                                                                                 
    let https_port = opts.https_port;
    let timeout = opts.boot_timeout;
    let deadline = Instant::now() + timeout;
    let url = format!("https://127.0.0.1:{https_port}{}", opts.probe_path);
    let mut last = String::from("(no response)");
    loop {
        if let Ok(Some(status)) = guard.child.try_wait() {
            return Err(DryrunError::BootFailed(format!(
                "qemu exited early ({status}) before recipes answered"
            )));
        }
                                                                                           
        match http_probe(https_port, &opts.probe_path) {
            Some(n) if (200..400).contains(&n) => return Ok(()),
            Some(n) => last = n.to_string(),
            None => {}
        }
        if Instant::now() >= deadline {
            return Err(DryrunError::HttpAssertFailed(format!(
                "recipes did not return 2xx/3xx on {url} within {}s (last HTTP code: {last})",
                timeout.as_secs()
            )));
        }
        sleep(Duration::from_secs(2));
    }
}

                                                                                                 
/// SSHes in + polls `s6-svstat /run/service/<svc>` (box-init's live tmpfs scandir) until it reports
/// `up (pid …)` — proving the box-init topology + s6 supervision boot a non-recipes tenant's services,
/// without asserting a recipes-specific HTTP contract. Services come up in parallel with dropbear, so
/// this polls to the boot timeout (and bails if QEMU dies early).
pub(super) fn assert_service_supervised(
    privkey: &Path,
    ssh_port: u16,
    svc: &str,
    timeout: Duration,
    guard: &mut QemuGuard,
) -> Result<(), DryrunError> {
    let deadline = Instant::now() + timeout;
    let svpath = format!("/run/service/{svc}");
    let mut last = String::from("(no s6-svstat output)");
    loop {
        if let Ok(Some(status)) = guard.child.try_wait() {
            return Err(DryrunError::BootFailed(format!(
                "qemu exited early ({status}) before the {svc} service was supervised"
            )));
        }
        if let Ok(o) = Command::new("ssh")
            .args(ssh_base_args(privkey, ssh_port))
            .arg(format!("s6-svstat {svpath}"))
            .output()
        {
            let report = String::from_utf8_lossy(&o.stdout);
                                                                                                 
            if o.status.success() && report.trim_start().starts_with("up (pid") {
                return Ok(());
            }
            if !report.trim().is_empty() {
                last = report.trim().to_string();
            }
        }
        if Instant::now() >= deadline {
            return Err(DryrunError::ServiceNotSupervised(format!(
                "{svpath} not `up (pid …)` within {}s; last s6-svstat: {last}",
                timeout.as_secs()
            )));
        }
        sleep(Duration::from_secs(2));
    }
}

pub(crate) fn assert_rootfs_ro(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let output = Command::new("ssh")
        .args(ssh_base_args(privkey, port))
        .arg("cat /proc/mounts")
        .output()
        .map_err(|e| DryrunError::RootfsNotReadOnly(format!("ssh cat /proc/mounts: {e}")))?;
    if !output.status.success() {
        return Err(DryrunError::RootfsNotReadOnly(format!(
            "ssh cat /proc/mounts exited {}",
            output.status
        )));
    }
    let mounts = String::from_utf8_lossy(&output.stdout);
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 && fields[1] == "/" {
                                                                                                        
                                                                                                       
                                                                                                         
                                                                                                         
                                                                                        
            let (dev, fstype, opts) = (fields[0], fields[2], fields[3]);
            if fstype == "squashfs" && opts.split(',').any(|opt| opt == "ro") {
                return Ok(());
            }
            return Err(DryrunError::RootfsNotReadOnly(format!(
                "/ must be a ro squashfs (the verity RO image); got device={dev} fstype={fstype} opts={opts}"
            )));
        }
    }
    Err(DryrunError::RootfsNotReadOnly(
        "no / mount in /proc/mounts".to_string(),
    ))
}

/// SSH `sync` into the box to flush `/persist` to disk. Used before the crash-sim unclean kill so the
/// crash-recovery boot tests **Case B — a crash of a PROVISIONED box**: the SIGKILL still leaves the fs
/// "not cleanly unmounted" (so `prepare-persist`'s `e2fsck -p` journal-replay recovery IS exercised),
/// but boot-1's `/persist` app state (`cookie.key`, the CA, the DB) is DURABLE → recipes must serve 303
/// again. Without the sync the immediate kill loses those just-written files and recipes/haproxy can't
/// start — a separate app-layer FIRST-BOOT-PROVISIONING durability gap, documented as a follow-up
                                                                                                 
pub(super) fn sync_persist_over_ssh(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let status = Command::new("ssh")
        .args(ssh_base_args(privkey, port))
        .arg("sync")
        .status()
        .map_err(|e| DryrunError::BootFailed(format!("ssh sync: {e}")))?;
    if !status.success() {
        return Err(DryrunError::BootFailed(format!("ssh sync exited {status}")));
    }
    Ok(())
}

/// Probe `https://127.0.0.1:<port>/` (curl -k — the box serves a self-signed cert). `Some(code)` iff
/// curl got an HTTP response; `None` on connection refused / timeout / no listener (curl's `000`).
pub(super) fn http_probe(https_port: u16, probe_path: &str) -> Option<u16> {
    let url = format!("https://127.0.0.1:{https_port}{probe_path}");
    let out = Command::new("curl")
        .args([
            "-k",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "10",
            &url,
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|n| *n != 0)
}

/// §8: `/proc/cmdline` shows the byte-patched `fb.rootfs-dev=/dev/vda2` (NOT the sentinel) — and
/// the baked `fb.net=` (proving `--net` reached the box, which is why it's NOT in rescue).
pub(super) fn assert_cmdline_rootfs_dev(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let output = Command::new("ssh")
        .args(ssh_base_args(privkey, port))
        .arg("cat /proc/cmdline")
        .output()
        .map_err(|e| DryrunError::CmdlineAssertFailed(format!("ssh cat /proc/cmdline: {e}")))?;
    if !output.status.success() {
        return Err(DryrunError::CmdlineAssertFailed(format!(
            "ssh cat /proc/cmdline exited {}",
            output.status
        )));
    }
    let cmdline = String::from_utf8_lossy(&output.stdout);
    let sentinel = recipes_image_builder::boot_fs::ROOTFS_DEV_SENTINEL;
    if cmdline.contains(sentinel) {
        return Err(DryrunError::CmdlineAssertFailed(format!(
            "the rootfs-dev sentinel {sentinel:?} is still on the cmdline — the byte-patch did not take: {cmdline:?}"
        )));
    }
    if !cmdline
        .split_whitespace()
        .any(|t| t == format!("fb.rootfs-dev={GATE_ROOTFS_DEV}"))
    {
        return Err(DryrunError::CmdlineAssertFailed(format!(
            "expected fb.rootfs-dev={GATE_ROOTFS_DEV} on the cmdline: {cmdline:?}"
        )));
    }
    if !cmdline.contains("fb.net=mode=static") {
        return Err(DryrunError::CmdlineAssertFailed(format!(
            "expected the baked fb.net=mode=static… on the cmdline (the box would be in rescue without it): {cmdline:?}"
        )));
    }
    Ok(())
}

/// SeabiosGpt §8 cmdline assertion: the runtime `/proc/cmdline` carries the BAKED rootfs selection —
/// `fb.firmware=seabios-gpt` + `fb.rootfs-dev=PARTUUID=<SLOT_A_PARTUUID>` (resolved in-init against the
/// on-disk GPT) — with NO `/dev` byte-patch and NO sentinel (the GPT-PARTUUID path is patch-free, like
/// UEFI). This is the runtime end of the H-1 seam: the box learned it is SeabiosGpt from the cmdline.
pub(super) fn assert_cmdline_partuuid(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let output = Command::new("ssh")
        .args(ssh_base_args(privkey, port))
        .arg("cat /proc/cmdline")
        .output()
        .map_err(|e| DryrunError::CmdlineAssertFailed(format!("ssh cat /proc/cmdline: {e}")))?;
    if !output.status.success() {
        return Err(DryrunError::CmdlineAssertFailed(format!(
            "ssh cat /proc/cmdline exited {}",
            output.status
        )));
    }
    let cmdline = String::from_utf8_lossy(&output.stdout);
    let sentinel = recipes_image_builder::boot_fs::ROOTFS_DEV_SENTINEL;
    if cmdline.contains(sentinel) {
        return Err(DryrunError::CmdlineAssertFailed(format!(
            "SeabiosGpt must bake the PARTUUID, never the deploy sentinel {sentinel:?}: {cmdline:?}"
        )));
    }
    if !cmdline
        .split_whitespace()
        .any(|t| t == "fb.firmware=seabios-gpt")
    {
        return Err(DryrunError::CmdlineAssertFailed(format!(
            "expected fb.firmware=seabios-gpt on the cmdline: {cmdline:?}"
        )));
    }
    let want = format!(
        "fb.rootfs-dev=PARTUUID={}",
        recipes_image_builder::boot_fs::SLOT_A_PARTUUID
    );
    if !cmdline.split_whitespace().any(|t| t == want) {
        return Err(DryrunError::CmdlineAssertFailed(format!(
            "expected {want} on the cmdline (the baked GPT PARTUUID): {cmdline:?}"
        )));
    }
    if !cmdline.contains("fb.net=mode=static") {
        return Err(DryrunError::CmdlineAssertFailed(format!(
            "expected the baked fb.net=mode=static… on the cmdline: {cmdline:?}"
        )));
    }
    Ok(())
}

/// §8: the persist partition was resize2fs-grown to fill its partition on first boot. The pre-baked
/// skeleton is 16 MiB; after grow it is ~1.25 GiB on the [`GATE_INSTALL_DISK_BYTES`] disk. Assert the
/// persist filesystem is well above the skeleton size (proving the first-boot grow ran), via `df`.
pub(super) fn assert_persist_grown(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let output = Command::new("ssh")
        .args(ssh_base_args(privkey, port))
        .arg("df -P -k /persist")
        .output()
        .map_err(|e| DryrunError::PersistNotGrown(format!("ssh df /persist: {e}")))?;
    if !output.status.success() {
        return Err(DryrunError::PersistNotGrown(format!(
            "ssh df -P -k /persist exited {} (is /persist mounted?)",
            output.status
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
                                                                                  
    let total_kib: u64 = text
        .lines()
        .last()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|b| b.parse().ok())
        .ok_or_else(|| {
            DryrunError::PersistNotGrown(format!("could not parse df output: {text:?}"))
        })?;
                                                                                                       
    const MIN_GROWN_KIB: u64 = 256 * 1024;
    if total_kib < MIN_GROWN_KIB {
        return Err(DryrunError::PersistNotGrown(format!(
            "persist is {total_kib} KiB — not grown past the 16 MiB skeleton (expected > {MIN_GROWN_KIB} KiB); resize2fs did not run"
        )));
    }
    Ok(())
}
