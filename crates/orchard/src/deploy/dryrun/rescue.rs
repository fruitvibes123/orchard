//! The rescue-path harness: a corrupt `/persist` diverts to the rescue bundle; assert ONLY rescue comes up + its contract.

use super::assertions::*;
use super::qemu::*;
use super::*;

/// Boot `img` with a DELIBERATELY-CORRUPT `/persist` to force the rescue path, then verify the rescue
/// contract (spec "/persist mount failure behavior"): the box diverts to rescue (the `prepare-persist`/
/// `mount-persist` bootstrap oneshots are `OnFailure::Rescue`; a no-filesystem /persist diverts at
/// `prepare-persist`'s `findfs LABEL=persist` guard, before the mount), bringing up ONLY the rescue
/// dropbear — reachable by the
/// baked recovery pubkey (`recovery_privkey`), presenting the deterministically-derived host key
/// (must equal `expected_rescue_host_fp`, the offline `derive-rescue-host-keys --image
/// --print-fingerprint` precompute — TOFU determinism) and the rescue banner — while recipes does
/// NOT answer. RAII-tears-down QEMU.
pub fn boot_rescue_and_verify(
    img: &Path,
    recovery_privkey: &Path,
    expected_rescue_host_fp: &str,
    opts: &DryrunOpts,
) -> Result<(), DryrunError> {
    preflight()?;
    let layout = parse_layout(&layout_sidecar(img))?;

    let workdir = tempfile::Builder::new()
        .prefix("recipes-rescue-")
        .tempdir()
        .map_err(DryrunError::io("creating rescue workdir"))?;
    let wd = workdir.path();

                                                                                                       
    let vmlinuz = local_artifact(img, "vmlinuz")?;
    let initramfs = local_artifact(img, "initramfs")?;
    let rootfs = wd.join("rootfs");
    let rootfs_data = wd.join("rootfs-data");
    slice(img, layout.rootfs_offset, layout.rootfs_size, &rootfs)?;
    slice(
        img,
        layout.rootfs_offset,
        layout.rootfs_verity_hash_offset,
        &rootfs_data,
    )?;
    let root_hash = recompute_verity_root_hash(&rootfs_data, &wd.join("verity.hash"))?;

                                                                                                    
                                                                                                 
                                                                  
    let persist = wd.join("persist-corrupt.img");
    stage_corrupt_persist(&persist)?;

    let console = wd.join("console.log");
    let mut guard = launch_qemu(
        &vmlinuz,
        &initramfs,
        &rootfs,
        &persist,
        &root_hash,
        layout.rootfs_verity_hash_offset,
        opts,
        &console,
    )?;

                                                                                                   
                                                                                                     
    wait_for_ssh(
        recovery_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        &console,
    )?;
                                                                                                   
                                                                                                    
                                                         
    assert_only_rescue_services(recovery_privkey, opts.ssh_port)?;
    assert_recipes_absent(opts, &mut guard)?;
                                                                                  
    assert_rescue_host_key_matches(opts.ssh_port, expected_rescue_host_fp)?;
                                                               
    assert_rescue_banner(recovery_privkey, opts.ssh_port)?;

    if opts.keep_running {
        let kept = workdir.keep();
        println!(
            "rescue dryrun: VM left running (--keep-running). Connect with:\n  \
             ssh -i {key} -p {port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1\n  \
             Workdir (delete + kill qemu manually when done): {wd}",
            key = recovery_privkey.display(),
            port = opts.ssh_port,
            wd = kept.display(),
        );
    }
    Ok(())
}

/// Acceptance #3b: boot with a real ext4 `/persist` corrupted to `e2fsck -p` rc=4 → the box must divert
/// to RESCUE (prepare-persist's `(rc & 0xFC) != 0` branch), never silently mount a corrupt /persist and
/// never reboot-loop. Reuses the same rescue contract as [`boot_rescue_and_verify`], but stages a real
/// rc=4 fs (not a no-fs disk) so it exercises the rc=4 path the no-fs case (findfs miss / rc≈8) does not.
/// Operator-run (needs mke2fs/dd + QEMU/KVM).
pub fn boot_rc4_corrupt_persist_and_verify(
    img: &Path,
    recovery_privkey: &Path,
    expected_rescue_host_fp: &str,
    opts: &DryrunOpts,
) -> Result<(), DryrunError> {
    preflight()?;
    let layout = parse_layout(&layout_sidecar(img))?;
    let workdir = tempfile::Builder::new()
        .prefix("recipes-rc4-")
        .tempdir()
        .map_err(DryrunError::io("creating rc4 workdir"))?;
    let wd = workdir.path();

    let vmlinuz = local_artifact(img, "vmlinuz")?;
    let initramfs = local_artifact(img, "initramfs")?;
    let rootfs = wd.join("rootfs");
    let rootfs_data = wd.join("rootfs-data");
    slice(img, layout.rootfs_offset, layout.rootfs_size, &rootfs)?;
    slice(
        img,
        layout.rootfs_offset,
        layout.rootfs_verity_hash_offset,
        &rootfs_data,
    )?;
    let root_hash = recompute_verity_root_hash(&rootfs_data, &wd.join("verity.hash"))?;

                                                                                                            
    let persist = wd.join("persist-rc4.img");
    stage_rc4_corrupt_persist(&persist)?;

    let console = wd.join("console.log");
    let mut guard = launch_qemu(
        &vmlinuz,
        &initramfs,
        &rootfs,
        &persist,
        &root_hash,
        layout.rootfs_verity_hash_offset,
        opts,
        &console,
    )?;
                                                                                                    
                                                         
    wait_for_ssh(
        recovery_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        &console,
    )?;
    assert_only_rescue_services(recovery_privkey, opts.ssh_port)?;
    assert_recipes_absent(opts, &mut guard)?;
    assert_rescue_host_key_matches(opts.ssh_port, expected_rescue_host_fp)?;
    assert_rescue_banner(recovery_privkey, opts.ssh_port)?;
    Ok(())
}

/// A raw 256 MiB disk with NO filesystem — `mount /persist` fails on it, forcing the rescue path.
fn stage_corrupt_persist(persist: &Path) -> Result<(), DryrunError> {
    let file = File::create(persist).map_err(DryrunError::io(format!(
        "create corrupt persist {}",
        persist.display()
    )))?;
    file.set_len(256 * 1024 * 1024)
        .map_err(DryrunError::io("sizing corrupt persist disk"))?;
    Ok(())
}

/// A REAL ext4 labelled `persist`, corrupted so `e2fsck -p` returns rc=4 (uncorrectable in preen mode →
/// box-init's prepare-persist diverts to rescue). Unlike `stage_corrupt_persist` (no fs → findfs miss /
/// rc≈8), this exercises the rc=4 BRANCH of the `(rc & 0xFC) != 0` gate end-to-end (acceptance #3b). The
/// primary superblock + LABEL stay intact (so `findfs LABEL=persist` resolves it and `e2fsck` opens it),
/// but the root inode is unrepairable-in-preen AND the clean flag is cleared (so `e2fsck -p` force-scans,
/// like the box's not-cleanly-unmounted post-crash fs). Verified 5/5 stable on e2fsprogs 1.47.x. Needs
/// `mke2fs` + `debugfs` (e2fsprogs / e2fsprogs-extra — present on the box, the build container, and the
/// gate host); if a future e2fsprogs changes the preen disposition, re-confirm `e2fsck -p` still returns
/// an error bit (any of `0xFC` diverts — rc=4 is the target, but rc=8 would also gate to rescue).
fn stage_rc4_corrupt_persist(persist: &Path) -> Result<(), DryrunError> {
    let path = persist.to_str().ok_or_else(|| {
        DryrunError::PersistStage(format!("non-utf8 persist path {}", persist.display()))
    })?;
                                                                                                         
                                                                                                     
    let f = File::create(persist).map_err(DryrunError::io("create rc4 persist"))?;
    f.set_len(256 * 1024 * 1024)
        .map_err(DryrunError::io("sizing rc4 persist"))?;
    drop(f);
    run_tool(
        "mke2fs",
        &[
            "-F",
            "-q",
            "-t",
            "ext4",
            "-b",
            "4096",
            "-L",
            "persist",
            "-O",
            "^has_journal",
            "-E",
            "lazy_itable_init=0",
            path,
        ],
    )?;
                                                                                                         
                                                                                                         
    run_tool("debugfs", &["-w", "-R", "sif <2> block[0] 9999999", path])?;
                                                                                                            
                                                                                                           
    run_tool("debugfs", &["-w", "-R", "ssv state 0", path])?;
    Ok(())
}

/// (a) In rescue, recipes/haproxy are NOT started. Probe a few times after dropbear is up; ANY
/// 2xx/3xx means a normal service leaked into rescue mode (a fail-open we must catch).
fn assert_recipes_absent(opts: &DryrunOpts, guard: &mut QemuGuard) -> Result<(), DryrunError> {
    for _ in 0..5 {
        if let Ok(Some(status)) = guard.child.try_wait() {
            return Err(DryrunError::BootFailed(format!(
                "qemu exited early ({status}) during the rescue absence check"
            )));
        }
        if let Some(code) =
            http_probe(opts.https_port, &opts.probe_path).filter(|n| (200..400).contains(n))
        {
            return Err(DryrunError::RescueServicesLeaked(format!(
                "recipes answered HTTP {code} in rescue mode (only the rescue dropbear should be up)"
            )));
        }
        sleep(Duration::from_secs(2));
    }
    Ok(())
}

/// (a, structural) The supervised scandir (`/run/service`, the tmpfs `s6-svscan` scans) must hold
/// ONLY the rescue bundle — no normal-service servicedir leaked in. Reads the structural fact
/// directly (timing-immune), closing the false-green window a fixed-duration HTTP probe leaves for a
/// future "service-leaked-into-rescue" regression.
fn assert_only_rescue_services(privkey: &Path, ssh_port: u16) -> Result<(), DryrunError> {
    let output = Command::new("ssh")
        .args(ssh_base_args(privkey, ssh_port))
        .arg("ls -1 /run/service")
        .output()
        .map_err(|e| DryrunError::RescueServicesLeaked(format!("ssh ls /run/service: {e}")))?;
    if !output.status.success() {
        return Err(DryrunError::RescueServicesLeaked(format!(
            "ssh ls /run/service exited {}",
            output.status
        )));
    }
    let leaked: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty() && !name.starts_with('.') && !name.starts_with("rescue-"))
        .map(str::to_string)
        .collect();
    if leaked.is_empty() {
        Ok(())
    } else {
        Err(DryrunError::RescueServicesLeaked(format!(
            "non-rescue servicedir(s) supervised in rescue mode: {} (only rescue-* should be present)",
            leaked.join(", ")
        )))
    }
}

/// The ed25519 host key the rescue dropbear presents, as an OpenSSH `SHA256:…` fingerprint.
pub(super) fn rescue_host_key_fingerprint(ssh_port: u16) -> Option<String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "ssh-keyscan -p {ssh_port} -t ed25519 127.0.0.1 2>/dev/null | ssh-keygen -lf -"
        ))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find(|t| t.starts_with("SHA256:"))
        .map(str::to_string)
}

/// (b) TOFU determinism: the rescue dropbear's host key must equal the offline precompute.
fn assert_rescue_host_key_matches(ssh_port: u16, expected_fp: &str) -> Result<(), DryrunError> {
    let Some(got) = rescue_host_key_fingerprint(ssh_port) else {
                                                                                               
                                                                                                       
        return Err(DryrunError::RescueHostKeyMismatch {
            expected: expected_fp.to_string(),
            got: "NONE — the rescue dropbear presented no ed25519 host key".to_string(),
        });
    };
    if got == expected_fp {
        Ok(())
    } else {
        Err(DryrunError::RescueHostKeyMismatch {
            expected: expected_fp.to_string(),
            got,
        })
    }
}

/// (d) The rescue dropbear's banner (`/etc/dropbear/rescue-banner`) is present + reads "RESCUE MODE".
fn assert_rescue_banner(privkey: &Path, ssh_port: u16) -> Result<(), DryrunError> {
    let out = Command::new("ssh")
        .args(ssh_base_args(privkey, ssh_port))
        .arg("cat /etc/dropbear/rescue-banner")
        .output()
        .map_err(|e| DryrunError::RescueBannerMissing(format!("ssh cat rescue-banner: {e}")))?;
    let banner = String::from_utf8_lossy(&out.stdout);
    if out.status.success() && banner.contains("RESCUE MODE") {
        Ok(())
    } else {
        Err(DryrunError::RescueBannerMissing(format!(
            "expected a 'RESCUE MODE' banner, got: {}",
            banner.trim()
        )))
    }
}
