//! The `-kernel` runtime dryrun: boot a built `.img` + verify the Phase-3 contract (dropbear / recipes / RO rootfs).

use super::assertions::*;
use super::qemu::*;
use super::*;

/// Boot `img` under QEMU/KVM and verify the runtime contract (dropbear pubkey / recipes HTTP /
/// ro rootfs). `img`'s sibling `<img-stem>.layout.toml` must be present. RAII-tears-down QEMU.
pub fn boot_and_verify(img: &Path, opts: &DryrunOpts) -> Result<(), DryrunError> {
    preflight()?;

    let layout_path = layout_sidecar(img);
    let layout = parse_layout(&layout_path)?;

    let workdir = tempfile::Builder::new()
        .prefix("recipes-dryrun-")
        .tempdir()
        .map_err(DryrunError::io("creating dryrun workdir"))?;
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

                                                                 
    let privkey = wd.join("id");
    let pubkey = wd.join("id.pub");
    ssh_keygen(&privkey)?;

                                                                                                     
    let persist = wd.join("persist.img");
    stage_persist_disk(&pubkey, wd, &persist)?;

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
        &privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        &console,
    )?;
                                                                                                        
                                                                                                    
    match &opts.service_check {
        ServiceCheck::RecipesHttp => assert_recipes_http(opts, &mut guard)?,
        ServiceCheck::SupervisedUp(svc) => {
            assert_service_supervised(&privkey, opts.ssh_port, svc, opts.boot_timeout, &mut guard)?
        }
    }
                                                    
    assert_rootfs_ro(&privkey, opts.ssh_port)?;

    if opts.keep_running {
        let kept = workdir.keep();                                                          
        println!(
            "dryrun: VM left running (--keep-running). Connect with:\n  \
             ssh -i {key} -p {port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1\n  \
             curl -k https://127.0.0.1:{https}/\nWorkdir (delete + kill qemu manually when done): {wd}",
            key = kept.join("id").display(),
            port = opts.ssh_port,
            https = opts.https_port,
            wd = kept.display(),
        );
    }
    Ok(())
}

/// Build a 256 MiB `LABEL=persist` ext4 image with the operator pubkey at
/// `/etc/ssh/authorized_keys.d/root`, owned root:root (via `fakeroot` so dropbear's
/// `checkpubkeyperms` accepts it — the file + parents must not be group/other-writable).
pub(super) fn stage_persist_disk(
    pubkey: &Path,
    wd: &Path,
    persist: &Path,
) -> Result<(), DryrunError> {
    let file = File::create(persist)
        .map_err(|e| DryrunError::PersistStage(format!("create {}: {e}", persist.display())))?;
    file.set_len(256 * 1024 * 1024)
        .map_err(|e| DryrunError::PersistStage(format!("truncate persist.img: {e}")))?;
    drop(file);

    let tree = wd.join("persist-tree");
                                                                                             
                                                                
    let script = r#"set -e
TREE="$1"; PUB="$2"; IMG="$3"
mkdir -p "$TREE/etc/ssh/authorized_keys.d"
cp "$PUB" "$TREE/etc/ssh/authorized_keys.d/root"
chmod 0644 "$TREE/etc/ssh/authorized_keys.d/root"
chmod 0755 "$TREE" "$TREE/etc" "$TREE/etc/ssh" "$TREE/etc/ssh/authorized_keys.d"
chown -R 0:0 "$TREE"
mke2fs -t ext4 -d "$TREE" -L persist -F -q "$IMG"
"#;
    let status = Command::new("fakeroot")
        .args(["--", "bash", "-c", script, "bash"])
        .arg(&tree)
        .arg(pubkey)
        .arg(persist)
        .status()
        .map_err(|e| DryrunError::PersistStage(format!("spawn fakeroot: {e}")))?;
    if !status.success() {
        return Err(DryrunError::PersistStage(format!(
            "fakeroot/mke2fs exited {status}"
        )));
    }
    Ok(())
}

/// A booted box left running for an external gate to drive (the T10 lifecycle gate). Holds the QEMU child
/// (RAII-killed on Drop; `PR_SET_PDEATHSIG` backstops an uncatchable signal since the gate runs
/// `keep_running=false`) + the workdir carrying the INSTALLED disk + the forwarded SSH endpoint + the
/// box's host-key fingerprint (so `orchard status`/`rotate-key` pin it non-interactively via
/// `--host-fingerprint`). Drop order (declaration order): the QEMU guard first (kill the VM, releasing the
/// disk file), then the workdir (delete the installed disk + slices).
pub struct LiveBox {
    _guard: QemuGuard,
    _workdir: tempfile::TempDir,
    pub host: String,
    pub ssh_port: u16,
    /// The operator private key the box was BUILT with (`--operator-pubkey` baked its `ssh-keygen -y`
    /// line into the persist-skeleton's `authorized_keys.d/root`) — the login the gate authenticates,
    /// reads, and rotates. Its derived line EQUALS `rotate_key::derive_line(operator_privkey)`, which the
    /// strict content-gate requires (a `.pub` baked with a `user@host` comment would be refused).
    pub operator_privkey: PathBuf,
    pub host_fingerprint: String,
    /// The box-side operator authorized_keys file the rotate-key gate reads/asserts (G1) — the SAME path
    /// `rotate_key`/`SshBox` target, so the gate and the verbs can never drift apart.
    pub authorized_keys_remote: String,
}

/// Boot `img` (a seabios-gpt A/B `.img`) THROUGH THE REAL dd-only INSTALL + SeaBIOS BOOT path and hand
/// back a live [`LiveBox`] the caller drives. The gate needs a seabios-gpt box — the ONLY kind carrying
                                                                                                          
/// `fb-init` selects slot-A by baked PARTUUID (like UEFI), REFUSING a bare `/dev/vda` by design. So the
/// `-kernel` raw-whole-disk dryrun path ([`boot_and_verify`]) CANNOT boot it; we instead run the SAME
/// dd-only installer the §8 gate proves ([`install_disk_and_verify`]'s `stage_install_disk` →
/// `run_installer_phase` → `boot_installed_disk`), then boot the INSTALLED disk. `operator_privkey` is the
/// key the `.img` was built with (its derived line is what the persist-skeleton bakes) — the login the
/// gate authenticates + rotates. Verifies dropbear-up (that baked key authenticates → the box reached
/// services, not rescue) before returning; the caller holds the guard, which keeps the VM alive until the
/// gate drops the [`LiveBox`].
pub fn boot_lifecycle_box(
    img: &Path,
    operator_privkey: &Path,
    opts: &DryrunOpts,
) -> Result<LiveBox, DryrunError> {
    preflight()?;
    let layout = parse_layout(&layout_sidecar(img))?;
    let vmlinuz = local_artifact(img, "vmlinuz")?;
    let initramfs = local_artifact(img, "initramfs")?;

    let workdir = tempfile::Builder::new()
        .prefix("recipes-lifecycle-gate-")
        .tempdir()
        .map_err(DryrunError::io("creating lifecycle-gate workdir"))?;
    let wd = workdir.path().to_path_buf();

                                                                                                        
                                                                                                         
                                                                                                           
                                                               
    let log_dir = std::env::var_os("RECIPES_PROD_GATE_LOGDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| wd.clone());
    if log_dir != wd {
        std::fs::create_dir_all(&log_dir)
            .map_err(DryrunError::io("creating lifecycle-gate log dir"))?;
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

                                                                                                
                                                                                                    
    let disk = wd.join("install-disk.img");
    let layout_info = super::install_seabios::gate_layout_info(
        &layout,
        crate::deploy::build_image::Firmware::SeabiosGpt,
    );
    let window = super::install_seabios::stage_install_disk(&image, &layout_info, &wd, &disk)?;
    let staged_sha = recipes_image_builder::image::sha256_hex(&image);
    super::install_seabios::run_installer_phase(
        &vmlinuz,
        &initramfs,
        &disk,
        &root_hash,
        layout.rootfs_verity_hash_offset,
        &layout_info,
        &window,
        &staged_sha,
        None,                                        
        None,                       
        opts,
        &log_dir.join("install-console.log"),
    )?;

                                                                                                           
                                                                                                    
    let console = log_dir.join("boot-console.log");
    let mut guard = boot_installed_disk(&disk, opts, &console, true)?;
                                                                                                  
                                                                                              
    wait_for_ssh(
        operator_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        &console,
    )?;

    let host_fingerprint = keyscan_fingerprint("127.0.0.1", opts.ssh_port)?;
    Ok(LiveBox {
        _guard: guard,
        _workdir: workdir,
        host: "127.0.0.1".to_string(),
        ssh_port: opts.ssh_port,
        operator_privkey: operator_privkey.to_path_buf(),
        host_fingerprint,
        authorized_keys_remote: crate::deploy::lifecycle::AUTHORIZED_KEYS_REMOTE_PATH.to_string(),
    })
}

/// ssh-keyscan the booted box's ed25519 host key → its `SHA256:…` fingerprint (for non-interactive
/// `--host-fingerprint` pinning).
fn keyscan_fingerprint(host: &str, port: u16) -> Result<String, DryrunError> {
    let scan = Command::new("ssh-keyscan")
        .args(["-t", "ed25519", "-p", &port.to_string(), host])
        .output()
        .map_err(|e| DryrunError::BootFailed(format!("ssh-keyscan: {e}")))?;
    let text = String::from_utf8_lossy(&scan.stdout);
    let line = text
        .lines()
        .find(|l| l.contains("ssh-ed25519") && !l.trim_start().starts_with('#'))
        .ok_or_else(|| {
            DryrunError::BootFailed("ssh-keyscan returned no ed25519 host key".into())
        })?;
    let mut f = tempfile::NamedTempFile::new()
        .map_err(|e| DryrunError::BootFailed(format!("keyscan temp: {e}")))?;
    use std::io::Write as _;
    writeln!(f, "{}", line.trim())
        .map_err(|e| DryrunError::BootFailed(format!("write keyscan: {e}")))?;
    let fpr = Command::new("ssh-keygen")
        .args(["-lf", &f.path().display().to_string()])
        .output()
        .map_err(|e| DryrunError::BootFailed(format!("ssh-keygen -lf: {e}")))?;
    String::from_utf8_lossy(&fpr.stdout)
        .split_whitespace()
        .find(|t| t.starts_with("SHA256:"))
        .map(str::to_string)
        .ok_or_else(|| DryrunError::BootFailed("ssh-keygen produced no SHA256 fingerprint".into()))
}
