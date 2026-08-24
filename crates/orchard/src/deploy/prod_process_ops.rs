//! `ProcessOps` — the real [`OrchestrationOps`] over `std::process::Command`: the FFI half of the
//! deploy-prod ceremony (hardened ssh/scp subprocesses, ssh-keyscan, the offline runtime-hostkey
//! derivation, veritysetup — all `Command` argv, never a local shell). Split out of
//! `prod_orchestrate.rs` for file length; a CHILD module of it, so `use super::*` reaches the flow's
//! private helpers (`firmware_deploy_eligible` / `layout_firmware_token`), the `OrchestrationOps`
//! trait, and the shared types without widening their visibility.

use super::*;
use crate::deploy::prod::{self, WipeConfirmed};
use std::path::Path;

/// The process-global cancellation flag SIGINT/SIGTERM handlers set (the only async-signal-safe
/// thing a handler may do here); the flow polls it between gates via
/// [`OrchestrationOps::cancel_requested`].
static CANCEL_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn set_cancel_flag(_sig: libc::c_int) {
                                                                                     
                                         
    CANCEL_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Install the SIGINT/SIGTERM → flag handlers (call once from the CLI arm before `deploy_prod`).
/// Replaces the default die-immediately disposition so a Ctrl-C lands on the next gate poll with
                                                                         
pub fn install_cancel_handler() {
                                                                                              
                                                         
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = set_cancel_flag as *const () as usize;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

/// The real [`OrchestrationOps`]: hardened ssh/scp subprocesses (pdeathsig-armed), ssh-keyscan,
/// the rescue_keys offline derivation, and veritysetup — all `Command` argv, never a local shell.
pub struct ProcessOps {
    pub ip: String,
    /// The target's sshd port — 22 for a real VPS; a forwarded high port under the QEMU e2e
    /// harness (the box reuses 22, so ONE port covers both legs through the same hostfwd).
    pub ssh_port: u16,
    /// Leg-A identity (the provisioning Debian's injected root key).
    pub ssh_identity: std::path::PathBuf,
    /// Leg-B identity (the operator's box-login key — `--pubkey`'s private half).
    pub box_login_identity: std::path::PathBuf,
    /// Leg-A known_hosts (operator-supplied via `--known-hosts`, or a flow-controlled temp file).
    pub provisioning_known_hosts: std::path::PathBuf,
    /// Leg-B known_hosts (always flow-controlled; pinned to the derived runtime key).
    pub reconnect_known_hosts: std::path::PathBuf,
    /// Component 1: the previous step-banner's start epoch, for elapsed-on-completion. `None` until
    /// the first `step()`. Display-only — never affects the ceremony.
    pub step_started: Option<i64>,
}

impl ProcessOps {
    fn leg_args(&self, leg: Leg) -> Vec<String> {
        match leg {
            Leg::Provisioning => prod_ssh_args(
                &self.ip,
                &self.ssh_identity,
                &self.provisioning_known_hosts,
                self.ssh_port,
            ),
            Leg::Reconnect => prod_ssh_args(
                &self.ip,
                &self.box_login_identity,
                &self.reconnect_known_hosts,
                self.ssh_port,
            ),
        }
    }

    fn run_capture(mut cmd: std::process::Command, what: &str) -> Result<String, String> {
        arm_pdeathsig(&mut cmd);
        let out = cmd.output().map_err(|e| format!("spawn {what}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "{what} exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl OrchestrationOps for ProcessOps {
    fn stdin_is_tty(&self) -> bool {
                                                  
        unsafe { libc::isatty(0) == 1 }
    }

    /// Prints the numbered banner + the PREVIOUS step's elapsed (lazily, on the next `step()`). The
    /// ceremony's FINAL step has no successor `step()`, so its own elapsed is not printed here — the
                                                                                                      
    fn step(&mut self, n: u32, of: u32, label: &str) {
        let now = self.now_epoch();
        if let Some(t0) = self.step_started.replace(now) {
            println!("  \u{2026} step {} done ({}s)", n - 1, now - t0);
        }
        println!("\nstep {n}/{of}: {label}");
    }

    fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    fn ambient_known_hosts_conflict(
        &self,
        ip: &str,
        presented_type: &str,
        presented_key: &str,
    ) -> Option<String> {
                                                                                                    
                                                                                                
        let home = std::env::var_os("HOME")?;
        let content =
            std::fs::read_to_string(std::path::Path::new(&home).join(".ssh/known_hosts")).ok()?;
        known_hosts_conflict_in(&content, ip, presented_type, presented_key)
    }

    fn say(&mut self, msg: &str) {
        println!("{msg}");
    }

    fn read_line(&mut self, prompt: &str) -> Option<String> {
        use std::io::Write as _;
        print!("{prompt} ");
        std::io::stdout().flush().ok()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok()?;
        Some(line)
    }

    fn cancel_requested(&self) -> bool {
        CANCEL_REQUESTED.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn sleep_secs(&mut self, secs: u64) {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }

    fn now_epoch(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn read_image_artifacts(&mut self, image: &Path) -> Result<ImageArtifacts, String> {
        let read = |p: &Path| -> Result<Vec<u8>, String> {
            std::fs::read(p).map_err(|e| format!("read {}: {e}", p.display()))
        };
        let read_text = |p: &Path| -> Result<String, String> {
            std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))
        };
        let err_str = |e: crate::deploy::dryrun::DryrunError| e.to_string();
        let vmlinuz_path =
            crate::deploy::dryrun::local_artifact(image, "vmlinuz").map_err(err_str)?;
        let initramfs_path =
            crate::deploy::dryrun::local_artifact(image, "initramfs").map_err(err_str)?;
        let layout_path = crate::deploy::dryrun::layout_sidecar(image);
        let layout_text = read_text(&layout_path)?;
                                                                                                     
                                                                                                            
                                                                                                  
                                                                                               
                                                                                                
                                                                                                    
                                                                                                
                                     
        let firmware = firmware_deploy_eligible(layout_firmware_token(&layout_text).as_deref())
            .map_err(|e| format!("{} {e}", image.display()))?;
        let l = crate::deploy::dryrun::parse_layout(&layout_path).map_err(err_str)?;
        let fpr_path = image.with_extension("operator-pubkey.fpr");
                                                                                                   
                                                                                                  
        let img_len = std::fs::metadata(image)
            .map_err(|e| format!("stat {}: {e}", image.display()))?
            .len();
        Ok(ImageArtifacts {
            img_len,
            vmlinuz: read(&vmlinuz_path)?,
            initramfs: read(&initramfs_path)?,
            layout: LayoutInfo {
                boot_offset: l.boot_offset,
                boot_size: l.boot_size,
                persist_skeleton_offset: l.persist_skeleton_offset,
                persist_skeleton_size: l.persist_skeleton_size,
                rootfs_offset: l.rootfs_offset,
                rootfs_size: l.rootfs_size,
                rootfs_verity_hash_offset: l.rootfs_verity_hash_offset,
                firmware,
                weights_offset: l.weights_offset,
                weights_size: l.weights_size,
            },
            img_sha_sidecar: read_text(&image.with_extension("sha256"))?,
            vmlinuz_sha_sidecar: read_text(&image.with_extension("vmlinuz.sha256"))?,
            initramfs_sha_sidecar: read_text(&image.with_extension("initramfs.sha256"))?,
            operator_pubkey_fpr_sidecar: std::fs::read_to_string(&fpr_path).ok(),
            img_path: image.to_path_buf(),
            vmlinuz_path,
            initramfs_path,
            layout_path,
        })
    }

    fn local_pubkey_fingerprint(&mut self, pubkey: &Path) -> Result<String, String> {
        let line = crate::deploy::build_image::read_validated_pubkey("operator", pubkey)
            .map_err(|e| e.to_string())?;
        let out = crate::deploy::build_image::ssh_keygen_pipe(
            &["-l", "-f", "/dev/stdin"],
            line.as_bytes(),
        )
        .ok_or("ssh-keygen -lf failed on --pubkey")?;
        out.split_whitespace()
            .find(|f| f.starts_with("SHA256:"))
            .map(str::to_string)
            .ok_or_else(|| format!("no SHA256: field in ssh-keygen output: {out:?}"))
    }

    fn derive_runtime_hostkey(&mut self, image: &Path) -> Result<(String, String), String> {
        crate::oneshots_offline::offline_runtime_hostkey(image).map_err(|e| {
            format!(
                "deriving the runtime host key from {} failed: {e} — without it the Leg-B \
                 reconnect cannot be pinned; failing closed",
                image.display()
            )
        })
    }

    fn recompute_root_hash(
        &mut self,
        img: &Path,
        rootfs_data_offset: u64,
        rootfs_data_len: u64,
    ) -> Result<String, String> {
        use std::io::{Read as _, Seek as _, Write as _};
                                                                                                 
                                                                                                 
                                                              
        let dir = tempfile::tempdir().map_err(|e| format!("verity tempdir: {e}"))?;
        let data = dir.path().join("rootfs-data");
        let mut src =
            std::fs::File::open(img).map_err(|e| format!("open {}: {e}", img.display()))?;
        src.seek(std::io::SeekFrom::Start(rootfs_data_offset))
            .map_err(|e| format!("seek rootfs data: {e}"))?;
        let mut dst =
            std::fs::File::create(&data).map_err(|e| format!("create rootfs-data temp: {e}"))?;
        let mut remaining = rootfs_data_len;
        let mut buf = vec![0u8; crate::deploy::prod::INSTALL_COPY_CHUNK_BYTES as usize];
        while remaining > 0 {
            let n = remaining.min(buf.len() as u64) as usize;
            src.read_exact(&mut buf[..n])
                .map_err(|e| format!("read rootfs data region: {e}"))?;
            dst.write_all(&buf[..n])
                .map_err(|e| format!("write rootfs-data temp: {e}"))?;
            remaining -= n as u64;
        }
        dst.flush()
            .map_err(|e| format!("flush rootfs-data temp: {e}"))?;
        drop(dst);
        crate::deploy::dryrun::recompute_verity_root_hash(&data, &dir.path().join("verity.hash"))
            .map_err(|e| e.to_string())
    }

    fn known_hosts_host(&self) -> String {
        if self.ssh_port == 22 {
            self.ip.clone()
        } else {
            format!("[{}]:{}", self.ip, self.ssh_port)
        }
    }

    fn scan_host_key(&mut self) -> Result<(String, String), String> {
        let mut cmd = std::process::Command::new("ssh-keyscan");
        cmd.args(["-T", "10", "-t", "ed25519", "-p"])
            .arg(self.ssh_port.to_string())
            .arg(&self.ip);
        let out = Self::run_capture(cmd, "ssh-keyscan")?;
        let line = out
            .lines()
            .find(|l| !l.trim_start().starts_with('#') && l.contains("ssh-ed25519"))
            .ok_or_else(|| format!("ssh-keyscan returned no ed25519 host key for {}", self.ip))?
            .trim()
            .to_string();
        let fpr_out = crate::deploy::build_image::ssh_keygen_pipe(
            &["-l", "-f", "/dev/stdin"],
            line.as_bytes(),
        )
        .ok_or("ssh-keygen -lf failed on the scanned host key")?;
        let fpr = fpr_out
            .split_whitespace()
            .find(|f| f.starts_with("SHA256:"))
            .map(str::to_string)
            .ok_or_else(|| format!("no SHA256: field in ssh-keygen output: {fpr_out:?}"))?;
        Ok((line, fpr))
    }

    fn pin_host_key(&mut self, leg: Leg, known_hosts_line: &str) -> Result<(), String> {
        use std::io::Write as _;
        let path = match leg {
            Leg::Provisioning => &self.provisioning_known_hosts,
            Leg::Reconnect => &self.reconnect_known_hosts,
        };
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        writeln!(f, "{known_hosts_line}").map_err(|e| format!("write {}: {e}", path.display()))
    }

    fn ssh_capture(&mut self, leg: Leg, remote_command: &str) -> Result<String, String> {
        let mut cmd = std::process::Command::new("ssh");
        cmd.args(self.leg_args(leg)).arg(remote_command);
        Self::run_capture(cmd, &format!("ssh {remote_command:.60}"))
    }

    fn scp_stage(&mut self, local: &Path, remote_path: &str) -> Result<(), String> {
        let mut cmd = std::process::Command::new("scp");
        cmd.args(prod_scp_args(
            &self.ip,
            &self.ssh_identity,
            &self.provisioning_known_hosts,
            self.ssh_port,
            local,
            remote_path,
        ));
        Self::run_capture(cmd, &format!("scp {}", local.display())).map(|_| ())
    }

    fn scp_image_bytes(&mut self, bytes: &[u8], remote_path: &str) -> Result<(), String> {
        use std::io::Write as _;
                                                                                                  
                                                                                                  
        let mut tmp = tempfile::NamedTempFile::new()
            .map_err(|e| format!("create temp for the staged bytes: {e}"))?;
        tmp.write_all(bytes)
            .map_err(|e| format!("write staged bytes to temp: {e}"))?;
        tmp.flush()
            .map_err(|e| format!("flush staged-bytes temp: {e}"))?;
        self.scp_stage(tmp.path(), remote_path)
    }

    fn stage_raw_window(
        &mut self,
        local_img: &Path,
        patch: Option<&crate::deploy::stage_stream::PatchSpec>,
        disk: &str,
        offset: u64,
    ) -> Result<[u8; 32], String> {
        use crate::deploy::stage_stream::apply_patch_window;
        use sha2::{Digest, Sha256};
        use std::io::{Read as _, Write as _};
                                                                                              
                                                                                                 
        if !crate::deploy::prod::is_whole_disk_name(disk) {
            return Err(format!(
                "stage_raw_window: {disk:?} is not a bare whole-disk name"
            ));
        }
        let mut f = std::fs::File::open(local_img)
            .map_err(|e| format!("open {}: {e}", local_img.display()))?;
                                                                                                
                                                                                              
                                                                                             
                                                        
          
                                                                                                      
                                                                                            
                                                                                                      
                                                                                                     
                                                                                                
        let remote = format!(
            "dd of=/dev/{disk} oflag=seek_bytes seek={offset} conv=notrunc,fsync bs=1M status=none"
        );
        let mut cmd = std::process::Command::new("ssh");
        cmd.args(self.leg_args(Leg::Provisioning))
            .arg(&remote)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        arm_pdeathsig(&mut cmd);
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("spawn staging dd over ssh: {e}"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or("staging dd: no stdin pipe (unreachable)")?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; crate::deploy::prod::INSTALL_COPY_CHUNK_BYTES as usize];
        let mut pos: u64 = 0;
        let stream = loop {
            let n = f
                .read(&mut buf)
                .map_err(|e| format!("read {}: {e}", local_img.display()))?;
            if n == 0 {
                break Ok(());
            }
            if let Some(p) = patch {
                apply_patch_window(&mut buf[..n], pos, p);
            }
            h.update(&buf[..n]);
            if let Err(e) = stdin.write_all(&buf[..n]) {
                break Err(format!("write to staging dd at byte {pos}: {e}"));
            }
            pos += n as u64;
        };
                                                                                               
                                                                                             
                                                                                               
                                                        
        drop(stdin);
        let out = child
            .wait_with_output()
            .map_err(|e| format!("wait for staging dd: {e}"))?;
        stream?;
        if !out.status.success() {
            return Err(format!(
                "staging dd exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(h.finalize().into())
    }

    fn fire_kexec(&mut self, _token: WipeConfirmed) -> Result<(), String> {
                                                                                                
                                                                                                  
                                                                                              
                                                                                             
                                                                                               
                                     
        let mut sync_cmd = std::process::Command::new("ssh");
        sync_cmd.args(self.leg_args(Leg::Provisioning)).arg("sync");
        Self::run_capture(sync_cmd, "ssh sync (pre-kexec)").map_err(|e| {
                                                                                                  
                                                                                                 
                                                                                               
            format!("pre-kexec sync on the target FAILED: {e}")
        })?;
        let mut cmd = std::process::Command::new("ssh");
        cmd.args(self.leg_args(Leg::Provisioning)).arg("kexec -e");
        arm_pdeathsig(&mut cmd);
        let out = cmd
            .output()
            .map_err(|e| format!("spawn ssh kexec -e: {e}"))?;
                                                                                                  
                                                                                              
                                                                                                  
        let stderr = String::from_utf8_lossy(&out.stderr);
        if prod::kexec_refused(out.status.success(), &stderr) {
                                                                                                    
                                                                                                
                                                                           
            return Err(format!(
                "kexec -e was refused on the target ({}): {} — nothing was written",
                out.status,
                stderr.trim()
            ));
        }
        Ok(())
    }
}
