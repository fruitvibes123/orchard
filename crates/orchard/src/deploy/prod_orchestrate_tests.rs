use super::*;
use std::path::Path;

#[test]
fn prod_ssh_args_diverge_from_dryrun_no_insecure_hostkey() {
    let a = prod_ssh_args("203.0.113.5", Path::new("/k"), Path::new("/kh"), 22);
                                                        
    assert!(!a.iter().any(|s| s.contains("StrictHostKeyChecking=no")));
    assert!(!a.iter().any(|s| s.contains("UserKnownHostsFile=/dev/null")));
    assert!(!a.iter().any(|s| s == "-v"));
                                                               
    assert!(a.iter().any(|s| s == "StrictHostKeyChecking=yes"));
    assert!(a.iter().any(|s| s == "UserKnownHostsFile=/kh"));
                                                                              
    let f = a.iter().position(|s| s == "-F").expect("-F");
    assert_eq!(a[f + 1], "/dev/null");
    assert!(a.iter().any(|s| s == "GlobalKnownHostsFile=/dev/null"));
                                                             
    assert!(a.iter().any(|s| s == "BatchMode=yes"));
    assert!(a.iter().any(|s| s == "PasswordAuthentication=no"));
    assert!(a.iter().any(|s| s == "KbdInteractiveAuthentication=no"));
    assert!(a.iter().any(|s| s == "IdentitiesOnly=yes"));
    let i = a.iter().position(|s| s == "-i").expect("-i");
    assert_eq!(a[i + 1], "/k");
    assert!(a.iter().any(|s| s == "LogLevel=ERROR"));
                                                                    
    let p = a.iter().position(|s| s == "-p").expect("-p");
    assert_eq!(a[p + 1], "22");
                                                                             
    assert_eq!(a.last().unwrap(), "root@203.0.113.5");
    assert!(!a.iter().any(|s| s.contains("127.0.0.1")));
}

#[test]
fn prod_args_carry_a_nonstandard_port_ssh_lowercase_scp_uppercase() {
                                                                                              
                                                                                         
    let ssh = prod_ssh_args("127.0.0.1", Path::new("/k"), Path::new("/kh"), 2222);
    let p = ssh.iter().position(|s| s == "-p").expect("ssh -p");
    assert_eq!(ssh[p + 1], "2222");
    assert!(!ssh.iter().any(|s| s == "-P"), "ssh must not use -P");

    let scp = prod_scp_args(
        "127.0.0.1",
        Path::new("/k"),
        Path::new("/kh"),
        2222,
        Path::new("/out/x.img"),
        "/var/tmp/recipes-deploy/x.img",
    );
    let p = scp.iter().position(|s| s == "-P").expect("scp -P");
    assert_eq!(scp[p + 1], "2222");
    assert!(!scp.iter().any(|s| s == "-p"), "scp must not use -p");
}

#[test]
fn known_hosts_host_token_brackets_nonstandard_port() {
                                                                                                
    let p22 = ProcessOps {
        ip: "127.0.0.1".into(),
        ssh_port: 22,
        ssh_identity: "/a".into(),
        box_login_identity: "/b".into(),
        provisioning_known_hosts: "/c".into(),
        reconnect_known_hosts: "/d".into(),
        step_started: None,
    };
    assert_eq!(p22.known_hosts_host(), "127.0.0.1");
    let p2222 = ProcessOps {
        ssh_port: 2222,
        ..p22
    };
    assert_eq!(p2222.known_hosts_host(), "[127.0.0.1]:2222");
}

#[test]
fn prod_scp_args_share_the_hardened_posture() {
    let a = prod_scp_args(
        "203.0.113.5",
        Path::new("/k"),
        Path::new("/kh"),
        22,
        Path::new("/out/recipes-image-abc.img"),
        "/var/tmp/recipes-deploy/recipes-image-abc.img",
    );
    assert!(!a.iter().any(|s| s.contains("StrictHostKeyChecking=no")));
    assert!(a.iter().any(|s| s == "StrictHostKeyChecking=yes"));
    assert!(a.iter().any(|s| s == "UserKnownHostsFile=/kh"));
    assert!(a.iter().any(|s| s == "BatchMode=yes"));
                                                      
    let src = a
        .iter()
        .position(|s| s == "/out/recipes-image-abc.img")
        .expect("local source");
    assert_eq!(
        a[src + 1],
        "root@203.0.113.5:/var/tmp/recipes-deploy/recipes-image-abc.img"
    );
    assert_eq!(src + 2, a.len(), "destination is last");
}

                                                                                 

/// A recording fake: every TARGET-FACING call lands in `target_calls` (the smoke tests
/// assert the gates short-circuit BEFORE any of those); remote commands answer from a
/// substring-matched canned table.
struct FakeOps {
    tty: bool,
    cancel: bool,
    pubkey_fpr: String,
    runtime_key: (String, String),
    artifacts: Option<ImageArtifacts>,
    scanned: (String, String),
    remote: Vec<(&'static str, String)>,
    /// Consumable one-shot replies, checked BEFORE `remote` and popped on first match — the
    /// reclaim-tail fixtures use them for state that flips across the reclaim reboot (the D-1
    /// extents, the dpkg status, the fstab content).
    remote_once: std::collections::VecDeque<(&'static str, String)>,
    target_calls: Vec<String>,
    said: Vec<String>,
    /// Component 1: the step-banner channel — SEPARATE from `target_calls` so the nine
    /// fail-closed asserts stay byte-valid (a banner is not a target-facing call).
    steps: Vec<(u32, u32, String)>,
    lines: std::collections::VecDeque<String>,
    root_hash: String,
    /// The bytes handed to `scp_image_bytes` (the patched `.img`) — captured so a test can assert
    /// the boot-fs was patched to the slot-A device, not left as the reboot-looping sentinel.
    staged_image: Option<Vec<u8>>,
    /// Hex digest of the last raw-window stage (the patched stream) — seam-test corroboration.
    raw_window_digest: Option<String>,
                                                                                             
    /// advances it (deterministic reconnect-wait timing); `None` ⇒ real wall-clock.
    mock_clock: Option<std::cell::Cell<i64>>,
    /// The mock-clock value at which the reconnect probe starts answering (slow-reconnect fixture).
    reconnect_up_at: Option<i64>,
                                                                                              
    known_hosts_conflict: Option<String>,
                                                                                             
    /// flips true AT THAT POINT — used to arm a cancel BETWEEN a verb's two
    /// `reclaim_cancel_check` sites (the plan `say` sits between them). Default None ⇒ inert.
    cancel_on_say: Option<&'static str>,
                                                                                                       
    /// the pre-fire, reachable-target refusal shape (a lockdown-refused `kexec -e` or a failed
    /// pre-kexec `sync`). Default None ⇒ fire_kexec returns Ok (fired), the shape the AC-R13 vectors
    /// and every other test drive.
    fire_kexec_err: Option<String>,
}

impl FakeOps {
    /// The synthetic `.img` byte layout shared by both firmware fixtures (512-aligned per the
    /// streaming grammar): boot [0,512) | skel [512,1024) | rootfs [1024,1536).
    fn synthetic_img(boot: Vec<u8>) -> Vec<u8> {
        assert_eq!(boot.len(), 512);
        let mut img = boot;
        img.extend_from_slice(&[0x9Eu8; 512]);                    
        img.extend_from_slice(&[0xABu8; 512]);          
        img
    }

    fn synthetic_layout(firmware: Firmware) -> LayoutInfo {
        LayoutInfo {
            boot_offset: 0,
            boot_size: 512,
            persist_skeleton_offset: 512,
            persist_skeleton_size: 512,
            rootfs_offset: 1024,
            rootfs_size: 512,
            rootfs_verity_hash_offset: 256,
            firmware,
            weights_offset: None,
            weights_size: None,
        }
    }

    fn synthetic_artifacts(dir: &Path) -> ImageArtifacts {
        use recipes_image_builder::image::sha256_hex;
                                                                                              
        let sentinel = recipes_image_builder::boot_fs::ROOTFS_DEV_SENTINEL;
        let mut boot = format!("APPEND fb.rootfs-dev={sentinel} ro").into_bytes();
        boot.resize(512, b' ');
        let img = Self::synthetic_img(boot);
        let vmlinuz = vec![0x07u8; 32];
        let initramfs = vec![0x08u8; 16];
        let name = |n: &str| dir.join(n);
        std::fs::write(name("r.img"), &img).unwrap();
        std::fs::write(name("r.vmlinuz"), &vmlinuz).unwrap();
        std::fs::write(name("r.initramfs"), &initramfs).unwrap();
        std::fs::write(name("r.layout.toml"), "synthetic").unwrap();
        ImageArtifacts {
            img_sha_sidecar: format!("{}  r.img\n", sha256_hex(&img)),
            vmlinuz_sha_sidecar: format!("{}  r.vmlinuz\n", sha256_hex(&vmlinuz)),
            initramfs_sha_sidecar: format!("{}  r.initramfs\n", sha256_hex(&initramfs)),
            operator_pubkey_fpr_sidecar: Some("SHA256:opfpr".into()),
            img_len: img.len() as u64,
            vmlinuz,
            initramfs,
            layout: Self::synthetic_layout(Firmware::Seabios),
            img_path: name("r.img"),
            vmlinuz_path: name("r.vmlinuz"),
            initramfs_path: name("r.initramfs"),
            layout_path: name("r.layout.toml"),
        }
    }

    /// A fake wired so the WHOLE ceremony succeeds non-interactively (the e2e shape):
    /// Leg-A pin matches the scan; every discovery probe answers sanely; the staged hashes
    /// + step-10 answers are computed from the same synthetic bytes the flow holds.
    fn happy(dir: &Path) -> FakeOps {
        use recipes_image_builder::image::sha256_hex;
        let art = Self::synthetic_artifacts(dir);
        let local_root_hash = "ab".repeat(32);
        let img = std::fs::read(&art.img_path).unwrap();
                                                                                              
                                                                                          
                                                                                                     
        let mut staged_img = img.clone();
        crate::deploy::prod::patch_rootfs_dev(&mut staged_img[0..512], "/dev/vda2").unwrap();
        let prefix_sha = sha256_hex(&staged_img[0..512]);
        let staged_img_sha = sha256_hex(&staged_img);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let remote = vec![
            ("findmnt -n -o SOURCE / ", "/dev/vda1\n".to_string()),
            (
                "mkdir -p /var/tmp/recipes-deploy",
                "/var/tmp/recipes-deploy\n".to_string(),
            ),
            ("findmnt -n -o SOURCE --target", "/dev/vda1\n".to_string()),
                                                                                                     
                                                                                                   
                                                                                                 
                                                                                                    
                                                                                              
                                              
            (
                "lsblk -nbro NAME,TYPE,START,SIZE",
                "vda disk  42949672960\nvda1 part 2048 3221225472\n".to_string(),
            ),
            ("lsblk", "vda disk  \nvda1 part / vda\n".to_string()),
            (
                "df -P -k",
                "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                     /dev/vda1 999999 1 999999 1% /\n"
                    .to_string(),
            ),
            ("cat /sys/class/block/vda/size", "83886080\n".to_string()),
            (
                "cat /proc/meminfo",
                "MemTotal:        4194304 kB\n".to_string(),
            ),
            ("command -v kexec", "/sbin/kexec\n".to_string()),
            ("date +%s", format!("{now}\n")),
                                                                                               
            (
                "dd if=/var/tmp/recipes-deploy/r.vmlinuz iflag=direct",
                format!("{}  -\n", sha256_hex(&art.vmlinuz)),
            ),
            (
                "dd if=/var/tmp/recipes-deploy/r.initramfs iflag=direct",
                format!("{}  -\n", sha256_hex(&art.initramfs)),
            ),
            (
                "dd if=/dev/vda iflag=direct,skip_bytes",
                format!("{staged_img_sha}  -\n"),
            ),
            ("kexec -l", String::new()),
            ("echo recipes-box-up", "recipes-box-up\n".to_string()),
            (
                "cat /proc/mounts",
                "/dev/dm-0 / squashfs ro,relatime 0 0\n".to_string(),
            ),
            (
                "cat /proc/cmdline",
                format!("console=ttyS0 fb.root-hash={local_root_hash} ro\n"),
            ),
            ("head -c 512 /dev/vda1", format!("{prefix_sha}  -\n")),
            ("wget", "  HTTP/1.1 303 See Other\n".to_string()),
            (
                "echo recipes-deploy-connected",
                "recipes-deploy-connected\n".to_string(),
            ),
        ];
        FakeOps {
            tty: false,
            cancel: false,
            pubkey_fpr: "SHA256:opfpr".into(),
            runtime_key: ("ssh-ed25519 AAAAfake".into(), "SHA256:runtimefpr".into()),
            artifacts: Some(art),
            scanned: (
                "203.0.113.5 ssh-ed25519 AAAAscan".into(),
                "SHA256:legA".into(),
            ),
            remote,
            remote_once: Default::default(),
            target_calls: vec![],
            said: vec![],
            lines: Default::default(),
            root_hash: local_root_hash,
            staged_image: None,
            raw_window_digest: None,
            steps: vec![],
            mock_clock: None,
            reconnect_up_at: None,
            known_hosts_conflict: None,
            cancel_on_say: None,
            fire_kexec_err: None,
        }
    }

    /// Synthetic artifacts for the seabios-gpt arm: a boot-fs with NO deploy sentinel (the GPT arm
    /// bakes a fixed PARTUUID), firmware = SeabiosGpt, no weights. Mirrors [`synthetic_artifacts`].
    fn synthetic_artifacts_gpt(dir: &Path) -> ImageArtifacts {
        use recipes_image_builder::image::sha256_hex;
                                                                                                       
                                                            
        let img = Self::synthetic_img(vec![0xC3u8; 512]);
        let vmlinuz = vec![0x07u8; 32];
        let initramfs = vec![0x08u8; 16];
        let name = |n: &str| dir.join(n);
        std::fs::write(name("r.img"), &img).unwrap();
        std::fs::write(name("r.vmlinuz"), &vmlinuz).unwrap();
        std::fs::write(name("r.initramfs"), &initramfs).unwrap();
        std::fs::write(name("r.layout.toml"), "synthetic-gpt").unwrap();
        ImageArtifacts {
            img_sha_sidecar: format!("{}  r.img\n", sha256_hex(&img)),
            vmlinuz_sha_sidecar: format!("{}  r.vmlinuz\n", sha256_hex(&vmlinuz)),
            initramfs_sha_sidecar: format!("{}  r.initramfs\n", sha256_hex(&initramfs)),
            operator_pubkey_fpr_sidecar: Some("SHA256:opfpr".into()),
            img_len: img.len() as u64,
            vmlinuz,
            initramfs,
            layout: Self::synthetic_layout(Firmware::SeabiosGpt),
            img_path: name("r.img"),
            vmlinuz_path: name("r.vmlinuz"),
            initramfs_path: name("r.initramfs"),
            layout_path: name("r.layout.toml"),
        }
    }

    /// A fake wired so the WHOLE seabios-gpt ceremony succeeds non-interactively (the GPT-arm shape):
    /// like [`happy`] but the image is a seabios-gpt `.img` staged VERBATIM (no rootfs-dev patch), so
    /// the box-side boot-fs prefix + the staged sha are over the RAW bytes (no patch replay).
    fn happy_gpt(dir: &Path) -> FakeOps {
        use recipes_image_builder::image::sha256_hex;
        let art = Self::synthetic_artifacts_gpt(dir);
        let local_root_hash = "ab".repeat(32);
                                                                                                   
                                                                            
        let img = std::fs::read(&art.img_path).unwrap();
        let prefix_sha = sha256_hex(&img[0..512]);
        let staged_img_sha = sha256_hex(&img);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let remote = vec![
            ("findmnt -n -o SOURCE / ", "/dev/vda1\n".to_string()),
            (
                "mkdir -p /var/tmp/recipes-deploy",
                "/var/tmp/recipes-deploy\n".to_string(),
            ),
            ("findmnt -n -o SOURCE --target", "/dev/vda1\n".to_string()),
                                                                                                     
                                                                                                   
                                                                                                 
                                                                                                    
                                                                                              
                                              
            (
                "lsblk -nbro NAME,TYPE,START,SIZE",
                "vda disk  42949672960\nvda1 part 2048 3221225472\n".to_string(),
            ),
            ("lsblk", "vda disk  \nvda1 part / vda\n".to_string()),
            (
                "df -P -k",
                "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                     /dev/vda1 999999 1 999999 1% /\n"
                    .to_string(),
            ),
            ("cat /sys/class/block/vda/size", "83886080\n".to_string()),
            (
                "cat /proc/meminfo",
                "MemTotal:        4194304 kB\n".to_string(),
            ),
            ("command -v kexec", "/sbin/kexec\n".to_string()),
            ("date +%s", format!("{now}\n")),
            (
                "dd if=/var/tmp/recipes-deploy/r.vmlinuz iflag=direct",
                format!("{}  -\n", sha256_hex(&art.vmlinuz)),
            ),
            (
                "dd if=/var/tmp/recipes-deploy/r.initramfs iflag=direct",
                format!("{}  -\n", sha256_hex(&art.initramfs)),
            ),
            (
                "dd if=/dev/vda iflag=direct,skip_bytes",
                format!("{staged_img_sha}  -\n"),
            ),
            ("kexec -l", String::new()),
            ("echo recipes-box-up", "recipes-box-up\n".to_string()),
            (
                "cat /proc/mounts",
                "/dev/dm-0 / squashfs ro,relatime 0 0\n".to_string(),
            ),
            (
                "cat /proc/cmdline",
                format!("console=ttyS0 fb.root-hash={local_root_hash} ro\n"),
            ),
            ("head -c 512 /dev/vda1", format!("{prefix_sha}  -\n")),
            ("wget", "  HTTP/1.1 303 See Other\n".to_string()),
            (
                "echo recipes-deploy-connected",
                "recipes-deploy-connected\n".to_string(),
            ),
        ];
        FakeOps {
            tty: false,
            cancel: false,
            pubkey_fpr: "SHA256:opfpr".into(),
            runtime_key: ("ssh-ed25519 AAAAfake".into(), "SHA256:runtimefpr".into()),
            artifacts: Some(art),
            scanned: (
                "203.0.113.5 ssh-ed25519 AAAAscan".into(),
                "SHA256:legA".into(),
            ),
            remote,
            remote_once: Default::default(),
            target_calls: vec![],
            said: vec![],
            steps: vec![],
            lines: Default::default(),
            root_hash: local_root_hash,
            staged_image: None,
            raw_window_digest: None,
            mock_clock: None,
            reconnect_up_at: None,
            known_hosts_conflict: None,
            cancel_on_say: None,
            fire_kexec_err: None,
        }
    }

    /// A happy fake whose reconnect probe fails until the mock clock reaches `up_at` — drives the
                                                                             
    fn reconnect_slow(dir: &Path, up_at: i64) -> FakeOps {
        let mut ops = Self::happy(dir);
        ops.mock_clock = Some(std::cell::Cell::new(0));
        ops.reconnect_up_at = Some(up_at);
        ops
    }

    fn set_known_hosts_conflict(&mut self, line: &str) {
        self.known_hosts_conflict = Some(line.to_string());
    }

    fn opts(dir: &Path) -> DeployProdOpts {
        DeployProdOpts {
            ip: "203.0.113.5".into(),
            pubkey: dir.join("op.pub"),
            image: dir.join("r.img"),
            host_fingerprint: Some("SHA256:legA".into()),
            known_hosts: None,
            runtime_hostkey_fingerprint: None,
            image_stage_dir: "/var/tmp/recipes-deploy".into(),
            wipe_confirmed: WipeConfirmed::from_flag(true),
            reconnect_timeout_secs: 30,
            restore_from: None,
            restore_min_ctr: None,
            artifact_pin: None,
            profile_sourced: Default::default(),
            reclaim_tail: false,
            reclaim_reboot_timeout_secs: None,
        }
    }
}

impl OrchestrationOps for FakeOps {
    fn stdin_is_tty(&self) -> bool {
        self.tty
    }
    fn step(&mut self, n: u32, of: u32, label: &str) {
        self.steps.push((n, of, label.to_string()));
    }
    fn ssh_port(&self) -> u16 {
        22
    }
    fn ambient_known_hosts_conflict(
        &self,
        _ip: &str,
        _presented_type: &str,
        _presented_key: &str,
    ) -> Option<String> {
        self.known_hosts_conflict.clone()
    }
    fn say(&mut self, msg: &str) {
                                                                                      
                                                                                             
                                                                                         
        let head: String = msg.chars().take(40).collect();
        self.target_calls.push(format!("say:{head}"));
        self.said.push(msg.to_string());
                                                                                              
        if let Some(needle) = self.cancel_on_say
            && msg.contains(needle)
        {
            self.cancel = true;
        }
    }
    fn read_line(&mut self, _prompt: &str) -> Option<String> {
        self.lines.pop_front()
    }
    fn cancel_requested(&self) -> bool {
        self.cancel
    }
    fn sleep_secs(&mut self, secs: u64) {
        if let Some(c) = &self.mock_clock {
            c.set(c.get() + secs as i64);
        }
    }
    fn now_epoch(&self) -> i64 {
        if let Some(c) = &self.mock_clock {
            return c.get();
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
    fn read_image_artifacts(&mut self, _image: &Path) -> Result<ImageArtifacts, String> {
        self.artifacts.take().ok_or("no artifacts staged".into())
    }
    fn local_pubkey_fingerprint(&mut self, _pubkey: &Path) -> Result<String, String> {
        Ok(self.pubkey_fpr.clone())
    }
    fn derive_runtime_hostkey(&mut self, _image: &Path) -> Result<(String, String), String> {
        Ok(self.runtime_key.clone())
    }
    fn recompute_root_hash(
        &mut self,
        _img: &Path,
        _rootfs_data_offset: u64,
        _rootfs_data_len: u64,
    ) -> Result<String, String> {
        Ok(self.root_hash.clone())
    }
    fn known_hosts_host(&self) -> String {
        "203.0.113.5".into()
    }
    fn scan_host_key(&mut self) -> Result<(String, String), String> {
        self.target_calls.push("scan_host_key".into());
        Ok(self.scanned.clone())
    }
    fn pin_host_key(&mut self, leg: Leg, line: &str) -> Result<(), String> {
        self.target_calls.push(format!("pin:{leg:?}:{line}"));
        Ok(())
    }
    fn ssh_capture(&mut self, leg: Leg, remote_command: &str) -> Result<String, String> {
        self.target_calls
            .push(format!("ssh:{leg:?}:{remote_command}"));
                                                                                                 
        if remote_command.contains("echo recipes-box-up")
            && let (Some(c), Some(up)) = (&self.mock_clock, self.reconnect_up_at)
            && c.get() < up
        {
            return Err("fake: box not up yet".into());
        }
        if let Some(idx) = self
            .remote_once
            .iter()
            .position(|(needle, _)| remote_command.contains(needle))
        {
            let (_, response) = self.remote_once.remove(idx).expect("index from position");
            return Ok(response);
        }
        for (needle, response) in &self.remote {
            if remote_command.contains(needle) {
                return Ok(response.clone());
            }
        }
        Err(format!("fake: unmatched remote command {remote_command:?}"))
    }
    fn scp_stage(&mut self, local: &Path, remote_path: &str) -> Result<(), String> {
        self.target_calls
            .push(format!("scp:{}:{remote_path}", local.display()));
        Ok(())
    }
    fn scp_image_bytes(&mut self, bytes: &[u8], remote_path: &str) -> Result<(), String> {
        self.target_calls.push(format!("scp_image:{remote_path}"));
        self.staged_image = Some(bytes.to_vec());
        Ok(())
    }
    fn stage_raw_window(
        &mut self,
        local_img: &Path,
        patch: Option<&crate::deploy::stage_stream::PatchSpec>,
        disk: &str,
        offset: u64,
    ) -> Result<[u8; 32], String> {
        use crate::deploy::stage_stream::apply_patch_window;
        use recipes_image_builder::image::sha256_hex;
        use sha2::{Digest, Sha256};
                                                                                                 
                                                                                                    
        self.target_calls
            .push(format!("stage_raw_window:{disk}:{offset}"));
        let mut staged =
            std::fs::read(local_img).map_err(|e| format!("read {}: {e}", local_img.display()))?;
        if let Some(p) = patch {
            apply_patch_window(&mut staged, 0, p);
        }
        let digest: [u8; 32] = Sha256::digest(&staged).into();
        self.raw_window_digest = Some(sha256_hex(&staged));
        self.staged_image = Some(staged);
        Ok(digest)
    }
    fn fire_kexec(&mut self, _token: WipeConfirmed) -> Result<(), String> {
        self.target_calls.push("fire_kexec".into());
                                                                                                  
                                                                                                     
                                                                                                  
        match &self.fire_kexec_err {
            Some(msg) => Err(msg.clone()),
            None => Ok(()),
        }
    }
}

#[test]
fn step_banners_record_on_their_own_channel_not_target_calls() {
                                                                                           
                                                                            
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    ops.step(6, 9, "staging image");
    assert!(
        ops.target_calls.is_empty(),
        "step() must NOT touch target_calls"
    );
    assert_eq!(ops.steps, vec![(6, 9, "staging image".to_string())]);
}

/// Drive the WHOLE happy ceremony through the fake and return the banner sequence (`ops.steps`).
/// `known_hosts` = operator-supplied (drops step 3); `restore` = a signed restore rides along.
fn run_happy_and_collect_steps(known_hosts: bool, restore: bool) -> Vec<(u32, u32, String)> {
    use recipes_image_builder::image::sha256_hex;
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    let mut opts = if restore {
        let img_bytes = fixture_restore_image();
        let (pin, img) = signed_restore_artifact(dir.path(), "restore-1.persist.img", &img_bytes);
        let o = restore_opts(dir.path(), &img, Some(pin));
                                                                                            
                                                                                                 
        let sig_path = crate::deploy::artifact_sign::sig_sidecar_path(&img);
        let sig_bytes = std::fs::read(&sig_path).unwrap();
        ops.remote.push((
            "dd if=/var/tmp/recipes-deploy/restore-1.persist.img iflag=direct",
            format!("{}  -\n", sha256_hex(&img_bytes)),
        ));
        ops.remote.push((
            "dd if=/var/tmp/recipes-deploy/restore-1.persist.img.sig",
            format!("{}  -\n", sha256_hex(&sig_bytes)),
        ));
        o
    } else {
        FakeOps::opts(dir.path())
    };
    if known_hosts {
        let kh = dir.path().join("kh");
        std::fs::write(&kh, "").unwrap();
        opts.known_hosts = Some(kh);
    }
    deploy_prod(&mut ops, opts).expect("happy ceremony succeeds");
    ops.steps
}

#[test]
fn banner_sequence_base_and_known_hosts_paths() {
                                                                                             
    let base = run_happy_and_collect_steps(false, false);
    let ns: Vec<u32> = base.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(
        ns,
        (1..=ns.len() as u32).collect::<Vec<_>>(),
        "contiguous 1..N: {base:?}"
    );
    assert!(
        base.iter().all(|(_, of, _)| *of == base.len() as u32),
        "every banner's `of` == N: {base:?}"
    );

                                                                                       
    let with_kh = run_happy_and_collect_steps(true, false);
    assert_eq!(
        with_kh.len(),
        base.len() - 1,
        "known-hosts drops one banner"
    );
    let kh_ns: Vec<u32> = with_kh.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(
        kh_ns,
        (1..=kh_ns.len() as u32).collect::<Vec<_>>(),
        "still contiguous: {with_kh:?}"
    );

                                                                                                
    let with_restore = run_happy_and_collect_steps(false, true);
    let base_labels: Vec<_> = base.iter().map(|(_, _, l)| l.clone()).collect();
    let restore_labels: Vec<_> = with_restore.iter().map(|(_, _, l)| l.clone()).collect();
    assert_eq!(
        restore_labels, base_labels,
        "restore adds no banner (rides says)"
    );
}

#[test]
fn banner_sequence_is_contiguous_on_the_gpt_path() {
                                                                                                      
                                                                                                     
                                                                                                       
                                                                                                             
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_gpt(dir.path());
    deploy_prod(&mut ops, FakeOps::opts(dir.path())).expect("happy seabios-gpt ceremony succeeds");
    let ns: Vec<u32> = ops.steps.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(
        ns,
        (1..=ns.len() as u32).collect::<Vec<_>>(),
        "contiguous 1..N on GPT: {:?}",
        ops.steps
    );
    assert!(
        ops.steps
            .iter()
            .all(|(_, of, _)| *of == ops.steps.len() as u32),
        "every banner's `of` == N on GPT: {:?}",
        ops.steps
    );
    let gpt_labels: Vec<_> = ops.steps.iter().map(|(_, _, l)| l.clone()).collect();
    let mbr_labels: Vec<_> = run_happy_and_collect_steps(false, false)
        .iter()
        .map(|(_, _, l)| l.clone())
        .collect();
    assert_eq!(
        gpt_labels, mbr_labels,
        "GPT banner sequence must match MBR (no firmware-conditional step)"
    );
}

#[test]
fn first_boot_wait_ticks_about_every_15s() {
                                                                                                 
                                                                      
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::reconnect_slow(dir.path(), 40);
    reconnect_wait(&mut ops, 600).expect("comes up before the deadline");
    let ticks = ops
        .said
        .iter()
        .filter(|s| s.contains("still waiting"))
        .count();
    assert!(
        (2..=4).contains(&ticks),
        "≈15s cadence over ~40s of wait, got {ticks}"
    );
}

#[test]
fn pre_wipe_summary_renders_all_fields_and_profile_annotation() {
                                                                                                 
                                                                                                     
    use std::collections::HashSet;
    let dir = tempfile::tempdir().unwrap();
    let ops = FakeOps::happy(dir.path());
    let art = FakeOps::synthetic_artifacts(dir.path());
    let opts = FakeOps::opts(dir.path());
    let profile_sourced: HashSet<&str> = ["port"].into_iter().collect();
    let out = render_pre_wipe_summary(
        &ops,
        &art,
        "verityroot_abc",
        "/var/tmp/recipes-deploy",
        &opts,
        None,
        &profile_sourced,
    );
    for needle in [
        "image:",
        "verity root:",
        "operator key:",
        "target:",
        "staging:",
    ] {
        assert!(out.contains(needle), "missing {needle}: {out}");
    }
    assert!(
        out.contains("(profile)"),
        "profile-sourced value annotated: {out}"
    );
}

#[test]
fn known_hosts_conflict_advisory_only_on_conflict() {
                                                                                               
                                                                     
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    assert!(maybe_known_hosts_advisory(&ops, "203.0.113.5", "ssh-ed25519", "AAAA").is_none());
    ops.set_known_hosts_conflict("203.0.113.5 ssh-ed25519 OLDKEY");
    let adv = maybe_known_hosts_advisory(&ops, "203.0.113.5", "ssh-ed25519", "AAAA")
        .expect("a conflict yields an advisory");
    assert!(adv.contains("ssh-keygen -R 203.0.113.5"), "{adv}");
    assert!(adv.contains("NOT a MITM"), "{adv}");
}

#[test]
fn known_hosts_conflict_is_keytype_aware() {
                                                                                             
                                                                                                
    let content = "203.0.113.5 ecdsa-sha2-nistp256 AAAAecdsa\n\
                   203.0.113.5 ssh-ed25519 AAAAed25519\n";
                                                                                                      
    assert!(
        known_hosts_conflict_in(content, "203.0.113.5", "ssh-ed25519", "AAAAed25519").is_none(),
        "a different-keytype line must not count as a conflict"
    );
                                                                            
    let c = known_hosts_conflict_in(content, "203.0.113.5", "ssh-ed25519", "AAAAnewkey");
    assert!(
        c.as_deref().is_some_and(|l| l.contains("ssh-ed25519")),
        "{c:?}"
    );
                                                                       
    assert!(
        known_hosts_conflict_in(
            "|1|hash== ssh-ed25519 K\n# c\n",
            "203.0.113.5",
            "ssh-ed25519",
            "X"
        )
        .is_none()
    );
    assert!(known_hosts_conflict_in(content, "203.0.113.5", "", "AAAAnewkey").is_none());
}

#[test]
fn pre_wipe_summary_trims_a_trailing_newline_sidecar() {
                                                                                              
                                                                            
    use std::collections::HashSet;
    let dir = tempfile::tempdir().unwrap();
    let ops = FakeOps::happy(dir.path());
    let mut art = FakeOps::synthetic_artifacts(dir.path());
    art.operator_pubkey_fpr_sidecar = Some("SHA256:realfpr\n".into());
    let opts = FakeOps::opts(dir.path());
    let out = render_pre_wipe_summary(&ops, &art, "vr", "/stage", &opts, None, &HashSet::new());
    assert!(
        out.contains("operator key: SHA256:realfpr\n"),
        "trimmed: {out:?}"
    );
    assert!(
        !out.contains("SHA256:realfpr\n\n"),
        "no stray blank line from an untrimmed fpr: {out:?}"
    );
                                                                                                   
                                                                                           
    let annotated: HashSet<&str> = ["operator_pubkey"].into_iter().collect();
    let out2 = render_pre_wipe_summary(&ops, &art, "vr", "/stage", &opts, None, &annotated);
    assert!(
        out2.contains("operator key: SHA256:realfpr (profile)\n"),
        "annotation on-line: {out2:?}"
    );
}

#[test]
fn profile_sourced_values_annotate_in_the_ceremony_summary() {
                                                                                                  
                                                                                              
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    let mut opts = FakeOps::opts(dir.path());
    opts.profile_sourced = ["port".to_string()].into_iter().collect();
    deploy_prod(&mut ops, opts).expect("ceremony succeeds");
    assert!(
        ops.said
            .iter()
            .any(|s| s.contains("deploy summary") && s.contains("(profile)")),
        "the summary should annotate the profile-sourced port: {:?}",
        ops.said
    );
}

#[test]
fn completion_message_names_the_cleanup_line() {
    let msg = completion_message("203.0.113.5", "SHA256:runtimefpr");
    assert!(msg.contains("ssh-keygen -R 203.0.113.5"), "{msg}");
    assert!(msg.contains("host-key"), "{msg}");
    assert!(msg.contains("SHA256:runtimefpr"), "{msg}");
}

#[test]
fn gates_short_circuit_before_any_target_facing_call() {
    let dir = tempfile::tempdir().unwrap();
                                                                       
    let mut ops = FakeOps::happy(dir.path());
    let mut o = FakeOps::opts(dir.path());
    o.wipe_confirmed = None;
    let err = deploy_prod(&mut ops, o).unwrap_err();
    assert!(err.contains("--wipe-confirmed"), "{err}");
    assert!(ops.target_calls.is_empty(), "{:?}", ops.target_calls);

                                                                                    
    let mut ops = FakeOps::happy(dir.path());
    let mut o = FakeOps::opts(dir.path());
    o.host_fingerprint = None;
    let err = deploy_prod(&mut ops, o).unwrap_err();
    assert!(err.contains("failing closed"), "{err}");
    assert!(ops.target_calls.is_empty(), "{:?}", ops.target_calls);

                                                          
    let mut ops = FakeOps::happy(dir.path());
    let mut o = FakeOps::opts(dir.path());
    o.image_stage_dir = "/var tmp/x".into();
    assert!(deploy_prod(&mut ops, o).is_err());
    assert!(ops.target_calls.is_empty(), "{:?}", ops.target_calls);

                                                                                              
    let mut ops = FakeOps::happy(dir.path());
    let mut o = FakeOps::opts(dir.path());
    o.host_fingerprint = Some("SHA256:other".into());
    let err = deploy_prod(&mut ops, o).unwrap_err();
    assert!(err.contains("MISMATCH"), "{err}");
    assert_eq!(ops.target_calls, vec!["scan_host_key".to_string()]);

                                                                                        
                                     
    let mut ops = FakeOps::happy(dir.path());
    let mut o = FakeOps::opts(dir.path());
    o.runtime_hostkey_fingerprint = Some("SHA256:wrong".into());
    let err = deploy_prod(&mut ops, o).unwrap_err();
    assert!(
        err.contains("does not match the fingerprint derived"),
        "{err}"
    );
    assert!(ops.target_calls.is_empty(), "{:?}", ops.target_calls);

                                                                                         
    let mut ops = FakeOps::happy(dir.path());
    ops.pubkey_fpr = "SHA256:notbaked".into();
    let err = deploy_prod(&mut ops, FakeOps::opts(dir.path())).unwrap_err();
    assert!(err.contains("baked into this image"), "{err}");
    assert!(ops.target_calls.is_empty(), "{:?}", ops.target_calls);
}

#[test]
fn grown_root_refuses_before_any_staging_or_kexec() {
                                                                                                   
                                                                                                     
                                                                                                    
                                                                                                     
                                                                                                       
                                                                                                       
                                                                                                   
                                                                                                    
                                                                                                
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    for (needle, resp) in &mut ops.remote {
        if *needle == "lsblk -nbro NAME,TYPE,START,SIZE" {
            *resp = "vda disk  42949672960\nvda1 part 2048 42948624384\n".to_string();
        }
    }
    let err = deploy_prod(&mut ops, FakeOps::opts(dir.path()))
        .expect_err("a window inside the grown root must abort the ceremony");
    assert!(err.contains("INTERSECTS"), "wrong refusal: {err}");
    assert!(
        ops.staged_image.is_none() && ops.raw_window_digest.is_none(),
        "no image byte may be staged before the D-1 refusal"
    );
    assert!(
        !ops.target_calls.iter().any(|c| c.contains("kexec")),
        "the ceremony must never reach kexec: {:?}",
        ops.target_calls
    );
}

#[test]
fn happy_path_orders_gates_and_says_the_advisory() {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    deploy_prod(&mut ops, FakeOps::opts(dir.path())).expect("ceremony succeeds");

                                                                                          
                               
    let advisory = ops
        .said
        .iter()
        .find(|s| s.contains("BRICKED-UNTIL-CONSOLE"))
        .expect("advisory said");
    assert!(advisory.contains("INSTALL-TIME TCB"), "{advisory}");
    assert!(
        advisory.contains("FRESH,\n    UNCOMPROMISED provisioning host")
            || advisory.contains("UNCOMPROMISED provisioning host"),
        "{advisory}"
    );

                                                                                             
                                                                                                    
                                                                                          
                                                                                                        
                                    
    let pos = |needle: &str| {
        ops.target_calls
            .iter()
            .position(|c| c.contains(needle))
            .unwrap_or_else(|| panic!("missing call {needle:?}: {:?}", ops.target_calls))
    };
    let scan = pos("scan_host_key");
    let pin_a = pos("pin:Provisioning");
    let discovery = pos("findmnt -n -o SOURCE /");
    let first_scp = pos("scp:");
    let window_stage = pos("stage_raw_window:vda:");
    let sibling_verify = pos("dd if=/var/tmp/recipes-deploy/r.vmlinuz iflag=direct");
    let window_readback = pos("dd if=/dev/vda iflag=direct,skip_bytes");
    let kexec_load = pos("kexec -l");
    let fire = pos("fire_kexec");
    let pin_b = pos("pin:Reconnect");
    let cmdline_read = pos("cat /proc/cmdline");
    assert!(scan < pin_a && pin_a < discovery, "{:?}", ops.target_calls);
    assert!(discovery < first_scp && first_scp < window_stage);
    assert!(
        window_stage < sibling_verify && sibling_verify < window_readback,
        "siblings re-verify AFTER the window write, then the window itself: {:?}",
        ops.target_calls
    );
    assert!(window_readback < kexec_load && kexec_load < fire);
    assert!(fire < pin_b && pin_b < cmdline_read);
                                                                
    assert!(
        ops.target_calls[pin_b].contains("203.0.113.5 ssh-ed25519 AAAAfake"),
        "{}",
        ops.target_calls[pin_b]
    );
                                                                                             
                                                                                          
                                                                              
    let advisory = pos("say:ADVISORY");
    assert!(
        advisory < first_scp,
        "the advisory must precede staging: {:?}",
        ops.target_calls
    );
}

#[test]
fn tty_leg_a_confirm_and_wipe_retype_plumbing() {
                                                                                           
                                                                                         
                                                                                       
                                                                                           
                                       
    let dir = tempfile::tempdir().unwrap();

                                                                                          
                                                               
    let mut ops = FakeOps::happy(dir.path());
    ops.tty = true;
    ops.lines = ["yes".to_string(), "203.0.113.5".to_string()]
        .into_iter()
        .collect();
    let mut o = FakeOps::opts(dir.path());
    o.host_fingerprint = None;
    deploy_prod(&mut ops, o).expect("TTY confirm + correct retype proceeds");
    assert!(
        ops.target_calls
            .iter()
            .any(|c| c.contains("pin:Provisioning")),
        "the confirmed key must be pinned: {:?}",
        ops.target_calls
    );
    assert!(ops.target_calls.iter().any(|c| c == "fire_kexec"));

                                                                                          
                                                                              
    let mut ops = FakeOps::happy(dir.path());
    ops.tty = true;
    ops.lines = ["no".to_string()].into_iter().collect();
    let mut o = FakeOps::opts(dir.path());
    o.host_fingerprint = None;
    let err = deploy_prod(&mut ops, o).unwrap_err();
    assert!(err.contains("declined"), "{err}");
    assert_eq!(
        ops.target_calls
            .iter()
            .filter(|c| !c.starts_with("say:"))
            .collect::<Vec<_>>(),
        vec!["scan_host_key"],
        "only the scan may have happened: {:?}",
        ops.target_calls
    );

                                                                                         
                                                     
    let mut ops = FakeOps::happy(dir.path());
    ops.tty = true;
    ops.lines = ["203.0.113.6".to_string()].into_iter().collect();
    let err = deploy_prod(&mut ops, FakeOps::opts(dir.path())).unwrap_err();
    assert!(err.contains("matches neither"), "{err}");
    assert!(
        !ops.target_calls
            .iter()
            .any(|c| c.contains("scp") || c.contains("kexec -l") || c == "fire_kexec"),
        "no staging/kexec after a failed retype: {:?}",
        ops.target_calls
    );

                                                                                  
    let mut ops = FakeOps::happy(dir.path());
    ops.tty = true;                                          
    let err = deploy_prod(&mut ops, FakeOps::opts(dir.path())).unwrap_err();
    assert!(err.contains("no retyped target"), "{err}");
}

#[test]
fn nvme_target_bakes_p_separated_slot_a_device() {
                                                                                          
                                                                                            
                                                                                            
                                                                                         
                                                                         
    use recipes_image_builder::boot_fs::ROOTFS_DEV_SENTINEL;
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
                                                         
    for (needle, resp) in &mut ops.remote {
        match *needle {
            "findmnt -n -o SOURCE / " | "findmnt -n -o SOURCE --target" => {
                *resp = "/dev/nvme0n1p1\n".to_string();
            }
            "lsblk" => {
                *resp = "nvme0n1 disk  \nnvme0n1p1 part / nvme0n1\n".to_string();
            }
            "lsblk -nbro NAME,TYPE,START,SIZE" => {
                *resp = "nvme0n1 disk  42949672960\nnvme0n1p1 part 2048 3221225472\n".to_string();
            }
            "df -P -k" => {
                *resp = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                             /dev/nvme0n1p1 999999 1 999999 1% /\n"
                    .to_string();
            }
            _ => {}
        }
    }
    ops.remote.push((
        "cat /sys/class/block/nvme0n1/size",
        "83886080\n".to_string(),
    ));
                                                                                                
    let art = ops.artifacts.as_ref().unwrap();
    let img = std::fs::read(&art.img_path).unwrap();
    let mut staged_img = img.clone();
    crate::deploy::prod::patch_rootfs_dev(&mut staged_img[0..512], "/dev/nvme0n1p2").unwrap();
    let prefix_sha = recipes_image_builder::image::sha256_hex(&staged_img[0..512]);
    let staged_sha = recipes_image_builder::image::sha256_hex(&staged_img);
    for (needle, resp) in &mut ops.remote {
        if *needle == "head -c 512 /dev/vda1" {
            *needle = "head -c 512 /dev/nvme0n1p1";
            *resp = format!("{prefix_sha}  -\n");
        }
        if *needle == "dd if=/dev/vda iflag=direct,skip_bytes" {
            *needle = "dd if=/dev/nvme0n1 iflag=direct,skip_bytes";
            *resp = format!("{staged_sha}  -\n");
        }
    }
    deploy_prod(&mut ops, FakeOps::opts(dir.path())).expect("nvme ceremony succeeds");
    let staged = ops.staged_image.expect("staged via stage_raw_window");
    let boot = String::from_utf8_lossy(&staged[0..512]);
    assert!(
        boot.contains("fb.rootfs-dev=/dev/nvme0n1p2"),
        "must bake the p-separated slot-A device: {boot:?}"
    );
    assert!(
        !boot.contains("/dev/nvme0n12"),
        "the fused letter-form device must be gone: {boot:?}"
    );
    assert!(!boot.contains(ROOTFS_DEV_SENTINEL));
                                                                   
    assert!(
        ops.target_calls
            .iter()
            .any(|c| c.contains("head -c 512 /dev/nvme0n1p1")),
        "step-10 must read the p-form boot partition: {:?}",
        ops.target_calls
    );
}

#[test]
fn staged_image_boot_fs_is_patched_to_slot_a_not_the_reboot_loop_sentinel() {
                                                                                        
                                                                                                
                                                                                                  
                                                                                              
                                                      
    use recipes_image_builder::boot_fs::ROOTFS_DEV_SENTINEL;
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    deploy_prod(&mut ops, FakeOps::opts(dir.path())).expect("ceremony succeeds");
    let staged = ops
        .staged_image
        .expect("the .img must be staged via scp_image_bytes (the patched bytes)");
    let boot = String::from_utf8_lossy(&staged[0..64]);
    assert!(
        boot.contains("fb.rootfs-dev=/dev/vda2"),
        "the staged boot-fs must carry the slot-A device: {boot:?}"
    );
    assert!(
        !boot.contains(ROOTFS_DEV_SENTINEL),
        "the reboot-looping sentinel must be gone from the staged image: {boot:?}"
    );
}

#[test]
fn cancellation_pre_kexec_aborts_and_removes_staged() {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    ops.remote.push(("rm -f", String::new()));
    ops.cancel = true;                                                              
    let err = deploy_prod(&mut ops, FakeOps::opts(dir.path())).unwrap_err();
    assert!(err.contains("cancelled"), "{err}");
    assert!(
        !ops.target_calls.iter().any(|c| c == "fire_kexec"),
        "kexec must never fire on a cancelled run"
    );
}

#[test]
fn staged_hash_mismatch_aborts_before_kexec() {
                                                                                                
                                                                                             
                                                 
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    for (needle, resp) in &mut ops.remote {
        if needle.contains("r.vmlinuz iflag=direct") {
            *resp = format!("{}  -\n", "deadbeef".repeat(8));
        }
    }
    let err = deploy_prod(&mut ops, FakeOps::opts(dir.path())).unwrap_err();
    assert!(err.contains("mismatch"), "{err}");
    assert!(
        !ops.target_calls
            .iter()
            .any(|c| c.contains("kexec -l") || c == "fire_kexec"),
        "no kexec after a staged-hash mismatch: {:?}",
        ops.target_calls
    );
                                     
    let mut ops2 = FakeOps::happy(dir.path());
    for (needle, resp) in &mut ops2.remote {
        if needle.contains("/dev/vda iflag=direct,skip_bytes") {
            *resp = format!("{}  -\n", "deadbeef".repeat(8));
        }
    }
    let err2 = deploy_prod(&mut ops2, FakeOps::opts(dir.path())).unwrap_err();
    assert!(err2.contains("readback mismatch"), "{err2}");
    assert!(
        !ops2
            .target_calls
            .iter()
            .any(|c| c.contains("kexec -l") || c == "fire_kexec"),
        "no kexec after a window-readback mismatch: {:?}",
        ops2.target_calls
    );
}

#[test]
fn staged_img_removal_gated_on_pre_kexec_spawn_only() {
                                                                                             
                                                                                            
    assert!(should_remove_staged_img(CancelState::PreKexecSpawn));
    assert!(!should_remove_staged_img(CancelState::KexecInFlight));
    assert!(!should_remove_staged_img(CancelState::PastNoReturn));
}

#[test]
fn lock_key_collides_spellings_and_is_filename_safe() {
                                                                                   
    assert_eq!(lock_key("Box.Example.CH"), lock_key("box.example.ch\n"));
    assert_eq!(lock_key(" 203.0.113.5 "), lock_key("203.0.113.5"));
    assert_ne!(lock_key("203.0.113.5"), lock_key("203.0.113.6"));
                                                                                          
                                                                                  
    let k = lock_key("fe80::1%eth0/../x");
    assert!(
        k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')),
        "{k}"
    );
}

#[test]
fn deploy_lock_refuses_a_second_holder_until_released() {
    let dir = tempfile::tempdir().unwrap();
    let first = acquire_deploy_lock(dir.path(), "203.0.113.5").expect("first acquire");
                                                     
    let second = acquire_deploy_lock(dir.path(), " 203.0.113.5 ");
    assert!(second.is_err(), "concurrent deploy prod must be refused");
    assert!(
        second.unwrap_err().contains("203.0.113.5"),
        "refusal names the target"
    );
                                              
    let _other = acquire_deploy_lock(dir.path(), "203.0.113.9").expect("other ip");
                                         
    drop(first);
                                                                                             
                                                                                               
                                                                                             
                                                                                              
                                                                                                  
                                                                                               
                                                                                           
                                                                                     
                                                                                             
                                                                                          
                                                      
    let mut third = None;
    for _ in 0..50 {
        match acquire_deploy_lock(dir.path(), "203.0.113.5") {
            Ok(lock) => {
                third = Some(lock);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
    assert!(
        third.is_some(),
        "the lock must be re-acquirable after the holder is dropped"
    );
}

#[test]
fn kexec_load_command_quotes_append_as_one_arg_and_validates_inputs() {
    let append = "fb.mode=installer fb.root-hash=ab12 fb.verity-hash-offset=4096 \
                      fb.image-raw=vda:10737418240:1024 \
                      lockdown=integrity";
    let cmd = build_kexec_load_command(
        "/var/tmp/recipes-deploy/r.vmlinuz",
        "/var/tmp/recipes-deploy/r.initramfs",
        append,
    )
    .expect("clean inputs compose");
                                                                             
    assert!(
        cmd.contains(&format!("--append='{append}'")),
        "append must be one quoted arg: {cmd}"
    );
    assert!(cmd.starts_with("kexec -l /var/tmp/recipes-deploy/r.vmlinuz"));
    assert!(cmd.contains("--initrd=/var/tmp/recipes-deploy/r.initramfs"));
                                                                                              
    for bad in ["a'b", "a\\b", "a\nb", "a\0b", "ä"] {
        assert!(
            build_kexec_load_command(
                "/var/tmp/recipes-deploy/r.vmlinuz",
                "/var/tmp/recipes-deploy/r.initramfs",
                bad,
            )
            .is_err(),
            "{bad:?} must fail closed"
        );
    }
                                                                              
    assert!(build_kexec_load_command("/a b/vmlinuz", "/var/tmp/r.initramfs", append).is_err());
    assert!(build_kexec_load_command("/var/tmp/r.vmlinuz", "relative/initramfs", append).is_err());
}

#[test]
fn deploy_prod_allowlists_seabios_and_seabios_gpt_fail_closing_on_the_rest() {
                                                                                                      
                                                                                             
                                                                                              
                                                                                                   
    assert_eq!(
        layout_firmware_token("boot_offset = 1048576\nfirmware = \"seabios\"\n").as_deref(),
        Some("seabios")                                                                    
    );
    assert_eq!(
        layout_firmware_token(
            "boot_offset = 1048576\nfirmware = \"uefi\"\nrootfs_offset = 2097152\n"
        )
        .as_deref(),
        Some("uefi")
    );
    assert_eq!(
        layout_firmware_token("firmware=\"seabios-gpt\"").as_deref(),
        Some("seabios-gpt")                       
    );
                                                                                                     
                                                                            
    assert!(layout_firmware_token("boot_offset = 1048576\n").is_none());
    assert!(layout_firmware_token("# firmware = \"seabios\"").is_none());

                                                                                                     
                                                                                                   
    use recipes_image_builder::image::{Layout, render_layout_toml};
    let layout = |fw| Layout {
        boot_offset: 1 << 20,
        boot_size: 128 << 20,
        persist_skeleton_offset: 0,
        persist_skeleton_size: 0,
        rootfs_offset: 0,
        rootfs_size: 0,
        rootfs_verity_hash_offset: 0,
        weights_offset: None,
        weights_size: None,
        weights_verity_hash_offset: None,
        firmware: fw,
        image_version: 0,
        min_delegation_ctr: 0,
    };
    assert_eq!(
        layout_firmware_token(&render_layout_toml(&layout(
            recipes_image_builder::firmware::Firmware::Seabios
        )))
        .as_deref(),
        Some("seabios")
    );
    assert_eq!(
        layout_firmware_token(&render_layout_toml(&layout(
            recipes_image_builder::firmware::Firmware::SeabiosGpt
        )))
        .as_deref(),
        Some("seabios-gpt")
    );
    assert_eq!(
        layout_firmware_token(&render_layout_toml(&layout(
            recipes_image_builder::firmware::Firmware::Uefi
        )))
        .as_deref(),
        Some("uefi")
    );

                                                                        
    assert_eq!(
        firmware_deploy_eligible(Some("seabios")).unwrap(),
        Firmware::Seabios
    );
    assert_eq!(
        firmware_deploy_eligible(Some("seabios-gpt")).unwrap(),
        Firmware::SeabiosGpt
    );
    assert!(firmware_deploy_eligible(Some("uefi")).is_err());
    assert!(firmware_deploy_eligible(None).is_err());
}

#[test]
fn firmware_deploy_eligible_allowlists_seabios_and_seabios_gpt_failing_closed_on_the_rest() {
                                                                                                        
                                                                                                 
    assert_eq!(
        firmware_deploy_eligible(Some("seabios")).unwrap(),
        Firmware::Seabios
    );
    assert_eq!(
        firmware_deploy_eligible(Some("seabios-gpt")).unwrap(),
        Firmware::SeabiosGpt
    );
    assert!(firmware_deploy_eligible(Some("uefi")).is_err());                                         
    assert!(firmware_deploy_eligible(None).is_err());                                        
    assert!(firmware_deploy_eligible(Some("bios")).is_err());                           
    assert!(firmware_deploy_eligible(Some("")).is_err());
}

#[test]
fn local_boot_fs_identity_hash_replays_mbr_patch_and_hashes_gpt_verbatim() {
    use recipes_image_builder::image::sha256_hex;
                                                                                                   
                          
    let sentinel = recipes_image_builder::boot_fs::ROOTFS_DEV_SENTINEL;
    let mut boot = format!("APPEND fb.rootfs-dev={sentinel} ro").into_bytes();
    boot.resize(64, b' ');
    let mut img = boot.clone();
    img.extend_from_slice(&[0xABu8; 64]);
    let dir = tempfile::tempdir().unwrap();
    let img_path = dir.path().join("r.img");
    std::fs::write(&img_path, &img).unwrap();
    let mbr = LayoutInfo {
        boot_offset: 0,
        boot_size: 64,
        persist_skeleton_offset: 64,
        persist_skeleton_size: 8,
        rootfs_offset: 64,
        rootfs_size: 64,
        rootfs_verity_hash_offset: 32,
        firmware: Firmware::Seabios,
        weights_offset: None,
        weights_size: None,
    };
                                                                                                 
    let mut want_patched = img[0..64].to_vec();
    crate::deploy::prod::patch_rootfs_dev(&mut want_patched, "/dev/vda2").unwrap();
    assert_eq!(
        local_boot_fs_identity_hash(&img_path, &mbr, "vda").unwrap(),
        sha256_hex(&want_patched)
    );
                                                                          
    let gpt = LayoutInfo {
        firmware: Firmware::SeabiosGpt,
        ..mbr
    };
    assert_eq!(
        local_boot_fs_identity_hash(&img_path, &gpt, "vda").unwrap(),
        sha256_hex(&img[0..64])
    );
                                                                                                       
                                                                                                        
    assert_ne!(
        local_boot_fs_identity_hash(&img_path, &gpt, "vda").unwrap(),
        sha256_hex(&want_patched)
    );
                                                                                                    
                                                                     
    let bad = LayoutInfo {
        boot_size: 999,
        ..gpt
    };
    assert!(local_boot_fs_identity_hash(&img_path, &bad, "vda").is_err());
}

#[test]
fn deploy_prod_stages_a_seabios_gpt_image_verbatim_and_identity_passes() {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_gpt(dir.path());
    let raw_img = std::fs::read(dir.path().join("r.img")).unwrap();                                        
    deploy_prod(&mut ops, FakeOps::opts(dir.path()))
        .expect("the seabios-gpt flow should install + pass step-10 identity");
                                                                                   
    assert_eq!(ops.staged_image.as_deref(), Some(raw_img.as_slice()));
}

#[test]
fn deploy_prod_proceeds_when_image_exceeds_target_ram() {
                                                                                                
                                                                                               
                                                                                                   
                                                                                                     
                                                                                                     
                                                                                                     
                 
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_gpt(dir.path());
    for (needle, resp) in ops.remote.iter_mut() {
        if *needle == "cat /proc/meminfo" {
                                                                                                     
                                                                                                   
                                                                                           
                                                                                              
                                                                                                   
                                                                                                    
            *resp = "MemTotal:        1986560 kB\n".to_string();
        }
    }
    deploy_prod(&mut ops, FakeOps::opts(dir.path()))
        .expect("image-vs-RAM must no longer gate the ceremony");
    assert!(
        ops.target_calls
            .iter()
            .any(|c| c.starts_with("stage_raw_window:")),
        "the flow must reach the raw-window staging: {:?}",
        ops.target_calls
    );
}

#[test]
fn deploy_prod_refuses_a_weights_box_on_a_tight_disk_pre_staging() {
                                                                                                   
                                                                                         
                                                                                             
                                                                                                    
                                                                                                     
                                                                                                 
                                                                                                  
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_gpt(dir.path());
    if let Some(art) = ops.artifacts.as_mut() {
                                                                                             
        art.layout.weights_offset = Some(1024);
        art.layout.weights_size = Some(512);
    }
                                                                                                    
                                                                                                  
    for (needle, resp) in ops.remote.iter_mut() {
        if *needle == "cat /sys/class/block/vda/size" {
            *resp = "409600\n".to_string();
        }
    }
    let err = deploy_prod(&mut ops, FakeOps::opts(dir.path())).unwrap_err();
    assert!(
        err.contains("weights-inclusive layout") || err.contains("unplaceable"),
        "{err}"
    );
    assert!(
        !ops.target_calls.iter().any(|c| {
            c.starts_with("scp") || c.starts_with("stage_raw_window") || c.as_str() == "fire_kexec"
        }),
        "the weights-inclusive fit refusal must abort pre-staging: {:?}",
        ops.target_calls
    );
}

#[test]
fn deploy_prod_refuses_an_over_ram_restore_pre_staging() {
                                                                                                
                                                                                               
                                                                      
    use recipes_image_builder::image::sha256_hex;
    let dir = tempfile::tempdir().unwrap();
    let fixture = fixture_restore_image();
    let (pin, img) = signed_restore_artifact(dir.path(), "restore-1.persist.img", &fixture);
    let _ = sha256_hex(&fixture);
    let mut ops = FakeOps::happy(dir.path());
    for (needle, resp) in ops.remote.iter_mut() {
        if *needle == "cat /proc/meminfo" {
                                                                                              
                                                                           
            *resp = "MemTotal:         270000 kB\n".to_string();
        }
    }
    let opts = restore_opts(dir.path(), &img, Some(pin));
    let err = deploy_prod(&mut ops, opts).unwrap_err();
    assert!(err.contains("restore"), "{err}");
    assert!(err.contains("RAM"), "{err}");
    assert!(
        !ops.target_calls.iter().any(|c| {
            c.starts_with("scp") || c.starts_with("stage_raw_window") || c.as_str() == "fire_kexec"
        }),
        "the restore-RAM refusal must abort pre-staging: {:?}",
        ops.target_calls
    );
}

#[test]
fn deploy_prod_refuses_when_old_root_free_space_is_below_the_window() {
                                                                                                
                                                                                              
                                                                                  
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_gpt(dir.path());
    for (needle, resp) in ops.remote.iter_mut() {
        if *needle == "df -P -k" {
                                                                                                
                                                                            
            *resp = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                     /dev/vda1 999999 999999 0 100% /\n"
                .to_string();
        }
    }
                                                                                        
    ops.remote.insert(
        0,
        (
            "df -P -k /var/tmp/recipes-deploy",
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
             /dev/vda1 999999 1 999999 1% /\n"
                .to_string(),
        ),
    );
    let err = deploy_prod(&mut ops, FakeOps::opts(dir.path())).unwrap_err();
    assert!(err.contains("free"), "{err}");
    assert!(
        !ops.target_calls.iter().any(|c| {
            c.starts_with("scp") || c.starts_with("stage_raw_window") || c.as_str() == "fire_kexec"
        }),
        "the free-space advisory must abort pre-staging: {:?}",
        ops.target_calls
    );
}

#[test]
fn deploy_prod_append_equals_the_v2_composer_output() {
                                                                                                 
                                                                                               
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_gpt(dir.path());
                                                                                    
    let art_ref = ops.artifacts.as_ref().unwrap();
    let layout = art_ref.layout;
    let img_len = art_ref.img_len;
    let img = std::fs::read(&art_ref.img_path).unwrap();
    deploy_prod(&mut ops, FakeOps::opts(dir.path())).expect("gpt ceremony succeeds");
    let kexec = ops
        .target_calls
        .iter()
        .find(|c| c.contains("kexec -l"))
        .expect("kexec load recorded")
        .clone();
    let staged_sha = recipes_image_builder::image::sha256_hex(&img);                       
                                                              
    let window = crate::deploy::staging_geometry::place_and_check_window(
        &layout,
        "vda",
        83_886_080 * 512,
        img_len,
        0,
    )
    .unwrap();
    let expected = crate::deploy::prod::build_installer_cmdline(
        &"ab".repeat(32),
        layout.rootfs_verity_hash_offset,
        &window,
        &staged_sha,
        &layout,
        None,
        None,
    )
    .unwrap();
    assert!(
        kexec.contains(&format!("--append='{expected}'")),
        "flow append must equal the composer output:\nflow:     {kexec}\ncomposer: {expected}"
    );
}

#[test]
fn deploy_prod_refuses_below_the_fixed_ram_floor() {
                                                                                                
                                                                                                   
                                                
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    for (needle, resp) in ops.remote.iter_mut() {
        if *needle == "cat /proc/meminfo" {
            *resp = "MemTotal:         204800 kB\n".to_string();                               
        }
    }
    let err = deploy_prod(&mut ops, FakeOps::opts(dir.path())).unwrap_err();
    assert!(err.contains("installer floor"), "{err}");
    assert!(
        !ops.target_calls.iter().any(|c| {
            c.starts_with("scp") || c.starts_with("stage_raw_window") || c.as_str() == "fire_kexec"
        }),
        "the floor refusal must abort before staging/kexec: {:?}",
        ops.target_calls
    );
}

                                                                                                 

/// The committed real-bake persist-skeleton fixture (T1, reader-crate-local): a genuine
/// `orchard restore-image`-class ext4 whose staged operator key is FIXTURE_PUBKEY_LINE.
fn fixture_restore_image() -> Vec<u8> {
    use std::io::Read as _;
    let gz = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../syslinux-install/tests/fixtures/persist-skeleton-16m.img.gz"
    ))
    .expect("the T1 fixture exists");
    let mut img = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut img)
        .expect("fixture gunzips");
    img
}
/// The REAL (throwaway, public-half-only) key baked into the fixture — must be
/// ssh-keygen-valid because leg 4 canonicalizes --pubkey via read_validated_pubkey.
const FIXTURE_PUBKEY_LINE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8lxt94RGN2sG/6ECF1NEO49z1nsPu61qOPl0dQ4HGJ restore-fixture@test";

/// Mint a real artifact key set + sign `bytes` as a Backup artifact at `dir/<name>`.
/// Returns (root pin, image path).
fn signed_restore_artifact(dir: &Path, name: &str, bytes: &[u8]) -> ([u8; 32], PathBuf) {
    use crate::deploy::artifact_keys::{Custody, generate_artifact_keys, load_artifact_keys};
    use crate::deploy::artifact_sign::{sign_file, test_authority};
    let keys = dir.join("keys");
    generate_artifact_keys(&keys, 365, false, Custody::Raw).unwrap();
    let set = load_artifact_keys(&keys).unwrap();
    let root_pub = set.root_pub;
    let auth = test_authority(set);
    let img_path = dir.join(name);
    std::fs::write(&img_path, bytes).unwrap();
    sign_file(&auth, dragonfruit::Purpose::Backup, &img_path).unwrap();
    (root_pub, img_path)
}

fn restore_opts(dir: &Path, image: &Path, pin: Option<[u8; 32]>) -> DeployProdOpts {
    let mut o = FakeOps::opts(dir);
    o.restore_from = Some(image.to_path_buf());
    o.artifact_pin = pin;
                                                                                     
    std::fs::write(dir.join("op.pub"), format!("{FIXTURE_PUBKEY_LINE}\n")).unwrap();
    o
}

#[test]
fn restore_preflight_no_pin_aborts_before_any_remote_action() {
                                                                                                  
                                                                           
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("restore-1.persist.img");
    std::fs::write(&img, fixture_restore_image()).unwrap();
    let mut ops = FakeOps::happy(dir.path());
    let opts = restore_opts(dir.path(), &img, None);
    let err = preflight_restore(&mut ops, &opts).unwrap_err();
    assert!(err.contains("pin"), "{err}");
    assert!(
        ops.target_calls.is_empty(),
        "no remote action on a preflight refusal: {:?}",
        ops.target_calls
    );
}

                                                                                                 
/// `deploy_prod` call site attaches the ceremony residue disclosure. Drive the WHOLE staging closure
/// to the composer's length refusal (a long on-target stage dir pushes the restore path past
/// `COMMAND_LINE_SIZE - 1`) and assert the surfaced error carries BOTH the interpolated staging path
/// and the "free-space tail" residue clause — the disclosure the call site now owns.
///
/// Claim (the call-site disclosure), not coverage: reverting the `map_err` at
/// `prod_orchestrate.rs` reds this test and no other in the suite.
#[test]
fn over_budget_composer_refusal_surfaces_the_call_site_residue_disclosure() {
    use recipes_image_builder::image::sha256_hex;
    let dir = tempfile::tempdir().unwrap();

                                                                                                  
                                                                                                      
                                                                                       
                                                                               
    let long_stage = format!("/var/tmp/{}", "d".repeat(1990));

    let img_bytes = fixture_restore_image();
    let (pin, img) = signed_restore_artifact(dir.path(), "restore-1.persist.img", &img_bytes);
    let opts = restore_opts(dir.path(), &img, Some(pin));

    let mut ops = FakeOps::happy(dir.path());
                                                                                                  
                                             
    ops.remote.insert(
        0,
        (
            "mkdir -p /var/tmp/recipes-deploy",
            format!("{long_stage}\n"),
        ),
    );
                                                                                                      
                                                                                                      
                                                                                           
    let vml_sha = sha256_hex(&[0x07u8; 32]);
    let ifs_sha = sha256_hex(&[0x08u8; 16]);
    let sig_path = crate::deploy::artifact_sign::sig_sidecar_path(&img);
    let sig_bytes = std::fs::read(&sig_path).unwrap();
    ops.remote
        .insert(0, ("/r.vmlinuz iflag=direct", format!("{vml_sha}  -\n")));
    ops.remote
        .insert(0, ("/r.initramfs iflag=direct", format!("{ifs_sha}  -\n")));
    ops.remote.insert(
        0,
        (
            "restore-1.persist.img iflag=direct",
            format!("{}  -\n", sha256_hex(&img_bytes)),
        ),
    );
    ops.remote.insert(
        0,
        (
            "restore-1.persist.img.sig iflag=direct",
            format!("{}  -\n", sha256_hex(&sig_bytes)),
        ),
    );

    let err = deploy_prod(&mut ops, opts)
        .expect_err("the over-budget restore path must refuse at the composer");
    assert!(
        err.contains(&long_stage),
        "the surfaced error must interpolate the staging path the call site holds: {err}"
    );
    assert!(
        err.contains("free-space tail"),
        "the surfaced error must carry the call-site residue disclosure: {err}"
    );
                                                                                                
                                                                                             
                                                                   
    assert!(
        err.contains("bzImage64_load") && err.contains("no token delivered"),
        "a length refusal must carry the kexec-consumer narration: {err}"
    );
}

                                                                                                  
/// site-scoped residue disclosure but NOT the length-only kexec-consumer narration. Drive the whole
/// staging closure to a shape refusal (`--restore-min-ctr` with no `--restore-from`) and assert the
/// narration is absent while the residue clause is present.
///
/// Claim (the variant-conditional split), not coverage: dropping the `matches!(CmdlineError::Length)`
/// guard at the `deploy_prod` map_err (attaching the narration unconditionally) reds this test.
#[test]
fn a_shape_composer_refusal_omits_the_length_only_kexec_narration() {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    let mut opts = FakeOps::opts(dir.path());
                                                                                       
                                                             
    opts.restore_min_ctr = Some(42);
    let err = deploy_prod(&mut ops, opts)
        .expect_err("min-ctr without restore must refuse at the composer's shape arm");
    assert!(
        err.contains("--restore-min-ctr given without --restore-from"),
        "the shape refusal must carry its own caller-agnostic mechanics: {err}"
    );
    assert!(
        err.contains("free-space tail"),
        "the site-scoped residue disclosure attaches to every composer refusal: {err}"
    );
    assert!(
        !err.contains("bzImage64_load") && !err.contains("no token delivered"),
        "a shape refusal must NOT carry the length-only kexec-consumer narration: {err}"
    );
}

#[test]
fn restore_preflight_leg1_missing_sig_aborts() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("restore-1.persist.img");
    std::fs::write(&img, fixture_restore_image()).unwrap();
    let mut ops = FakeOps::happy(dir.path());
    let opts = restore_opts(dir.path(), &img, Some([0x42; 32]));
    let err = preflight_restore(&mut ops, &opts).unwrap_err();
    assert!(err.contains(".sig"), "{err}");
    assert!(ops.target_calls.is_empty());
}

#[test]
fn restore_preflight_leg2_bad_signature_aborts() {
                                                                                      
    let dir = tempfile::tempdir().unwrap();
    let (_real_pin, img) = signed_restore_artifact(
        dir.path(),
        "restore-1.persist.img",
        &fixture_restore_image(),
    );
    let mut ops = FakeOps::happy(dir.path());
    let opts = restore_opts(dir.path(), &img, Some([0x42; 32]));             
    let err = preflight_restore(&mut ops, &opts).unwrap_err();
    assert!(err.contains("verify FAILED"), "{err}");
    assert!(ops.target_calls.is_empty());
}

#[test]
fn restore_preflight_leg3_rejects_a_signed_non_ext4() {
                                                                                               
                                                                                       
    let dir = tempfile::tempdir().unwrap();
    let (pin, img) =
        signed_restore_artifact(dir.path(), "data-1.tar.gz", b"not-an-ext4-image-at-all");
    let mut ops = FakeOps::happy(dir.path());
    let opts = restore_opts(dir.path(), &img, Some(pin));
    let err = preflight_restore(&mut ops, &opts).unwrap_err();
    assert!(err.contains("ext4") || err.contains("superblock"), "{err}");
    assert!(
        ops.said.iter().any(|s| s.contains("monotonic_ctr")),
        "leg 2 verified (and printed the ctr) BEFORE leg 3 refused: {:?}",
        ops.said
    );
    assert!(
        ops.target_calls.iter().all(|c| c.starts_with("say:")),
        "nothing remote ran: {:?}",
        ops.target_calls
    );
}

#[test]
fn restore_preflight_leg4_rejects_a_wrong_staged_key() {
                                                                                               
                                                                                    
    let dir = tempfile::tempdir().unwrap();
    let (pin, img) = signed_restore_artifact(
        dir.path(),
        "restore-1.persist.img",
        &fixture_restore_image(),
    );
    let mut ops = FakeOps::happy(dir.path());
    let mut opts = restore_opts(dir.path(), &img, Some(pin));
                                                                         
    let other = dir.path().join("other");
    assert!(
        std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-q", "-f"])
            .arg(&other)
            .status()
            .unwrap()
            .success()
    );
    opts.pubkey = other.with_extension("pub");
    let err = preflight_restore(&mut ops, &opts).unwrap_err();
    assert!(err.contains("STAGED IN"), "{err}");
    assert!(ops.target_calls.iter().all(|c| c.starts_with("say:")));
}

#[test]
fn restore_preflight_happy_carries_the_bytes_and_prints_the_ctr() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = fixture_restore_image();
    let (pin, img) = signed_restore_artifact(dir.path(), "restore-1.persist.img", &fixture);
    let mut ops = FakeOps::happy(dir.path());
    let opts = restore_opts(dir.path(), &img, Some(pin));
    let pre = preflight_restore(&mut ops, &opts)
        .expect("all five legs pass")
        .expect("Some for --restore-from");
    assert_eq!(
        pre.image_bytes, fixture,
        "the verified bytes are carried verbatim"
    );
    assert_eq!(pre.image_name, "restore-1.persist.img");
    assert_eq!(pre.sig_name, "restore-1.persist.img.sig");
                                                                                          
    let v = crate::deploy::artifact_verify::verify_artifact_returning(
        &pin,
        dragonfruit::Purpose::Backup,
        &img,
    )
    .unwrap();
    assert_eq!(pre.printed_ctr, v.monotonic_ctr());
    assert!(
        ops.said
            .iter()
            .any(|s| s.contains(&format!("monotonic_ctr = {}", pre.printed_ctr))),
        "{:?}",
        ops.said
    );
                                                      
    let g = preflight_restore(&mut ops, &FakeOps::opts(dir.path())).unwrap();
    assert!(g.is_none());
}

#[test]
fn restore_ceremony_stages_the_pair_and_threads_the_tokens() {
                                                                                              
                                                                                            
                                                                
    use recipes_image_builder::image::sha256_hex;
    let dir = tempfile::tempdir().unwrap();
    let fixture = fixture_restore_image();
    let (pin, img) = signed_restore_artifact(dir.path(), "restore-1.persist.img", &fixture);
    let sig_bytes = std::fs::read(img.with_extension("persist.img.sig"))
        .unwrap_or_else(|_| std::fs::read(format!("{}.sig", img.display())).expect(".sig exists"));
    let mut ops = FakeOps::happy(dir.path());
                                                                  
    ops.remote.push((
        "dd if=/var/tmp/recipes-deploy/restore-1.persist.img iflag=direct",
        format!("{}  -\n", sha256_hex(&fixture)),
    ));
    ops.remote.push((
        "dd if=/var/tmp/recipes-deploy/restore-1.persist.img.sig",
        format!("{}  -\n", sha256_hex(&sig_bytes)),
    ));
    let mut opts = restore_opts(dir.path(), &img, Some(pin));
    opts.restore_min_ctr = Some(7);
    deploy_prod(&mut ops, opts).expect("the restore ceremony completes");
                                                                
    assert!(
        ops.target_calls
            .iter()
            .any(|c| c == "scp_image:/var/tmp/recipes-deploy/restore-1.persist.img"),
        "{:?}",
        ops.target_calls
    );
    assert!(
        ops.target_calls
            .iter()
            .any(|c| c == "scp_image:/var/tmp/recipes-deploy/restore-1.persist.img.sig")
    );
                                                                                 
    let kexec = ops
        .target_calls
        .iter()
        .find(|c| c.contains("kexec -l"))
        .expect("kexec load recorded");
    assert!(
        kexec.contains("fb.restore-from=disk:vda1:/var/tmp/recipes-deploy/restore-1.persist.img"),
        "{kexec}"
    );
    assert!(kexec.contains("fb.min-ctr=7"), "{kexec}");
}

#[test]
fn probe_f2_step4_clock_skew_overflow_refuses_not_panics() {
                                                                                                
                                                                                                    
                                                                                                     
                                                                              
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    ops.remote_once
        .push_back(("date +%s", "9223372036854775808\n".to_string()));
    let err = deploy_prod(&mut ops, FakeOps::opts(dir.path()))
        .expect_err("an out-of-range target clock must refuse, not overflow");
    assert!(
        err.contains("out of i64 range") && err.contains("aborting"),
        "F-2 refusal names the out-of-range clock and aborts: {err}"
    );
}

#[test]
fn probe_f4_reconnect_deadline_overflow_refuses_not_panics() {
                                                                                              
                                                                                                 
                                                                                                     
                                                                                                   
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    ops.mock_clock = Some(std::cell::Cell::new(1_780_000_000));
    let err = reconnect_wait(&mut ops, i64::MAX as u64)
        .expect_err("an out-of-range reconnect timeout must refuse, not overflow");
    assert!(
        err.contains("reconnect-timeout-secs") && err.contains("aborting"),
        "F-4 refusal names the flag and aborts: {err}"
    );
}

                                                                                                 
                                                                                         
#[path = "prod_orchestrate_reclaim_tests.rs"]
mod reclaim;
