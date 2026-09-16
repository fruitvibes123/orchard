                                                                                                   
//! Task 11/12). This is the PRODUCED-BYTES proof for the operator ceremony: it boots a real Debian
//! cloud image under QEMU, lets cloud-init inject an ephemeral provisioning key,
//! then drives the REAL [`super::prod_orchestrate::deploy_prod`] over the REAL
//! [`super::prod_orchestrate::ProcessOps`] (hardened ssh/scp/ssh-keyscan/kexec — only the sshd
//! PORT differs, forwarded by QEMU user-net) against that guest. A green run means the box was
//! installed onto the guest by kexec-takeover, the step-10 crypto identity passed over the
//! derived-fingerprint-pinned reconnect, AND the harness's own non-ceremony post-condition probe
//! corroborated it (acceptance #1 — never only the tool-under-test's self-verdict).
//!
//! Unlike the `dryrun`/`deploy_prod_qemu` gates (which boot the box `.img` directly via `-kernel`),
//! this harness boots Debian's OWN kernel (no `-kernel`/`-initrd`, reboot PERMITTED so the post-kexec
//! install→reboot→box transition runs through SeaBIOS), with the box `.img` carried in only as the
//! operator-supplied artifact the ceremony scp's + kexecs — exactly the real flow.
//!
//! Operator-run (`make boot-gate`); the integration test is `#[ignore]` + panics without its env.
//! It consumes THREE operator inputs: the built box `.img` (+ its sidecars/vmlinuz/initramfs, built
//! with `--operator-pubkey` + `--net` for the QEMU user-net), the matching operator private key, and
//! a Debian generic-cloud-derived fixture (`RECIPES_PROD_E2E_DEBIAN_IMG`). The harness downloads
//! nothing — the fixture is operator-supplied, built once by [`prepare_kexec_fixture`], which prints
                                                                                              
//! `pins.toml`/`consume-pins.toml` build inputs, the fixture sha is recorded in prose, not asserted
//! by any gate run, so a fixture built from a different Debian base would green while describing an
//! unspecified target. The two obvious wrong-image cases still fail closed — no `kexec-tools` → the
//! kexec-discovery timeout; `cloud-initramfs-growroot` present → D-1's partition-intersection refusal.
//!
//! **The guest runs HERMETIC** (`-netdev user,…,restrict=on`; [`DebianE2eOpts::restrict_net`]) — no
                                                                                                 
//! manifest ships a live `fb-acme-renew`, so a box booted under open NAT placed real Let's Encrypt
//! **production** orders from the operator's IP on every run. The cost is that `kexec-tools` can no
//! longer be apt-installed at boot, so it is baked into a one-time fixture image by
//! [`prepare_kexec_fixture`] (`make e2e-kexec-fixture`) — which also removes an unpinned live-network
//! dependency from a produced-bytes gate, and deletes the apt fetch from every run's critical path.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::dryrun::{QemuGuard, console_tail, wait_for_ssh};
use super::prod::{WipeConfirmed, validate_target_host};
use super::prod_orchestrate::{
    DeployProdOpts, ImageArtifacts, Leg, OrchestrationOps, ProcessOps, deploy_prod,
};

/// Knobs for the Debian-guest e2e. Defaults are generous — a nested-KVM Debian boot + cloud-init
/// apt-install + the full box install + two reboots are heavier than a bare box dryrun.
#[derive(Debug, Clone)]
pub struct DebianE2eOpts {
    /// Host port forwarded to the guest's sshd (22 inside the guest; the box reuses 22 after
    /// install, so ONE forward covers both the provisioning leg and the reconnect leg).
    /// PORT DISCIPLINE (the `deploy_rescue_smoke` lesson): tests in one binary run on parallel
    /// test threads, each booting its own QEMU — concurrent tests MUST claim distinct host ports
    /// or the second `hostfwd` bind fails. The happy path keeps this 2222 default; the negatives
    /// test takes 2224 (2223/8444 are the rescue smoke's; 8443 is the dryrun https default).
    pub forward_port: u16,
    /// Guest RAM (MiB) — the box install runs entirely in the guest.
    pub memory_mb: u32,
    /// How long to wait for the guest's cloud-init to finish (inject the key + bring sshd up).
    /// Generous: a nested-KVM cold boot is slow. No longer covers an apt fetch — `kexec-tools` comes
    /// pre-installed on the fixture (see [`prepare_kexec_fixture`]).
    pub guest_boot_timeout: Duration,
    /// Make the guest network HERMETIC (`-netdev user,…,restrict=on`): the `hostfwd` inbound port
    /// still works (every ssh leg and the ceremony's reconnect are unaffected), but the guest — and
    /// the BOX installed into it — gets NO outbound NAT/DNS.
    ///
                                                                                                    
    /// runs a real `fb-acme-renew` longrun, so a box booted under open NAT places a live **Let's
    /// Encrypt production** order — creating an ACME account from the operator's public IP on every
    /// gate run, and burning rate limits against the endpoint the real-domain order will need. Same
                                                                                           
    /// [`super::dryrun::DryrunOpts::restrict_net`]); this is that fix reaching the prod-e2e path.
    /// Blocking egress also keeps the guest's `ntpd` off the public internet.
    ///
    /// The ONLY caller that legitimately sets this `false` is [`prepare_kexec_fixture`], whose whole
    /// job is the one-time apt fetch — outbound access is explicit and scoped to fixture prep, never
    /// inherited by a gate.
    pub restrict_net: bool,
    /// How long to wait for the installed box to come up post-kexec (install + reboot + first-boot
    /// grow). Passed straight to [`DeployProdOpts::reconnect_timeout_secs`].
    pub reconnect_timeout_secs: u64,
                                                                                                        
    /// `image + INSTALL_MIN_RAM_BYTES > guest RAM` (whole-image buffering cannot fit), plus a
    /// weights-payload floor against the profile's pinned bytes. `Some` only on the weights leg; the
    /// standard happy leg leaves this `None`.
    ///
    /// MEASURED (produced bytes): at the prod 2 GiB config the VL-pair image is 1804 MiB — just UNDER
    /// the guest — so the naive `image > RAM` is FALSE at prod and asserting it would fail the gate on
    /// the genuine production artifact. The sum form is the true statement and keeps real margin
    /// (1804.4 + 256 = 2060.4 > 2048.0, by only 12.4 MiB). See [`super::dryrun::assert_prod_weights_shape`].
    pub weights_proof: Option<super::dryrun::ProdWeightsProof>,
    /// Grow the guest's qcow2 overlay to this many bytes (`None` = inherit the Debian base's 3 GiB).
    ///
    /// The streaming ceremony stages the `.img` on a raw window at the target disk's TAIL, which must
    /// not reach down into the installed partitions — so the target needs room for the install footprint
    /// PLUS the whole image. A production-sized image does not fit a 3 GiB disk, and the ceremony's own
    /// geometry preflight aborts pre-write. Real 2 GiB-RAM VPS targets ship far more disk than this;
    /// the weights leg sizes the guest accordingly so the gate models a plausible target rather than an
    /// artificially cramped one. Sparse: costs only what the guest actually writes.
    pub guest_disk_bytes: Option<u64>,
                                                                                   
    /// resize_rootfs true) so the default-provisioned fixture keeps its class behaviour across
    /// the harness's reboots. Only the reclaim legs set this.
    pub grown_user_data: bool,
                                                                                        
    /// everywhere else, so every existing leg's ceremony inputs are byte-identical.
    pub reclaim_tail: bool,
}

/// The box's PROD install RAM (2026-07-24 directive: prod = a 2B model at 2 GiB). Both re-anchored
/// gates size their guest to this.
pub const PROD_INSTALL_RAM_MIB: u32 = 2048;

impl Default for DebianE2eOpts {
    fn default() -> Self {
        DebianE2eOpts {
            forward_port: 2222,
            memory_mb: PROD_INSTALL_RAM_MIB,
            guest_boot_timeout: Duration::from_secs(420),
            reconnect_timeout_secs: 600,
            weights_proof: None,
                                                                                                        
                                                                                                  
                                                                                                     
                                                                 
            guest_disk_bytes: Some(REFERENCE_E2E_GUEST_DISK_BYTES),
                                                                                                         
            restrict_net: true,
            grown_user_data: false,
            reclaim_tail: false,
        }
    }
}

/// The REFERENCE legs' guest disk: 6 GiB.
///
/// Not a tuning knob — a D-1 requirement. The stock Debian genericcloud image is 3 GiB virtual and
/// its root partition ALREADY spans sectors 262144→6289407 as shipped, leaving about 1 MB of free
/// space on the whole disk (measured with `sgdisk -p` on the pinned base). So even with `growpart`
/// disabled there is no tail for the raw staging window to live in, and `place_and_check_window`
/// would happily place one INSIDE the mounted root fs — which is exactly what D-1 now refuses.
///
/// Growing the disk (and only the disk — `growpart` stays off, so the partition does NOT follow)
/// creates ~3 GiB of genuinely unpartitioned tail, which is where the window belongs. Sparse: costs
/// only what the guest actually writes.
pub const REFERENCE_E2E_GUEST_DISK_BYTES: u64 = 6 * 1024 * 1024 * 1024;

                                                                                                             
/// (measured: the ceremony refused at 3 GiB, wanting the tail window to sit above byte 2,001,731,584 with
/// a 1,892,032,512-byte image). 12 GiB gives that real headroom and is modest for a 2 GiB-RAM VPS.
pub const PROD_E2E_GUEST_DISK_BYTES: u64 = 12 * 1024 * 1024 * 1024;

/// The nocloud `user-data` injected into the Debian guest: write the ephemeral provisioning pubkey
/// to root's `authorized_keys`. `disable_root: false` keeps cloud-init from prefixing the key with
/// its no-login forced command; the stock Debian-genericcloud sshd already admits root PUBKEY login
/// (`PermitRootLogin prohibit-password`), so NO sshd restart is added — one would race and drop the
/// in-flight cloud-init-wait ssh session. PURE — unit-tested; the I/O (cloud-localds, QEMU) is
/// integration-proven by the `#[ignore]` gate.
///
                                                                                                     
/// HARD-aborts without `kexec`, but installing it here needed `package_update: true` + an apt fetch
/// over the guest's outbound NAT — and that same open NAT is what let a booted box place live Let's
/// Encrypt production orders. The package now comes pre-installed on the fixture built by
/// [`prepare_kexec_fixture`], which is what lets [`DebianE2eOpts::restrict_net`] default to `true`.
///
                                                                                                     
/// The streaming ceremony places its raw staging window at the extreme disk TAIL, and cloud-init's
/// `growpart` grows the root partition to the disk's END — so on a default-provisioned cloud image
/// the two ALWAYS intersect, at any disk size. That is not a rare race: it is the Debian/Ubuntu
                                                                                                       
/// inside the live mounted root fs and passed only because the digest happened not to catch a
/// writeback.
///
/// With `growpart` off the root stays at the base image's ~3 GiB, the grown 12 GiB disk keeps a
/// genuinely UNPARTITIONED tail, and the gate proves the streaming install without a writeback race
/// in the middle of it. What this gate therefore no longer models is a DEFAULT-provisioned provider
/// — and against such a target `orchard prod` now refuses outright, by design, until the
/// consent-gated `--reclaim-tail` (spec D-2, its own cycle) can shrink the doomed root fs. D-1's
                                                                                 
pub fn render_cloud_init_user_data(provisioning_pubkey_line: &str) -> String {
                                                                                                  
                                                                                                     
                                                                                                      
                                                                                                   
                                                                                                
    format!(
                                                                                                
                                                                                                      
                                                                                                  
                                                              
        "#cloud-config\n\
         disable_root: false\n\
         ssh_pwauth: false\n\
         growpart:\n\
         \x20 mode: 'off'\n\
         resize_rootfs: false\n\
         write_files:\n\
         \x20 - path: /root/.ssh/authorized_keys\n\
         \x20   owner: 'root:root'\n\
         \x20   permissions: '0600'\n\
         \x20   content: |\n\
         \x20     {provisioning_pubkey_line}\n\
         runcmd:\n\
         \x20 - [ install, -d, -m, '0700', -o, root, -g, root, /root/.ssh ]\n\
         \x20 - [ chmod, '0600', /root/.ssh/authorized_keys ]\n\
         \x20 - [ chown, 'root:root', /root/.ssh/authorized_keys ]\n\
         \x20 - [ install, -d, -m, '0700', -o, debian, -g, debian, /home/debian/.ssh ]\n\
         \x20 - [ cp, /root/.ssh/authorized_keys, /home/debian/.ssh/authorized_keys ]\n\
         \x20 - [ chmod, '0600', /home/debian/.ssh/authorized_keys ]\n\
         \x20 - [ chown, 'debian:debian', /home/debian/.ssh/authorized_keys ]\n"
    )
}

                                                                                         
/// exercises — growpart ON (`mode: auto`) and `resize_rootfs: true`, exactly the two knobs a
/// provider default supplies, with `cloud-initramfs-growroot` RETAINED by the grown fixture
/// builder. Everything else (hermetic, no packages, root pubkey wiring) matches the base
/// renderer; the existing fail-closed assertion on that renderer stays intact and keeps
/// covering every other leg (Decision 5).
pub fn render_cloud_init_user_data_grown(provisioning_pubkey_line: &str) -> String {
    format!(
        "#cloud-config\n\
         disable_root: false\n\
         ssh_pwauth: false\n\
         growpart:\n\
         \x20 mode: auto\n\
         resize_rootfs: true\n\
         write_files:\n\
         \x20 - path: /root/.ssh/authorized_keys\n\
         \x20   owner: 'root:root'\n\
         \x20   permissions: '0600'\n\
         \x20   content: |\n\
         \x20     {provisioning_pubkey_line}\n\
         runcmd:\n\
         \x20 - [ install, -d, -m, '0700', -o, root, -g, root, /root/.ssh ]\n\
         \x20 - [ chmod, '0600', /root/.ssh/authorized_keys ]\n\
         \x20 - [ chown, 'root:root', /root/.ssh/authorized_keys ]\n\
         \x20 - [ install, -d, -m, '0700', -o, debian, -g, debian, /home/debian/.ssh ]\n\
         \x20 - [ cp, /root/.ssh/authorized_keys, /home/debian/.ssh/authorized_keys ]\n\
         \x20 - [ chmod, '0600', /home/debian/.ssh/authorized_keys ]\n\
         \x20 - [ chown, 'debian:debian', /home/debian/.ssh/authorized_keys ]\n"
    )
}

/// Host tools this harness AND the ceremony it drives shell out to, checked HERE (this fn is the
/// only preflight on this path — there is no `dryrun::preflight` delegation): the QEMU image
/// tooling, the cloud-init seed builder, the full ssh client set (`scp` stages the artifacts),
/// and `veritysetup` (the ceremony's local fb.root-hash recompute plus the harness's own
                                                                                               
/// missing one failed mid-flight (safely, pre-kexec) instead of at preflight.
const E2E_HOST_TOOLS: [&str; 8] = [
    "qemu-system-x86_64",
    "qemu-img",
    "cloud-localds",
    "ssh",
    "scp",
    "ssh-keygen",
    "ssh-keyscan",
    "veritysetup",
];

fn e2e_preflight() -> Result<(), String> {
    for tool in E2E_HOST_TOOLS {
        let found = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {tool}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !found {
            return Err(format!(
                "required host tool not found on PATH: {tool} (the prod e2e needs: {})",
                E2E_HOST_TOOLS.join(", ")
            ));
        }
    }
    if !Path::new("/dev/kvm").exists() {
        return Err("/dev/kvm not available — the prod e2e boots Debian nested under KVM".into());
    }
    Ok(())
}

/// Generate a throwaway ed25519 provisioning keypair in `dir`; return `(privkey path, pubkey line)`.
/// The pubkey is what cloud-init injects into the guest's root `authorized_keys`; the privkey is the
/// ceremony's Leg-A `--ssh-identity`.
fn generate_provisioning_keypair(dir: &Path) -> Result<(PathBuf, String), String> {
    let priv_path = dir.join("provisioning_id");
    let status = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "recipes-prod-e2e",
            "-q",
            "-f",
        ])
        .arg(&priv_path)
        .status()
        .map_err(|e| format!("spawn ssh-keygen: {e}"))?;
    if !status.success() {
        return Err(format!(
            "ssh-keygen for the provisioning key exited {status}"
        ));
    }
    let pub_line = std::fs::read_to_string(priv_path.with_extension("pub"))
        .map_err(|e| format!("read provisioning pubkey: {e}"))?
        .trim()
        .to_string();
    if pub_line.is_empty() {
        return Err("provisioning pubkey is empty".into());
    }
    Ok((priv_path, pub_line))
}

/// Build the nocloud seed disk (cloud-localds) carrying the rendered user-data.
fn build_seed(user_data: &str, dir: &Path) -> Result<PathBuf, String> {
    let ud_path = dir.join("user-data");
    std::fs::write(&ud_path, user_data).map_err(|e| format!("write user-data: {e}"))?;
    let seed = dir.join("seed.img");
    let status = Command::new("cloud-localds")
        .arg(&seed)
        .arg(&ud_path)
        .status()
        .map_err(|e| format!("spawn cloud-localds: {e}"))?;
    if !status.success() {
        return Err(format!("cloud-localds exited {status}"));
    }
    Ok(seed)
}

/// A qcow2 copy-on-write overlay over the operator's Debian image, so the pinned base is NEVER
/// mutated (the guest — and the box installer after kexec — writes only the overlay).
fn make_overlay(
    debian_img: &Path,
    dir: &Path,
    grow_to_bytes: Option<u64>,
) -> Result<PathBuf, String> {
    let overlay = dir.join("guest-overlay.qcow2");
    let backing = debian_img
        .canonicalize()
        .map_err(|e| format!("canonicalize Debian image {}: {e}", debian_img.display()))?;
    let mut cmd = Command::new("qemu-img");
    cmd.args(["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b"])
        .arg(&backing)
        .arg(&overlay);
                                                                                                    
                                                                                                    
                                                                                                         
                                                                                                        
                                                                                                         
    if let Some(bytes) = grow_to_bytes {
        cmd.arg(bytes.to_string());
    }
    let status = cmd
        .status()
        .map_err(|e| format!("spawn qemu-img create: {e}"))?;
    if !status.success() {
        return Err(format!(
            "qemu-img create overlay exited {status} (is {} a qcow2? convert raw images first)",
            debian_img.display()
        ));
    }
    Ok(overlay)
}

/// The Debian-guest `-netdev` argument. `restrict=on` isolates the guest from the host and the
/// internet; QEMU's own contract is that it "does not affect any explicitly set forwarding rules", so
/// the `hostfwd` keeps working and every inbound ssh leg is unaffected — only EGRESS dies. That
                                                                                                    
/// QEMU itself, so the guest still gets its lease. Pure so the hermetic wiring is a TESTABLE property
                                                                           
pub(crate) fn debian_user_netdev_arg(forward_port: u16, restrict_net: bool) -> String {
    format!(
        "user,id=n0,hostfwd=tcp:127.0.0.1:{forward_port}-:22{}",
        if restrict_net { ",restrict=on" } else { "" }
    )
}

/// Launch the Debian guest: its OWN kernel (no `-kernel`), reboot PERMITTED (the post-kexec
/// install→reboot→box transition must run through SeaBIOS), the nocloud seed as a second virtio
/// disk, user-net forwarding `forward_port`→guest 22. `PR_SET_PDEATHSIG` ties QEMU's lifetime to
/// ours so a killed gate never orphans the VM (the dryrun pattern).
fn launch_debian_guest(
    overlay: &Path,
    seed: &Path,
    opts: &DebianE2eOpts,
    console: &Path,
) -> Result<QemuGuard, String> {
    let log = std::fs::File::create(console).map_err(|e| format!("create console log: {e}"))?;
    let log_err = log
        .try_clone()
        .map_err(|e| format!("clone console log handle: {e}"))?;
    let mem = opts.memory_mb.to_string();
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(["-enable-kvm", "-cpu", "host", "-m", &mem])
        .arg("-drive")
        .arg(format!("file={},format=qcow2,if=virtio", overlay.display()))
        .arg("-drive")
        .arg(format!("file={},format=raw,if=virtio", seed.display()))
        .arg("-netdev")
        .arg(debian_user_netdev_arg(opts.forward_port, opts.restrict_net))
        .args(["-device", "virtio-net-pci,netdev=n0", "-nographic"])
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(log_err);
                                                                                                  
                                                                                                
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            Ok(())
        });
    }
    let child: Child = cmd
        .spawn()
        .map_err(|e| format!("spawn qemu-system-x86_64: {e}"))?;
    Ok(QemuGuard::adopt(child, false))
}

/// ssh-keyscan the booted guest on `port` and return its `SHA256:…` host fingerprint — the value an
/// operator would read off the provider console and pass as `--host-fingerprint`. The ceremony
/// re-scans + compares against this, so the harness is simulating that out-of-band check.
fn scan_guest_fingerprint(port: u16) -> Result<String, String> {
    let scan = Command::new("ssh-keyscan")
        .args(["-T", "10", "-t", "ed25519", "-p"])
        .arg(port.to_string())
        .arg("127.0.0.1")
        .output()
        .map_err(|e| format!("spawn ssh-keyscan: {e}"))?;
    let line = String::from_utf8_lossy(&scan.stdout)
        .lines()
        .find(|l| !l.trim_start().starts_with('#') && l.contains("ssh-ed25519"))
        .map(str::to_string)
        .ok_or("ssh-keyscan returned no ed25519 host key for the guest")?;
    let fpr_out = Command::new("ssh-keygen")
        .args(["-l", "-f", "/dev/stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write as _;
            c.stdin
                .take()
                .ok_or_else(|| std::io::Error::other("no stdin"))?
                .write_all(line.as_bytes())?;
            c.wait_with_output()
        })
        .map_err(|e| format!("ssh-keygen -lf on the scanned key: {e}"))?;
    String::from_utf8_lossy(&fpr_out.stdout)
        .split_whitespace()
        .find(|f| f.starts_with("SHA256:"))
        .map(str::to_string)
        .ok_or_else(|| "no SHA256: field in ssh-keygen output".into())
}

/// Run a plain `root@127.0.0.1` ssh command against the guest with the provisioning key (no host-key
/// pinning — used only by the harness's own post-condition checks, never the ceremony).
fn guest_ssh(provisioning_privkey: &Path, port: u16, remote: &str) -> Result<String, String> {
    let out = Command::new("ssh")
        .args([
            "-i",
            &provisioning_privkey.display().to_string(),
            "-p",
            &port.to_string(),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "LogLevel=ERROR",
            "root@127.0.0.1",
            remote,
        ])
        .output()
        .map_err(|e| format!("spawn guest ssh: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "guest ssh {remote:?} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Boot the Debian guest + wait for cloud-init to bring sshd up on the provisioning key. Returns the
/// live `QemuGuard` (RAII-kills QEMU on drop) + the workdir tempdir (kept alive for the seed/keys) +
/// the provisioning privkey path. Shared by the happy + negative harnesses. `console` is the
/// caller-named console log — PER-TEST names (same discipline as the forward port): parallel tests
/// share one log dir, so a shared `guest-console.log` would interleave/clobber across QEMUs.
                                                                                                
/// reclaim legs (RT-1/RT-2) set it, so their guest boots with growpart ON + `resize_rootfs: true`
/// — the default-provisioned-VPS shape D-1 refuses and the reclaim exists to unblock, which is what
                                                                                                   
/// off), byte-identical to before. Before this selector the field was read nowhere, so both reclaim
/// legs booted on the base config with cloud-init growth disabled.
fn provisioning_user_data(opts: &DebianE2eOpts, provisioning_pubkey_line: &str) -> String {
    if opts.grown_user_data {
        render_cloud_init_user_data_grown(provisioning_pubkey_line)
    } else {
        render_cloud_init_user_data(provisioning_pubkey_line)
    }
}

/// Boot a hermetic Debian guest, provisioned via cloud-init with a fresh keypair, and return the
/// live `QemuGuard` (RAII-kills QEMU on drop), the workdir tempdir (holds the seed/keys), and the
                                                                                         
/// `orchard run` installs onto — the boot-and-hand-back primitive `run_debian_kexec_takeover_e2e`
/// builds on, without the takeover the ceremony itself performs. The caller MUST keep the guard +
/// workdir in scope for the whole ceremony (the guest stays up only while they live). The guest
/// authenticates the `debian` user on `opts.forward_port` with the returned key.
pub fn boot_provisioned_guest(
    debian_img: &Path,
    opts: &DebianE2eOpts,
    console: &Path,
) -> Result<(QemuGuard, tempfile::TempDir, PathBuf), String> {
    e2e_preflight()?;
    let workdir = tempfile::Builder::new()
        .prefix("recipes-prod-e2e-")
        .tempdir()
        .map_err(|e| format!("create e2e workdir: {e}"))?;
    let wd = workdir.path();

    let (provisioning_privkey, provisioning_pubkey) = generate_provisioning_keypair(wd)?;
    let user_data = provisioning_user_data(opts, &provisioning_pubkey);
    let seed = build_seed(&user_data, wd)?;
    let overlay = make_overlay(debian_img, wd, opts.guest_disk_bytes)?;

    let mut guard = launch_debian_guest(&overlay, &seed, opts, console)?;
                                                                                                      
    wait_for_ssh(
        &provisioning_privkey,
        opts.forward_port,
        opts.guest_boot_timeout,
        &mut guard,
        console,
    )
    .map_err(|e| {
        format!(
            "the Debian guest's sshd did not come up on the provisioning key within {}s \
             (cloud-init may still be early-booting, or root login was refused): {e}",
            opts.guest_boot_timeout.as_secs()
        )
    })?;
                                                                                                
                                                                                                     
                                                                                                      
                                                                                                
                                   
    wait_for_kexec_tools(
        &provisioning_privkey,
        opts.forward_port,
        opts.guest_boot_timeout,
    )?;
    Ok((guard, workdir, provisioning_privkey))
}

/// Poll the booted guest (fresh ssh per attempt — robust to a transient cloud-init-induced drop)
/// until `command -v kexec` succeeds. Fail-closed on timeout.
///
                                                                                              
/// timeout here means the operator pointed at the WRONG IMAGE — the stock Debian base instead of the
/// prepared fixture. The message says so; blaming "the guest's outbound apt route" (as it used to)
/// would now be actively misleading, because the gate deliberately runs with no outbound route.
fn wait_for_kexec_tools(
    provisioning_privkey: &Path,
    port: u16,
    timeout: Duration,
) -> Result<(), String> {
    poll_for_kexec(provisioning_privkey, port, timeout).map_err(|()| {
        format!(
                "`kexec` is not present on the Debian guest after {}s: the ceremony would HARD-abort \
                 its kexec discovery probe. This gate runs the guest HERMETIC \
                 (restrict=on, no outbound route) and expects `kexec-tools` PRE-INSTALLED on the \
                 image — so this almost certainly means the stock Debian base was passed instead of \
                 the prepared fixture. Build one with `make e2e-kexec-fixture` and point \
                 RECIPES_PROD_E2E_DEBIAN_IMG at its output (see `prepare_kexec_fixture`)",
            timeout.as_secs()
        )
    })
}

/// The shared poll: fresh ssh per attempt (robust to a transient cloud-init-induced drop) until
/// `command -v kexec` succeeds. `Err(())` carries NO message on purpose — the two callers have
/// genuinely different diagnoses for the same timeout (fixture prep: the apt fetch failed; a gate
/// run: the wrong image was passed), and a shared-but-vague message would be wrong for both.
fn poll_for_kexec(provisioning_privkey: &Path, port: u16, timeout: Duration) -> Result<(), ()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(out) = guest_ssh(provisioning_privkey, port, "command -v kexec || true")
            && out.trim().contains("kexec")
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(());
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// The fixture's prep `user-data`: the provisioning key (so the prep can be driven over ssh) PLUS
/// the apt-install that the per-run [`render_cloud_init_user_data`] no longer carries. This is the
/// ONE place in the harness that legitimately needs the network.
pub fn render_fixture_prep_user_data(provisioning_pubkey_line: &str) -> String {
    format!(
        "#cloud-config\n\
         disable_root: false\n\
         ssh_pwauth: false\n\
         package_update: true\n\
         packages:\n\
         \x20 - kexec-tools\n\
         write_files:\n\
         \x20 - path: /root/.ssh/authorized_keys\n\
         \x20   owner: 'root:root'\n\
         \x20   permissions: '0600'\n\
         \x20   content: |\n\
         \x20     {provisioning_pubkey_line}\n\
         runcmd:\n\
         \x20 - [ install, -d, -m, '0700', -o, root, -g, root, /root/.ssh ]\n\
         \x20 - [ chmod, '0600', /root/.ssh/authorized_keys ]\n\
         \x20 - [ chown, 'root:root', /root/.ssh/authorized_keys ]\n"
    )
}

/// Build the one-time Debian fixture the hermetic gate needs: the operator's pinned genericcloud
/// base with `kexec-tools` PRE-INSTALLED and cloud-init RESET. Returns the fixture's sha256 hex.
///
                                                                                                  
/// the target, and this is the one boot allowed outbound access to put it there.
///
/// **`cloud-init clean` is mandatory, not hygiene.** `cloud-localds` writes a FIXED
/// `instance-id: iid-local01` when given no meta-data file (verified in the script itself), so every
/// seed this harness builds presents the same instance identity. Without the reset, cloud-init on a
/// prepped fixture would recognise "already provisioned as iid-local01" and SKIP its per-instance
/// modules — including the `write_files` that injects the provisioning key — and every gate run would
/// fail to authenticate. Wiping `/var/lib/cloud` makes the next boot a first boot again.
///
/// Deliberately refuses to overwrite an existing `out`: a fixture is an input to produced-bytes
/// gates, so replacing one silently would change what those gates ran against.
pub fn prepare_kexec_fixture(base_img: &Path, out: &Path) -> Result<String, String> {
    e2e_preflight()?;
    if out.exists() {
        return Err(format!(
            "refusing to overwrite an existing fixture at {} — remove it first if you really mean \
             to rebuild (it is an input to produced-bytes gates)",
            out.display()
        ));
    }
    let result = build_kexec_fixture(base_img, out);
    if result.is_err() {
                                                                                                     
                                                                                                         
                                                                                               
        let _ = std::fs::remove_file(out);
    }
    result
}

/// The grown-fixture disk size (reclaim-tail D-2 §9): the class shape the Q1 spike measured —
/// a 12 GiB disk the default growth machinery fills on first boot.
pub const GROWN_FIXTURE_DISK_BYTES: u64 = 12 * 1024 * 1024 * 1024;

/// Build the DEFAULT-PROVISIONED fixture (reclaim-tail D-2 §9):
/// `debian-12-genericcloud-amd64+kexec+grown.qcow2`. The same kexec-tools prep as
/// [`prepare_kexec_fixture`], with `cloud-initramfs-growroot` RETAINED and the disk resized to
/// [`GROWN_FIXTURE_DISK_BYTES`], so the first boot grows the root to fill the disk exactly as a
/// provider default does. Fails closed the OPPOSITE way from the kexec fixture: growroot must
/// STILL be installed, the root must have actually GROWN, and its fstab must still carry
                                                                                                      
            
pub fn prepare_grown_fixture(base_img: &Path, out: &Path) -> Result<String, String> {
    e2e_preflight()?;
    if out.exists() {
        return Err(format!(
            "refusing to overwrite an existing fixture at {} — remove it first if you really mean \
             to rebuild (it is an input to produced-bytes gates)",
            out.display()
        ));
    }
    let result = build_grown_fixture(base_img, out);
    if result.is_err() {
        let _ = std::fs::remove_file(out);
    }
    result
}

fn build_grown_fixture(base_img: &Path, out: &Path) -> Result<String, String> {
    let base = base_img
        .canonicalize()
        .map_err(|e| format!("canonicalize Debian base {}: {e}", base_img.display()))?;
    let status = Command::new("qemu-img")
        .args(["convert", "-O", "qcow2"])
        .arg(&base)
        .arg(out)
        .status()
        .map_err(|e| format!("spawn qemu-img convert: {e}"))?;
    if !status.success() {
        return Err(format!("qemu-img convert exited {status}"));
    }
                                                                                        
                                                                                                
    let status = Command::new("qemu-img")
        .args(["resize", "-f", "qcow2"])
        .arg(out)
        .arg(GROWN_FIXTURE_DISK_BYTES.to_string())
        .status()
        .map_err(|e| format!("spawn qemu-img resize: {e}"))?;
    if !status.success() {
        return Err(format!("qemu-img resize exited {status}"));
    }

    let workdir = tempfile::Builder::new()
        .prefix("recipes-grown-fixture-")
        .tempdir()
        .map_err(|e| format!("create fixture workdir: {e}"))?;
    let wd = workdir.path();
    let console = wd.join("fixture-console.log");
    let (privkey, pubkey) = generate_provisioning_keypair(wd)?;
    let seed = build_seed(&render_fixture_prep_user_data(&pubkey), wd)?;
    let opts = DebianE2eOpts {
        restrict_net: false,
        ..DebianE2eOpts::default()
    };
    let mut guard = launch_debian_guest(out, &seed, &opts, &console)?;
    wait_for_ssh(
        &privkey,
        opts.forward_port,
        opts.guest_boot_timeout,
        &mut guard,
        &console,
    )
    .map_err(|e| format!("grown-fixture guest's sshd did not come up: {e}"))?;
    guest_ssh(
        &privkey,
        opts.forward_port,
        "timeout 900 cloud-init status --wait || true",
    )
    .map_err(|e| format!("waiting for cloud-init on the grown-fixture guest: {e}"))?;
    poll_for_kexec(&privkey, opts.forward_port, opts.guest_boot_timeout).map_err(|()| {
        format!(
            "the grown fixture's apt-install of kexec-tools did not complete within {}s; \
             console: {}",
            opts.guest_boot_timeout.as_secs(),
            console_tail(&console)
        )
    })?;

                                                                                      
                                  
    let growroot = guest_ssh(
        &privkey,
        opts.forward_port,
        "dpkg-query -W -f='${Status}' cloud-initramfs-growroot 2>/dev/null || echo absent",
    )
    .unwrap_or_else(|_| "unknown".to_string());
    if !growroot.contains("install ok installed") {
        return Err(format!(
            "cloud-initramfs-growroot is NOT installed on the grown fixture ({growroot:?}) — \
             RT-1 would not exercise R12's neutralization; the fixture must keep the class's \
             re-grow machinery"
        ));
    }
                                                          
    let root_size = guest_ssh(
        &privkey,
        opts.forward_port,
        "lsblk -nbro NAME,SIZE | awk '$1==\"vda1\"{print $2}'",
    )
    .unwrap_or_default();
    let grown_bytes: u64 = root_size.trim().parse().unwrap_or(0);
    if grown_bytes < GROWN_FIXTURE_DISK_BYTES / 2 {
        return Err(format!(
            "the grown fixture's root is {grown_bytes} bytes — the growth machinery did not run \
             (disk {GROWN_FIXTURE_DISK_BYTES}); a fixture whose root did not grow makes RT-1 \
             vacuous (D-1 would pass and short-circuit)"
        ));
    }
                                                                                                        
                                                             
    let fstab = guest_ssh(&privkey, opts.forward_port, "cat /etc/fstab").unwrap_or_default();
    if !fstab.contains("x-systemd.growfs") {
        return Err(
            "the grown fixture's fstab carries no x-systemd.growfs token — RT-1 would not \
             exercise the fstab strip"
                .to_string(),
        );
    }
    println!(
        "grown fixture: growroot RETAINED; root grew to {grown_bytes} bytes of \
         {GROWN_FIXTURE_DISK_BYTES}; fstab token present"
    );

    guest_ssh(&privkey, opts.forward_port, "apt-get clean")
        .map_err(|e| format!("apt-get clean on the grown-fixture guest: {e}"))?;
    guest_ssh(&privkey, opts.forward_port, "cloud-init clean --logs")
        .map_err(|e| format!("cloud-init clean on the grown-fixture guest: {e}"))?;
    let _ = guest_ssh(&privkey, opts.forward_port, "poweroff");
    guard
        .wait_for_exit(Duration::from_secs(120))
        .map_err(|e| format!("grown-fixture guest did not power off cleanly: {e}"))?;
    sha256_file(out)
}

fn build_kexec_fixture(base_img: &Path, out: &Path) -> Result<String, String> {
                                                                                                    
                                                                          
    let base = base_img
        .canonicalize()
        .map_err(|e| format!("canonicalize Debian base {}: {e}", base_img.display()))?;
    let status = Command::new("qemu-img")
        .args(["convert", "-O", "qcow2"])
        .arg(&base)
        .arg(out)
        .status()
        .map_err(|e| format!("spawn qemu-img convert: {e}"))?;
    if !status.success() {
        return Err(format!("qemu-img convert exited {status}"));
    }

    let workdir = tempfile::Builder::new()
        .prefix("recipes-kexec-fixture-")
        .tempdir()
        .map_err(|e| format!("create fixture workdir: {e}"))?;
    let wd = workdir.path();
    let console = wd.join("fixture-console.log");

    let (privkey, pubkey) = generate_provisioning_keypair(wd)?;
    let seed = build_seed(&render_fixture_prep_user_data(&pubkey), wd)?;

                                                                                                    
                                                                                  
                                                                                                   
                                                                                               
                                                                                                
    let opts = DebianE2eOpts {
        restrict_net: false,
        ..DebianE2eOpts::default()
    };
    let mut guard = launch_debian_guest(out, &seed, &opts, &console)?;

    wait_for_ssh(
        &privkey,
        opts.forward_port,
        opts.guest_boot_timeout,
        &mut guard,
        &console,
    )
    .map_err(|e| format!("fixture guest's sshd did not come up: {e}"))?;

                                                                                                  
                                                                                          
                                                                                                
                                                                                                      
                                                                                                
                                                                           
    guest_ssh(
        &privkey,
        opts.forward_port,
        "timeout 900 cloud-init status --wait || true",
    )
    .map_err(|e| format!("waiting for cloud-init to finish on the fixture guest: {e}"))?;

    poll_for_kexec(&privkey, opts.forward_port, opts.guest_boot_timeout).map_err(|()| {
        format!(
            "the fixture's apt-install of kexec-tools did not complete within {}s — THIS boot is \
             the one that needs outbound network, so check the host's route to the Debian mirrors. \
             Console: {}",
            opts.guest_boot_timeout.as_secs(),
            console_tail(&console)
        )
    })?;

                                                                                                   
                                                                                                   
                                                                                                     
                                                                                                    
                                                                                                     
                                                                                                    
                                                    
      
                                                                                                     
                                                                                             
    let had_growroot = guest_ssh(
        &privkey,
        opts.forward_port,
        "dpkg-query -W -f='${Status}' cloud-initramfs-growroot 2>/dev/null || echo absent",
    )
    .unwrap_or_else(|_| "unknown".to_string());
    guest_ssh(
        &privkey,
        opts.forward_port,
        "DEBIAN_FRONTEND=noninteractive apt-get purge -y cloud-initramfs-growroot 2>&1 | tail -3 \
         || true",
    )
    .map_err(|e| format!("purging cloud-initramfs-growroot on the fixture guest: {e}"))?;
                                                                                                    
                                                                                                
                                                                                                  
                                                                                        
                                                                      
    let still = guest_ssh(
        &privkey,
        opts.forward_port,
        "dpkg-query -W -f='${Status}' cloud-initramfs-growroot 2>/dev/null || echo absent",
    )
    .map_err(|e| {
        format!(
            "re-checking cloud-initramfs-growroot after the purge failed over ssh — cannot confirm \
             the fixture is clean, refusing rather than shipping an unverified fixture: {e}"
        )
    })?;
    if still.trim() != "absent" {
        return Err(format!(
            "cloud-initramfs-growroot is not provably purged from the fixture (dpkg status \
             {still:?}, expected the clean `absent`; was: {had_growroot:?}) — the fixture's root \
             would keep auto-growing to fill the disk and every gate run would hit D-1's \
             partition-intersection refusal"
        ));
    }
    println!("fixture: cloud-initramfs-growroot before={had_growroot:?} after={still:?}");

                                                                                                    
                                                           
    guest_ssh(&privkey, opts.forward_port, "apt-get clean")
        .map_err(|e| format!("apt-get clean on the fixture guest: {e}"))?;
    guest_ssh(&privkey, opts.forward_port, "cloud-init clean --logs")
        .map_err(|e| format!("cloud-init clean on the fixture guest: {e}"))?;

                                                                                                      
                                                                               
    let _ = guest_ssh(&privkey, opts.forward_port, "poweroff");
    guard
        .wait_for_exit(Duration::from_secs(120))
        .map_err(|e| format!("fixture guest did not power off cleanly: {e}"))?;

    sha256_file(out)
}

/// sha256 of a file, lowercase hex — the fixture's provenance record.
fn sha256_file(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// The REAL [`ProcessOps`] with its two stdin-shaped seams pinned NON-INTERACTIVE, so the gate
/// behaves identically whether `cargo test` inherits a terminal (operator-run) or not (make/CI).
/// With raw `ProcessOps`, the live `isatty(0)` probe flips the ceremony's wipe gate between the
/// TTY retype arm — which BLOCKS the test on real stdin (the first run needed an external
/// `yes … |` pipe to un-stick it) — and the token-only arm. The e2e's designed shape is the
/// NON-INTERACTIVE contract: the [`WipeConfirmed`] token + an explicit `--host-fingerprint` pin,
/// zero prompts. Only the harness carries this wrapper; production keeps the real probe, and the
/// un-bypassable token gate is UNTOUCHED (it is demanded by `fire_kexec` in both arms).
struct NonInteractiveOps(ProcessOps);

impl OrchestrationOps for NonInteractiveOps {
    /// Pinned `false` — the ceremony deterministically takes its non-interactive arm.
    fn stdin_is_tty(&self) -> bool {
        false
    }
    /// Fail-closed `None`: nothing on the non-TTY path reads a line; if a future path asks
    /// anyway, "no answer" declines/aborts — never fabricated consent.
    fn read_line(&mut self, _prompt: &str) -> Option<String> {
        None
    }
                                                                           
    fn say(&mut self, msg: &str) {
        self.0.say(msg)
    }
    fn cancel_requested(&self) -> bool {
        self.0.cancel_requested()
    }
    fn sleep_secs(&mut self, secs: u64) {
        self.0.sleep_secs(secs)
    }
    fn ssh_port(&self) -> u16 {
        self.0.ssh_port()
    }
    fn now_epoch(&self) -> i64 {
        self.0.now_epoch()
    }
    fn read_image_artifacts(&mut self, image: &Path) -> Result<ImageArtifacts, String> {
        self.0.read_image_artifacts(image)
    }
    fn local_pubkey_fingerprint(&mut self, pubkey: &Path) -> Result<String, String> {
        self.0.local_pubkey_fingerprint(pubkey)
    }
    fn derive_runtime_hostkey(&mut self, image: &Path) -> Result<(String, String), String> {
        self.0.derive_runtime_hostkey(image)
    }
    fn recompute_root_hash(
        &mut self,
        img: &Path,
        rootfs_data_offset: u64,
        rootfs_data_len: u64,
    ) -> Result<String, String> {
        self.0
            .recompute_root_hash(img, rootfs_data_offset, rootfs_data_len)
    }
    fn known_hosts_host(&self) -> String {
        self.0.known_hosts_host()
    }
    fn scan_host_key(&mut self) -> Result<(String, String), String> {
        self.0.scan_host_key()
    }
    fn pin_host_key(&mut self, leg: Leg, known_hosts_line: &str) -> Result<(), String> {
        self.0.pin_host_key(leg, known_hosts_line)
    }
    fn ssh_capture(&mut self, leg: Leg, remote_command: &str) -> Result<String, String> {
        self.0.ssh_capture(leg, remote_command)
    }
    fn scp_stage(&mut self, local: &Path, remote_path: &str) -> Result<(), String> {
        self.0.scp_stage(local, remote_path)
    }
    fn scp_image_bytes(&mut self, bytes: &[u8], remote_path: &str) -> Result<(), String> {
        self.0.scp_image_bytes(bytes, remote_path)
    }
    fn stage_raw_window(
        &mut self,
        local_img: &Path,
        patch: Option<&crate::deploy::stage_stream::PatchSpec>,
        disk: &str,
        offset: u64,
    ) -> Result<[u8; 32], String> {
        self.0.stage_raw_window(local_img, patch, disk, offset)
    }
    fn fire_kexec(&mut self, token: WipeConfirmed) -> Result<(), String> {
        self.0.fire_kexec(token)
    }
}

/// Build the (non-interactive) ops + [`DeployProdOpts`] the ceremony runs with, against the
/// forwarded guest. `host_fingerprint` / `runtime_hostkey_fingerprint` are caller-chosen so the
/// negative paths can feed deliberately-wrong pins. The reconnect/provisioning known_hosts live
/// in `wd`.
fn ceremony_inputs(
    wd: &Path,
    box_img: &Path,
    operator_privkey: &Path,
    provisioning_privkey: &Path,
    opts: &DebianE2eOpts,
    host_fingerprint: Option<String>,
    runtime_hostkey_fingerprint: Option<String>,
) -> Result<(NonInteractiveOps, DeployProdOpts), String> {
    let ip = validate_target_host("127.0.0.1")?;
    let pubkey = operator_pubkey_path(operator_privkey)?;
    let ops = NonInteractiveOps(ProcessOps {
                                                                                        
                                                                                                 
                                                                                              
                                                                                                  
                              
        provisioning_user: crate::deploy::prod_orchestrate::DEFAULT_PROVISIONING_USER.to_string(),
        ip: ip.clone(),
        ssh_port: opts.forward_port,
        ssh_identity: provisioning_privkey.to_path_buf(),
        box_login_identity: operator_privkey.to_path_buf(),
        provisioning_known_hosts: wd.join("known_hosts_provisioning"),
        reconnect_known_hosts: wd.join("known_hosts_box"),
        step_started: None,
    });
    let deploy_opts = DeployProdOpts {
        ip,
        pubkey,
        image: box_img.to_path_buf(),
        host_fingerprint,
        known_hosts: None,
        runtime_hostkey_fingerprint,
        image_stage_dir: "/var/tmp/recipes-deploy".into(),
        wipe_confirmed: WipeConfirmed::from_flag(true),
        reconnect_timeout_secs: opts.reconnect_timeout_secs,
        restore_from: None,                                                                      
        restore_min_ctr: None,
        artifact_pin: None,
        profile_sourced: Default::default(),
        reclaim_tail: opts.reclaim_tail,
        reclaim_reboot_timeout_secs: None,
    };
    Ok((ops, deploy_opts))
}

                                                                                               
/// derives the privkey by STRIPPING `.pub`, so the inverse is always an append — never
/// `with_extension`, which would mangle a `key.priv`-style name into `key.pub`).
fn operator_pubkey_path(operator_privkey: &Path) -> Result<PathBuf, String> {
    let mut s = operator_privkey.as_os_str().to_os_string();
    s.push(".pub");
    let p = PathBuf::from(s);
    if !p.is_file() {
        return Err(format!(
            "operator pubkey {} not found beside the private key — the e2e needs the .pub the box \
             was built with",
            p.display()
        ));
    }
    Ok(p)
}

/// RT-2 (reclaim-tail D-2 §9, AC-R2's produced-bytes half): the SAME grown target, NO flag.
                                                                                                 
/// partition table untouched: the first 34 and last 33 sectors (the GPT primary + backup regions
                                                                                                  
/// must be identical.
pub fn run_reclaim_no_flag_untouched_e2e(
    box_img: &Path,
    operator_privkey: &Path,
    debian_img: &Path,
    opts: &DebianE2eOpts,
    log_dir: &Path,
) -> Result<(), String> {
    let console = log_dir.join("guest-console-reclaim-noflag.log");
    let (_guard, workdir, provisioning_privkey) =
        boot_provisioned_guest(debian_img, opts, &console)?;
    let wd = workdir.path();

                                                                                                 
                                                                                             
                 
    let snapshot = |privkey: &Path| -> Result<(String, String, String), String> {
        let head = guest_ssh(
            privkey,
            opts.forward_port,
            "dd if=/dev/vda bs=512 count=34 status=none | sha256sum",
        )?;
        let tail = guest_ssh(
            privkey,
            opts.forward_port,
            "end=$(blockdev --getsz /dev/vda); dd if=/dev/vda bs=512 skip=$((end-33)) count=33 \
             status=none | sha256sum",
        )?;
        let dump = guest_ssh(privkey, opts.forward_port, "sfdisk --dump /dev/vda")?;
        Ok((head, tail, dump))
    };
    let before = snapshot(&provisioning_privkey)?;

    let guest_fp = scan_guest_fingerprint(opts.forward_port)?;
    let (_runtime_line, runtime_fp) = crate::oneshots_offline::offline_runtime_hostkey(box_img)
        .map_err(|e| format!("derive the box runtime host-key fingerprint: {e}"))?;
    let (mut ops, deploy_opts) = ceremony_inputs(
        wd,
        box_img,
        operator_privkey,
        &provisioning_privkey,
        opts,
        Some(guest_fp),
        Some(runtime_fp),
    )?;
    if deploy_opts.reclaim_tail {
        return Err(
            "RT-2 must run WITHOUT --reclaim-tail — the leg proves the unflagged \
                    boundary"
                .to_string(),
        );
    }
    let err = match deploy_prod(&mut ops, deploy_opts) {
        Err(e) => e,
        Ok(()) => {
            return Err(format!(
                "RT-2: `orchard prod` SUCCEEDED against a grown target without --reclaim-tail — \
                 D-1 must refuse (the staging window sits inside the grown root). Console:\n{}",
                console_tail(&console)
            ));
        }
    };
    if !err.contains("INTERSECTS") {
        return Err(format!("RT-2: refusal is not D-1's: {err}"));
    }
    if !err.contains("orchard reclaim-tail") {
        return Err(format!(
            "RT-2: D-1's refusal does not name the reclaim-tail remedy: {err}"
        ));
    }

    let after = snapshot(&provisioning_privkey)?;
    if before.0 != after.0 {
        return Err(format!(
            "RT-2: the first 34 sectors CHANGED across the refusal: {:?} -> {:?}",
            before.0, after.0
        ));
    }
    if before.1 != after.1 {
        return Err(format!(
            "RT-2: the last 33 sectors CHANGED across the refusal: {:?} -> {:?}",
            before.1, after.1
        ));
    }
    if before.2 != after.2 {
        return Err("RT-2: the `sfdisk --dump` text CHANGED across the refusal".to_string());
    }
    println!(
        "RT-2: refused at D-1 naming the remedy; first-34 {} last-33 {} and the --dump text are \
         byte-identical across the refusal",
        before.0.split_whitespace().next().unwrap_or("?"),
        before.1.split_whitespace().next().unwrap_or("?")
    );
    Ok(())
}

/// Acceptance #1 — the Debian-guest kexec-takeover happy path. Boots Debian, drives the REAL
/// ceremony to a kexec-takeover install, and asserts step-10 crypto identity passed TWO ways:
/// the ceremony's `Ok` (its own verity-root-hash + boot-fs-prefix + liveness verdict over the
/// derived-fingerprint-pinned reconnect) AND a non-ceremony post-condition probe (a fresh
/// operator-key ssh on a harness-built pin asserting the harness-recomputed root hash) — so the
                                                                                             
///
/// `expected_firmware_token`: when `Some`, additionally assert the booted cmdline carries
                                                                                                               
pub fn run_debian_kexec_takeover_e2e(
    box_img: &Path,
    operator_privkey: &Path,
    debian_img: &Path,
    opts: &DebianE2eOpts,
    log_dir: &Path,
    expected_firmware_token: Option<&str>,
) -> Result<(), String> {
                                                                                                  
    let console = log_dir.join("guest-console-happy.log");
    let (_guard, workdir, provisioning_privkey) =
        boot_provisioned_guest(debian_img, opts, &console)?;
    let wd = workdir.path();

                                                                                                 
    let guest_fp = scan_guest_fingerprint(opts.forward_port)?;
                                                                                                     
                                                                                            
    let (runtime_line, runtime_fp) = crate::oneshots_offline::offline_runtime_hostkey(box_img)
        .map_err(|e| {
            format!(
                "derive the box runtime host-key fingerprint from {}: {e}",
                box_img.display()
            )
        })?;

    let (mut ops, deploy_opts) = ceremony_inputs(
        wd,
        box_img,
        operator_privkey,
        &provisioning_privkey,
        opts,
        Some(guest_fp),
        Some(runtime_fp),
    )?;

                                                                                                         
                                                                                                          
                                                                                                    
                                                                                                       
                                                                                                    
                                                                                                        
                                                     
    if let Some(proof) = opts.weights_proof {
        super::dryrun::assert_prod_weights_shape(box_img, opts.memory_mb, proof)
            .map_err(|e| format!("prod-weights: {e}"))?;
    }

                                                                                                        
                                                                                                  
                                                                                                   
    deploy_prod(&mut ops, deploy_opts).map_err(|e| {
        format!(
            "deploy_prod kexec-takeover against the Debian guest failed: {e}\n\
             guest console tail:\n{}",
            console_tail(&console)
        )
    })?;

                                                                                                 
                                                                                                    
                                                                                                
                                                                                            
                                                                                               
                                                                                               
                                                                                              
                                                                                           
    let expected_root_hash = harness_recomputed_root_hash(box_img)?;
    let probe_known_hosts = wd.join("known_hosts_probe");
                                                                                            
    let host_token = if opts.forward_port == 22 {
        "127.0.0.1".to_string()
    } else {
        format!("[127.0.0.1]:{}", opts.forward_port)
    };
    std::fs::write(&probe_known_hosts, format!("{host_token} {runtime_line}\n"))
        .map_err(|e| format!("write probe known_hosts: {e}"))?;
    let cmdline = operator_ssh_capture(
        operator_privkey,
        &probe_known_hosts,
        opts.forward_port,
        "cat /proc/cmdline",
    )?;
    let expected_token = format!("fb.root-hash={expected_root_hash}");
    if !cmdline.split_whitespace().any(|t| t == expected_token) {
        return Err(format!(
            "post-condition probe FAILED: the box's /proc/cmdline does not carry the \
             harness-recomputed {expected_token} — the ceremony's Ok self-verdict is not \
             corroborated; cmdline: {cmdline}"
        ));
    }
                                                                                                     
                                                                                                      
                                                                                                           
    if let Some(tok) = expected_firmware_token {
        let want = format!("fb.firmware={tok}");
        if !cmdline.split_whitespace().any(|t| t == want) {
            return Err(format!(
                "post-condition probe FAILED: the box's /proc/cmdline does not carry {want} — a \
                 mis-wired firmware env cannot false-green the seabios-gpt gate; cmdline: {cmdline}"
            ));
        }
    }
    Ok(())
}

/// Recompute the `.img`'s verity root hash for the post-condition probe — the HARNESS's own
/// layout parse + slice (independent of the ceremony's flow; the veritysetup primitive is shared).
fn harness_recomputed_root_hash(box_img: &Path) -> Result<String, String> {
    let layout = super::dryrun::parse_layout(&super::dryrun::layout_sidecar(box_img))
        .map_err(|e| e.to_string())?;
    let img = std::fs::read(box_img).map_err(|e| format!("read {}: {e}", box_img.display()))?;
    let start = layout.rootfs_offset as usize;
    let end = start
        .checked_add(layout.rootfs_verity_hash_offset as usize)
        .filter(|&e| e <= img.len())
        .ok_or("layout rootfs offsets exceed the .img")?;
    let dir = tempfile::tempdir().map_err(|e| format!("probe verity tempdir: {e}"))?;
    let data = dir.path().join("rootfs-data");
    std::fs::write(&data, &img[start..end]).map_err(|e| format!("write rootfs-data: {e}"))?;
    super::dryrun::recompute_verity_root_hash(&data, &dir.path().join("verity.hash"))
        .map_err(|e| e.to_string())
}

/// A fresh operator-key ssh against the installed box for the post-condition probe — pinned
/// (`StrictHostKeyChecking=yes`) to the harness-built known_hosts via the ceremony's own hardened
/// argv builder; deliberately NOT [`guest_ssh`], which is the lax provisioning-key helper.
fn operator_ssh_capture(
    operator_privkey: &Path,
    known_hosts: &Path,
    port: u16,
    remote: &str,
) -> Result<String, String> {
    let mut cmd = Command::new("ssh");
    cmd.args(super::prod_orchestrate::prod_ssh_args(
        "127.0.0.1",
        operator_privkey,
        known_hosts,
        port,
    ))
    .arg(remote);
    let out = cmd
        .output()
        .map_err(|e| format!("spawn post-condition probe ssh: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "post-condition probe ssh {remote:?} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Acceptance #2/#4 — both fail-closed negatives over the REAL ops on ONE booted guest (neither
/// wipes it): Leg-A (a mismatched `--host-fingerprint` non-interactively) aborts after the scan,
                                                                                                
                                                                                            
/// untouched: still on its Debian root, the stage dir holding no staged `.img`.
pub fn run_negative_paths_e2e(
    box_img: &Path,
    operator_privkey: &Path,
    debian_img: &Path,
    opts: &DebianE2eOpts,
    log_dir: &Path,
) -> Result<(), String> {
                                                                                                   
    let console = log_dir.join("guest-console-negatives.log");
    let (_guard, workdir, provisioning_privkey) =
        boot_provisioned_guest(debian_img, opts, &console)?;
    let wd = workdir.path();
    let guest_fp = scan_guest_fingerprint(opts.forward_port)?;
    let (_line, runtime_fp) = crate::oneshots_offline::offline_runtime_hostkey(box_img)
        .map_err(|e| format!("derive runtime fp: {e}"))?;

                                                                            
    {
        let wrong = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let (mut ops, deploy_opts) = ceremony_inputs(
            wd,
            box_img,
            operator_privkey,
            &provisioning_privkey,
            opts,
            Some(wrong.to_string()),
            Some(runtime_fp.clone()),
        )?;
        let err = deploy_prod(&mut ops, deploy_opts)
            .expect_err("a mismatched --host-fingerprint must fail closed");
        if !err.contains("MISMATCH") {
            return Err(format!(
                "Leg-A negative aborted, but not with a host-key MISMATCH error: {err}"
            ));
        }
        assert_guest_untouched(&provisioning_privkey, opts.forward_port, "Leg-A")?;
    }

                                                                    
    {
        let wrong = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let (mut ops, deploy_opts) = ceremony_inputs(
            wd,
            box_img,
            operator_privkey,
            &provisioning_privkey,
            opts,
            Some(guest_fp.clone()),
            Some(wrong.to_string()),
        )?;
        let err = deploy_prod(&mut ops, deploy_opts)
            .expect_err("a wrong --runtime-hostkey-fingerprint must fail closed");
        if !err.contains("does not match the fingerprint derived") {
            return Err(format!(
                "Leg-B negative aborted, but not with the runtime-fingerprint error: {err}"
            ));
        }
        assert_guest_untouched(&provisioning_privkey, opts.forward_port, "Leg-B")?;
    }
    Ok(())
}

/// After a fail-closed abort, the guest must be exactly as cloud-init left it: still reachable on the
/// provisioning key (NOT wiped into the box), and its stage dir holding no staged `.img` (no scp ran).
fn assert_guest_untouched(provisioning_privkey: &Path, port: u16, leg: &str) -> Result<(), String> {
                                                                                                     
                                                                                
    let whoami = guest_ssh(provisioning_privkey, port, "id -un").map_err(|e| {
        format!(
            "{leg}: the guest is no longer reachable on the provisioning key after an abort: {e}"
        )
    })?;
    if whoami.trim() != "root" {
        return Err(format!("{leg}: unexpected guest identity {whoami:?}"));
    }
                                                                  
    let staged = guest_ssh(
        provisioning_privkey,
        port,
        "ls -1 /var/tmp/recipes-deploy/ 2>/dev/null | grep -c . || true",
    )?;
    if staged.trim() != "0" && !staged.trim().is_empty() {
        return Err(format!(
            "{leg}: the stage dir is not empty after a pre-scp abort (found {staged:?}) — bytes \
             were transferred before failing closed"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debian_e2e_opts_default_is_hermetic_and_wires_restrict_on() {
                                                                                                       
                                                                                                      
                                                                                                     
                                                                           
                                                          
        assert!(
            DebianE2eOpts::default().restrict_net,
            "the prod-e2e guest must be hermetic by default"
        );
        let hermetic = debian_user_netdev_arg(2222, true);
        assert!(
            hermetic.contains(",restrict=on"),
            "restrict_net=true must wire restrict=on: {hermetic}"
        );
        assert!(
            hermetic.contains("hostfwd=tcp:127.0.0.1:2222-:22"),
            "the inbound hostfwd must survive restrict=on: {hermetic}"
        );
        let open = debian_user_netdev_arg(2222, false);
        assert!(
            !open.contains("restrict=on"),
            "the explicit fixture-prep opt-out must not carry restrict=on: {open}"
        );
    }

    #[test]
    fn cloud_init_injects_key_kexec_tools_and_root_login() {
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEEXAMPLEEXAMPLEEXAMPLE recipes-prod-e2e";
        let ud = render_cloud_init_user_data(key);
        assert!(
            ud.starts_with("#cloud-config\n"),
            "must be a cloud-config doc"
        );
                                                                             
        assert!(
            ud.contains(key),
            "the provisioning pubkey must be injected verbatim"
        );
        assert!(
            ud.contains("/root/.ssh/authorized_keys"),
            "the key must target root's authorized_keys (the ceremony connects as root)"
        );
                                                                                               
                                                                                                   
                                                                                                      
                                                                                                
                                                                         
        assert!(
            !ud.contains("kexec-tools"),
            "the per-run user-data must NOT apt-install kexec-tools — it is baked into the fixture \
             (prepare_kexec_fixture) so the guest can run hermetic"
        );
        assert!(
            !ud.contains("packages:") && !ud.contains("package_update"),
            "the per-run user-data must request NO packages — the guest has no outbound route"
        );
                                                                                                    
                                                                                                   
                                                                                                
                                                                                             
        assert!(
            ud.contains("growpart:") && ud.contains("mode: 'off'"),
            "growpart must be explicitly disabled — the staging window lives in the disk tail that \
             growpart would otherwise hand to the root partition"
        );
        assert!(
            ud.contains("resize_rootfs: false"),
            "resize_rootfs must be off alongside growpart, so both knobs state the same intent"
        );
                                                                                                    
                                                                                                  
        assert!(ud.contains("disable_root: false"));
        assert!(
            !ud.contains("systemctl, restart, ssh"),
            "no sshd restart — it would race + drop the kexec-wait ssh session"
        );
    }

    #[test]
    fn grown_variant_pins_the_default_provisioned_knobs_and_the_base_stays_off() {
                                                                                            
                                                                                             
                                                                                                
                                                                                           
                                                                                            
                               
        let key = "ssh-ed25519 AAAAtest fixture@e2e";
        let base = render_cloud_init_user_data(key);
        assert!(base.contains("mode: 'off'") && base.contains("resize_rootfs: false"));
        let grown = render_cloud_init_user_data_grown(key);
        assert!(
            grown.contains("growpart:") && grown.contains("mode: auto"),
            "{grown}"
        );
        assert!(grown.contains("resize_rootfs: true"), "{grown}");
        assert!(grown.contains(key));
        assert!(
            !grown.contains("packages:") && !grown.contains("kexec-tools"),
            "the grown per-run user-data must stay hermetic: {grown}"
        );
        assert!(!grown.contains("systemctl, restart, ssh"));
    }

    #[test]
    fn boot_provisioned_guest_selects_the_grown_renderer_by_opt() {
                                                                                                    
                                                                                                     
                                                                                                    
                                                                                           
        let key = "ssh-ed25519 AAAAtest fixture@e2e";
        let grown = DebianE2eOpts {
            grown_user_data: true,
            ..DebianE2eOpts::default()
        };
        let base = DebianE2eOpts {
            grown_user_data: false,
            ..DebianE2eOpts::default()
        };
        assert_eq!(
            provisioning_user_data(&grown, key),
            render_cloud_init_user_data_grown(key),
            "a grown leg must seed the grown user-data"
        );
        assert_eq!(
            provisioning_user_data(&base, key),
            render_cloud_init_user_data(key),
            "a base leg must seed the base user-data"
        );
        assert!(provisioning_user_data(&grown, key).contains("mode: auto"));
        assert!(provisioning_user_data(&grown, key).contains("resize_rootfs: true"));
        assert!(provisioning_user_data(&base, key).contains("mode: 'off'"));
    }

    /// The other half of the split: what the per-run user-data gave up, the FIXTURE prep must carry.
    /// Migrated from the original combined assertion rather than dropped — the requirement ("the
    /// ceremony HARD-aborts discovery without `kexec` on the target") did not go away, it moved.
    #[test]
    fn fixture_prep_user_data_installs_kexec_tools_and_the_key() {
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEEXAMPLEEXAMPLEEXAMPLE recipes-prod-e2e";
        let ud = render_fixture_prep_user_data(key);
        assert!(ud.starts_with("#cloud-config\n"));
        assert!(
            ud.contains("kexec-tools"),
            "the fixture is the ONE place kexec-tools gets installed"
        );
        assert!(
            ud.contains("package_update: true"),
            "the prep boot refreshes apt — it is the only outbound-permitted boot"
        );
                                                                                     
        assert!(ud.contains(key));
        assert!(ud.contains("/root/.ssh/authorized_keys"));
        assert!(ud.contains("disable_root: false"));
    }

    #[test]
    fn the_cloud_init_user_data_authorizes_the_cloud_user_too() {
                                                                                           
                                                                                                
                                                                                                  
                                                                       
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 fixture";
        for ud in [
            render_cloud_init_user_data(key),
            render_cloud_init_user_data_grown(key),
        ] {
            assert!(
                ud.contains("/home/debian/.ssh/authorized_keys"),
                "the cloud user is authorized: {ud}"
            );
            assert!(
                ud.contains("'debian:debian'"),
                "and the file is owned by it: {ud}"
            );
                                                                                          
            assert!(ud.contains("/root/.ssh/authorized_keys"), "{ud}");
        }
    }

    #[test]
    fn harness_ops_are_pinned_non_interactive() {
                                                                                             
                                                                                                  
                                                                                                
                                                         
        let mut ops = NonInteractiveOps(ProcessOps {
                                                                                               
                                                                        
            provisioning_user: crate::deploy::prod_orchestrate::DEFAULT_PROVISIONING_USER
                .to_string(),
            ip: "127.0.0.1".into(),
            ssh_port: 2222,
            ssh_identity: "/k".into(),
            box_login_identity: "/b".into(),
            provisioning_known_hosts: "/kh-a".into(),
            reconnect_known_hosts: "/kh-b".into(),
            step_started: None,
        });
        assert!(!ops.stdin_is_tty(), "harness ops must never claim a TTY");
        assert_eq!(
            ops.read_line("retype the target:"),
            None,
            "harness ops must never answer a prompt"
        );
    }

    #[test]
    fn operator_pubkey_path_appends_pub_suffix() {
                                                                                                    
        let dir = tempfile::tempdir().unwrap();
        let dotted = dir.path().join("op.key");
        std::fs::write(dir.path().join("op.key.pub"), "x").unwrap();
        assert_eq!(
            operator_pubkey_path(&dotted).unwrap(),
            dir.path().join("op.key.pub")
        );
                                       
        let missing = dir.path().join("nope");
        assert!(operator_pubkey_path(&missing).is_err());
    }
}
