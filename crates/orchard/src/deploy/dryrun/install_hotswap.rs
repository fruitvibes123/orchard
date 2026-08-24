                                                                                                    
//! PRODUCED BYTES. Installs a `--firmware seabios-gpt --weights-anchor runtime --manifest
//! hotswap-tenant.toml` `.img` onto a blank disk, boots the INSTALLED GPT disk, and drives the
//! WHOLE swap surface over the operator SSH + the real `deploy-model` ceremony:
//!
//!   Leg 1 ([`install_hotswap_and_verify_swaps`]) — the swap battery on a clean box:
                                                                                                    
                                                                                           
                                                                                            
//!            control: `fb.root-hash=` IS present).
                                                                                        
                                                                                              
//!            reach the persisted record, or run the swap — root-only, each with a root-side
//!            positive control.
                                                                                                 
//!            byte-unchanged and the OLD engine still up (disk untouched).
                                                                                            
//!            DIFFERENT model → COMMITTED (the box-side REAL-inference health passed), uptime
//!            continuity (no reboot), the record advanced to the pushed verity root.
                                                                                                  
                                                                                                 
//!            200); the box stays up (haproxy supervised, SSH live). A clean re-push RESTORES.
//!     Rider 3  a CLEAN reboot (TERM to PID-1) comes back serving the PUSHED model from the
//!            persisted record (persisted-not-baked).
//!
//!   Leg 2 ([`install_hotswap_torn_and_verify_recovery`]) — the degrade/torn-state battery:
                                                                                            
//!            corrupt sha, STALE verity root) streams fully, mounts, and the kernel EIOs the read
//!            → DEGRADED, engine down + VISIBLE, box up; the dm-verity EIO is probed directly
//!            (`dd` as the tenant uid). A clean re-push restores.
                                                                                        
                                                                                              
//!            fine and ONLY the engine down (s6-scoped, the normal runtime, not rescue);
                                                                                              
//!
//! Both legs finish with a console-log kernel-panic scan: the boot phase runs WITHOUT `-no-reboot`
//! (the in-guest reboots must come back in the same VM), so a `panic=10` recovery reboot could
//! otherwise masquerade as a healthy pass (the M-β/S4-M1 lesson).
//!
//! `#[ignore]`-gated in `orchard/tests/deploy_model_gate.rs`; run via `make boot-gate-hotswap`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use super::install_dha::{rc_zero, ssh_capture};
use super::install_seabios::run_installer_phase;
use super::qemu::{boot_installed_disk, ssh_base_args, wait_for_ssh, wait_for_ssh_down};
use super::*;
use crate::deploy::deploy_model::{
    ModelPushReport, PreparedModelPush, SshModelOps, frame_model_push, prepare_model_push,
    run_model_ceremony, sign_model_manifest,
};
use crate::deploy::host_pins::HostPinOpts;
use crate::deploy::update::{Authorize, CeremonyOpts};

/// The engine's s6 service + tenant uid (hotswap-tenant.toml `resource_domain.engine` /
/// `identities`) — duplicated here like install_dha's consts; a drift fails the produced-bytes
/// assertions, never silently passes.
const ENGINE_SERVICE: &str = "creatine";
const TENANT_UID: &str = "dha";
/// The engine's loopback listen port (hotswap-tenant.toml `CREATINE_BIND` / models.toml
/// `[health].port`) in /proc/net/tcp hex form: 8377 = 0x20B9.
const ENGINE_PORT_HEX: &str = ":20B9";
/// The raw weights partition node on the bench box (GPT entry 5 on the single virtio disk).
const WEIGHTS_DEV: &str = "/dev/vda5";
/// The persisted trust record (fb-weights `stores::WEIGHTS_DIR`/`CURRENT_FILE`).
const RECORD_PATH: &str = "/persist/weights/current";
/// The golden 3-rule Option-C IMA policy (image-builder `config.rs`) — asserted BYTE-level on the
                                                      
const IMA_GOLDEN_RULES: [&str; 3] = [
    "appraise func=BPRM_CHECK fowner=0 appraise_type=imasig",
    "appraise func=MMAP_CHECK fowner=0 appraise_type=imasig",
    "appraise func=MODULE_CHECK appraise_type=imasig",
];

/// Everything the two legs need beyond the `.img`: the operator SSH identity, the artifact key
/// set that signed the bake (signs the pushes), a PRE-REDELEGATE snapshot of the same set (its
                                                                                            
/// (MUST differ from the baked one and fit the partition), and the pinned build container (the
/// push packing runs the SAME squashfs+verity the bake uses).
pub struct HotswapGateEnv {
    pub img: PathBuf,
    pub operator_privkey: PathBuf,
    pub keys_dir: PathBuf,
    pub keys_old_dir: PathBuf,
    pub push_gguf: PathBuf,
    pub container_image: String,
}

/// Leg 1 — install a clean v4 `.img`, boot it, and drive the full swap battery (see the module
/// doc). One install, one VM (rebootable), sequential SSH assertions.
pub fn install_hotswap_and_verify_swaps(
    env: &HotswapGateEnv,
    opts: &DryrunOpts,
) -> Result<(), DryrunError> {
    let workdir = tempfile::Builder::new()
        .prefix("recipes-hotswap-gate-")
        .tempdir()
        .map_err(DryrunError::io("creating hotswap-gate workdir"))?;
    let wd = workdir.path();
    let console = hotswap_log_path(wd, "hotswap-boot-console.log");
    let mut guard = install_and_boot_hotswap(env, opts, wd, &console)?;
    let port = opts.ssh_port;
    let key = &env.operator_privkey;

                                                                                   
    assert_negative_cmdline(key, port)?;

                                                                                          
    assert_models_mounted(key, port, true)?;
    assert_engine_stable_and_listening(key, port)?;

                                                    
    assert_rootfs_ro_and_ima_golden(key, port)?;

                                                                      
    assert_tenant_cannot_touch_swap_machinery(key, port)?;

                                                                                        
    let baseline = record_sha(key, port)?;
                                                                                  
    let (throwaway, _keys_guard) = throwaway_keys()?;
    raw_refusal_push(env, key, port, &throwaway, 4096, "manifest verify")?;
                                                                                                 
                                                                                                
                                                                                        
    raw_refusal_push(env, key, port, &env.keys_old_dir, 4096, "CounterBelowFloor")?;
                                                                                             
    raw_refusal_push(env, key, port, &env.keys_dir, 16 << 30, "does not fit")?;
                                                                                    
    assert_record_sha_is(key, port, &baseline, "after the refusal battery")?;
    assert_engine_stable_and_listening(key, port)?;

                                                                                                  
    let uptime_before = read_uptime(key, port)?;
    let prepared = prepare_model_push(&env.push_gguf, &env.container_image, &orchard_repo_root()?)
        .map_err(DryrunError::HotswapCheckFailed)?;
    let report = ceremony_push(env, opts, &prepared)?;
    if report != ModelPushReport::Committed {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "the valid different-model push did not COMMIT: {report:?}"
        )));
    }
    let uptime_after = read_uptime(key, port)?;
    if uptime_after <= uptime_before {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "uptime did not continue monotonically across the swap \
             ({uptime_before} -> {uptime_after}) — did the box reboot?"
        )));
    }
    assert_record_carries_root(key, port, &prepared.root_hash, "after the committed swap")?;
    assert_engine_stable_and_listening(key, port)?;

                                                                                             
    let committed_sha = record_sha(key, port)?;
    let garbage = wd.join("garbage-model.gguf");
    write_garbage_gguf(&garbage)?;
    let garbage_prepared =
        prepare_model_push(&garbage, &env.container_image, &orchard_repo_root()?)
            .map_err(DryrunError::HotswapCheckFailed)?;
    let report = ceremony_push(env, opts, &garbage_prepared)?;
    if !matches!(report, ModelPushReport::Degraded { .. }) {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "the mounts-but-cannot-infer push must DEGRADE via the real-inference health \
             gate, got {report:?}"
        )));
    }
    assert_record_sha_is(key, port, &committed_sha, "after the degraded garbage push")?;
    assert_engine_down_no_listener(key, port, "")?;
    assert_box_up_besides_engine(key, port)?;

                                                                         
    let report = ceremony_push(env, opts, &prepared)?;
    if report != ModelPushReport::Committed {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "restore re-push after the degraded state did not COMMIT: {report:?}"
        )));
    }
    assert_engine_stable_and_listening(key, port)?;

                                                                                           
    clean_reboot_via_term(key, opts, &mut guard, &console)?;
    assert_models_mounted(key, port, true)?;
    assert_record_carries_root(key, port, &prepared.root_hash, "after the clean reboot")?;
    assert_engine_stable_and_listening(key, port)?;

    assert_console_no_panic(&console)?;
    Ok(())
}

/// Leg 2 — the degrade/torn-state battery on a fresh install (see the module doc).
pub fn install_hotswap_torn_and_verify_recovery(
    env: &HotswapGateEnv,
    opts: &DryrunOpts,
) -> Result<(), DryrunError> {
    let workdir = tempfile::Builder::new()
        .prefix("recipes-hotswap-torn-")
        .tempdir()
        .map_err(DryrunError::io("creating hotswap-torn workdir"))?;
    let wd = workdir.path();
    let console = hotswap_log_path(wd, "hotswap-torn-console.log");
    let mut guard = install_and_boot_hotswap(env, opts, wd, &console)?;
    let port = opts.ssh_port;
    let key = &env.operator_privkey;
    assert_models_mounted(key, port, true)?;
    assert_engine_stable_and_listening(key, port)?;

                                                                                                   
    let baseline = record_sha(key, port)?;
    let prepared = prepare_model_push(&env.push_gguf, &env.container_image, &orchard_repo_root()?)
        .map_err(DryrunError::HotswapCheckFailed)?;
    let (code, err) = corrupt_signed_push(env, key, port, &prepared)?;
    if code != Some(4) {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "the corrupt-bytes push must DEGRADE (exit 4), got {code:?}: {err}"
        )));
    }
                                                                                                    
                                                                                                      
                                                                                                     
                                                                                             
                                                                                                     
                                                                                                    
                                                                                                      
                                                                               
    assert_record_sha_is(key, port, &baseline, "after the corrupt-bytes push")?;
    assert_models_mounted(key, port, false)?;
    let _ = err;
    assert_engine_down_no_listener(key, port, "")?;
    assert_box_up_besides_engine(key, port)?;

                                                                       
    let report = ceremony_push(env, opts, &prepared)?;
    if report != ModelPushReport::Committed {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "restore re-push after the EIO degrade did not COMMIT: {report:?}"
        )));
    }
    assert_engine_stable_and_listening(key, port)?;

                                                                                                   
                                                                                                     
                                                                                                   
                                                                                              
                                                                                                 
                                                      
    let torn_gguf = wd.join("torn-model.gguf");
    write_garbage_gguf(&torn_gguf)?;
    let torn_prepared = prepare_model_push(&torn_gguf, &env.container_image, &orchard_repo_root()?)
        .map_err(DryrunError::HotswapCheckFailed)?;
    truncated_mid_write_push(env, key, port, &torn_prepared)?;
    let (alive, _) = ssh_capture(key, port, "echo ALIVE")?;
    if !alive {
        return Err(DryrunError::HotswapCheckFailed(
            "the box became unreachable after the killed mid-write push".into(),
        ));
    }
    wait_engine_down(key, port, "post-kill")?;

                                                                                    
    clean_reboot_via_term(key, opts, &mut guard, &console)?;
                                                                                                   
                                                                                                   
                                                                                         
    assert_box_up_besides_engine(key, port)?;
                                                                                                 
    wait_engine_down(key, port, "")?;
    assert_models_mounted(key, port, false)?;

                                                                              
    let report = ceremony_push(env, opts, &prepared)?;
    if report != ModelPushReport::Committed {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "the restore re-push from the torn state did not COMMIT \
             (the teardown already-done tolerance): {report:?}"
        )));
    }
    assert_models_mounted(key, port, true)?;
    assert_record_carries_root(
        key,
        port,
        &prepared.root_hash,
        "after the torn-state restore",
    )?;
    assert_engine_stable_and_listening(key, port)?;

    assert_console_no_panic(&console)?;
    Ok(())
}

/// Leg 3 — the deterministic crash-injection battery (spec Component B). Drives the four
/// [`PausePoint`]s in spec-table order, each on a FRESH install+boot: the pause-push streams the
/// SAME real model `env.push_gguf` (call it R, healthy + distinct from the baked model B, which
/// the fresh box commits) with `FB_WEIGHTS_PAUSE_AT` set, the leg polls the on-box marker, SIGKILLs
/// the paused swap, asserts the point's postcondition, and proves a plain re-push (no env) recovers
/// to COMMITTED. A fresh box per point is REQUIRED, not incidental: `mid-write`/`pre-commit`'s
/// degrade proofs need the pushed bytes (R) to differ from the currently-committed model, and only
/// the baked B (always committed on a fresh box) is a second healthy-and-distinct model — recovering
/// to R and re-pushing R would silently make the degrade untorn.
pub fn install_hotswap_crash_injection_and_verify_recovery(
    env: &HotswapGateEnv,
    opts: &DryrunOpts,
) -> Result<(), DryrunError> {
                                                                                                   
                                                                        
    let prepared = prepare_model_push(&env.push_gguf, &env.container_image, &orchard_repo_root()?)
        .map_err(DryrunError::HotswapCheckFailed)?;
    for point in ["pre-write", "mid-write", "pre-commit", "pre-rename"] {
        run_one_pause_point(env, opts, &prepared, point)?;
    }
    Ok(())
}

/// One crash-injection point on its own fresh box: install+boot (commits the baked model B), inject
/// the paused push of R at `point`, SIGKILL, assert the spec-table postcondition, then recover with
/// a plain re-push → COMMITTED + real-inference health.
fn run_one_pause_point(
    env: &HotswapGateEnv,
    opts: &DryrunOpts,
    prepared: &PreparedModelPush,
    point: &str,
) -> Result<(), DryrunError> {
    let workdir = tempfile::Builder::new()
        .prefix(&format!("recipes-hotswap-crash-{point}-"))
        .tempdir()
        .map_err(DryrunError::io("creating crash-injection workdir"))?;
    let wd = workdir.path();
    let console = hotswap_log_path(wd, &format!("hotswap-crash-{point}-console.log"));
    let mut guard = install_and_boot_hotswap(env, opts, wd, &console)?;
    let port = opts.ssh_port;
    let key = &env.operator_privkey;
    assert_models_mounted(key, port, true)?;
    assert_engine_stable_and_listening(key, port)?;
    let baseline = record_sha(key, port)?;                                                  

                                                                                                    
    let sig = sign_model_manifest(
        &env.keys_dir,
        &env.keys_dir.join("no-pin"),
        &prepared.manifest,
    )
    .map_err(|e| {
        DryrunError::HotswapCheckFailed(format!("signing the crash-injection push: {e}"))
    })?;
    let frame = frame_model_push(&prepared.manifest, &sig, &prepared.image);

                                                                                                  
                                                                              
    let push = std::thread::scope(|scope| -> Result<(), DryrunError> {
        let pushed = scope.spawn(|| raw_swap_push_paused(key, port, &frame, point));
                                                                
        let pid = poll_pause_marker(key, port, point)?;
                                                                                         
        let (ok, out) = ssh_capture(key, port, &format!("kill -9 {pid}"))?;
        if !ok {
            return Err(DryrunError::HotswapCheckFailed(format!(
                "{point}: kill -9 {pid} failed: {out}"
            )));
        }
        let _ = pushed.join().expect("push thread panicked");
        Ok(())
    });
    push?;

                                                     
    match point {
        "pre-write" => {
                                                                                                   
                                                                                          
            assert_record_sha_is(key, port, &baseline, "after the pre-write kill")?;
        }
        "mid-write" => {
                                                                                       
                                                                                               
                                                                                             
                                                                                                  
            clean_reboot_via_term(key, opts, &mut guard, &console)?;
            assert_box_up_besides_engine(key, port)?;
            wait_engine_down(key, port, "AC-B3 (mid-write reboot)")?;
            assert_models_mounted(key, port, false)?;
        }
        "pre-commit" => {
                                                                                                  
                                               
            assert_models_mounted(key, port, true)?;
            assert_engine_stable_and_listening(key, port)?;
            assert_record_sha_is(key, port, &baseline, "pre-commit: record still OLD")?;
                                                                                              
            clean_reboot_via_term(key, opts, &mut guard, &console)?;
            assert_box_up_besides_engine(key, port)?;
            wait_engine_down(key, port, "AC-B4 (pre-commit reboot)")?;
            assert_models_mounted(key, port, false)?;
        }
        "pre-rename" => {
                                                                                              
                                                                                      
            assert_record_sha_is(key, port, &baseline, "pre-rename: record still OLD")?;
            assert_tmp_residue_present(key, port)?;
        }
        other => {
            return Err(DryrunError::HotswapCheckFailed(format!(
                "unknown crash-injection point {other:?}"
            )));
        }
    }

                                                                                                     
                                                                                                  
                                                         
    let report = ceremony_push(env, opts, prepared)?;
    if report != ModelPushReport::Committed {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "{point}: the recovery re-push did not COMMIT: {report:?}"
        )));
    }
    assert_models_mounted(key, port, true)?;
    assert_record_carries_root(
        key,
        port,
        &prepared.root_hash,
        "after the crash-injection recovery",
    )?;
    assert_engine_stable_and_listening(key, port)?;
    assert_console_no_panic(&console)?;
    Ok(())
}

/// Poll the on-box pause marker (`/run/fb-weights.paused`, `<point> <pid>\n`) until the expected
/// point appears, returning the paused swap's PID. Bounded — a marker that never appears (a missing
/// seam, an unhonored env, a preflight-refused push) times out into a loud failure.
fn poll_pause_marker(privkey: &Path, port: u16, point: &str) -> Result<String, DryrunError> {
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
                                                                                           
        let (_ok, out) = ssh_capture(
            privkey,
            port,
            "cat /run/fb-weights.paused 2>/dev/null; true",
        )?;
        if let Some(line) = out.lines().find(|l| l.starts_with(point)) {
            let mut it = line.split_whitespace();
            if let (Some(p), Some(pid)) = (it.next(), it.next())
                && p == point
                && pid.parse::<u32>().is_ok()
            {
                return Ok(pid.to_string());
            }
        }
        if Instant::now() >= deadline {
            return Err(DryrunError::HotswapCheckFailed(format!(
                "{point}: the pause marker never appeared (the swap never reached the seam): {out}"
            )));
        }
        sleep(Duration::from_secs(2));
    }
}

/// AC-B5: the fsynced `.current.tmp` residue exists after a pre-rename kill (root positive control:
/// the record dir itself is present, so an absent tmp is a real "rename already happened / no
/// residue" miss, not a wrong-path false pass).
fn assert_tmp_residue_present(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let (ok, out) = ssh_capture(
        privkey,
        port,
        "test -d /persist/weights && test -f /persist/weights/.current.tmp; echo RC=$?",
    )?;
    if !ok || !rc_zero(&out) {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "AC-B5: the .current.tmp residue is absent after the pre-rename kill: {out}"
        )));
    }
    Ok(())
}

                                                                                                                                                                                                                                                                      

/// Shared prologue (the install_dha shape): parse the layout (a weights-bearing `.img` REQUIRED),
/// stage the install disk, run the dd-only installer (VM sized to hold the whole image — the
/// pre-baked installer Vec-reads it), boot the installed GPT disk REBOOTABLE (the legs' in-guest
/// reboots must come back in the same VM), and wait for the operator-key SSH.
fn install_and_boot_hotswap(
    env: &HotswapGateEnv,
    opts: &DryrunOpts,
    wd: &Path,
    console: &Path,
) -> Result<QemuGuard, DryrunError> {
    preflight()?;
    let img = &env.img;
    let layout = parse_layout(&layout_sidecar(img))?;
    if layout.weights_offset.is_none() || layout.weights_size.is_none() {
        return Err(DryrunError::HotswapCheckFailed(
            "the `.layout.toml` has no weights keys — not a weights-bearing v4 `.img`".into(),
        ));
    }
    let vmlinuz = local_artifact(img, "vmlinuz")?;
    let initramfs = local_artifact(img, "initramfs")?;

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
    let window = super::install_seabios::stage_install_disk(&image, &layout_info, wd, &disk)?;
    let staged_sha = recipes_image_builder::image::sha256_hex(&image);

                                                                                                  
                                                                       
    run_installer_phase(
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
        &hotswap_log_path(wd, "hotswap-install-console.log"),
    )?;

                                                                                              
                                                                                                 
                                            
    let mut guard = boot_installed_disk(&disk, opts, console, false)?;
    wait_for_ssh(
        &env.operator_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        console,
    )?;
    Ok(guard)
}

/// The M-β clean-reboot pattern: TERM to PID-1 (the s6 tree-stop → sync/umount → reboot exec),
/// wait for the box to go DOWN, then wait for SSH back up (the same VM — no `-no-reboot`).
fn clean_reboot_via_term(
    privkey: &Path,
    opts: &DryrunOpts,
    guard: &mut QemuGuard,
    console: &Path,
) -> Result<(), DryrunError> {
    let _ = Command::new("ssh")
        .args(ssh_base_args(privkey, opts.ssh_port))
        .arg("kill -s TERM 1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    wait_for_ssh_down(privkey, opts.ssh_port, opts.boot_timeout, guard, console)?;
    wait_for_ssh(privkey, opts.ssh_port, opts.boot_timeout, guard, console)
}

                                                                                                                                                                                                                                                                  

/// Run the REAL operator ceremony (`SshModelOps` — keyscan → pinned known_hosts → framed stdin
/// push) against the booted bench box. The host pin bootstraps against the fingerprint the box
/// presents (captured via the same keyscan path), pinned into a per-leg temp store.
fn ceremony_push(
    env: &HotswapGateEnv,
    opts: &DryrunOpts,
    prepared: &PreparedModelPush,
) -> Result<ModelPushReport, DryrunError> {
    let ops = SshModelOps::new(
        "127.0.0.1".to_string(),
        opts.ssh_port,
        env.operator_privkey.clone(),
        false,
    );
    use crate::deploy::deploy_model::DeployModelOps as _;
    let presented = ops
        .host_fingerprint()
        .map_err(DryrunError::HotswapCheckFailed)?;
    let pin_dir = tempfile::Builder::new()
        .prefix("hotswap-host-pins-")
        .tempdir()
        .map_err(DryrunError::io("host-pin tempdir"))?;
    let cer = CeremonyOpts {
        host: "127.0.0.1",
        keys_dir: &env.keys_dir,
        authorize: Authorize::Confirmed,
        host_pin: HostPinOpts {
            host_fingerprint: Some(&presented),
            is_tty: false,
            pin_dir: pin_dir.path(),
        },
    };
                                                                                         
                                                                                    
                                                     
    run_model_ceremony(prepared, &env.keys_dir.join("no-pin"), &cer, &ops)
        .map_err(DryrunError::HotswapCheckFailed)
}

/// Craft a signed 4-line weights manifest (the fb-weights `stores` grammar, pinned here from the
/// CONSUMER side so a producer drift fails the gate) and push its HEADER-ONLY frame: the box's
/// preflight must REFUSE (exit 3, `expect_marker` in its stderr) before ever reading image bytes.
fn raw_refusal_push(
    _env: &HotswapGateEnv,
    privkey: &Path,
    port: u16,
    sign_keys: &Path,
    image_size: u64,
    expect_marker: &str,
) -> Result<(), DryrunError> {
    let manifest = format!(
        "verity-root-hash={}\nverity-offset={}\nimage-sha256={}\nimage-size={}\n",
        "ab".repeat(32),
        image_size.saturating_sub(4096),
        "cd".repeat(32),
        image_size
    )
    .into_bytes();
    let sig =
        sign_model_manifest(sign_keys, &sign_keys.join("no-pin"), &manifest).map_err(|e| {
            DryrunError::HotswapCheckFailed(format!("signing the refusal-probe manifest: {e}"))
        })?;
                                                                                             
    let mut frame = Vec::with_capacity(24 + manifest.len() + sig.len());
    frame.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
    frame.extend_from_slice(&manifest);
    frame.extend_from_slice(&(sig.len() as u64).to_le_bytes());
    frame.extend_from_slice(&sig);
    frame.extend_from_slice(&image_size.to_le_bytes());

    let (code, err) = raw_swap_push(privkey, port, &frame, None)?;
    if code != Some(3) {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "expected a preflight REFUSAL (exit 3, {expect_marker:?}), got {code:?}: {err}"
        )));
    }
    if !err.contains(expect_marker) {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "the refusal fired for the wrong reason — wanted {expect_marker:?} in: {err}"
        )));
    }
    Ok(())
}

                                                                                                 
/// manifest over the CORRUPT sha but the ORIGINAL (now-stale) verity root — validly signed, streams
/// and mounts, and the kernel EIOs the read. Full-frame push; expect exit 4.
fn corrupt_signed_push(
    env: &HotswapGateEnv,
    privkey: &Path,
    port: u16,
    prepared: &PreparedModelPush,
) -> Result<(Option<i32>, String), DryrunError> {
    use sha2::{Digest, Sha256};
    let mut image = prepared.image.clone();
                                                                                              
                                                                                   
    let orig = String::from_utf8_lossy(&prepared.manifest).to_string();
    let verity_offset = orig
        .lines()
        .find_map(|l| l.strip_prefix("verity-offset="))
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| {
            DryrunError::HotswapCheckFailed("no verity-offset in the packed manifest".into())
        })?;
                                                                                                   
                                                                                                   
                                                                                              
                                                                                                  
                                                                                                     
                                                                                                 
    let _ = verity_offset;
    image[0] ^= 0xFF;
    let corrupt_sha: [u8; 32] = Sha256::digest(&image).into();
    let hex: String = corrupt_sha.iter().map(|b| format!("{b:02x}")).collect();
    let manifest = format!(
        "verity-root-hash={}\nverity-offset={}\nimage-sha256={}\nimage-size={}\n",
        prepared.root_hash,
        verity_offset,
        hex,
        image.len()
    )
    .into_bytes();
    let sig = sign_model_manifest(&env.keys_dir, &env.keys_dir.join("no-pin"), &manifest).map_err(
        |e| DryrunError::HotswapCheckFailed(format!("signing the corrupt-bytes manifest: {e}")),
    )?;
    let frame = frame_model_push(&manifest, &sig, &image);
    raw_swap_push(privkey, port, &frame, None)
}

                                                                                                  
/// close stdin — the box's `fb-weights swap` short-reads at EOF mid-write and DEGRADES, leaving the
/// partition torn (old bytes already overwritten by the partial stream) and the engine stopped.
/// Asserts the DEGRADED exit (4) — a deterministic short-EOF, not a raced ssh-client kill.
fn truncated_mid_write_push(
    env: &HotswapGateEnv,
    privkey: &Path,
    port: u16,
    prepared: &PreparedModelPush,
) -> Result<(), DryrunError> {
    let sig = sign_model_manifest(
        &env.keys_dir,
        &env.keys_dir.join("no-pin"),
        &prepared.manifest,
    )
    .map_err(|e| DryrunError::HotswapCheckFailed(format!("signing the mid-write push: {e}")))?;
    let frame = frame_model_push(&prepared.manifest, &sig, &prepared.image);
                                                                                                   
                                                                                                   
                                                                                                   
                                                                                                      
                                                                                                  
                                                                                                 
                                                                                   
    let cut = frame.len() - prepared.image.len() / 2;                            
    let (code, err) = raw_swap_push(privkey, port, &frame, Some(cut))?;
    if code != Some(4) {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "the truncated mid-write push must DEGRADE (exit 4, torn partition), got {code:?}: {err}"
        )));
    }
    Ok(())
}

/// Stream `frame[..cut.unwrap_or(len)]` to `fb-weights swap` over the operator ssh, then close
/// stdin and collect (exit code, stderr). A `cut` sends a TRUNCATED stream (the interrupted-write
/// shape): the box short-reads at EOF and DEGRADES — a clean, deterministic outcome, unlike killing
/// the ssh client (which races the box's own progress). The writer runs on a scoped thread: a
/// refusing box stops reading at the preflight, and a serial write-then-wait would deadlock on the
/// pipe (the update-gate stream_frame lesson).
fn raw_swap_push(
    privkey: &Path,
    port: u16,
    frame: &[u8],
    cut: Option<usize>,
) -> Result<(Option<i32>, String), DryrunError> {
    raw_swap_push_cmd(privkey, port, frame, cut, "fb-weights swap")
}

/// Leg 3: the pause-injecting push — the env is set INSIDE the root remote command (dropbear runs
/// it through the login shell), NOT via ssh client-env forwarding (which dropbear rejects: the
/// seam's security argument stays intact — a client cannot inject the pause env). The pushed swap
/// runs to `point` and blocks; the caller polls the marker + SIGKILLs it.
fn raw_swap_push_paused(
    privkey: &Path,
    port: u16,
    frame: &[u8],
    point: &str,
) -> Result<(Option<i32>, String), DryrunError> {
    let remote = format!("FB_WEIGHTS_PAUSE_AT={point} fb-weights swap");
    raw_swap_push_cmd(privkey, port, frame, None, &remote)
}

fn raw_swap_push_cmd(
    privkey: &Path,
    port: u16,
    frame: &[u8],
    cut: Option<usize>,
    remote_cmd: &str,
) -> Result<(Option<i32>, String), DryrunError> {
    let mut child = Command::new("ssh")
        .args(ssh_base_args(privkey, port))
        .arg(remote_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| DryrunError::HotswapCheckFailed(format!("spawn swap ssh: {e}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| DryrunError::HotswapCheckFailed("swap ssh stdin unavailable".into()))?;
    let end = cut.unwrap_or(frame.len());
    std::thread::scope(|s| {
        let writer = s.spawn(move || {
            use std::io::Write as _;
                                                                                               
                                                                                                   
                                                                                           
            let _ = stdin.write_all(&frame[..end]);
            let _ = stdin.flush();
            drop(stdin);
        });
        writer.join().expect("swap writer thread");
    });
    let out = child
        .wait_with_output()
        .map_err(|e| DryrunError::HotswapCheckFailed(format!("await swap ssh: {e}")))?;
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.code(), combined))
}

                                                                                                                                                                                                                                                        

                                                                                           
/// cmdline) and NO `fb.weights-` token (the initramfs fatal-mount is structurally skipped).
fn assert_negative_cmdline(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let (ok, out) = ssh_capture(privkey, port, "cat /proc/cmdline")?;
    if !ok || !out.contains("fb.root-hash=") {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "could not read a real boot cmdline (no fb.root-hash=): {out}"
        )));
    }
    if out.contains("fb.weights-") {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "VIOLATED: the v4 box's cmdline carries a fb.weights-* token: {out}"
        )));
    }
    Ok(())
}

/// `/models` mount state: `expect_mounted` ⇒ an RO squashfs line in /proc/mounts; else NO line.
fn assert_models_mounted(
    privkey: &Path,
    port: u16,
    expect_mounted: bool,
) -> Result<(), DryrunError> {
    let (ok, out) = ssh_capture(privkey, port, "grep ' /models ' /proc/mounts; echo RC=$?")?;
    if !ok {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "/models mount probe did not run: {out}"
        )));
    }
    let mounted = out.lines().any(|l| l.contains(" /models squashfs ro"));
    if expect_mounted && !mounted {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "/models is not an RO squashfs mount: {out}"
        )));
    }
    if !expect_mounted && out.lines().any(|l| l.contains(" /models ")) {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "expected NO /models mount (torn state), found one: {out}"
        )));
    }
    Ok(())
}

/// The engine is supervised-up, STABLE (same pid across an 8 s window — a crash-looping loud-fail
/// flips pids), and LISTENING on its loopback port.
fn assert_engine_stable_and_listening(privkey: &Path, port: u16) -> Result<(), DryrunError> {
                                                                                       
    let deadline = Instant::now() + Duration::from_secs(90);
    let pid = loop {
        match engine_pid(privkey, port)? {
            Some(pid) => break pid,
            None if Instant::now() < deadline => sleep(Duration::from_secs(3)),
            None => {
                let (_ok, sv) = ssh_capture(
                    privkey,
                    port,
                    &format!("s6-svstat /run/service/{ENGINE_SERVICE}"),
                )?;
                return Err(DryrunError::HotswapCheckFailed(format!(
                    "{ENGINE_SERVICE} never reached supervised-up: {sv}"
                )));
            }
        }
    };
    sleep(Duration::from_secs(8));
    let pid2 = engine_pid(privkey, port)?;
    if pid2 != Some(pid.clone()) {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "{ENGINE_SERVICE} is not stable (pid {pid} -> {pid2:?}) — crash-looping?"
        )));
    }
                                                                                                  
                                    
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (ok, out) = ssh_capture(
            privkey,
            port,
            &format!("sh -c \"grep '{ENGINE_PORT_HEX}' /proc/net/tcp | grep ' 0A ' | wc -l\""),
        )?;
        if ok && out.trim().parse::<u32>().unwrap_or(0) >= 1 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(DryrunError::HotswapCheckFailed(format!(
                "no LISTEN socket on the engine port ({ENGINE_PORT_HEX}): {out}"
            )));
        }
        sleep(Duration::from_secs(3));
    }
}

/// The engine's supervised pid, `None` when not up.
fn engine_pid(privkey: &Path, port: u16) -> Result<Option<String>, DryrunError> {
    let (_ok, out) = ssh_capture(
        privkey,
        port,
        &format!("s6-svstat /run/service/{ENGINE_SERVICE}"),
    )?;
    let t = out.trim_start();
    if !t.starts_with("up (pid") {
        return Ok(None);
    }
    Ok(t.split_whitespace()
        .nth(2)
        .map(|p| p.trim_end_matches(')').to_string()))
}

                                                                                                 
/// NO LISTEN socket on its port — a stub answering 200 would hold the listener open.
fn assert_engine_down_no_listener(privkey: &Path, port: u16, leg: &str) -> Result<(), DryrunError> {
    wait_engine_down(privkey, port, leg)?;
    let (ok, out) = ssh_capture(
        privkey,
        port,
        &format!("sh -c \"grep '{ENGINE_PORT_HEX}' /proc/net/tcp | grep ' 0A ' | wc -l\""),
    )?;
    if !ok || out.trim().parse::<u32>().unwrap_or(999) != 0 {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "{leg}: the engine port still has a LISTEN socket (a stub serving?): {out}"
        )));
    }
    Ok(())
}

/// Wait (bounded) for the engine to leave supervised-up — the restart cap needs its window
/// (3 restarts / 30 s) before s6-permafailon downs it.
fn wait_engine_down(privkey: &Path, port: u16, leg: &str) -> Result<(), DryrunError> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if engine_pid(privkey, port)?.is_none() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let (_ok, sv) = ssh_capture(
                privkey,
                port,
                &format!("s6-svstat /run/service/{ENGINE_SERVICE}"),
            )?;
            return Err(DryrunError::HotswapCheckFailed(format!(
                "{leg}: {ENGINE_SERVICE} is still up (expected loud-fail → restart-cap down): {sv}"
            )));
        }
        sleep(Duration::from_secs(3));
    }
}

/// The box besides the engine, s6-scoped proof: box-critical services serve (dropbear answers a
/// fresh SSH sentinel) AND the box is in the NORMAL runtime (box-init built the tenant cgroup
/// tree — rescue would not). Deliberately NOT haproxy: on a bench box with no provisioned domain
/// cert, haproxy fail-loops on the absent `/persist/acme/<domain>/full.pem` bind cert (and, with
/// an empty tenant `mtls_paths`, the `is_android_api` ACL renders empty — a latent
/// config-rendering defect shared with dha-tenant.toml, orthogonal to the weights mechanism and
                                                                                                  
                                                                                           
/// normal-runtime prove exactly that; the engine-down assertion is the caller's separate leg.
fn assert_box_up_besides_engine(privkey: &Path, port: u16) -> Result<(), DryrunError> {
                                                                                                    
    let (ok, out) = ssh_capture(privkey, port, "echo BOX_CRITICAL_ALIVE")?;
    if !ok || !out.contains("BOX_CRITICAL_ALIVE") {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "box-critical dropbear did not answer a fresh SSH sentinel: {out}"
        )));
    }
    assert_normal_runtime(privkey, port)
}

/// The box is in the NORMAL runtime, not the rescue branch: box-init built the tenant resource
/// domain (`/sys/fs/cgroup/dha`), which the rescue path never provisions.
fn assert_normal_runtime(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let (ok, out) = ssh_capture(
        privkey,
        port,
        "test -d /sys/fs/cgroup/dha && echo NORMAL || echo RESCUE_OR_ABSENT",
    )?;
    if !ok || !out.contains("NORMAL") {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "the box is not in the normal runtime (rescue/brick?): {out}"
        )));
    }
    Ok(())
}

                                                                                                 
/// set (an allowlist compare over the non-comment lines — a 4th rule or a dropped rule both fail).
fn assert_rootfs_ro_and_ima_golden(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let (ok, out) = ssh_capture(privkey, port, "grep ' / squashfs ro' /proc/mounts | wc -l")?;
    if !ok || out.trim().parse::<u32>().unwrap_or(0) != 1 {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "/ is not a single RO squashfs mount: {out}"
        )));
    }
    let (ok, out) = ssh_capture(privkey, port, "cat /etc/ima/policy")?;
    if !ok {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "could not read /etc/ima/policy: {out}"
        )));
    }
    let rules: Vec<&str> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if rules != IMA_GOLDEN_RULES {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "the IMA policy is not the golden 3-rule set: {rules:?}"
        )));
    }
    Ok(())
}

                                                                                                
/// each probe hits a real object (a missing node would fail-for-the-wrong-reason otherwise).
fn assert_tenant_cannot_touch_swap_machinery(privkey: &Path, port: u16) -> Result<(), DryrunError> {
                                                                                                 
                                
    for probe in [
        format!("test -b {WEIGHTS_DEV}"),
        "test -c /dev/mapper/control".to_string(),
        format!("test -f {RECORD_PATH}"),
        format!("dd if={WEIGHTS_DEV} of=/dev/null bs=512 count=1 2>/dev/null"),
    ] {
        let (ok, out) = ssh_capture(privkey, port, &format!("{probe}; echo RC=$?"))?;
        if !ok || !rc_zero(&out) {
            return Err(DryrunError::HotswapCheckFailed(format!(
                "positive control failed ({probe}): {out}"
            )));
        }
    }
                                                                  
    for (what, cmd) in [
        (
            "write the raw weights partition",
            format!("printf x > {WEIGHTS_DEV}"),
        ),
        (
            "read the raw weights partition",
            format!("dd if={WEIGHTS_DEV} of=/dev/null bs=512 count=1"),
        ),
        (
            "open the DM control node",
            "printf x > /dev/mapper/control".to_string(),
        ),
        ("read the persisted record", format!("cat {RECORD_PATH}")),
        (
            "write the weights store",
            "touch /persist/weights/tenant-was-here".to_string(),
        ),
        ("run the swap", "fb-weights swap < /dev/null".to_string()),
    ] {
        let (ok, out) = ssh_capture(
            privkey,
            port,
            &format!("s6-setuidgid {TENANT_UID} sh -c '{cmd}' 2>&1; echo RC=$?"),
        )?;
        if !ok {
            return Err(DryrunError::HotswapCheckFailed(format!(
                "probe did not run ({what}): {out}"
            )));
        }
        if rc_zero(&out) {
            return Err(DryrunError::HotswapCheckFailed(format!(
                "VIOLATED: the tenant uid could {what}: {out}"
            )));
        }
    }
    Ok(())
}

/// sha256 of the persisted record (the disk-untouched baseline).
fn record_sha(privkey: &Path, port: u16) -> Result<String, DryrunError> {
    let (ok, out) = ssh_capture(privkey, port, &format!("sha256sum {RECORD_PATH}"))?;
    let sha = out.split_whitespace().next().unwrap_or("").to_string();
    if !ok || sha.len() != 64 {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "could not hash {RECORD_PATH}: {out}"
        )));
    }
    Ok(sha)
}

fn assert_record_sha_is(
    privkey: &Path,
    port: u16,
    expected: &str,
    when: &str,
) -> Result<(), DryrunError> {
    let now = record_sha(privkey, port)?;
    if now != expected {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "the persisted record CHANGED {when} (expected byte-identical): {expected} -> {now}"
        )));
    }
    Ok(())
}

/// The record's (ASCII) manifest names the given verity root — the committed-trust pointer probe.
fn assert_record_carries_root(
    privkey: &Path,
    port: u16,
    root_hash: &str,
    when: &str,
) -> Result<(), DryrunError> {
    let (ok, out) = ssh_capture(
        privkey,
        port,
        &format!("grep -a -c {root_hash} {RECORD_PATH}"),
    )?;
    if !ok || out.trim() != "1" {
        return Err(DryrunError::HotswapCheckFailed(format!(
            "the persisted record does not carry the pushed verity root {when}: {out}"
        )));
    }
    Ok(())
}

                                                                                              
fn read_uptime(privkey: &Path, port: u16) -> Result<f64, DryrunError> {
    let (ok, out) = ssh_capture(privkey, port, "cat /proc/uptime")?;
    let v = out.split_whitespace().next().and_then(|f| f.parse().ok());
    match (ok, v) {
        (true, Some(u)) => Ok(u),
        _ => Err(DryrunError::HotswapCheckFailed(format!(
            "could not read /proc/uptime: {out}"
        ))),
    }
}

/// A deterministic not-a-GGUF payload, large enough to pack into a real squashfs+verity volume.
fn write_garbage_gguf(path: &Path) -> Result<(), DryrunError> {
    let mut bytes = vec![0u8; 8 * 1024 * 1024];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    std::fs::write(path, bytes).map_err(DryrunError::io("write the garbage gguf"))
}

/// A throwaway artifact key set (the wrong-key negative): freshly minted, never the box's root.
fn throwaway_keys() -> Result<(PathBuf, tempfile::TempDir), DryrunError> {
    let dir = tempfile::Builder::new()
        .prefix("hotswap-throwaway-keys-")
        .tempdir()
        .map_err(DryrunError::io("throwaway keys tempdir"))?;
    crate::deploy::artifact_keys::generate_artifact_keys(
        dir.path(),
        365,
        false,
        crate::deploy::artifact_keys::Custody::Raw,
    )
    .map_err(|e| DryrunError::HotswapCheckFailed(format!("mint throwaway keys: {e}")))?;
    Ok((dir.path().to_path_buf(), dir))
}

/// The orchard repo root (CARGO_MANIFEST_DIR = crates/orchard → two parents up) — the
/// `prepare_model_push` docker mount root.
fn orchard_repo_root() -> Result<PathBuf, DryrunError> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| DryrunError::HotswapCheckFailed("no orchard repo root".into()))
}

/// End-of-leg false-green guard: the legs boot WITHOUT `-no-reboot`, so a `panic=10` recovery
/// reboot could hide inside an otherwise-green run — the console must carry no panic marker.
fn assert_console_no_panic(console: &Path) -> Result<(), DryrunError> {
    let log = std::fs::read_to_string(console).unwrap_or_default();
    if log.contains("Kernel panic - not syncing") {
        return Err(DryrunError::HotswapCheckFailed(
            "the console log carries a kernel-panic marker — a panic-recovery reboot hid inside \
             this leg"
                .into(),
        ));
    }
    Ok(())
}

/// The console log path — honoring `RECIPES_HOTSWAP_GATE_LOGDIR` (survival past the tempdir
/// auto-clean, for diagnosing a boot failure), else the workdir.
fn hotswap_log_path(wd: &Path, name: &str) -> PathBuf {
    match std::env::var_os("RECIPES_HOTSWAP_GATE_LOGDIR") {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            let _ = std::fs::create_dir_all(&dir);
            dir.join(name)
        }
        None => wd.join(name),
    }
}
