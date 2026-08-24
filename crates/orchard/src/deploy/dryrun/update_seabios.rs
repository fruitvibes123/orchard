                                                                                                       
//! box-side update engine (`fb-update apply` / `fb-mark-good`) and the `SeabiosGptSelector`'s real
//! block-device I/O (raw slot write + re-read verify, e2fsck-gated boot-fs mount, on-disk ADV arm/clear,
//! the udev-free PARTUUID resolve) work on produced bytes — `make verify` green is not a deploy green,
//! and the box-side apply/mark-good paths STUB nothing in this gate (the host-unit tests fake the
                                                                                         
//!
//! It drives, on the REAL installed seabios-gpt box over SSH, a genuine v1→v2 A/B cycle and its failure
//! modes. Two GENUINELY-DIFFERENT builds are the inputs: v1 (installed, `--image-version 1`) + v2
//! (streamed, `--image-version 2`) — different rootfs (the baked version stamp) ⇒ different verity
//! `root_hash`, both validly signed by the same operator root. The push stream is composed + signed +
//! framed by the SAME [`crate::deploy::update`] wire the `orchard update` ceremony uses (the ceremony's
//! orchestration is FakeOps-unit-tested; the WIRE + the box side are proven here).
//!
                                             
//!   - **G1** happy E2E: apply v2 → BOOTONCE slot-B → `fb-mark-good` probes healthy → commit (DEFAULT
//!     patched, floors advanced-by-set) → still v2 after a clean reboot (durable) — AND the commit is
//!     idempotent on a second `fb-mark-good` iteration (no floor regression; the row-9 re-commit seam).
//!   - **G5** refusal battery: wrong-key / tampered-manifest / below-floor-version / wrong-firmware /
//!     truncated-stream each REFUSE with a distinct exit + reason, leaving the box un-promoted (no
//!     probation record, DEFAULT unchanged, still boots v1) — the never-brick invariant; then a VALID
//!     v2 still applies (the refusals corrupted nothing).
//!   - **G3** bad `root_hash`: the slot-B rootfs stages OK but the label carries a wrong verity root →
//!     boot-B panics on the verity mismatch → `panic=10` reboots → BOOTONCE already cleared → DEFAULT
//!     (slot-A/v1). Covers the **G2** `panic=10`-reboot mechanism + **G6** durability (a second reboot
//!     stays on v1, no re-fire) + **G9(i)** same-version retry (re-applying v2 after the rollback
//!     ACCEPTS — the floor never advanced).
//!   - **G7** unloadable kernel: a truncated slot-B kernel → the loader's `NOESCAPE` auto-boots DEFAULT
//!     (no console prompt) → v1.
//!   - **G4** unhealthy tenant: a THIRD image (`v2_unhealthy`, its `[probe]` a closed port) BOOTS +
//!     verity-OK, so `fb-mark-good` RUNS on the bad slot — it re-clears the ADV (§4e/M1), probes →
//!     unhealthy each cycle, rides the 300 s probation deadline, and `reboot()`s to v1. The one rollback
//!     path where mark-good's OWN `Decision::Rollback` + `reboot()` drive the fallback (asserted by the
//!     deadline-rollback console marker), vs the loader-level G3/G7 where mark-good never runs.
//!
//! Documented residuals (each needs a BESPOKE broken bake / injection, out of this gate — named, not
                                                                                                     
//! heals-on-retry (a probe that flips healthy mid-probation); **G8** update-then-restore floor re-seed
//! (the restore-from gate proves the reseed mechanism; the update↔restore interaction is the new bit);
//! the **G1-rerun** mid-`fb-mark-good` kill injection (T18's `commit_is_idempotent_on_rerun` seam proves
//! the idempotence; a healthy second iteration is asserted here); the **S4-M1** produced-bytes finish-
//! handler negative (a broken-`finish`-symlink bake; T7's unit proves the detector, and the clean finish
//! path IS exercised by G1's durable reboot). These ride the next dha/weights bake cycle.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use dragonfruit::Purpose;

use super::assertions::assert_recipes_http;
use super::install_seabios::{run_installer_phase, stage_install_disk};
use super::qemu::{boot_installed_disk, ssh_base_args, wait_for_ssh};
use super::{
    DryrunError, DryrunOpts, layout_sidecar, local_artifact, parse_layout,
    recompute_verity_root_hash, slice,
};
use crate::deploy::artifact_keys::{Custody, generate_artifact_keys};
use crate::deploy::artifact_sign::{SignPlan, plan_signing, sign_bytes};
use crate::deploy::build_image::Firmware;
use crate::deploy::update::{
    BoxStatus, UpdateManifest, frame_apply_pipe, parse_status, prepare_local_image,
};

/// How long to wait for `fb-mark-good` to commit an update after boot-B (its cadence is 10 s; a couple
/// of iterations + the probe round-trip). Generous — a false ROLLBACK on a slow-but-good box is the
/// exact bug the deadline exists to avoid.
const COMMIT_DEADLINE: Duration = Duration::from_secs(150);
/// How long to wait for a ROLLBACK path to land back on v1 (panic=10 reboot / NOESCAPE fallthrough +
/// the boot).
const ROLLBACK_DEADLINE: Duration = Duration::from_secs(180);
/// PER-PHASE upper bound for the fb-mark-good DEADLINE rollback (G4): the slot boots + serves, but the
/// probe fails, so mark-good waits out the whole `MARK_GOOD_DEADLINE_SECS` (300 s) of uptime before it
/// `reboot()`s. `drive_markgood_rollback` applies this TWICE in sequence (candidate answers ssh, then
/// a fresh clock for the rollback to land), so it is NOT the ceremony's whole-ceremony watch deadline
/// (`update::WATCH_DEADLINE`, derived from the same box quantities but measured from apply-return in
/// one span) — the two measure different intervals from different origins and must NOT be aliased
                                                                                        
const MARKGOOD_ROLLBACK_DEADLINE: Duration = Duration::from_secs(450);

                                                                                                    
/// `.img`s built with `--image-version 1` / `--image-version 2` (+ `--operator-pubkey` + `--net`), whose
/// `<stem>.vmlinuz`/`.initramfs`/`.layout.toml` sidecars sit beside them; `operator_privkey` is the SSH
/// key both were built with; `keys_dir` is the ARTIFACT key set (with the UpdateImage delegation —
/// `orchard redelegate`) the manifests are signed with, whose `artifact-root.pub` is v1's baked box
/// anchor. `v2_unhealthy_img` is a THIRD seabios-gpt `.img` (version 2, a `--manifest` whose `[probe]`
/// points at a CLOSED port) — it boots + verity-OK, but fb-mark-good's probe fails persistently, so the
/// slot rides the probation deadline into mark-good's OWN `reboot()` rollback (G4, the one rollback path
/// where mark-good runs on the bad slot — unlike the loader-level G3/G7). RAII-tears-down every QEMU
/// child.
pub fn install_update_and_verify(
    v1_img: &Path,
    v2_img: &Path,
    v2_unhealthy_img: &Path,
    operator_privkey: &Path,
    keys_dir: &Path,
    opts: &DryrunOpts,
) -> Result<(), DryrunError> {
    super::preflight()?;
    let workdir = tempfile::Builder::new()
        .prefix("recipes-update-gate-")
        .tempdir()
        .map_err(DryrunError::io("creating update-gate workdir"))?;
    let wd = workdir.path();
    let log_dir = std::env::var_os("RECIPES_PROD_GATE_LOGDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| wd.to_path_buf());
    if log_dir != wd {
        std::fs::create_dir_all(&log_dir).map_err(DryrunError::io("creating gate log dir"))?;
    }
                                                                                                       
    let v1_image = std::fs::read(v1_img).map_err(DryrunError::io("read v1 .img"))?;

                                                                                                      
                                                                                                     
    let prepared = prepare_local_image(v2_img, keys_dir)
        .map_err(|e| DryrunError::InstallDiskStage(format!("compose v2 push: {e}")))?;
                                                                                      
                                                                                      
                                                                          
    let set = match plan_signing(keys_dir, &wd.join("no-pin"))
        .map_err(|e| DryrunError::InstallDiskStage(format!("plan the gate signing: {e}")))?
    {
        SignPlan::Host(set) => set,
        other => {
            return Err(DryrunError::InstallDiskStage(format!(
                "gate keys at {} must be a RAW (Host-rung) set, got {}",
                keys_dir.display(),
                match other {
                    SignPlan::Docker => "Docker",
                    _ => "UnsignedFloor",
                }
            )));
        }
    };
    let (rootfs, kernel, initramfs) = prepared.components();
    let wire = prepared.manifest.to_wire();

                                                                                                
    let sign = |manifest: &str| -> Result<Vec<u8>, DryrunError> {
        sign_bytes(&set, Purpose::UpdateImage, manifest.as_bytes())
            .map_err(|e| DryrunError::InstallDiskStage(format!("sign the push manifest: {e}")))
    };
    let good_bundle = sign(&wire)?;
    let good = frame_apply_pipe(wire.as_bytes(), &good_bundle, rootfs, kernel, initramfs);

                                                                                                        
                                                                              
    let unhealthy = prepare_local_image(v2_unhealthy_img, keys_dir).map_err(|e| {
        DryrunError::InstallDiskStage(format!("compose the unhealthy v2 push: {e}"))
    })?;
    let (u_rootfs, u_kernel, u_initramfs) = unhealthy.components();
    let u_wire = unhealthy.manifest.to_wire();
    let u_bundle = sign(&u_wire)?;
    let unhealthy_stream = frame_apply_pipe(
        u_wire.as_bytes(),
        &u_bundle,
        u_rootfs,
        u_kernel,
        u_initramfs,
    );

                                                                                                            
    let wrong_dir = wd.join("wrong-artifact-keys");
    generate_artifact_keys(&wrong_dir, 365, false, Custody::Raw)
        .map_err(|e| DryrunError::InstallDiskStage(format!("mint the wrong-key set: {e}")))?;
    let wrong_set = match plan_signing(&wrong_dir, &wd.join("no-pin"))
        .map_err(|e| DryrunError::InstallDiskStage(format!("plan the wrong-key signing: {e}")))?
    {
        SignPlan::Host(set) => set,
        _ => {
            return Err(DryrunError::InstallDiskStage(
                "the freshly-minted wrong-key set must be a RAW (Host-rung) set".to_string(),
            ));
        }
    };
    let wrong_bundle = sign_bytes(&wrong_set, Purpose::UpdateImage, wire.as_bytes())
        .map_err(|e| DryrunError::InstallDiskStage(format!("sign with the wrong key: {e}")))?;

                                                                                                        
                                                                                                 
    let mutate = |m: &UpdateManifest, k: &[u8]| -> Result<Vec<u8>, DryrunError> {
        let w = m.to_wire();
        let b = sign(&w)?;
        Ok(frame_apply_pipe(w.as_bytes(), &b, rootfs, k, initramfs))
    };

                                                                                                        
    let mut bad_rh = prepared.manifest.clone();
    bad_rh.root_hash = flip_hex(&bad_rh.root_hash);
    let bad_root_hash = mutate(&bad_rh, kernel)?;

                                                                                                       
                                                                                                          
    let short_kernel = &kernel[..kernel.len() / 2];
    let mut short_k = prepared.manifest.clone();
    short_k.kernel_sha256 = sha256(short_kernel);
    short_k.kernel_size = short_kernel.len() as u64;
    let unloadable_kernel = mutate(&short_k, short_kernel)?;

                                                                                                       
                                                                                      
                                                                                                       
    {
        let disk = fresh_v1_disk(&v1_image, v1_img, wd, "g5")?;
        let console = log_dir.join("g5-boot-console.log");
        let mut guard = boot_installed_disk(&disk, opts, &console, false)?;
        wait_for_ssh(
            operator_privkey,
            opts.ssh_port,
            opts.boot_timeout,
            &mut guard,
            &console,
        )?;
        assert_recipes_http(opts, &mut guard)?;
        let before = ssh_status(operator_privkey, opts.ssh_port)?;
        if before.image_version != 1 || before.firmware != "seabios-gpt" {
            return Err(DryrunError::UnexpectedBoot(format!(
                "G5: v1 box must report firmware=seabios-gpt image_version=1, got {:?}",
                before
            )));
        }

                                                                                 
        let mut below = prepared.manifest.clone();
        below.version = before.version_floor;        
        let below_floor = mutate(&below, kernel)?;
                                                                                                           
        let wf_wire = wire.replace("firmware = seabios-gpt", "firmware = seabios");
        let wf_bundle = sign(&wf_wire)?;
        let wrong_fw = frame_apply_pipe(wf_wire.as_bytes(), &wf_bundle, rootfs, kernel, initramfs);
                                                                                              
        let tampered_wire = flip_first_digit(&wire);
        let tampered = frame_apply_pipe(
            tampered_wire.as_bytes(),
            &good_bundle,
            rootfs,
            kernel,
            initramfs,
        );
                                                                 
        let mut truncated = good.clone();
        truncated.truncate(good.len().saturating_sub(4096));

        for (label, framed, reason) in [
            (
                "wrong-key",
                &frame_apply_pipe(wire.as_bytes(), &wrong_bundle, rootfs, kernel, initramfs),
                "verify",
            ),
            ("tampered-manifest", &tampered, "verify"),
            ("below-floor-version", &below_floor, "floor"),
            ("wrong-firmware", &wrong_fw, "firmware"),
            ("truncated-stream", &truncated, ""),
        ] {
                                                                                                     
                                                                                                         
                                                                                                     
                                           
            let detail = match ssh_apply(operator_privkey, opts.ssh_port, framed)? {
                crate::deploy::update::ApplyExit::Refused { detail } => detail,
                other => {
                    return Err(DryrunError::UnexpectedBoot(format!(
                        "G5/{label}: apply must REFUSE but classified {other:?} — the box may have \
                         armed a bad update"
                    )));
                }
            };
            if !reason.is_empty() && !detail.to_lowercase().contains(reason) {
                return Err(DryrunError::UnexpectedBoot(format!(
                    "G5/{label}: refused (good) but the reason didn't name {reason:?}: {detail}"
                )));
            }
                                                                                
            let s = ssh_status(operator_privkey, opts.ssh_port)?;
            if s.image_version != 1 || s.probation {
                return Err(DryrunError::UnexpectedBoot(format!(
                    "G5/{label}: a REFUSED apply left the box promoted/probation-armed: {s:?}"
                )));
            }
        }

                                                                            
        drive_commit(
            &good,
            operator_privkey,
            opts,
            &mut guard,
            &console,
            "g5-then-valid",
        )?;
    }

                                                                                                       
                                                                                       
                                                                                                       
    {
        let disk = fresh_v1_disk(&v1_image, v1_img, wd, "g1")?;
        let console = log_dir.join("g1-boot-console.log");
        let mut guard = boot_installed_disk(&disk, opts, &console, false)?;
        wait_for_ssh(
            operator_privkey,
            opts.ssh_port,
            opts.boot_timeout,
            &mut guard,
            &console,
        )?;
        let before = ssh_status(operator_privkey, opts.ssh_port)?;
        drive_commit(&good, operator_privkey, opts, &mut guard, &console, "g1")?;
        let committed = ssh_status(operator_privkey, opts.ssh_port)?;
                                                                                  
        if committed.version_floor <= before.version_floor {
            return Err(DryrunError::UnexpectedBoot(format!(
                "G1: version_floor did not advance on commit ({} -> {})",
                before.version_floor, committed.version_floor
            )));
        }
                                                                                                      
                                                                                              
        std::thread::sleep(Duration::from_secs(12));
        let again = ssh_status(operator_privkey, opts.ssh_port)?;
        if again.image_version != committed.image_version
            || again.version_floor != committed.version_floor
            || again.probation
        {
            return Err(DryrunError::UnexpectedBoot(format!(
                "G1: the commit was not idempotent — a later status drifted: {committed:?} -> {again:?}"
            )));
        }
                                                                                    
        clean_reboot(operator_privkey, opts, &mut guard, &console)?;
        let after = ssh_status(operator_privkey, opts.ssh_port)?;
        if after.image_version != committed.image_version {
            return Err(DryrunError::UnexpectedBoot(format!(
                "G1: the committed slot did not survive a clean reboot ({} -> {})",
                committed.image_version, after.image_version
            )));
        }
    }

                                                                                                       
                                                                                               
                                                                                                       
    {
        let disk = fresh_v1_disk(&v1_image, v1_img, wd, "g3")?;
        let console = log_dir.join("g3-boot-console.log");
        let mut guard = boot_installed_disk(&disk, opts, &console, false)?;
        wait_for_ssh(
            operator_privkey,
            opts.ssh_port,
            opts.boot_timeout,
            &mut guard,
            &console,
        )?;
        drive_rollback(
            &bad_root_hash,
            operator_privkey,
            opts,
            &mut guard,
            &console,
            "g3",
        )?;
                                                                                                  
        clean_reboot(operator_privkey, opts, &mut guard, &console)?;
        let s = ssh_status(operator_privkey, opts.ssh_port)?;
        if s.image_version != 1 {
            return Err(DryrunError::UnexpectedBoot(format!(
                "G6: the bad slot re-fired on a warm reboot (image_version={})",
                s.image_version
            )));
        }
                                                                                                        
        drive_commit(
            &good,
            operator_privkey,
            opts,
            &mut guard,
            &console,
            "g9i-retry",
        )?;
    }

                                                                                                       
                                                                                  
                                                                                                       
    {
        let disk = fresh_v1_disk(&v1_image, v1_img, wd, "g7")?;
        let console = log_dir.join("g7-boot-console.log");
        let mut guard = boot_installed_disk(&disk, opts, &console, false)?;
        wait_for_ssh(
            operator_privkey,
            opts.ssh_port,
            opts.boot_timeout,
            &mut guard,
            &console,
        )?;
        drive_rollback(
            &unloadable_kernel,
            operator_privkey,
            opts,
            &mut guard,
            &console,
            "g7",
        )?;
    }

                                                                                                       
                                                                                                              
                                                                                                       
                                                                                                            
                                                                                                       
    {
        let disk = fresh_v1_disk(&v1_image, v1_img, wd, "g4")?;
        let console = log_dir.join("g4-boot-console.log");
        let mut guard = boot_installed_disk(&disk, opts, &console, false)?;
        wait_for_ssh(
            operator_privkey,
            opts.ssh_port,
            opts.boot_timeout,
            &mut guard,
            &console,
        )?;
        drive_markgood_rollback(
            &unhealthy_stream,
            operator_privkey,
            opts,
            &mut guard,
            &console,
        )?;
    }

    Ok(())
}

/// Stage a fresh greenfield-installed v1 seabios-gpt disk (a full on-box installer run over real block
/// devices), ready to boot. Each case gets its OWN so the cases are independent.
fn fresh_v1_disk(
    v1_image: &[u8],
    v1_img: &Path,
    wd: &Path,
    tag: &str,
) -> Result<std::path::PathBuf, DryrunError> {
    let v1_layout = parse_layout(&layout_sidecar(v1_img))?;
    let v1_vmlinuz = local_artifact(v1_img, "vmlinuz")?;
    let v1_initramfs = local_artifact(v1_img, "initramfs")?;
    let rootfs_data = wd.join(format!("{tag}-rootfs-data"));
    slice(
        v1_img,
        v1_layout.rootfs_offset,
        v1_layout.rootfs_verity_hash_offset,
        &rootfs_data,
    )?;
    let root_hash =
        recompute_verity_root_hash(&rootfs_data, &wd.join(format!("{tag}-verity.hash")))?;
    let disk = wd.join(format!("{tag}-install-disk.img"));
                                                                                                    
                                                                
    let layout_info = super::install_seabios::gate_layout_info(&v1_layout, Firmware::SeabiosGpt);
    let window = stage_install_disk(v1_image, &layout_info, wd, &disk)?;
    let staged_sha = recipes_image_builder::image::sha256_hex(v1_image);
    run_installer_phase(
        &v1_vmlinuz,
        &v1_initramfs,
        &disk,
        &root_hash,
        v1_layout.rootfs_verity_hash_offset,
        &layout_info,
        &window,
        &staged_sha,
        None,
        None,
        &DryrunOpts::default(),
        &wd.join(format!("{tag}-install-console.log")),
    )?;
    Ok(disk)
}

/// Apply a stream that must ACCEPT, then poll until `fb-mark-good` COMMITS (probation cleared + the new
/// version is active). The box reboots itself into slot-B (BOOTONCE), mark-good probes healthy, commits.
fn drive_commit(
    framed: &[u8],
    privkey: &Path,
    opts: &DryrunOpts,
    guard: &mut super::QemuGuard,
    console: &Path,
    tag: &str,
) -> Result<(), DryrunError> {
                                                                                                      
                                                                                                     
                                                                                              
                                                            
    match ssh_apply(privkey, opts.ssh_port, framed)? {
        crate::deploy::update::ApplyExit::Refused { detail } => {
            return Err(DryrunError::UnexpectedBoot(format!(
                "{tag}: a VALID apply was REFUSED by the box: {detail}"
            )));
        }
        crate::deploy::update::ApplyExit::Streamed
        | crate::deploy::update::ApplyExit::SeveredProceedToWatch { .. } => {}
    }
                                                                                                       
    wait_for_ssh(privkey, opts.ssh_port, opts.boot_timeout, guard, console)?;
    let deadline = Instant::now() + COMMIT_DEADLINE;
    loop {
        if let Ok(s) = ssh_status(privkey, opts.ssh_port)
            && !s.probation
            && s.image_version == 2
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let s = ssh_status(privkey, opts.ssh_port).ok();
            return Err(DryrunError::BootTimeout(format!(
                "{tag}: fb-mark-good did not COMMIT within {}s (final status: {s:?}); console tail:\n{}",
                COMMIT_DEADLINE.as_secs(),
                super::console_tail(console)
            )));
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// Apply a stream that ACCEPTS (stages + arms) but whose slot-B is unbootable (bad verity / corrupt
/// kernel), so the box rolls back: the loader clears BOOTONCE, the bad boot fails, and the box lands on
/// DEFAULT (slot-A / v1). Poll until it's back on v1.
fn drive_rollback(
    framed: &[u8],
    privkey: &Path,
    opts: &DryrunOpts,
    guard: &mut super::QemuGuard,
    console: &Path,
    tag: &str,
) -> Result<(), DryrunError> {
                                                                                                       
                                                                               
    if let crate::deploy::update::ApplyExit::Refused { detail } =
        ssh_apply(privkey, opts.ssh_port, framed)?
    {
        return Err(DryrunError::UnexpectedBoot(format!(
            "{tag}: the rollback stream was REFUSED at apply (it should stage+arm, then fail at boot): {detail}"
        )));
    }
                                                                                                            
    wait_for_ssh(privkey, opts.ssh_port, ROLLBACK_DEADLINE, guard, console)?;
    let deadline = Instant::now() + ROLLBACK_DEADLINE;
    loop {
        if let Ok(s) = ssh_status(privkey, opts.ssh_port)
            && s.image_version == 1
            && !s.probation
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let s = ssh_status(privkey, opts.ssh_port).ok();
            return Err(DryrunError::BootTimeout(format!(
                "{tag}: the box did not ROLL BACK to v1 within {}s (final status: {s:?}); console tail:\n{}",
                ROLLBACK_DEADLINE.as_secs(),
                super::console_tail(console)
            )));
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// G4 — apply an UNHEALTHY-but-bootable v2 (its probe target is closed), then prove fb-mark-good's OWN
/// deadline rollback on produced bytes: the slot boots + verity-OK, mark-good runs on it (re-clears the
/// ADV, probes → unhealthy each cycle), rides the `MARK_GOOD_DEADLINE_SECS` deadline, and `reboot()`s to
/// the old slot. Distinguished from the loader-level G3/G7 by asserting the mark-good deadline-rollback
/// marker on the console — proof that fb-mark-good's `Decision::Rollback` + `reboot()` (not the loader)
/// drove the fallback.
fn drive_markgood_rollback(
    framed: &[u8],
    privkey: &Path,
    opts: &DryrunOpts,
    guard: &mut super::QemuGuard,
    console: &Path,
) -> Result<(), DryrunError> {
                                                                                                     
                                                               
    if let crate::deploy::update::ApplyExit::Refused { detail } =
        ssh_apply(privkey, opts.ssh_port, framed)?
    {
        return Err(DryrunError::UnexpectedBoot(format!(
            "g4: the unhealthy stream was REFUSED at apply (it must stage+arm+boot, then mark-good \
             rolls it back at the deadline): {detail}"
        )));
    }
                                                                                                               
                                                              
    wait_for_ssh(
        privkey,
        opts.ssh_port,
        MARKGOOD_ROLLBACK_DEADLINE,
        guard,
        console,
    )?;
    let deadline = Instant::now() + MARKGOOD_ROLLBACK_DEADLINE;
    loop {
        if let Ok(s) = ssh_status(privkey, opts.ssh_port)
            && s.image_version == 1
            && !s.probation
        {
                                                                                                     
                                                                                                 
            let log = std::fs::read_to_string(console).unwrap_or_default();
            if !log.contains("fb-mark-good: probation deadline exceeded") {
                return Err(DryrunError::UnexpectedBoot(format!(
                    "g4: the box is back on v1 but the fb-mark-good deadline-rollback marker is absent — \
                     the rollback was NOT driven by mark-good's reboot() path (the G4 target); console \
                     tail:\n{}",
                    super::console_tail(console)
                )));
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            let s = ssh_status(privkey, opts.ssh_port).ok();
            return Err(DryrunError::BootTimeout(format!(
                "g4: fb-mark-good did not deadline-roll-back to v1 within {}s (final status: {s:?}); \
                 console tail:\n{}",
                MARKGOOD_ROLLBACK_DEADLINE.as_secs(),
                super::console_tail(console)
            )));
        }
        std::thread::sleep(Duration::from_secs(10));
    }
}

/// Trigger a CLEAN reboot (SIGTERM to PID-1, the s6-svscan finish→reboot path) and wait for the box to
/// come back to SSH. Reuses the SAME guard (an in-place guest reboot; QEMU keeps running).
fn clean_reboot(
    privkey: &Path,
    opts: &DryrunOpts,
    guard: &mut super::QemuGuard,
    console: &Path,
) -> Result<(), DryrunError> {
                                                                                          
    let _ = Command::new("ssh")
        .args(ssh_base_args(privkey, opts.ssh_port))
        .arg("kill -s TERM 1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
                                                                                                        
    std::thread::sleep(Duration::from_secs(6));
    wait_for_ssh(privkey, opts.ssh_port, opts.boot_timeout, guard, console)
}

/// Stream a framed apply pipe to `fb-update apply` over ssh (stdin = the frame) and classify the
/// outcome through the SHIPPED classifier — so the produced-bytes gate exercises the exact transport +
                                                                                                    
/// `fb-update apply` reads the frame from ssh stdin (§4c). The scoped-writer + `ServerAliveInterval`
/// semantics live in [`crate::deploy::update::stream_apply_and_classify`]; the harness only supplies
/// the argv (its own `StrictHostKeyChecking=no` known_hosts policy — the box's key rotates every bake).
fn ssh_apply(
    privkey: &Path,
    port: u16,
    framed: &[u8],
) -> Result<crate::deploy::update::ApplyExit, DryrunError> {
    let mut cmd = Command::new("ssh");
    cmd.args(ssh_base_args(privkey, port))
                                                                                                        
                                                                  
        .args(["-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3"])
        .arg("fb-update apply");
    crate::deploy::update::stream_apply_and_classify(cmd, framed).map_err(DryrunError::QemuLaunch)
}

/// Read `fb-update status` over ssh and parse the §4g block.
fn ssh_status(privkey: &Path, port: u16) -> Result<BoxStatus, DryrunError> {
    let out = Command::new("ssh")
        .args(ssh_base_args(privkey, port))
        .arg("fb-update status")
        .output()
        .map_err(|e| DryrunError::QemuLaunch(format!("ssh fb-update status: {e}")))?;
    if !out.status.success() {
        return Err(DryrunError::UnexpectedBoot(format!(
            "fb-update status exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    parse_status(&String::from_utf8_lossy(&out.stdout))
        .map_err(|e| DryrunError::UnexpectedBoot(format!("parse fb-update status: {e}")))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// Flip the first hex nibble of a 64-hex string (a different-but-still-valid-hex root_hash).
fn flip_hex(h: &str) -> String {
    let mut c: Vec<char> = h.chars().collect();
    if let Some(first) = c.first_mut() {
        *first = if *first == '0' { '1' } else { '0' };
    }
    c.into_iter().collect()
}

/// Flip the first ASCII digit in the manifest wire (a one-byte tamper the sha256 catches).
fn flip_first_digit(wire: &str) -> String {
    let mut done = false;
    wire.chars()
        .map(|ch| {
            if !done && ch.is_ascii_digit() {
                done = true;
                if ch == '9' { '8' } else { '9' }
            } else {
                ch
            }
        })
        .collect()
}
