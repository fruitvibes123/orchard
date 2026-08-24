                                                                                                   
//! `--firmware seabios-gpt --manifest dha-tenant.toml` `.img` (so the real 5th GPT weights partition
//! materializes + the installer dd's it, E1a) onto a blank disk, boots the INSTALLED disk through
//! SeaBIOS, and asserts the five box guarantees over SSH (dropbear gives a full shell for the remote
//! commands — unlike the tenant manifest's word-argv, so the harness can drive the breach + kill-to-cap):
//!
//!   F1  controller-present   — `/sys/fs/cgroup/cgroup.controllers` carries `memory` (+ `pids`) — else
                                                                                 
//!   F2  ancestor-Σ survival  — the engine is placed in `dha/creatine`; a SIMULATED breach (the harness
//!                              spawns anon-RSS hogs in uncapped `dha/work/<id>` leaves, since the light
//!                              `sleep` stand-ins can't reach aggregate-Σ) drives `dha/` to its Σ OOM;
//!                              `dha-orchestrator` (disjoint `work/orch` leaf, small footprint) SURVIVES
//!                              and the OOM stayed cgroup-scoped — box-critical services never died
                                                                                                             
//!   F3  descendants backstop — a `work/`-process (the dha uid) cannot create more than the root-owned
                                                                                   
//!   F4  restart-cap          — a capped longrun killed ≥N×/window goes permanently DOWN via
                                                                                              
//!   F5  weights-tamper→EIO   — an offline-corrupted weights block yields dm-verity DEFAULT-mode EIO to a
//!                              reader; the box BOOTS (no `restart_on_corruption` boot-loop — H-R4-1) and
                                                                                   
//!
//! The tenant is the REAL creatine/dha-orchestrator/epa (dha's 2nd supply-chain tenant). Beyond F1–F5
//! (the box mechanism), the gate asserts the §4.6 real-bin legs: per-uid leg 4 (the two configs baked
                                                                                                          
//! (H2/Option-A) + dha's AC-I1..I11 suite GATE on dha's published bins + staged scripts. `#[ignore]`-gated
//! in `orchard/tests/deploy_dha.rs`; run via `make boot-gate-dha` (a from-pins dha `.img` + KVM — which
//! itself needs dha's published bins).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use super::install_seabios::{run_installer_phase, stage_install_disk};
use super::qemu::{boot_installed_disk, ssh_base_args, wait_for_ssh};
use super::*;

/// The dha resource-domain names the legs assert against — MUST match `dha-tenant.toml`'s
/// `resource_domain` + the box's fixed leaf mapping (`service_tree::dha_leaf_cgroup`): engine →
/// `dha/creatine`, orchestrator → `dha/work/orch`. Duplicated here (the test can't read the fixture at
/// runtime on the booted box); a drift is caught by the produced-bytes assertion failing.
const DHA_ROOT: &str = "/sys/fs/cgroup/dha";
const ORCH_SERVICE: &str = "dha-orchestrator";
const ENGINE_SERVICE: &str = "creatine";

/// The staged path of dha's `intake-probe.sh` on the box — a dha-deliverable CONTRACT (the exact box
/// staging path is settled when dha ships `deploy/intake-probe.sh`; reconciled at `make boot-gate-dha`).
const DHA_INTAKE_PROBE: &str = "/opt/dha/intake-probe.sh";
/// The staged path of dha's AC-I1..I11 acceptance harness (the `cgroup-k4-selftest.sh` derivative,
/// S-INTAKE-WIRE §7) — likewise a dha-deliverable contract reconciled at the boot-gate.
const DHA_AC_I_HARNESS: &str = "/opt/dha/ac-i-selftest.sh";
/// The staged path of dha's REAL-JOB probe — submits an ACCEPTED job (vs the intake probe's REJECTED
/// round-trip) so the client-config path (`runtime.json` `client.config` → `/opt/dha/epa.json`) is
/// exercised end-to-end (a dha deliverable; reconciled at the boot-gate).
const DHA_REAL_JOB_PROBE: &str = "/opt/dha/real-job-probe.sh";

/// Install a clean dha `.img`, boot it, and assert F1–F4 (confinement/survival) PLUS the §4.6 real-bin
/// legs (per-uid config-owner + weights; the dha-gated intake probe + AC-I suite) — one boot, sequential
/// SSH assertions, the real-bin legs BEFORE the F2 breach / F4 kill (which take the orchestrator down).
pub fn install_dha_disk_and_verify(
    img: &Path,
    operator_privkey: &Path,
    opts: &DryrunOpts,
) -> Result<(), DryrunError> {
    let workdir = tempfile::Builder::new()
        .prefix("recipes-dha-gate-")
        .tempdir()
        .map_err(DryrunError::io("creating dha-gate workdir"))?;
    let wd = workdir.path();
    let console = dha_log_path(wd, "dha-boot-console.log");
                                                                                                         
                                                                                                         
    let _guard = install_and_boot_dha(img, operator_privkey, opts, wd, false, &console)?;

    let port = opts.ssh_port;
    assert_controller_present(operator_privkey, port)?;
    assert_run_dha_provisioned(operator_privkey, port)?;
                                                                                                       
                                                                                                     
                                                                                                           
    assert_dha_configs_owner(operator_privkey, port)?;
    assert_weights_readable(operator_privkey, port)?;
    assert_intake_probe(operator_privkey, port)?;
    assert_real_job(operator_privkey, port)?;
    assert_ac_i_harness(operator_privkey, port)?;
    assert_ancestor_sigma_survival(operator_privkey, port)?;
    assert_descendants_backstop(operator_privkey, port)?;
    assert_restart_cap(operator_privkey, port)?;
    Ok(())
}

/// F5 — install a dha `.img` whose weights component has ONE offline-corrupted block, boot it, and
/// assert the box survives (dm-verity DEFAULT/EIO mode, not a `restart_on_corruption` boot-loop): the
/// box reaches the NORMAL runtime (not rescue) and a read of `/models/model.gguf` as the dha uid EIOs.
pub fn install_dha_weights_tamper_and_verify_survival(
    img: &Path,
    operator_privkey: &Path,
    opts: &DryrunOpts,
) -> Result<(), DryrunError> {
    let workdir = tempfile::Builder::new()
        .prefix("recipes-dha-tamper-")
        .tempdir()
        .map_err(DryrunError::io("creating dha-tamper workdir"))?;
    let wd = workdir.path();
    let console = dha_log_path(wd, "dha-tamper-console.log");
                                                                                                       
                                                                                                    
                                                                                                     
    let _guard = install_and_boot_dha(img, operator_privkey, opts, wd, true, &console)?;
    let port = opts.ssh_port;

                                                                                                         
                                                                                                        
                                                                                                        
                                                                                                 
    let (ok, out) = ssh_capture(
        operator_privkey,
        port,
        &format!("test -d {DHA_ROOT}/creatine && echo NORMAL || echo RESCUE_OR_ABSENT"),
    )?;
    if !ok || !out.contains("NORMAL") {
        return Err(DryrunError::DhaCheckFailed(format!(
            "F5: corrupt weights did NOT reach the normal dha runtime (boot-loop or rescue divert?): {out}"
        )));
    }

                                                                                                       
                                                                                                         
                                                                                                       
                                                    
    let (read_ok, read_out) = ssh_capture(
        operator_privkey,
        port,
        &format!(
            "s6-setuidgid {ENGINE_SERVICE_UID} dd if=/models/model.gguf of=/dev/null bs=1M 2>&1; echo RC=$?"
        ),
    )?;
                                                                                                       
                                                                                         
    let dd_failed = !rc_zero(&read_out) || read_out.to_lowercase().contains("i/o error");
    if !read_ok {
        return Err(DryrunError::DhaCheckFailed(format!(
            "F5: the weights read probe did not run over SSH: {read_out}"
        )));
    }
    if !dd_failed {
        return Err(DryrunError::DhaCheckFailed(format!(
            "F5: reading the CORRUPTED weights succeeded (expected dm-verity EIO on the tampered block): {read_out}"
        )));
    }

                                                                                                       
    let (alive, _) = ssh_capture(operator_privkey, port, "echo ALIVE")?;
    if !alive {
        return Err(DryrunError::DhaCheckFailed(
            "F5: the box became unreachable after the weights EIO (expected: box survives)".into(),
        ));
    }
                                                                                  
    Ok(())
}

/// The dha uid the stand-in engine/orchestrator drop to (`dha-tenant.toml` identity `dha` = uid 110);
/// `s6-setuidgid` takes the NAME, resolved on the box against the baked passwd.
const ENGINE_SERVICE_UID: &str = "dha";

/// Shared prologue: parse the layout, (optionally corrupt a weights block), stage the single install
/// disk, run the dd-only installer (it reboots), boot the INSTALLED GPT disk through SeaBIOS, and wait
/// for the operator-key SSH. Returns the live QEMU guard. Mirrors `install_disk_and_verify`'s SeabiosGpt
/// arm (no `/dev`-sentinel patch — SeabiosGpt bakes a fixed PARTUUID) + threads the weights corruption.
fn install_and_boot_dha(
    img: &Path,
    operator_privkey: &Path,
    opts: &DryrunOpts,
    wd: &Path,
    corrupt_weights: bool,
    console: &Path,
) -> Result<QemuGuard, DryrunError> {
    preflight()?;
                                                                                                          
                                                                                                          
                                                                                                         
                                                                                                      
                                             
    if let Some(proof) = opts.weights_proof {
        super::assert_prod_weights_shape(img, opts.memory_mb, proof)
            .map_err(DryrunError::ProdShapeGuard)?;
    }
    let layout = parse_layout(&layout_sidecar(img))?;
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

                                                                                                     
                                                                                                          
    let mut image =
        std::fs::read(img).map_err(DryrunError::io(format!("read {}", img.display())))?;
    if corrupt_weights {
        corrupt_one_weights_block(&mut image, &layout)?;
    }

    let disk = wd.join("install-disk.img");
    let layout_info = super::install_seabios::gate_layout_info(
        &layout,
        crate::deploy::build_image::Firmware::SeabiosGpt,
    );
    let window = stage_install_disk(&image, &layout_info, wd, &disk)?;
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
        &dha_log_path(wd, "dha-install-console.log"),
    )?;

    let mut guard = boot_installed_disk(&disk, opts, console, true)?;
                                                                                                  
    wait_for_ssh(
        operator_privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        console,
    )?;
    Ok(guard)
}

/// Flip one byte in the MIDDLE of the weights component (`layout.weights_offset..+weights_size`) so a
/// dm-verity data block fails verification on read. A dha `.img` MUST carry the weights keys; their
/// absence is a fail-closed error (this leg is meaningless on a non-dha image).
fn corrupt_one_weights_block(image: &mut [u8], layout: &Layout) -> Result<(), DryrunError> {
    let (Some(off), Some(size)) = (layout.weights_offset, layout.weights_size) else {
        return Err(DryrunError::DhaCheckFailed(
            "F5: the `.layout.toml` has no weights_offset/size — not a dha (weights-bearing) `.img`".into(),
        ));
    };
    let off = off as usize;
    let size = size as usize;
    if size == 0 || off.saturating_add(size) > image.len() {
        return Err(DryrunError::DhaCheckFailed(format!(
            "F5: weights region [{off}..+{size}) is out of the {}-byte image",
            image.len()
        )));
    }
                                                                                                         
                                                                                                            
    let target = off + size / 2;
    image[target] ^= 0xFF;
    Ok(())
}

                                                                                                                                                                                                                              

/// F1 — the booted box kernel exposes the `memory` controller (and `pids`) at the cgroup2 root, else the
                                                                                                           
fn assert_controller_present(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let (ok, out) = ssh_capture(privkey, port, "cat /sys/fs/cgroup/cgroup.controllers")?;
    if !ok {
        return Err(DryrunError::DhaCheckFailed(format!(
            "F1: could not read /sys/fs/cgroup/cgroup.controllers: {out}"
        )));
    }
    for want in ["memory", "pids"] {
        if !out.split_whitespace().any(|c| c == want) {
            return Err(DryrunError::DhaCheckFailed(format!(
                "F1: cgroup2 root is missing the `{want}` controller (the Σ/fork-bomb defense is inert): {out}"
            )));
        }
    }
    Ok(())
}

/// D6 / §4.2 step 8 (M-6) — box-init pre-created the orchestrator intake uds dir `/run/dha` 0700 dha:dha,
/// so the orchestrator binds `/run/dha/orchestrator.sock` (0600) inside it + fails closed otherwise. The
/// box does NOT front the orchestrator via haproxy (D6). Proves the provisioning on produced bytes (the
/// box-init unit test covers the write logic; this is the end-to-end anchor dha's intake-wire binds to).
fn assert_run_dha_provisioned(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let (ok, out) = ssh_capture(privkey, port, "stat -c '%a %U:%G' /run/dha 2>&1")?;
    let t = out.trim();
    if !ok || !t.starts_with("700 ") || !t.contains("dha") {
        return Err(DryrunError::DhaCheckFailed(format!(
            "/run/dha is not provisioned 0700 dha:dha (box / §4.2 step 8): stat → {t:?}"
        )));
    }
    Ok(())
}

/// F2 — under a simulated aggregate-Σ breach the orchestrator SURVIVES and the OOM stays cgroup-scoped.
fn assert_ancestor_sigma_survival(privkey: &Path, port: u16) -> Result<(), DryrunError> {
                                                                                                           
    let (ok, procs) = ssh_capture(
        privkey,
        port,
        &format!("cat {DHA_ROOT}/creatine/cgroup.procs"),
    )?;
    if !ok || procs.split_whitespace().next().is_none() {
        return Err(DryrunError::DhaCheckFailed(format!(
            "F2: no process in {DHA_ROOT}/creatine — the engine was not placed in its leaf: {procs}"
        )));
    }
    assert_service_up(privkey, port, ORCH_SERVICE)?;                                     

                                                                                                         
                                                                                                            
                                                                                                          
                                                                                                                
                                                                                                          
                                                                                         
    let breach = format!(
        "s6-setuidgid {ENGINE_SERVICE_UID} sh -c '\
           for i in 1 2 3; do \
             mkdir -p {DHA_ROOT}/work/breach$i 2>/dev/null; \
             ( echo $$ > {DHA_ROOT}/work/breach$i/cgroup.procs 2>/dev/null; \
               x=x; while : ; do x=$x$x; done ) & \
           done; \
           wait'; \
         for i in 1 2 3; do rmdir {DHA_ROOT}/work/breach$i 2>/dev/null || true; done; \
         echo BREACH_DONE"
    );
    let (_bok, bout) = ssh_capture(privkey, port, &breach)?;
    if !bout.contains("BREACH_DONE") {
                                                                                                       
        return Err(DryrunError::DhaCheckFailed(format!(
            "F2: the box did not survive the breach to return the driver (global OOM took init/dropbear?): {bout}"
        )));
    }

                                                                                                        
                                                                                                            
                                                                                          
    assert_service_up(privkey, port, ORCH_SERVICE)?;
    assert_service_up(privkey, port, ENGINE_SERVICE)?;
    let (ev_ok, events) = ssh_capture(privkey, port, &format!("cat {DHA_ROOT}/memory.events"))?;
    if !ev_ok {
        return Err(DryrunError::DhaCheckFailed(format!(
            "F2: could not read {DHA_ROOT}/memory.events after the breach: {events}"
        )));
    }
    let oom_kills = parse_events_counter(&events, "oom_kill");
    if oom_kills == 0 {
        return Err(DryrunError::DhaCheckFailed(format!(
            "F2: no oom_kill recorded on {DHA_ROOT} — the breach did not trip the scoped Σ OOM: {events}"
        )));
    }
    Ok(())
}

/// F3 — the dha uid (owning the delegated `work/`) cannot create more than the root-owned
/// `cgroup.max.descendants` sub-cgroups: the mkdir loop hits the backstop (EAGAIN) well before running away.
fn assert_descendants_backstop(privkey: &Path, port: u16) -> Result<(), DryrunError> {
                                                                                                     
                                                                                                        
    let probe = format!(
        "s6-setuidgid {ENGINE_SERVICE_UID} sh -c '\
           i=0; while [ $i -lt 100 ] && mkdir {DHA_ROOT}/work/desc$i 2>/dev/null; do i=$((i+1)); done; \
           echo COUNT=$i'; \
         i=0; while [ $i -lt 100 ]; do rmdir {DHA_ROOT}/work/desc$i 2>/dev/null; i=$((i+1)); done; \
         echo CLEANED"
    );
    let (ok, out) = ssh_capture(privkey, port, &probe)?;
    if !ok {
        return Err(DryrunError::DhaCheckFailed(format!(
            "F3: the descendants probe did not run: {out}"
        )));
    }
    let count = out
        .lines()
        .find_map(|l| l.strip_prefix("COUNT="))
        .and_then(|n| n.trim().parse::<u32>().ok())
        .ok_or_else(|| {
            DryrunError::DhaCheckFailed(format!("F3: no COUNT= in the probe output: {out}"))
        })?;
                                                                                                     
                                                                                                         
                    
    if count >= 100 || count > 16 {
        return Err(DryrunError::DhaCheckFailed(format!(
            "F3: the dha uid created {count} work/<id> cgroups — the cgroup.max.descendants=16 backstop did not hold"
        )));
    }
    Ok(())
}

/// F4 — a RestartCap'd longrun killed ≥ max_restarts times within the window goes permanently DOWN via
/// `s6-permafailon` (`exit 125`), NOT an infinite restart. Kill the orchestrator stand-in 4×/≈12s
/// (cap = 3 / 30s) and assert s6-supervise stops wanting it up. (F4 is LAST — it takes the orchestrator
/// down; F2 already asserted it survives the breach.)
fn assert_restart_cap(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    assert_service_up(privkey, port, ORCH_SERVICE)?;                                 
    let kill = format!(
        "for n in 1 2 3 4; do s6-svc -k /run/service/{ORCH_SERVICE}; sleep 3; done; echo KILLED"
    );
    let (_ok, out) = ssh_capture(privkey, port, &kill)?;
    if !out.contains("KILLED") {
        return Err(DryrunError::DhaCheckFailed(format!(
            "F4: the kill loop did not complete: {out}"
        )));
    }
    sleep(Duration::from_secs(3));                                        
    let (_svok, svstat) = ssh_capture(
        privkey,
        port,
        &format!("s6-svstat /run/service/{ORCH_SERVICE}"),
    )?;
                                                                                                 
                                                                                             
    if svstat.trim_start().starts_with("up (pid") {
        return Err(DryrunError::DhaCheckFailed(format!(
            "F4: {ORCH_SERVICE} is still up after ≥cap kills — s6-permafailon did not cap it: {svstat}"
        )));
    }
    if !svstat.contains("down") {
        return Err(DryrunError::DhaCheckFailed(format!(
            "F4: {ORCH_SERVICE} is neither up nor cleanly down after the restart storm: {svstat}"
        )));
    }
    Ok(())
}

                                                                                                                        

                                                                                                        
                                                                                                       
/// OwnerException → baked 0600 dha:dha → the dropped orchestrator reads them). A root-owned `0600` would
/// EACCES the dropped reader; a `0644` workaround dha's loader refuses (`mode & 0o077 != 0`).
fn assert_dha_configs_owner(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    for cfg in ["/etc/dha/box.json", "/etc/dha/runtime.json"] {
        let (ok, out) = ssh_capture(privkey, port, &format!("stat -c '%U %a' {cfg} 2>&1"))?;
        let t = out.trim();
        if !ok || t != "dha 600" {
            return Err(DryrunError::DhaCheckFailed(format!(
                "per-uid leg 4: {cfg} is not `dha 600` (the baked dha-owned 0600 config): stat → {t:?}"
            )));
        }
    }
    Ok(())
}

/// Per-uid leg 2 — on a CLEAN `.img` the RO dm-verity weights volume is mounted at `/models` and
/// `/models/model.gguf` is READABLE by the dha uid (the complement of F5's tampered-EIO leg). Proves the
/// weights bake + the RO mount + the dha uid reaching its model under the `Ownership::Map` bake.
fn assert_weights_readable(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let (ok, out) = ssh_capture(
        privkey,
        port,
        &format!(
            "s6-setuidgid {ENGINE_SERVICE_UID} dd if=/models/model.gguf of=/dev/null bs=1M 2>&1; echo RC=$?"
        ),
    )?;
    if !ok || !rc_zero(&out) || out.to_lowercase().contains("i/o error") {
        return Err(DryrunError::DhaCheckFailed(format!(
            "per-uid leg 2: the dha uid could not cleanly read /models/model.gguf (weights RO mount / Map ownership): {out}"
        )));
    }
    Ok(())
}

/// The intake-probe leg (§2 / H2 Option-A) — run dha's staged `intake-probe.sh` over SSH: it frames a
/// request to `/run/dha/orchestrator.sock` + asserts the expected `rejected/bad_request` reply. A reply
/// TRANSITIVELY proves the H2/Option-A config read: the orchestrator cannot bind + serve the socket
/// without loading BOTH `dha`-owned `0600` configs AS the dropped uid. GATES on dha's published
/// `dha-orchestrator` + the staged probe ([`DHA_INTAKE_PROBE`], a dha deliverable) — green once dha ships.
fn assert_intake_probe(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let (ok, out) = ssh_capture(
        privkey,
        port,
        &format!("sh {DHA_INTAKE_PROBE} 2>&1; echo RC=$?"),
    )?;
    if !ok || !rc_zero(&out) {
        return Err(DryrunError::DhaCheckFailed(format!(
            "intake-probe (§2/H2): dha's intake-probe.sh did not complete the framed round-trip on \
             /run/dha/orchestrator.sock (did the orchestrator load both dha-owned configs?): {out}"
        )));
    }
    Ok(())
}

/// The AC-I1..I11 leg — run dha's `cgroup-k4-selftest.sh`-derived acceptance suite over SSH (the
/// S-INTAKE-WIRE §7 end-to-end matrix, [`DHA_AC_I_HARNESS`]). GATES on dha's published bins + staged
/// harness — green once dha ships.
fn assert_ac_i_harness(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let (ok, out) = ssh_capture(
        privkey,
        port,
        &format!("sh {DHA_AC_I_HARNESS} 2>&1; echo RC=$?"),
    )?;
    if !ok || !rc_zero(&out) {
        return Err(DryrunError::DhaCheckFailed(format!(
            "AC-I1..I11: dha's acceptance harness did not pass end-to-end: {out}"
        )));
    }
    Ok(())
}

/// The real-job leg (§4.6, audit R1-MED guard) — run dha's staged real-job probe, which submits an
/// ACCEPTED job (unlike the intake probe's REJECTED round-trip, which returns before dispatching a
/// client). This exercises the FULL client path: the orchestrator dispatches the pinned `epa` client with
/// its `runtime.json` `client.config` (`/opt/dha/epa.json`), so a dangling/missing client config surfaces
/// HERE instead of passing the gate. GATES on dha's published bins + the staged probe + epa's config
/// ([`DHA_REAL_JOB_PROBE`]) — green once dha ships.
fn assert_real_job(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let (ok, out) = ssh_capture(
        privkey,
        port,
        &format!("sh {DHA_REAL_JOB_PROBE} 2>&1; echo RC=$?"),
    )?;
    if !ok || !rc_zero(&out) {
        return Err(DryrunError::DhaCheckFailed(format!(
            "real-job (§4.6): dha's real-job probe did not run an accepted job end-to-end (is client.config \
             /opt/dha/epa.json staged + reachable?): {out}"
        )));
    }
    Ok(())
}

                                                                                                                                                                                                                                                        

/// Run a remote command over the operator-key SSH; return `(exit-succeeded, stdout⧺stderr)`. The remote
/// shell (dropbear) runs `cmd`, so this carries full shell logic (the harness's, not the tenant's argv).
pub(super) fn ssh_capture(
    privkey: &Path,
    port: u16,
    cmd: &str,
) -> Result<(bool, String), DryrunError> {
    let out = Command::new("ssh")
        .args(ssh_base_args(privkey, port))
        .arg(cmd)
        .output()
        .map_err(|e| DryrunError::DhaCheckFailed(format!("ssh spawn failed: {e}")))?;
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !stderr.trim().is_empty() {
        combined.push_str(&stderr);
    }
    Ok((out.status.success(), combined))
}

/// True iff the LAST line of `out` is exactly `RC=0` (the appended `echo RC=$?` sentinel) — an EXACT
/// trailing-token check, not a `contains`, so a script that prints `RC=0` in its own body then exits
/// non-zero cannot false-pass (audit R1-Info).
pub(super) fn rc_zero(out: &str) -> bool {
    out.lines().last().map(str::trim) == Some("RC=0")
}

/// Assert a named longrun is supervised + up (`s6-svstat … up (pid …)`), used as a survival check.
pub(super) fn assert_service_up(
    privkey: &Path,
    port: u16,
    service: &str,
) -> Result<(), DryrunError> {
    let (_ok, out) = ssh_capture(privkey, port, &format!("s6-svstat /run/service/{service}"))?;
    if !out.trim_start().starts_with("up (pid") {
        return Err(DryrunError::DhaCheckFailed(format!(
            "expected {service} supervised-up; s6-svstat: {out}"
        )));
    }
    Ok(())
}

/// Parse a cgroup `memory.events` (`key value\n` lines) counter, defaulting to 0 if absent/garbled.
fn parse_events_counter(events: &str, key: &str) -> u64 {
    events
        .lines()
        .find_map(|l| {
            let mut it = l.split_whitespace();
            (it.next() == Some(key)).then(|| it.next().and_then(|v| v.parse::<u64>().ok()))
        })
        .flatten()
        .unwrap_or(0)
}

/// The console log path — honoring `RECIPES_DHA_GATE_LOGDIR` (full-console survival past the tempdir
/// auto-clean, for diagnosing a boot failure), else the workdir.
fn dha_log_path(wd: &Path, name: &str) -> PathBuf {
    match std::env::var_os("RECIPES_DHA_GATE_LOGDIR") {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            let _ = std::fs::create_dir_all(&dir);
            dir.join(name)
        }
        None => wd.join(name),
    }
}
