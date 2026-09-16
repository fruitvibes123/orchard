//! Persist trust-file self-heal boot-gate (plan Task 5) — the produced-bytes proof of the PT-03 /
                                              
//!
//! Each leg stages a virgin from-pins reference box (its boot oneshots mint the trust files onto the
//! staged `/persist`), corrupts a trust file over root SSH and reads it back to confirm the corruption
//! landed at that path, then re-boots from the SAME persist disk and asserts the heal on the next
//! boot. The re-boot is `drop(guard)` (SIGKILL of QEMU) then a second `launch_qemu` on the same disk;
                                                                                                  
//! no-flush unclean-stop shape. Each `launch_qemu` re-runs initramfs → box-init → the boot oneshots.
//!
                                       
//! - Arm 1 truncates `full.pem` to non-cert bytes; the served `:443` leaf on the next boot must differ
//!   from boot 1's. `generate_selfsigned_pem` (`fb-oneshots/src/selfsign.rs`) mints a fresh key per
//!   call, so a regeneration always changes the leaf and a tear that landed nowhere never does.
//! - Arm 2 leaves `full.pem` a valid cert but overwrites its `full.pem.sha256` provenance marker with
//!   a non-matching hash; the served leaf changing again proves the v2 marker predicate
//!   (`full_pem_valid`) treats a valid-cert-wrong-marker as missing. A parse-only predicate — the
//!   shape the v2 closure replaced — would leave the valid cert and serve the unchanged leaf.
//!
                                                                                        
//! `device_certs == 0` (virgin box). The `bootstrap-ca` oneshot (`recipes-admin`) re-derives `ca.crt`
//! from `ca.key`; the same key yields the same deterministic canonical cert, so the boot-2 `ca.crt`
//! fingerprint equals boot 1's, and the box reaches services (the operator key authenticates, not the
//! rescue recovery key). `device_certs == 0` selects the re-derive arm. Leg D tears only `ca.crt`, so
//! `full.pem` is left: its served `:443` leaf must be unchanged across the reboot — the no-op/leave
//! arm that completes Leg C's regenerate arms (a never-admit `full_pem_valid` would fail it).
//!
                                                                                                      
//! the `device_certs > 0` fail-safe → rescue); Leg D's "a pairing succeeds" arm (no mTLS client-cert
                                                                                      
//!
//! `#[ignore]`-gated in `tests/deploy_persist_selfheal.rs`; run via `make boot-gate-persist`.

use std::path::Path;

use super::acme_lifecycle::{
    cert_fingerprint, discover_domain, require_openssl, served_leaf_fp, ssh_capture,
};
use super::assertions::{assert_recipes_http, sync_persist_over_ssh};
use super::qemu::*;
use super::*;

/// Re-type a reused helper's error as this gate's, so a persist-gate failure does not surface as a
/// donor variant (`AcmeLifecycle` or an SSH helper's).
fn wrap(e: DryrunError) -> DryrunError {
    DryrunError::PersistSelfheal(e.to_string())
}

/// The recipes CA cert path. The tear and the fingerprint read use this one literal so they cannot
                      
const CA_CRT: &str = "/persist/recipes/ca.crt";

/// Values shared by both legs: the boot inputs (kernel/initramfs/rootfs slice + recomputed verity
/// root hash), the workdir, the ephemeral operator key, and the (hermetic) opts.
struct GateCtx<'a> {
    vmlinuz: &'a Path,
    initramfs: &'a Path,
    rootfs: &'a Path,
    root_hash: &'a str,
    verity_hash_offset: u64,
    wd: &'a Path,
    privkey: &'a Path,
    pubkey: &'a Path,
    opts: &'a DryrunOpts,
}

                                                                                                 
/// `fb-acme-renew`, so restrict outbound to keep every run off production Let's Encrypt. `keep_running`
/// is forced off — the reboot mechanism needs `QemuGuard::drop` to kill each boot.
pub fn boot_persist_selfheal_and_verify(img: &Path, opts: &DryrunOpts) -> Result<(), DryrunError> {
    preflight()?;
    require_openssl().map_err(wrap)?;

    let hermetic = DryrunOpts {
        restrict_net: true,
        keep_running: false,
        ..opts.clone()
    };
    let opts = &hermetic;

    let layout = parse_layout(&layout_sidecar(img))?;
    let workdir = tempfile::Builder::new()
        .prefix("recipes-persist-gate-")
        .tempdir()
        .map_err(DryrunError::io("creating persist-gate workdir"))?;
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

    let ctx = GateCtx {
        vmlinuz: &vmlinuz,
        initramfs: &initramfs,
        rootfs: &rootfs,
        root_hash: &root_hash,
        verity_hash_offset: layout.rootfs_verity_hash_offset,
        wd,
        privkey: &privkey,
        pubkey: &pubkey,
        opts,
    };

    verify_leg_c_full_pem(&ctx)?;
    verify_leg_d_ca_crt(&ctx)?;
    Ok(())
}

/// Stage a virgin persist disk carrying only the operator pubkey, boot, and wait for the operator SSH.
/// A success means the box reached SERVICES (the operator key authenticates dropbear; rescue runs the
/// recovery key instead), so this doubles as the not-rescue assertion.
fn boot_virgin(ctx: &GateCtx, persist: &Path, console: &Path) -> Result<QemuGuard, DryrunError> {
    stage_persist_disk(ctx.pubkey, ctx.wd, persist)?;
    boot_from(ctx, persist, console)
}

/// Boot `persist` (already staged) and wait for the operator SSH. Used for each reboot, which re-reads
/// the corrupted trust file the previous boot's disk carries.
fn boot_from(ctx: &GateCtx, persist: &Path, console: &Path) -> Result<QemuGuard, DryrunError> {
    let mut guard = launch_qemu(
        ctx.vmlinuz,
        ctx.initramfs,
        ctx.rootfs,
        persist,
        ctx.root_hash,
        ctx.verity_hash_offset,
        ctx.opts,
        console,
    )?;
    wait_for_ssh(
        ctx.privkey,
        ctx.opts.ssh_port,
        ctx.opts.boot_timeout,
        &mut guard,
        console,
    )?;
    Ok(guard)
}

/// Overwrite a `/persist` file with `payload` over root SSH, read it back to confirm the write landed
/// at that path, then flush. `printf %s` keeps the payload literal; `>` truncates in place, preserving
/// owner and mode, so the heal predicate reads a regular in-mode file — the treat-as-missing arm, not
/// a mode/inode fail-safe.
fn corrupt_and_verify(
    ctx: &GateCtx,
    remote_path: &str,
    payload: &str,
    what: &str,
) -> Result<(), DryrunError> {
    let port = ctx.opts.ssh_port;
    let (ok, out) = ssh_capture(
        ctx.privkey,
        port,
        &format!("printf %s '{payload}' > {remote_path}"),
    )
    .map_err(wrap)?;
    if !ok {
        return Err(DryrunError::PersistSelfheal(format!(
            "{what}: writing {remote_path} failed: {out}"
        )));
    }
    let (ok, back) = ssh_capture(ctx.privkey, port, &format!("cat {remote_path}")).map_err(wrap)?;
    if !ok || back != payload {
        return Err(DryrunError::PersistSelfheal(format!(
            "{what}: corruption did not land at {remote_path} (read back {back:?}, wanted {payload:?})"
        )));
    }
    sync_persist_over_ssh(ctx.privkey, port).map_err(wrap)
}

/// Leg C: a torn `full.pem` (arm 1) and a valid cert with a wrong provenance marker (arm 2) both
/// regenerate, changing the served `:443` leaf on the next boot.
fn verify_leg_c_full_pem(ctx: &GateCtx) -> Result<(), DryrunError> {
    let persist = ctx.wd.join("persist-legc.img");
    let mut guard = boot_virgin(ctx, &persist, &ctx.wd.join("legc-boot1.log"))?;
    assert_recipes_http(ctx.opts, &mut guard).map_err(wrap)?;
    let domain = discover_domain(ctx.privkey, ctx.opts.ssh_port).map_err(wrap)?;
    let full = format!("/persist/acme/{domain}/full.pem");
    let marker = format!("{full}.sha256");
    let fp1 = served_leaf_fp(ctx.opts.https_port, &domain).map_err(wrap)?;

    corrupt_and_verify(ctx, &full, "torn", "Leg C arm 1 (torn full.pem)")?;
    drop(guard);
    let mut g2 = boot_from(ctx, &persist, &ctx.wd.join("legc-boot2.log"))?;
    assert_recipes_http(ctx.opts, &mut g2).map_err(wrap)?;
    let fp2 = served_leaf_fp(ctx.opts.https_port, &domain).map_err(wrap)?;
    if fp2 == fp1 {
        return Err(DryrunError::PersistSelfheal(format!(
            "Leg C arm 1: the served leaf did not change after the torn-full.pem reboot (still {fp1}) \
             — bootstrap-acme-cert did not regenerate"
        )));
    }

    corrupt_and_verify(ctx, &marker, &"0".repeat(64), "Leg C arm 2 (wrong marker)")?;
    drop(g2);
    let mut g3 = boot_from(ctx, &persist, &ctx.wd.join("legc-boot3.log"))?;
    assert_recipes_http(ctx.opts, &mut g3).map_err(wrap)?;
    let fp3 = served_leaf_fp(ctx.opts.https_port, &domain).map_err(wrap)?;
    if fp3 == fp2 {
        return Err(DryrunError::PersistSelfheal(format!(
            "Leg C arm 2: the served leaf did not change after the wrong-marker reboot (still {fp2}) \
             — full_pem_valid did not treat a valid-cert-wrong-marker as missing (a parse-only \
             predicate would leave it)"
        )));
    }
    drop(g3);
    Ok(())
}

/// Leg D: a torn `ca.crt` with a valid `ca.key` and no devices re-derives to the same identity, and
/// the box reaches services.
fn verify_leg_d_ca_crt(ctx: &GateCtx) -> Result<(), DryrunError> {
    let persist = ctx.wd.join("persist-legd.img");
    let mut guard = boot_virgin(ctx, &persist, &ctx.wd.join("legd-boot1.log"))?;
    assert_recipes_http(ctx.opts, &mut guard).map_err(wrap)?;
    let domain = discover_domain(ctx.privkey, ctx.opts.ssh_port).map_err(wrap)?;
    let leaf1 = served_leaf_fp(ctx.opts.https_port, &domain).map_err(wrap)?;
    let fp1 = ca_crt_fingerprint(ctx, "Leg D boot 1")?;

    corrupt_and_verify(ctx, CA_CRT, "torn", "Leg D (torn ca.crt)")?;
    drop(guard);

    let mut g2 = boot_from(ctx, &persist, &ctx.wd.join("legd-boot2.log"))?;
    assert_recipes_http(ctx.opts, &mut g2).map_err(wrap)?;
                                                                                                     
                                                                                            
    let leaf2 = served_leaf_fp(ctx.opts.https_port, &domain).map_err(wrap)?;
    if leaf2 != leaf1 {
        return Err(DryrunError::PersistSelfheal(format!(
            "Leg D: the served :443 leaf changed ({leaf1} -> {leaf2}) after a boot that only tore \
             ca.crt — full_pem_valid did not leave a valid full.pem (a never-admit predicate)"
        )));
    }
    let fp2 = ca_crt_fingerprint(ctx, "Leg D boot 2")?;
    if fp2 != fp1 {
        return Err(DryrunError::PersistSelfheal(format!(
            "Leg D: ca.crt did not re-derive to the original identity across the reboot \
             (boot1 {fp1}, boot2 {fp2})"
        )));
    }
    drop(g2);
    Ok(())
}

/// Fetch `/persist/recipes/ca.crt` over root SSH and return its SHA-256 fingerprint. A parse failure
/// (the torn file, or a re-derive that did not run) surfaces as the error.
fn ca_crt_fingerprint(ctx: &GateCtx, what: &str) -> Result<String, DryrunError> {
    let (ok, pem) =
        ssh_capture(ctx.privkey, ctx.opts.ssh_port, &format!("cat {CA_CRT}")).map_err(wrap)?;
    if !ok {
        return Err(DryrunError::PersistSelfheal(format!(
            "{what}: could not read {CA_CRT}: {pem}"
        )));
    }
    let local = ctx.wd.join("ca-crt-fetch.pem");
    std::fs::write(&local, pem.as_bytes()).map_err(DryrunError::io("write fetched ca.crt"))?;
    cert_fingerprint(&local).map_err(|e| {
        DryrunError::PersistSelfheal(format!("{what}: ca.crt is not a parseable cert: {e}"))
    })
}
