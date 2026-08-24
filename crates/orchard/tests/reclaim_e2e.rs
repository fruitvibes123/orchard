//! D-2 reclaim-tail — the produced-bytes gate (spec `2026-07-28-reclaim-tail-design.md` §9).
//!
//! These legs run the REAL ceremony against a DEFAULT-PROVISIONED Debian guest: the grown fixture
//! (`make e2e-grown-fixture`) whose root was grown to fill its disk by the class's own machinery,
//! with `cloud-initramfs-growroot` retained and its fstab still carrying `x-systemd.growfs` on the
                                                                                              
                                                                                               
//! reclaim means anything.
//!
//! `#[ignore]` + panics without its env, like every other operator-run leg in this crate; run via
//! `make boot-gate-reclaim`, which guards on an exact pass count so a silently-skipped leg cannot
//! report a green.
//!
//! Env (all required):
//!   RECIPES_RECLAIM_IMG            — the box `.img` to install (Bake B, the prod co-tenant).
//!   RECIPES_RECLAIM_PRIVKEY        — the matching operator private key (its `.pub` is the baked key).
//!   RECIPES_RECLAIM_E2E_DEBIAN_IMG — the GROWN fixture (never the stock base, never the hermetic
//!                                    kexec fixture: both have an ungrown root, which makes every
//!                                    leg here vacuous by short-circuiting at D-1).
//! Optional: RECIPES_PROD_E2E_LOGDIR — a dir the console logs survive into (else a tempdir).

use orchard::deploy::prod_e2e::{
    DebianE2eOpts, PROD_INSTALL_RAM_MIB, run_debian_kexec_takeover_e2e,
    run_reclaim_no_flag_untouched_e2e,
};
use std::path::PathBuf;
use std::time::Duration;

fn env_or_panic(key: &str) -> PathBuf {
    let raw = std::env::var(key).unwrap_or_else(|_| {
        panic!(
            "{key} is not set — the reclaim gate needs RECIPES_RECLAIM_IMG + \
             RECIPES_RECLAIM_PRIVKEY + RECIPES_RECLAIM_E2E_DEBIAN_IMG (the GROWN fixture from \
             `make e2e-grown-fixture`). Run via `make boot-gate-reclaim`."
        )
    });
    PathBuf::from(raw)
}

/// The three inputs plus a log dir. Panics (never skips) under `--ignored`.
fn reclaim_env() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let box_img = env_or_panic("RECIPES_RECLAIM_IMG");
    let privkey = env_or_panic("RECIPES_RECLAIM_PRIVKEY");
    let debian = env_or_panic("RECIPES_RECLAIM_E2E_DEBIAN_IMG");
    for p in [&box_img, &privkey, &debian] {
        assert!(p.exists(), "input does not exist: {}", p.display());
    }
    let log_dir = match std::env::var("RECIPES_PROD_E2E_LOGDIR") {
        Ok(d) => {
            let d = PathBuf::from(d);
            std::fs::create_dir_all(&d).expect("create the log dir");
            d
        }
        Err(_) => std::env::temp_dir(),
    };
    (box_img, privkey, debian, log_dir)
}

/// Shared shape for both legs: the GROWN fixture, hermetic, at the production RAM figure, with
/// **`guest_disk_bytes: None`** — the fixture is already 12 GiB and already grown, and re-sizing
/// it here would either fail or hand the leg a target whose root does not reach the disk end,
/// which is the one state that makes these legs vacuous.
fn grown_opts(forward_port: u16) -> DebianE2eOpts {
    DebianE2eOpts {
        forward_port,
        memory_mb: PROD_INSTALL_RAM_MIB,
        guest_boot_timeout: Duration::from_secs(600),
        reconnect_timeout_secs: 900,
        restrict_net: true,
        guest_disk_bytes: None,
                                                                                              
                                                                                
        grown_user_data: true,
        ..DebianE2eOpts::default()
    }
}

/// **RT-1 / AC-R1** — the centerpiece. `orchard prod --reclaim-tail` against the grown target,
                                                                                                   
/// arming scan is demoted, so there is no pre-flight scan to false-refuse it), D-1 records
/// rather than aborts, the wipe gate runs unchanged, the reclaim shrinks the filesystem and its
/// partition across one reboot, D-1 passes on the re-read extents, the image streams onto the
/// now-unpartitioned window, and the box boots and serves.
#[test]
#[ignore = "boot gate: needs RECIPES_RECLAIM_IMG + RECIPES_RECLAIM_PRIVKEY + RECIPES_RECLAIM_E2E_DEBIAN_IMG (the GROWN fixture) + /dev/kvm; run via `make boot-gate-reclaim`"]
fn rt1_reclaim_tail_installs_the_box_on_a_default_provisioned_target() {
    let (box_img, privkey, debian, log_dir) = reclaim_env();
    run_debian_kexec_takeover_e2e(
        &box_img,
        &privkey,
        &debian,
        &DebianE2eOpts {
            reclaim_tail: true,
            ..grown_opts(2232)
        },
        &log_dir,
        Some("seabios-gpt"),
    )
    .expect(
        "RT-1: `orchard prod --reclaim-tail` must reclaim the grown root and install the box \
         (AC-R1)",
    );
}

/// **RT-2 / AC-R2** — the untouched-disk boundary on produced bytes. The same grown target with
                                                                                              
/// the partition table is byte-identical across the refusal — the first 34 and last 33 sectors
                                                                                     
#[test]
#[ignore = "boot gate: needs RECIPES_RECLAIM_IMG + RECIPES_RECLAIM_PRIVKEY + RECIPES_RECLAIM_E2E_DEBIAN_IMG (the GROWN fixture) + /dev/kvm; run via `make boot-gate-reclaim`"]
fn rt2_no_flag_refuses_and_leaves_the_partition_table_untouched() {
    let (box_img, privkey, debian, log_dir) = reclaim_env();
    run_reclaim_no_flag_untouched_e2e(&box_img, &privkey, &debian, &grown_opts(2234), &log_dir)
        .expect("RT-2: the unflagged ceremony must refuse and touch nothing (AC-R2)");
}
