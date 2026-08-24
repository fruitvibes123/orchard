//! The dha orchestrator's two `dha`-owned `0600` configs — `box.json` (the Phase-1 confinement gate,
//! dha `startup::Config`) + `runtime.json` (the deploy config, dha `orchestrator::runtime::
                                                                                                     
//!
//! The `dha-orchestrator` bin reads BOTH as the dropped `dha` uid (`argv = box.json runtime.json`,
//! both `mode & 0o077 == 0`-enforced). So the box bakes them `dha`-owned `0600` via the per-uid
//! [`OwnerException`] seam (`build.rs` step 8 → the mksquashfs `m` pseudo-line + the EVM `h_misc`):
//! a root-owned `0600` config would EACCES the dropped reader, and a `0644` workaround is refused by
//! dha's loader. The two mirror structs below match dha's `deny_unknown_fields` deserializers
//! FIELD-FOR-FIELD — a drift is caught by the host key-set test here + dha's own loader at the
//! boot-gate (Task 7). `parent_cgroup` + `budget` are DERIVED from the [`ResourceDomain`] (single-
//! sourced: the delegated cgroup + the per-job budget cannot diverge from the resource domain).
//!
//! **Mirror-drift note (audit R1-Info I-R2-2):** the structs below track dha's `orchestrator::runtime::
//! OrchestratorRuntime` (`~/Projects/dha/src/orchestrator/runtime.rs`) + `startup::Config`
//! (`~/Projects/dha/src/lib.rs`), verified field-for-field as of 2026-07-08. A box-side add/typo is
//! caught by the host key-set test (`per_uid_baking.rs`); a DHA-side field RENAME drifts SILENTLY until
//! dha's own `deny_unknown_fields` loader rejects it at the boot-gate — re-verify these mirrors whenever
//! the pinned dha bins bump.

use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;

use fb_manifest::manifest::{ClientKind, CreatineMode};
use fb_manifest::ValidatedManifest;

use crate::ownership::OwnerException;

/// `box.json` — mirrors dha `startup::Config` (all fields optional/defaulted there; we emit the
/// operator-declared set). `scratch`/`logdir`/`in_process` skip-if-absent.
#[derive(Serialize)]
struct BoxJson<'a> {
    sensitive: bool,
    tier_b: bool,
    root: &'a str,
    secrets: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scratch: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logdir: Option<&'a str>,
    git: bool,
    creatine_mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    in_process: Option<InProcessJson>,
}

/// `box.json.in_process` — mirrors dha `startup::InProcessAck`.
#[derive(Serialize)]
struct InProcessJson {
    combined_unit_cgroup: bool,
    input_parse_hardening: bool,
}

/// `runtime.json` — mirrors dha `orchestrator::runtime::OrchestratorRuntime`. `socket_path` /
/// `client_oom_score_adj` skip-if-absent (dha defaults them).
#[derive(Serialize)]
struct RuntimeJson<'a> {
    parent_cgroup: String,
    max_jobs: u32,
    max_conns: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    socket_path: Option<&'a str>,
    client: ClientJson<'a>,
    budget: BudgetJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_oom_score_adj: Option<i32>,
    creatine: CreatineJson<'a>,
}

/// `runtime.json.client` — mirrors dha `runtime::ClientSpec`.
#[derive(Serialize)]
struct ClientJson<'a> {
    kind: &'static str,
    program: &'a str,
    config: &'a str,
}

/// `runtime.json.budget` — mirrors dha `runtime::BudgetSpec` (DERIVED from `resource_domain.work`).
#[derive(Serialize)]
struct BudgetJson {
    memory_max_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pids_max: Option<u32>,
}

/// `runtime.json.creatine` — mirrors dha `runtime::CreatineProbeSpec`. `s6_svstat_bin` skip-if-absent.
#[derive(Serialize)]
struct CreatineJson<'a> {
    memory_events: &'a str,
    uds: &'a str,
    service_dir: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    s6_svstat_bin: Option<&'a str>,
}

/// dha `CreatineMode` serializes kebab-case (`in-process`/`uds`/`remote`).
fn creatine_mode_str(m: CreatineMode) -> &'static str {
    match m {
        CreatineMode::InProcess => "in-process",
        CreatineMode::Uds => "uds",
        CreatineMode::Remote => "remote",
    }
}

/// dha `ClientKind` serializes lowercase (`pecan`/`epa`).
fn client_kind_str(k: ClientKind) -> &'static str {
    match k {
        ClientKind::Pecan => "pecan",
        ClientKind::Epa => "epa",
    }
}

/// Render `etc/dha/box.json` + `etc/dha/runtime.json` into `staging` at `0600` and return one
/// [`OwnerException`] per file (uid=gid=`resource_domain.delegate_uid` — the uid the orchestrator drops
/// to; config-owner ≡ delegate_uid). Returns `Ok(vec![])` and creates NOTHING when the manifest has no
                                                                                                       
/// `resource_domain` fails closed (parent_cgroup/budget cannot be derived).
pub fn render_dha_configs(
    staging: &Path,
    manifest: &ValidatedManifest,
) -> io::Result<Vec<OwnerException>> {
    let m = manifest.manifest();
    let (Some(bc), Some(rc)) = (&m.box_config, &m.runtime_config) else {
        return Ok(Vec::new());                                                       
    };
                                                                                                    
    let rd = m.resource_domain.as_ref().ok_or_else(|| {
        io::Error::other(
            "box_config present but no resource_domain — cannot derive parent_cgroup/budget",
        )
    })?;
                                                                                                        
                                                                                                   
    let owner = rd.delegate_uid.0;

    let box_json = BoxJson {
        sensitive: bc.sensitive,
        tier_b: bc.tier_b,
        root: &bc.root,
        secrets: &bc.secrets,
        scratch: bc.scratch.as_deref(),
        logdir: bc.logdir.as_deref(),
        git: bc.git,
        creatine_mode: creatine_mode_str(bc.creatine_mode),
        in_process: bc.in_process.as_ref().map(|ip| InProcessJson {
            combined_unit_cgroup: ip.combined_unit_cgroup,
            input_parse_hardening: ip.input_parse_hardening,
        }),
    };
    let runtime_json = RuntimeJson {
        parent_cgroup: format!("/sys/fs/cgroup/{}/work", rd.name),
        max_jobs: rc.max_jobs,
        max_conns: rc.max_conns,
        socket_path: rc.socket_path.as_deref(),
        client: ClientJson {
            kind: client_kind_str(rc.client.kind),
            program: &rc.client.program,
            config: &rc.client.config,
        },
        budget: BudgetJson {
            memory_max_bytes: rd.work.job_memory_max.0,
            pids_max: rd.work.job_pids_max,
        },
        client_oom_score_adj: rc.client_oom_score_adj,
        creatine: CreatineJson {
            memory_events: &rc.creatine.memory_events,
            uds: &rc.creatine.uds,
            service_dir: &rc.creatine.service_dir,
            s6_svstat_bin: rc.creatine.s6_svstat_bin.as_deref(),
        },
    };

    let dir = staging.join("etc/dha");
    std::fs::create_dir_all(&dir)?;
    write_config_0600(&dir.join("box.json"), &box_json)?;
    write_config_0600(&dir.join("runtime.json"), &runtime_json)?;

    Ok(vec![
        OwnerException {
            rel_path: PathBuf::from("etc/dha/box.json"),
            uid: owner,
            gid: owner,
        },
        OwnerException {
            rel_path: PathBuf::from("etc/dha/runtime.json"),
            uid: owner,
            gid: owner,
        },
    ])
}

/// Serialize `value` as pretty JSON (+ trailing newline) and write it `0600` (`create_new` so a
/// double-render fails loud). The mode is forced to exactly `0600` after write — the [`OwnershipMap`]
                                                                                                    
fn write_config_0600<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    use std::io::Write;
    let mut bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(&bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
