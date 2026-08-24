                                                                                                       
//! BOOT is the operator-run `make boot-gate-dha`; see `orchard/tests/deploy_dha.rs`). Proves
//! `dha-tenant.toml` validates through the §4.1 gate (distinct placed leaves + cap-coherence +
//! OS-disjoint `delegate_uid`) and that the box RENDERS the fail-closed cgroup placement prologue + the
//! `s6-permafailon` finish for the two dha longruns from the manifest DECLARATIONS (the §7
//! renders-from-declarations seam). The stand-ins are busybox (the toy-tenant precedent); the real
//! creatine/dha-orchestrator end-to-end is a SEPARATE follow-on component, not this gate.

use fb_manifest::argv::ArgvToken;
use fb_manifest::manifest::ServiceShape;
use fb_manifest::PlaceholderCtx;
use recipes_image_builder::config;
use recipes_image_builder::service_tree;

const DHA: &str = include_str!("../dha-tenant.toml");

fn dha() -> fb_manifest::ValidatedManifest {
    fb_manifest::parse_and_validate(DHA, &config::os_identities())
        .expect("the dha stand-in manifest must validate through the §4.1 bake gate")
}

fn ctx() -> PlaceholderCtx {
    PlaceholderCtx {
        domain: "dha.test".into(),
        source_date_epoch: 0,
    }
}

/// Extract an `Exec` service's binary path (the dha longruns are all `Exec`).
fn exec_binary(shape: &ServiceShape) -> &str {
    match shape {
        ServiceShape::Exec { binary, .. } => binary,
        _ => panic!("expected an Exec service"),
    }
}

/// Extract an `Exec` service's argv as literal strings (the orchestrator's two config-path args).
fn exec_argv(shape: &ServiceShape) -> Vec<String> {
    let ServiceShape::Exec { argv, .. } = shape else {
        panic!("expected an Exec service");
    };
    argv.iter()
        .map(|t| match t {
            ArgvToken::Literal { value } => value.clone(),
            other => panic!("expected a literal argv token, got {other:?}"),
        })
        .collect()
}

/// Task 2 — the dha manifest declares the REAL creatine + dha-orchestrator bins (replacing the busybox
/// stand-ins), the orchestrator's two-config argv (`box.json` then `runtime.json`), the creatine inline
/// env, and both opt-in config blocks. The box renders the two config blocks to `dha`-owned 0600 JSON
/// (Task 4) and the creatine env before `exec` (Task 5); Task 2 pins the manifest DATA those consume.
#[test]
fn dha_manifest_declares_real_bins_and_configs() {
    let vm = dha();
    let m = vm.manifest();
    let creatine = m
        .services
        .iter()
        .find(|s| s.name == "creatine")
        .expect("creatine service present");
    let dha_orch = m
        .services
        .iter()
        .find(|s| s.name == "dha-orchestrator")
        .expect("dha-orchestrator service present");
    assert_eq!(exec_binary(&creatine.shape), "/usr/bin/creatine");
    assert_eq!(exec_binary(&dha_orch.shape), "/usr/bin/dha-orchestrator");
                                                                                          
    assert_eq!(
        exec_argv(&dha_orch.shape),
        vec![
            "/etc/dha/box.json".to_string(),
            "/etc/dha/runtime.json".to_string(),
        ]
    );
                                                                                         
    assert!(m.box_config.is_some(), "box_config declared");
    assert!(m.runtime_config.is_some(), "runtime_config declared");
                                                                                            
    let ServiceShape::Exec { env, .. } = &creatine.shape else {
        panic!("creatine is an Exec");
    };
    let env = env.as_ref().expect("creatine declares inline env");
    assert!(
        env.iter().any(|kv| kv.key == "CREATINE_BIND"),
        "creatine env carries CREATINE_BIND"
    );
                                              
    assert_eq!(
        m.runtime_config.as_ref().unwrap().client.program,
        "/usr/bin/epa"
    );
}

#[test]
fn the_dha_manifest_validates_and_carries_the_boot_gate_sized_resource_domain() {
    let m = dha();
    let rd = m
        .manifest()
        .resource_domain
        .as_ref()
        .expect("a dha box carries a resource_domain");
    assert_eq!(rd.name, "dha");
    assert_eq!(rd.delegate_uid.0, 110);
    let engine = rd.engine.as_ref().expect("uds mode → an engine leaf");
    assert_eq!(engine.service, "creatine");
    assert_eq!(rd.work.orchestrator, "dha-orchestrator");
                                                                                                         
                                                                                                    
    assert!(
        engine.memory_max.0 < rd.memory_max.0,
        "engine cap must bite before Σ (per-leaf localization)"
    );
    assert!(
        rd.work.job_memory_max.0 > 0 && rd.work.job_memory_max.0 <= rd.memory_max.0,
        "job cap ∈ (0, Σ]"
    );
    assert!(
        rd.work.work_pids_max > 0,
        "aggregate fork-bomb backstop set"
    );
    assert!(
        rd.work.job_pids_max.expect("job_pids_max set") <= rd.work.work_pids_max,
        "job_pids ≤ work_pids"
    );
    assert!(
        engine.oom_group,
        "creatine is oom.group=1 (killable as a whole unit — the ancestor-Σ victim)"
    );
}

#[test]
fn the_box_renders_placement_and_finish_for_both_dha_longruns() {
    let m = dha();
    let dirs = service_tree::servicedirs(
        &m.manifest().services,
        m.manifest().resource_domain.as_ref(),
        &ctx(),
        &m.manifest().probe,
        service_tree::EngineWeightsSetup::None,
    );
    let creatine = dirs
        .iter()
        .find(|d| d.name == "creatine")
        .expect("the creatine longrun is supervised");
    let orch = dirs
        .iter()
        .find(|d| d.name == "dha-orchestrator")
        .expect("the dha-orchestrator longrun is supervised");
                                                                                                           
                                                                                                     
    assert!(
        creatine
            .run
            .contains("/sys/fs/cgroup/dha/creatine/cgroup.procs"),
        "creatine places into dha/creatine: {}",
        creatine.run
    );
    assert!(
        orch.run
            .contains("/sys/fs/cgroup/dha/work/orch/cgroup.procs"),
        "orchestrator places into dha/work/orch: {}",
        orch.run
    );
    assert!(
        creatine.run.contains("s6-setuidgid 'dha'"),
        "drops to the dha delegate uid: {}",
        creatine.run
    );
    assert!(
        creatine.run.contains("/usr/bin/creatine"),
        "runs the declared real creatine binary: {}",
        creatine.run
    );
                                                                                         
    assert!(
        creatine
            .finish
            .as_deref()
            .unwrap_or_default()
            .contains("s6-permafailon"),
        "creatine carries the s6-permafailon finish: {:?}",
        creatine.finish
    );
    assert!(
        orch.finish
            .as_deref()
            .unwrap_or_default()
            .contains("s6-permafailon"),
        "orchestrator carries the s6-permafailon finish: {:?}",
        orch.finish
    );
}

/// Task 5 (§4.5) — creatine's inline env is rendered as `export KEY='VAL'` lines (the value
/// single-quoted — env values are NUL/newline-free but NOT charset-restricted, so a space/metachar must
/// not break the word) AFTER the cgroup placement prologue and BEFORE the `s6-setuidgid` drop (which
                                                                                                      
/// the M0 stub).
#[test]
fn creatine_run_script_exports_env_before_exec() {
    let m = dha();
    let dirs = service_tree::servicedirs(
        &m.manifest().services,
        m.manifest().resource_domain.as_ref(),
        &ctx(),
        &m.manifest().probe,
        service_tree::EngineWeightsSetup::None,
    );
    let run = &dirs.iter().find(|d| d.name == "creatine").unwrap().run;
    assert!(
        run.contains("export CREATINE_BIND='unix:/run/creatine/creatine.sock'"),
        "{run}"
    );
    assert!(
        run.contains("export CREATINE_MODEL_PATH='/models/model.gguf'"),
        "{run}"
    );
    assert!(
        run.contains("export CREATINE_MODEL='qwen2.5-coder-3b'"),
        "{run}"
    );
                                 
    let env_pos = run.find("CREATINE_BIND").expect("env present");
    let exec_pos = run
        .find("exec s6-setuidgid 'dha'")
        .expect("exec drop present");
    assert!(env_pos < exec_pos, "env must precede the exec drop:\n{run}");
                            
    assert!(!run.contains("--uds") && !run.contains("--model"), "{run}");
}

/// Task 5 — the orchestrator renders its TWO positional config-path args (each single-quoted, the
                                                                                                      
/// (no `export` lines).
#[test]
fn dha_orchestrator_run_script_passes_two_config_argv() {
    let m = dha();
    let dirs = service_tree::servicedirs(
        &m.manifest().services,
        m.manifest().resource_domain.as_ref(),
        &ctx(),
        &m.manifest().probe,
        service_tree::EngineWeightsSetup::None,
    );
    let run = &dirs
        .iter()
        .find(|d| d.name == "dha-orchestrator")
        .unwrap()
        .run;
    assert!(
        run.contains(
            "exec s6-setuidgid 'dha' '/usr/bin/dha-orchestrator' '/etc/dha/box.json' '/etc/dha/runtime.json'"
        ),
        "{run}"
    );
    assert!(
        !run.contains("export "),
        "orchestrator declares no env:\n{run}"
    );
}
