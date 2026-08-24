                                                                                                       
//! boot is `make boot-gate-hotswap`; see `orchard/tests/deploy_model_gate.rs`). Pins the two
//! cross-artifact contracts a drift in which would otherwise only surface as a 120-second health
//! timeout deep inside the KVM gate:
//!
//!   1. `hotswap-tenant.toml` validates through the same §4.1 bake gate as every tenant manifest,
//!      and its engine service is the `resource_domain.engine` (the run-script that gets the
//!      `fb-weights setup` prelude).
//!   2. The swap's real-inference health probe (`models.toml` `[health]`) is COHERENT with the
//!      engine's baked env: the probed port is the port creatine's `CREATINE_BIND` binds, and the
//!      probe body's `"model"` id is the baked `CREATINE_MODEL` (creatine 404s an unknown route and
                                                                        

use recipes_image_builder::config;
use recipes_image_builder::models::Models;
use std::path::Path;

const HOTSWAP: &str = include_str!("../hotswap-tenant.toml");
                                                                                                      
/// stem here must stay the real one or this test would check a profile the bake never reads.
const HOTSWAP_MANIFEST: &str = "crates/image-builder/hotswap-tenant.toml";

fn hotswap() -> fb_manifest::ValidatedManifest {
    fb_manifest::parse_and_validate(HOTSWAP, &config::os_identities())
        .expect("the hotswap bench manifest must validate through the §4.1 bake gate")
}

/// The engine's inline env as (key, value) pairs.
fn engine_env(vm: &fb_manifest::ValidatedManifest) -> Vec<(String, String)> {
    let m = vm.manifest();
    let engine = m
        .resource_domain
        .as_ref()
        .and_then(|rd| rd.engine.as_ref())
        .expect("the bench manifest must declare a resource_domain engine (the swap's target)");
    let svc = m
        .services
        .iter()
        .find(|s| s.name == engine.service)
        .expect("the engine service must be a declared longrun");
    let fb_manifest::manifest::ServiceShape::Exec { env, .. } = &svc.shape else {
        panic!("the engine service must be an Exec longrun");
    };
    env.as_ref()
        .expect("the engine must carry its inline CREATINE_* env")
        .iter()
        .map(|kv| (kv.key.clone(), kv.value.clone()))
        .collect()
}

fn env_value<'a>(env: &'a [(String, String)], key: &str) -> &'a str {
    env.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("engine env must carry {key}"))
}

/// The repo-root `models.toml` (CARGO_MANIFEST_DIR = crates/image-builder → two parents up).
fn models() -> Models {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root");
    Models::load(root).expect("models.toml must load + validate")
}

#[test]
fn bench_manifest_validates_and_names_creatine_as_the_engine() {
    let vm = hotswap();
    let m = vm.manifest();
    let engine = m
        .resource_domain
        .as_ref()
        .and_then(|rd| rd.engine.as_ref())
        .expect("resource_domain.engine");
    assert_eq!(engine.service, "creatine");
                                                                                              
                                                                                 
}

#[test]
fn health_probe_is_coherent_with_the_baked_engine_env() {
    let env = engine_env(&hotswap());
                                                                                                    
                                                                                               
    let models = models();
    let health = models
        .profile_for_manifest(Some(Path::new(HOTSWAP_MANIFEST)))
        .expect("the hotswap tenant must have a models.toml pin profile")
        .health
        .clone()
        .expect(
            "the hotswap profile must carry [health] — a RuntimeRecord build refuses without it",
        );

                                                                               
    let bind = env_value(&env, "CREATINE_BIND");
    assert_eq!(
        bind,
        format!("tcp:127.0.0.1:{}", health.port),
        "the [health] port must be the engine's tcp loopback bind (a uds/other bind fails every \
         post-swap health check)"
    );

                                                                                             
    let model_id = env_value(&env, "CREATINE_MODEL");
    let body: serde_json::Value =
        serde_json::from_str(&health.body).expect("[health].body must be one-line JSON");
    assert_eq!(
        body.get("model").and_then(|v| v.as_str()),
        Some(model_id),
        "the [health] body's model id must equal the baked CREATINE_MODEL"
    );
    assert_eq!(
        health.path, "/v1/chat/completions",
        "creatine's serve route"
    );
    assert!(
        body.get("messages").is_some_and(|m| m.is_array()),
        "the probe must be a real chat request (a metadata probe skips the forward pass)"
    );

                                                                                               
                                                                                     
    assert_eq!(env_value(&env, "CREATINE_LOWMEM"), "1");
}
