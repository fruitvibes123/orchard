                                                                                   
//!
//! Proves the `--manifest` de-hardcoding (the f436e5f seam) actually threads a NON-recipes manifest
//! through: the toy tenant (`toy-tenant.toml` — app `widget`, uid 200) renders to outputs that carry
//! the TENANT's identity, not recipes'. This is the render-level half of E.2; the produced-bytes toy
//! BOOT (a real `orchard build --manifest` + a generalized dryrun) is its companion.
//!
//! E.4 (operator decision = "toy-render no-leak gate"): the MANIFEST-DERIVED render surface
//! (passwd/group, the service NAMES + the tenant run-script, the box-init topology, the envdir values)
//! carries NO `recipes` tenant string for a non-recipes tenant — the `orchard`-name warrant from the
//! output side.
//!
//! KNOWN de-hardcoding gaps — OS-template / brand strings that STILL say `recipes` by design at
                                                                      
//! `known_de_hardcoding_gaps_stay_present_until_their_blocker` below so they can't silently close):
//!   - the haproxy backend NAME `recipes_be` (config.rs) and the nftables generator comment
                                                              
//!   - the hardcoded envdir WRITE path `etc/recipes/env` (build.rs), the `recipes.*` kernel cmdline
                                                                                                         

use fb_manifest::PlaceholderCtx;
use recipes_image_builder::build::{staged_usr_bin_names, OS_BINS};
use recipes_image_builder::config;
use recipes_image_builder::service_tree::{self, NetMode};
use std::collections::BTreeSet;

const TOY: &str = include_str!("../toy-tenant.toml");

fn toy() -> fb_manifest::ValidatedManifest {
    fb_manifest::parse_and_validate(TOY, &config::os_identities())
        .expect("the toy non-recipes manifest must validate through the bake gate")
}

fn ctx() -> PlaceholderCtx {
    PlaceholderCtx {
        domain: "toy.test".into(),
        source_date_epoch: 0,
    }
}

const DHA: &str = include_str!("../dha-tenant.toml");

fn dha() -> fb_manifest::ValidatedManifest {
    fb_manifest::parse_and_validate(DHA, &config::os_identities())
        .expect("the dha manifest must validate through the bake gate")
}

fn os_bin_set() -> BTreeSet<String> {
    OS_BINS.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn the_toy_manifest_validates_through_the_real_bake_wiring() {
    let m = toy();
    assert_eq!(m.manifest().identities[0].name, "widget");
    assert_eq!(m.manifest().identities[0].uid, 200);
}

#[test]
fn passwd_and_group_carry_the_toy_identity_not_recipes() {
    let m = toy();
    let passwd = config::passwd(&m.manifest().identities);
    let group = config::group(&m.manifest().identities);
    assert!(
        passwd.contains("widget:x:200"),
        "toy identity must be baked: {passwd}"
    );
                                                                                                  
    assert!(
        !passwd.contains("recipes"),
        "passwd leaked recipes for a non-recipes tenant: {passwd}"
    );
    assert!(
        !group.contains("recipes"),
        "group leaked recipes for a non-recipes tenant: {group}"
    );
}

#[test]
fn the_service_set_and_tenant_run_script_come_from_the_manifest() {
    let dirs = service_tree::servicedirs(
        &toy().manifest().services,
        None,
        &ctx(),
        &toy().manifest().probe,
        service_tree::EngineWeightsSetup::None,
    );
                                                                                           
    let widget = dirs
        .iter()
        .find(|d| d.name == "widget")
        .expect("the widget longrun is supervised");
    assert!(
        widget.run.contains("s6-setuidgid 'widget'"),
        "drops to the toy identity (single-quoted): {}",
        widget.run
    );
    assert!(
        widget.run.contains("/bin/busybox"),
        "runs the declared binary: {}",
        widget.run
    );
    assert!(
        !widget.run.contains("recipes"),
        "the tenant run-script leaked recipes: {}",
        widget.run
    );
                                                                                                      
                                                                                                     
                                                                                      
    assert!(
        dirs.iter().all(|d| !d.name.contains("recipes")),
        "a servicedir is named recipes for a non-recipes tenant: {:?}",
        dirs.iter().map(|d| &d.name).collect::<Vec<_>>()
    );
}

#[test]
fn the_box_init_topology_carries_the_toy_hook_not_recipes() {
    let topo = fb_manifest::topology::Topology {
        schema_version: fb_manifest::SCHEMA_VERSION,
        boot_hooks: toy().manifest().boot_hooks.clone(),
        persist: toy().manifest().persist.clone(),
        resource_domain: toy().manifest().resource_domain.clone(),
    };
    let rendered =
        fb_manifest::topology::render_topology(&topo).expect("the toy topology serializes");
    assert!(
        rendered.contains("widget-init"),
        "the toy boot-hook must be in the topology: {rendered}"
    );
    assert!(
        !rendered.contains("recipes"),
        "the topology leaked recipes: {rendered}"
    );
}

#[test]
fn the_envdir_values_carry_no_recipes() {
    for (k, v) in service_tree::box_env(&toy().manifest().env, &ctx()) {
        assert!(!v.contains("recipes"), "env {k} value leaked recipes: {v}");
    }
}

#[test]
fn known_de_hardcoding_gaps_stay_present_until_their_blocker() {
                                                                                                   
                                                                                                       
                                                                                                     
                                                                                        
    let m = toy();
    let haproxy = config::haproxy_config(&m.manifest().edge, &ctx()).expect("haproxy render");
    assert!(
        haproxy.contains("recipes_be"),
        "the haproxy backend name is the documented hardcoded gap"
    );
    let nft = service_tree::nftables_config(&m.manifest().nftables, NetMode::Static);
    assert!(
        nft.contains("recipes-image-builder"),
        "the nftables generator comment is the crate-name gap"
    );
}

/// AC-A2 (debt-burndown Component A): the toy tenant declares `mtls_paths = []`, so the rendered
/// haproxy carries the placeholder comment and NONE of the gate acls/denies — no bare
/// `acl is_android_api ` (parse-fatal), no dead cert acls, no unreachable 401s.
#[test]
fn empty_mtls_paths_renders_no_gate_block() {
    let m = toy();
    let haproxy = config::haproxy_config(&m.manifest().edge, &ctx()).expect("haproxy render");
    assert!(
        haproxy.contains("# (3) no mTLS-gated paths declared by this tenant."),
        "the empty-set placeholder comment is missing: {haproxy}"
    );
    for needle in [
        "acl is_android_api",
        "acl cert_present",
        "acl cert_verified",
        "http-request deny status 401",
    ] {
        assert!(
            !haproxy.contains(needle),
            "empty-set render leaked: {needle}"
        );
    }
}

                                                                                                     

                                                                                                     
/// `widget-init` are `/bin/busybox`, provided by the base rootfs) stages EXACTLY the OS_BINS base. So a
/// non-dha box's staged-bin set is unchanged by the genericization (the `recipes` bins staged-but-unused
/// remain the pre-existing accepted de-hardcoding gap — see the module doc / toy-tenant.toml header).
#[test]
fn a_non_dha_manifest_stages_exactly_the_os_bins() {
    assert_eq!(staged_usr_bin_names(&toy()), os_bin_set());
}

/// §4.1 — the dha manifest adds its three tenant bins ON TOP of the OS_BINS base: `creatine` +
/// `dha-orchestrator` from `services[].binary`, `epa` from `runtime_config.client.program` (all
/// `/usr/bin`); `dha-init`'s `/bin/busybox` boot-hook is base-provided, so it is NOT staged.
#[test]
fn a_dha_manifest_stages_the_os_bins_plus_the_three_dha_bins() {
    let mut expect = os_bin_set();
    expect.extend([
        "creatine".to_string(),
        "dha-orchestrator".to_string(),
        "epa".to_string(),
    ]);
    assert_eq!(staged_usr_bin_names(&dha()), expect);
}
