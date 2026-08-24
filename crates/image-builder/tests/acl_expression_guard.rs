//! Fail-closed acl-expression guard (hotswap debt-burndown spec Component A, AC-A3).
//!
//! The empty-`mtls_paths` defect rendered `acl is_android_api ` — a bare acl with no criterion,
//! which haproxy REJECTS at parse ("missing fetch method in ACL expression"), discovered only on
//! the box. This guard renders every fixture tenant (the three crate-root manifests + the sample)
//! and refuses any `acl` line that carries no expression, covering every `compose_*` helper FOR
                                                                                                  

use recipes_image_builder::config;

const SAMPLE: &str = include_str!("fixtures/sample-tenant.toml");
const TOY: &str = include_str!("../toy-tenant.toml");
const DHA: &str = include_str!("../dha-tenant.toml");
const HOTSWAP: &str = include_str!("../hotswap-tenant.toml");

fn ctx(domain: &str) -> fb_manifest::PlaceholderCtx {
    fb_manifest::PlaceholderCtx {
        domain: domain.to_string(),
        source_date_epoch: 0,
    }
}

/// Render haproxy.cfg for all four fixture tenants: the sample via the golden test's own loader
/// shape (`parse_validated_manifest`), the three crate-root tomls via the toy test's
/// `parse_and_validate` + `os_identities` shape.
fn render_all_fixture_tenants() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let sample = config::parse_validated_manifest(SAMPLE).expect("the sample tenant validates");
    out.push((
        "sample".to_string(),
        config::haproxy_config(&sample.manifest().edge, &ctx("recipes.example"))
            .expect("haproxy render"),
    ));
    for (name, toml) in [("toy", TOY), ("dha", DHA), ("hotswap", HOTSWAP)] {
        let m = fb_manifest::parse_and_validate(toml, &config::os_identities())
            .unwrap_or_else(|e| panic!("the {name} manifest must validate: {e}"));
        out.push((
            name.to_string(),
            config::haproxy_config(&m.manifest().edge, &ctx(&format!("{name}.test")))
                .expect("haproxy render"),
        ));
    }
    out
}

/// Fail-closed guard (spec AC-A3): every rendered `acl` line must carry an expression —
/// a minimal valid acl is `acl <name> <fetch>` = 3 whitespace-separated tokens; the
/// empty-splice defect renders 2. Covers every compose_* helper FOR THE FIXTURE RENDERS
                                                                              
fn assert_no_empty_acl_expressions(cfg: &str, tenant: &str) {
    for line in cfg.lines() {
        let t = line.trim_start();
        if !t.starts_with("acl ") {
            continue;
        }
        let tokens = t.split_whitespace().count();
        assert!(
            tokens >= 3,
            "{tenant}: acl line with an empty expression (only {tokens} tokens): {line:?}"
        );
    }
}

#[test]
fn no_fixture_tenant_renders_an_empty_acl_expression() {
    for (name, cfg) in render_all_fixture_tenants() {
        assert_no_empty_acl_expressions(&cfg, &name);
    }
}

#[test]
fn the_guard_itself_fires_on_a_synthetic_empty_acl() {
                                                                                            
    let synthetic = "frontend x\n    acl is_broken \n    acl ok path_beg /a\n";
    let r = std::panic::catch_unwind(|| assert_no_empty_acl_expressions(synthetic, "synthetic"));
    assert!(r.is_err(), "the guard did not fire on a 2-token acl line");
}

#[test]
fn an_empty_throttle_paths_rule_is_refused_at_render() {
                                                                                                
                                                             
    let m = config::parse_validated_manifest(SAMPLE).expect("the sample tenant validates");
    let mut edge = m.manifest().edge.clone();
    edge.throttle_rules
        .push(fb_manifest::manifest::ThrottleRule {
            paths: vec![],
            match_kind: fb_manifest::manifest::ThrottleMatch::Prefix,
            max_req_rate: 10,
        });
    let err = config::haproxy_config(&edge, &ctx("recipes.example")).unwrap_err();
    assert!(err.contains("declares no paths"), "{err}");
}
