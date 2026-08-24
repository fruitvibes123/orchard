                                                                         
//!
//! The manifest declares the TENANT topology (app, services, edge path-set, ports, persist, …). It must
//! NOT be able to alter the OS-invariant controls (§5.2): the loader cmdline/APPEND, the haproxy
//! strip-then-set `X-SSL-Client-*` discipline + HSTS, the nftables default-deny, lockdown/IMA/EVM, the
//! rescue branch. The existing byte-goldens prove the OS-invariant CONTENT is present for a tenant; THIS
//! file proves the PARTITION — a manifest field cannot reach those controls — two ways:
//!   (a) structurally: the render fn takes no manifest field for the invariant + a schema-surface
//!       negative fixture (deny_unknown_fields refuses any attempt to ADD such a field), and
//!   (b) behaviorally: mutating the manifest's DATA (edge paths / ports) leaves the OS-invariant lines
//!       byte-identical while the data-driven lines change (so it is a real de-hardcoding, not a no-op).
//!
//! The partition is tenant-agnostic (no manifest field reaches the OS controls regardless of tenant), so
                                                                                                          
                                                                                                        
//! kernel cmdline beyond the grammar-validated `net` token (a CLI arg, not manifest data).

use fb_manifest::{parse_and_validate, PlaceholderCtx, ValidatedManifest};
use recipes_image_builder::boot_fs::{render_boot_fs_extlinux, render_uefi_cmdline};
use recipes_image_builder::config::{self, haproxy_config};
use recipes_image_builder::firmware::Firmware;
use recipes_image_builder::service_tree::{nftables_config, NetMode};

const SAMPLE: &str = include_str!("fixtures/sample-tenant.toml");

fn ctx() -> PlaceholderCtx {
    PlaceholderCtx {
        domain: "box.test".into(),
        source_date_epoch: 1_700_000_000,
    }
}

fn validated(toml: &str) -> ValidatedManifest {
    parse_and_validate(toml, &config::os_identities()).expect("fixture must validate")
}

/// A schema-surface probe: a manifest that tries to express an OS-invariant control MUST be refused
/// (deny_unknown_fields → no such field exists, and none can be silently added later).
fn schema_offers_no_field(mutated: String) {
    assert!(
        parse_and_validate(&mutated, &config::os_identities()).is_err(),
        "the manifest schema must offer NO surface to express this OS-invariant control"
    );
}

                                                                                                         

#[test]
fn loader_cmdline_carries_only_os_invariant_tokens_plus_the_net_token() {
                                                                                                         
                                                                                                 
                                                                       
    let net = "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3";
    for cmdline in [
        render_boot_fs_extlinux("ROOTHASH", 4096, Some(net), Firmware::Seabios, None),
        render_uefi_cmdline("ROOTHASH", 4096, Some(net), None),
    ] {
                                                                                                          
        assert!(cmdline.contains("lockdown=integrity"), "{cmdline:?}");
        assert!(cmdline.contains("ima_appraise=enforce"), "{cmdline:?}");
        assert!(
            cmdline.contains("sysctl.kernel.yama.ptrace_scope=2"),
            "{cmdline:?}"
        );
                                                                                                       
        assert!(cmdline.contains(&format!("fb.net={net}")), "{cmdline:?}");
                                                                                                 
        for leak in [
            "/usr/bin/",
            "fb-acme",
            "/persist/blogd",
            "setuidgid",
            "/etc/blogd/env",
        ] {
            assert!(
                !cmdline.contains(leak),
                "manifest data {leak:?} leaked into the loader cmdline: {cmdline:?}"
            );
        }
    }
}

#[test]
fn with_no_net_the_loader_has_no_operator_influenced_token() {
                                                                                                      
                                         
    let cmdline = render_boot_fs_extlinux("ROOTHASH", 4096, None, Firmware::Seabios, None);
    assert!(!cmdline.contains("fb.net="), "{cmdline:?}");
    assert!(
        cmdline.contains("lockdown=integrity ima_appraise=enforce"),
        "{cmdline:?}"
    );
}

#[test]
fn the_manifest_schema_offers_no_loader_cmdline_surface() {
                                                                                                            
    schema_offers_no_field(SAMPLE.replacen(
        "schema_version = 1",
        "schema_version = 1\nkernel_cmdline = \"ima_appraise=off\"",
        1,
    ));
                                                                             
    schema_offers_no_field(format!("{SAMPLE}\n[loader]\nappend = \"lockdown=none\"\n"));
}

                                                                                                      

#[test]
fn haproxy_strip_then_set_is_invariant_under_edge_mutation() {
    let c = ctx();
    let ref_edge = validated(SAMPLE).manifest().edge.clone();
                                                                                                         
                                                                                               
    let mutated = validated(&SAMPLE.replacen("\"/upload/\"", "\"/upload/\", \"/extra/\"", 1));
    let mut_edge = mutated.manifest().edge.clone();
    let a = haproxy_config(&ref_edge, &c).expect("haproxy render");
    let b = haproxy_config(&mut_edge, &c).expect("haproxy render");
    assert_ne!(
        a, b,
        "the edge path-set is data — mutating it must change the rendered haproxy config"
    );
                                                                                                         
                                                                            
    for invariant in [
        "http-request del-header X-SSL-Client-Verify",
        "http-request del-header X-SSL-Client-CN",
        "http-request del-header X-SSL-Client-DN",
        "http-request del-header X-SSL-Client-Fingerprint",
        "http-response set-header Strict-Transport-Security",
    ] {
        assert!(
            a.contains(invariant) && b.contains(invariant),
            "strip-then-set / HSTS invariant {invariant:?} must be in both renders"
        );
    }
}

#[test]
fn the_edge_schema_offers_no_header_control_surface() {
                                                                                        
    schema_offers_no_field(SAMPLE.replacen(
        "backend = \"127.0.0.1:8000\"",
        "backend = \"127.0.0.1:8000\"\ndel_header = \"X-SSL-Client-Verify\"",
        1,
    ));
}

                                                                                                        

#[test]
fn nftables_default_deny_is_invariant_under_port_mutation() {
    let ref_nft = validated(SAMPLE).manifest().nftables.clone();
    let mutated =
        validated(&SAMPLE.replacen("tcp_ports = [ 22, 80, 443 ]", "tcp_ports = [ 443 ]", 1));
    let mut_nft = mutated.manifest().nftables.clone();
    let a = nftables_config(&ref_nft, NetMode::Static);
    let b = nftables_config(&mut_nft, NetMode::Static);
    assert_ne!(
        a, b,
        "the ingress port-set is data — mutating it must change the firewall"
    );
                                                                                                
    assert_eq!(
        a.matches("policy drop;").count(),
        3,
        "input/forward/output default-deny"
    );
    assert_eq!(
        b.matches("policy drop;").count(),
        3,
        "input/forward/output default-deny"
    );
    let input_deny = "type filter hook input priority filter; policy drop;";
    assert!(
        a.contains(input_deny) && b.contains(input_deny),
        "the input chain default-deny is OS-invariant"
    );
}

#[test]
fn the_nftables_schema_offers_no_policy_override_surface() {
                                                                                                    
                                    
    schema_offers_no_field(SAMPLE.replacen(
        "tcp_ports = [ 22, 80, 443 ]",
        "tcp_ports = [ 22, 80, 443 ]\npolicy = \"accept\"",
        1,
    ));
}

                                                                                                   
                                                                                                    
                                                                                                      
