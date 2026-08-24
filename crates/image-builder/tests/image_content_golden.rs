                                                                                                     
//! from the deleted NixOS `tests/openssh_authorized_keys_routing.rs` to golden-file assertions over
//! the new substrate's RENDERED image content (the `image-builder::config` module). Each maps a
//! "this NixOS module rejects {pam,tmpfiles,…}" sentry to "this rendered image-content
//! contains/does-not-contain {pam-disabled, dropbear-without-PAM, strip-then-set, …}".
//!
                                                                                                 
//! exact-content equality (a change breaks the test — the "checked-in expected" contract); the
//! parameterized haproxy/dropbear configs are asserted by load-bearing structural excerpts. The
//! full-IMAGE byte-identical sha256 reproducibility golden lives in Task 2.3's `build_reproducible`
//! (over the assembled `.img`), not here — these sentries pin config CONTENT, that pins image BYTES.

use recipes_image_builder::boot_fs::render_boot_fs_extlinux;
use recipes_image_builder::config::{
    check_no_forbidden_components, check_no_pam_needed, dropbear_argv, dropbear_run_script,
    ConfigError, FORBIDDEN_DROPBEAR_FLAGS, FSTAB, IMA_POLICY,
};
use recipes_image_builder::firmware::Firmware;

const TEST_DOMAIN: &str = "recipes.example";

/// The synthetic sample tenant (post-shed: orchard holds no recipes manifest). The tenant-AGNOSTIC edge
/// controls — strip-then-set, HSTS, mTLS-deny, the DoS stick-table/caps/timeouts — render identically
/// for ANY tenant, so the sample exercises them; the tenant-SPECIFIC edge data (paths/throttle) is the
/// sample's own (the recipes edge render is sealed by the boot-gate).
const SAMPLE_TENANT: &str = include_str!("fixtures/sample-tenant.toml");

fn sample_haproxy(domain: &str) -> String {
    let m = recipes_image_builder::config::parse_validated_manifest(SAMPLE_TENANT)
        .expect("the sample tenant validates");
    recipes_image_builder::config::haproxy_config(
        &m.manifest().edge,
        &fb_manifest::PlaceholderCtx {
            domain: domain.to_string(),
            source_date_epoch: 0,
        },
    )
    .expect("haproxy render")
}

                                                                                                                                                                
#[test]
fn s01_dropbear_pins_the_exact_flag_set() {
    let argv = dropbear_argv();
                                                                                                     
                                                                                                        
                                                                                                      
                                                                                            
    assert!(
        argv.contains(&"-s".to_string()),
        "-s (disable password auth) missing"
    );
    assert!(
        !argv.contains(&"-R".to_string()),
        "-R must be DROPPED (BOOT-1: regenerates on RO /etc)"
    );
                                                                 
    let g = argv.iter().position(|a| a == "-G").expect("-G present");
    assert_eq!(
        argv.get(g + 1).map(String::as_str),
        Some("ssh"),
        "-G value must be ssh"
    );
                               
    for (flag, val) in [("-I", "1800"), ("-K", "300"), ("-T", "3")] {
        let i = argv
            .iter()
            .position(|a| a == flag)
            .unwrap_or_else(|| panic!("{flag} present"));
        assert_eq!(
            argv.get(i + 1).map(String::as_str),
            Some(val),
            "{flag} value must be {val}"
        );
    }
                                                                                                    
    let r = argv.iter().position(|a| a == "-r").expect("-r present");
    assert_eq!(
        argv.get(r + 1).map(String::as_str),
        Some("/run/dropbear/dropbear_ed25519_host_key"),
        "-r must point at the writable staged host key"
    );
}

                                                                                                                                                                            
#[test]
fn s02_dropbear_run_script_has_no_forbidden_flags() {
    let script = dropbear_run_script();
    for forbidden in FORBIDDEN_DROPBEAR_FLAGS {
                                                                                                   
                                                                                                    
        let present_as_token = script.split_whitespace().any(|tok| tok == forbidden);
        assert!(
            !present_as_token,
            "forbidden dropbear flag {forbidden:?} present in run script:\n{script}"
        );
    }
}

                                                                                                                                       
#[test]
fn s03_dropbear_no_pam_build_check() {
                                                                                                      
                                                                                     
    let pam_linked = vec![(
        "usr/sbin/dropbear".to_string(),
        vec![
            "libc.musl-x86_64.so.1".to_string(),
            "libpam.so.0".to_string(),
        ],
    )];
    assert_eq!(
        check_no_pam_needed(&pam_linked),
        Err(ConfigError::DropbearPam)
    );
    let clean = vec![(
        "usr/sbin/dropbear".to_string(),
        vec!["libc.musl-x86_64.so.1".to_string()],
    )];
    assert_eq!(check_no_pam_needed(&clean), Ok(()));
}

                                                                                                                    
#[test]
fn s04_haproxy_strips_all_trust_headers() {
    let cfg = sample_haproxy(TEST_DOMAIN);
    for h in [
        "X-SSL-Client-Verify",
        "X-SSL-Client-CN",
        "X-SSL-Client-DN",
        "X-SSL-Client-Fingerprint",
        "X-Forwarded-Client-Cert",
        "X-Forwarded-For",
        "X-Forwarded-Proto",
        "X-Forwarded-Host",
        "Forwarded",
        "X-Real-IP",
        "Via",
        "True-Client-IP",
        "CF-Connecting-IP",
    ] {
        assert!(
            cfg.contains(&format!("http-request del-header {h}")),
            "haproxy config missing del-header for {h}"
        );
    }
}

                                                                                                                                           
#[test]
fn s05_haproxy_set_header_gated_on_ssl_c_used() {
    let cfg = sample_haproxy(TEST_DOMAIN);
    for h in [
        "X-SSL-Client-Verify",
        "X-SSL-Client-CN",
        "X-SSL-Client-Fingerprint",
    ] {
        let line = cfg
            .lines()
            .find(|l| l.contains(&format!("set-header {h} ")))
            .unwrap_or_else(|| panic!("set-header for {h} present"));
        assert!(
            line.contains("if { ssl_c_used }"),
            "set-header {h} not gated on ssl_c_used: {line}"
        );
    }
}

                                                                                                                                                 
                                                                             
                                                                              
                                                                                   
                                                                            
                                                                      
#[test]
fn s05b_haproxy_fingerprint_is_sha256_of_der() {
    let cfg = sample_haproxy(TEST_DOMAIN);
    assert!(
        cfg.contains(
            "set-header X-SSL-Client-Fingerprint %[ssl_c_der,sha2(256),hex] if { ssl_c_used }"
        ),
        "fingerprint header must be SHA-256(DER) (ssl_c_der,sha2(256),hex), ssl_c_used-gated"
    );
    assert!(
        !cfg.contains("ssl_c_sha1"),
        "fingerprint must not use SHA-1 (ssl_c_sha1) — the guard stores SHA-256"
    );
}

                                                                                                           
#[test]
fn s06_haproxy_mtls_gate_denies_unverified() {
    let cfg = sample_haproxy(TEST_DOMAIN);
    assert!(
        cfg.contains("acl cert_present ssl_c_used"),
        "cert_present ACL missing"
    );
    assert!(
        cfg.contains("acl cert_verified ssl_c_verify -m int 0"),
        "cert_verified ACL (int-match) missing/malformed"
    );
    assert!(
        cfg.contains("http-request deny status 401 if is_android_api !cert_present"),
        "no-cert deny rule missing"
    );
    assert!(
        cfg.contains("http-request deny status 401 if is_android_api !cert_verified"),
        "verify-failed deny rule missing"
    );
                                                                                                  
    for line in cfg.lines() {
        let t = line.trim_start();
        if t.starts_with('#') {
            continue;
        }
        assert!(
            !t.contains("ssl_c_used,ssl_c_verify"),
            "broken converter-chain regression: {line}"
        );
    }
}

                                                                                                                                                                                                          
#[test]
fn s07_haproxy_sets_hsts() {
    let cfg = sample_haproxy(TEST_DOMAIN);
    assert!(
        cfg.contains("http-response set-header Strict-Transport-Security"),
        "HSTS response header missing"
    );
}

                                                                                                                                                                          
#[test]
fn s08_haproxy_runs_master_worker() {
    let cfg = sample_haproxy(TEST_DOMAIN);
                                                                
    let directive = cfg.lines().any(|l| l.trim() == "master-worker");
    assert!(
        directive,
        "master-worker directive missing from global block"
    );
}

                                                                                                                                                                                              
#[test]
fn s09_haproxy_uses_persist_cert_and_ca_paths() {
    let cfg = sample_haproxy(TEST_DOMAIN);
    assert!(
        cfg.contains(&format!("crt /persist/acme/{TEST_DOMAIN}/full.pem")),
        "haproxy cert path not at /persist/acme/<domain>/full.pem"
    );
    assert!(
        cfg.contains("ca-file /persist/blogd/ca.crt"),
        "haproxy ca-file not at /persist/blogd/ca.crt"
    );
}

                                                                                                                              
#[test]
fn s10_ima_policy_is_the_pinned_appraise_ruleset() {
                                                                                                   
                                                                                                 
    assert_eq!(
        IMA_POLICY,
        "appraise func=BPRM_CHECK fowner=0 appraise_type=imasig\n\
         appraise func=MMAP_CHECK fowner=0 appraise_type=imasig\n\
         appraise func=MODULE_CHECK appraise_type=imasig\n"
    );
}

                                                                                                                                    
#[test]
fn s11_fstab_hardens_persist_and_mounts_boot_readonly() {
                                                                                              
                                                                   
    let boot = FSTAB
        .lines()
        .find(|l: &&str| l.contains("/boot"))
        .expect("/boot entry");
    for opt in ["ro", "nodev", "nosuid", "noexec"] {
        assert!(boot.contains(opt), "/boot fstab missing {opt}: {boot}");
    }
    let persist = FSTAB
        .lines()
        .find(|l: &&str| l.contains("/persist"))
        .expect("/persist entry");
    for opt in ["nosuid", "nodev", "noexec"] {
        assert!(
            persist.contains(opt),
            "/persist fstab missing {opt}: {persist}"
        );
    }
                                                                                                        
                                                                                                        
                                                                                                           
    assert!(
        persist.contains("errors=remount-ro"),
        "/persist fstab must carry errors=remount-ro (fail-closed on run-time fs errors): {persist}"
    );
                                                                                                           
                                                                                                          
                                                                                                       
                                                                                                        
                                                               
    for pseudo in ["auto", "nofail"] {
        assert!(
            !persist.contains(pseudo),
            "/persist must NOT carry fstab pseudo-option {pseudo}: {persist}"
        );
    }
                                                                                         
    let run = FSTAB
        .lines()
        .find(|l: &&str| l.contains("/run"))
        .expect("/run entry");
    for opt in ["nosuid", "nodev", "noexec"] {
        assert!(run.contains(opt), "/run fstab missing {opt}: {run}");
    }
                                                                                      
    assert!(
        !FSTAB.lines().any(|l: &str| {
            let mut f = l.split_whitespace();
            f.next();          
            f.next() == Some("/")              
        }),
        "rootfs / must not be in fstab (the init verity-mounts it)"
    );
}

                                                                                                                                    
#[test]
fn s12_no_forbidden_components() {
                                                                                                
                                                         
    let clean = [
        "/sbin/init",
        "/usr/sbin/dropbear",
        "/usr/sbin/haproxy",
        "/bin/busybox",
        "/bin/s6-svscan",
        "/usr/bin/recipes",
    ];
    assert_eq!(check_no_forbidden_components(clean), Ok(()));

    for bad in [
        "/usr/lib/systemd/systemd",
        "/sbin/apk",
        "/etc/pam.d/sshd",
        "/usr/lib/libpam.so.0",
    ] {
        let manifest = ["/sbin/init", bad];
        assert!(
            matches!(
                check_no_forbidden_components(manifest),
                Err(ConfigError::ForbiddenComponent(_))
            ),
            "expected {bad:?} rejected as a forbidden component"
        );
    }
}

                                                                                                                                    
                                                                                                     
                                                                                                    
                                                                          
#[test]
fn s13_haproxy_dos_defenses_present() {
    let cfg = sample_haproxy(TEST_DOMAIN);
    for needle in [
        "stick-table type ip size 100k expire 1m store conn_cur,conn_rate(60s),http_req_rate(60s)",
        "tcp-request connection reject if { sc_conn_cur(0) gt 20 }",               
        "http-request deny status 429 if { sc_http_req_rate(0) gt 200 }",                      
        "http-request deny status 410 unless is_acme",                                  
        "timeout http-request 10s",                                                
        "timeout http-keep-alive 5s",                                                  
    ] {
        assert!(
            cfg.contains(needle),
            "haproxy config dropped a DoS defense: {needle}"
        );
    }
                                                                                                          
                                                                                                      
                                                                                                
                                                          
    assert!(
        cfg.contains("acl is_login path /login"),
        "the tenant throttle_rules must render the path-derived ACL"
    );
    assert!(
        cfg.contains("http-request deny status 429 if is_login { sc_http_req_rate(0) gt 10 }"),
        "the tenant /login rule must render a per-path 429 cap"
    );
}

#[test]
fn s14_haproxy_redacts_secret_tokens_in_logs() {
    let cfg = sample_haproxy(TEST_DOMAIN);
                                                                                                    
                                                                              
    assert!(
        cfg.contains("%[var(txn.logged_url)]"),
        "log-format must use the redacted var, not %HU"
    );
                                                                                                         
                                                                                                        
                                                                                                         
                                                                                                          
    let setvar = "http-request set-var(txn.logged_url) url,\
        regsub(^/admin/[^/?]+,/admin/<redacted>),\
        regsub(token=[^&]+,token=<redacted>)";
    assert!(
        cfg.matches(setvar).count() >= 2,
        "both http-in and https-in must populate the full secret-token-redaction log var"
    );
                                                                                             
    for needle in [
        "regsub(^/admin/[^/?]+,/admin/<redacted>)",
        "regsub(token=[^&]+,token=<redacted>)",
    ] {
        assert!(
            cfg.contains(needle),
            "haproxy log redaction set drifted from the tenant edge: missing {needle}"
        );
    }
}

                                                                                                                                                                                              
#[test]
fn s15_baked_box_topology_parses_back_with_the_app_domain_hooks() {
                                                                                                      
                                                                                                    
                                                                                                       
                                                                                                      
                                                                                                        
                                                                                              
                         
    use fb_manifest::topology::{parse_topology, render_topology, Topology};
    let manifest = recipes_image_builder::config::parse_validated_manifest(SAMPLE_TENANT)
        .expect("the sample tenant validates");
    let topology = Topology {
        schema_version: fb_manifest::SCHEMA_VERSION,
        boot_hooks: manifest.manifest().boot_hooks.clone(),
                                                                                                   
                                                                            
        persist: manifest.manifest().persist.clone(),
        resource_domain: manifest.manifest().resource_domain.clone(),
    };
    let rendered = render_topology(&topology).expect("the sample topology serializes");
    let parsed = parse_topology(&rendered).expect("box-init parse_topology accepts the baked file");
    let names: Vec<&str> = parsed.boot_hooks.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(
        names,
        ["set-hostname", "blogd-init"],
        "exactly the manifest's app-domain boot-hooks (OS-infra hooks stay box-init-owned)"
    );
    assert_eq!(
        parsed
            .boot_hooks
            .iter()
            .map(|h| h.order)
            .collect::<Vec<_>>(),
        vec![10, 20],
        "the orders box-init interleaves the app-domain hooks by"
    );
                                                                                                         
                                                                                  
    let timeout = |name: &str| {
        parsed
            .boot_hooks
            .iter()
            .find(|h| h.name == name)
            .expect("hook present")
            .timeout_secs
    };
    assert_eq!(timeout("set-hostname"), 30);
    assert_eq!(timeout("blogd-init"), 60, "the 60s keygen-margin bound");
                                                                                                  
                                                                                     
    assert_eq!(parsed.persist.len(), 1, "the sample tenant's persist dir");
    assert_eq!(parsed.persist[0].path, "blogd");
    assert_eq!(parsed.persist[0].uid, 100);
}

                                                                                                                                                                                            
#[test]
fn s16_baked_fb_backup_config_carries_the_manifest_backup_set() {
                                                                                                        
                                                                                                            
                                                                                                       
                                                                                                     
                                                                                                          
    use recipes_image_builder::config::{fb_backup_config, parse_validated_manifest};
    let manifest = parse_validated_manifest(SAMPLE_TENANT).expect("the sample tenant validates");
    let cfg = fb_backup_config(&manifest.manifest().backup);
    let data: Vec<&str> = cfg
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .collect();
    assert_eq!(
        data,
        [
            "vacuum blogd.db",
            "source posts",
            "source media",
            "source secrets",
            "source ca.crt",
        ],
        "the baked fb-backup config must carry exactly the [backup] set"
    );
                                                                                                       
                                                                                                      
                                                                                                         
    assert!(
        data.contains(&"source ca.crt"),
        "the backup set must include ca.crt (Secrets-3) — manifest-declared"
    );
}

                                                                                                               
#[test]
fn s17_seabios_gpt_patchable_fields_are_single_sector_contained() {
                                                                                                    
                                                                                                  
                                                                                                    
                                                                                                       
                                                                                                    
                                                                                                      
                                                                                           
                                                                                              
                                                                                                   
                                                                                                 
                                                  
    let hex = "ab".repeat(32);                                                                  
    let conf = render_boot_fs_extlinux(&hex, 8192, None, Firmware::SeabiosGpt, None);

                                                                                                       
    let field_after = |anchor: &str, occurrence: usize, width: usize| -> (usize, usize) {
        let mut from = 0;
        for _ in 0..occurrence {
            let at = conf[from..]
                .find(anchor)
                .unwrap_or_else(|| panic!("anchor {anchor:?} occurrence {occurrence} not found"));
            from += at + anchor.len();
        }
        let start = from;                           
        (start, start + width - 1)
    };

                                                                                    
    let (def_start, def_end) = field_after("DEFAULT ", 1, 8);
    assert_eq!(def_start, 8, "DEFAULT value starts right after `DEFAULT `");
    assert!(
        def_end < 512,
        "DEFAULT value must lie wholly in sector 0 (start {def_start}, end {def_end})"
    );

                                                                                                 
    for occ in 1..=2 {
        let (h_start, h_end) = field_after("fb.root-hash=", occ, 64);
        assert_eq!(
            h_start / 512,
            h_end / 512,
            "label-{occ} fb.root-hash straddles a sector ({h_start}..={h_end}) — pad the template"
        );
        let (o_start, o_end) = field_after("fb.verity-hash-offset=", occ, 12);
        assert_eq!(
            o_start / 512,
            o_end / 512,
            "label-{occ} fb.verity-hash-offset straddles a sector ({o_start}..={o_end})"
        );
    }

                                                                                                   
    let mbr = render_boot_fs_extlinux(&hex, 8192, None, Firmware::Seabios, None);
    assert_eq!(mbr.matches("LABEL ").count(), 1, "MBR stays single-label");
}
