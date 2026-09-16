                                                            
//! and the domain-class rule. Every arm runs without a boot — the fixtures are files.

use std::path::Path;

use orchard::ceremony::gate_record::{
    BuildParams, PROVENANCE_SCHEMA_VERSION, ProducedHashes, Provenance, compose, provenance_path,
    read, read_sha256_sidecar, write,
};
use orchard::ceremony::test_domains::{DomainClass, TEST_DOMAINS, classify};

fn hex_of(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

/// A fixture image triple with the build's own sha256 sidecars beside it.
fn triple(
    dir: &Path,
    label: &str,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let base = recipes_image_builder::image::image_output_base(label);
    let img = dir.join(format!("{base}.img"));
    let layout = dir.join(format!("{base}.layout.toml"));
    let vmlinuz = dir.join(format!("{base}.vmlinuz"));
    let initramfs = dir.join(format!("{base}.initramfs"));
    for (p, body) in [
        (&img, "IMG"),
        (&layout, "layout = 1"),
        (&vmlinuz, "KERNEL"),
        (&initramfs, "INITRD"),
    ] {
        std::fs::write(p, body).expect("write artifact");
    }
    std::fs::write(
        dir.join(format!("{base}.sha256")),
        format!("{}  {base}.img\n", hex_of(0x11)),
    )
    .expect("w");
    std::fs::write(
        dir.join(format!("{base}.vmlinuz.sha256")),
        format!("{}  {base}.vmlinuz\n", hex_of(0x22)),
    )
    .expect("w");
    std::fs::write(
        dir.join(format!("{base}.initramfs.sha256")),
        format!("{}  {base}.initramfs\n", hex_of(0x33)),
    )
    .expect("w");
    (img, layout, vmlinuz, initramfs)
}

fn params() -> BuildParams {
    BuildParams {
        domain: "box.test".into(),
        net: "mode=dhcp".into(),
        firmware: "seabios".into(),
        image_version: 3,
        git_sha: "a".repeat(40),
    }
}

#[test]
fn the_provenance_sidecar_declares_what_the_build_produced() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (img, layout, vmlinuz, initramfs) = triple(tmp.path(), "abc1234");
    let p = compose("abc1234", params(), &img, &layout, &vmlinuz, &initramfs).expect("compose");
                                                                                                
                                          
    assert_eq!(p.produced.img, hex_of(0x11));
    assert_eq!(p.produced.vmlinuz, hex_of(0x22));
    assert_eq!(p.produced.initramfs, hex_of(0x33));
    assert_eq!(
        p.produced.layout.len(),
        64,
        "the small sidecar is hashed directly"
    );
    assert_eq!(p.schema_version, PROVENANCE_SCHEMA_VERSION);
    let path = write(&img, &p).expect("write");
    assert_eq!(path, provenance_path(&img));
    assert_eq!(read(&img).expect("read"), p, "the sidecar round-trips");
}

#[test]
fn the_gate_harness_refuses_when_the_sidecar_is_absent_and_never_falls_back() {
                                                                                                 
                                                                         
    let tmp = tempfile::tempdir().expect("tempdir");
    let (img, _, _, _) = triple(tmp.path(), "abc1234");
    let e = read(&img).expect_err("absent sidecar refuses");
    assert_eq!(e.id.token(), "provenance-unusable");
    assert!(
        e.cure().as_str().contains("orchard build"),
        "the cure names the producer: {}",
        e.cure().as_str()
    );
                                                                                                 
    unsafe {
        std::env::set_var("RECIPES_DOMAIN", "attacker.example");
    }
    let still = read(&img).expect_err("still refuses");
    assert_eq!(still.id.token(), "provenance-unusable");
    unsafe {
        std::env::remove_var("RECIPES_DOMAIN");
    }
}

#[test]
fn a_newer_or_unparseable_sidecar_refuses_rather_than_being_read_partially() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (img, layout, vmlinuz, initramfs) = triple(tmp.path(), "abc1234");
    let mut p = compose("abc1234", params(), &img, &layout, &vmlinuz, &initramfs).expect("compose");
    p.schema_version = PROVENANCE_SCHEMA_VERSION + 1;
    write(&img, &p).expect("write");
    let e = read(&img).expect_err("a newer schema refuses");
    assert_eq!(e.id.token(), "provenance-unusable");
    assert!(e.detail.contains("schema-version"), "{}", e.detail);
    std::fs::write(provenance_path(&img), "this is not toml = = =").expect("w");
    assert_eq!(
        read(&img).expect_err("unparseable refuses").id.token(),
        "provenance-unusable"
    );
                                                                                            
                                                                       
    let mut text = toml::to_string_pretty(&Provenance {
        schema_version: PROVENANCE_SCHEMA_VERSION,
        image_label: "abc1234".into(),
        params: params(),
        produced: ProducedHashes {
            img: hex_of(0x11),
            layout: hex_of(0x44),
            vmlinuz: hex_of(0x22),
            initramfs: hex_of(0x33),
        },
    })
    .expect("ser");
    text.push_str("\nsurprise = true\n");
    std::fs::write(provenance_path(&img), text).expect("w");
    assert_eq!(
        read(&img).expect_err("unknown field refuses").id.token(),
        "provenance-unusable"
    );
}

#[test]
fn compose_refuses_when_the_builds_own_hash_sidecar_is_missing() {
                                                                                             
                                  
    let tmp = tempfile::tempdir().expect("tempdir");
    let (img, layout, vmlinuz, initramfs) = triple(tmp.path(), "abc1234");
    let base = recipes_image_builder::image::image_output_base("abc1234");
    std::fs::remove_file(tmp.path().join(format!("{base}.vmlinuz.sha256"))).expect("rm");
    let e = compose("abc1234", params(), &img, &layout, &vmlinuz, &initramfs)
        .expect_err("a missing sidecar refuses");
    assert_eq!(e.id.token(), "provenance-unusable");
    assert!(e.detail.contains("vmlinuz"), "{}", e.detail);
}

#[test]
fn a_malformed_sha256_sidecar_reads_as_no_declared_hash_never_as_an_empty_one() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let p = tmp.path().join("x.sha256");
    for body in [
        "",
        "  \n",
        "notahash  x.img\n",
        &format!("{}  x.img\n", "1".repeat(63)),
    ] {
        std::fs::write(&p, body).expect("w");
        assert_eq!(read_sha256_sidecar(&p), None, "body {body:?}");
    }
    std::fs::write(&p, format!("{}  x.img\n", hex_of(0xab))).expect("w");
    assert_eq!(read_sha256_sidecar(&p), Some(hex_of(0xab)));
}

#[test]
fn the_domain_class_allowlist_is_exact_and_everything_else_is_real() {
                                                                                                
                                                                                                  
                                                                                      
    for d in TEST_DOMAINS {
        assert_eq!(classify(d), DomainClass::Test, "{d}");
        assert_eq!(
            classify(&d.to_ascii_uppercase()),
            DomainClass::Test,
            "DNS is case-insensitive"
        );
        assert_eq!(
            classify(&format!("{d}.")),
            DomainClass::Test,
            "a trailing root dot is the same name"
        );
    }
    for d in [
        "",
        "   ",
        "rezepte.example.org",
        "example.com",
                                                                 
        "evil-box.test.example.com",
        "notbox.test",
        "box.test.evil.com",
        "xbox.test",
    ] {
        assert_eq!(classify(d), DomainClass::Real, "{d:?} must classify REAL");
    }
}

                                                                                                    

use orchard::ceremony::gate_record::{
    BootPath, DeclaredComposition, GATE_RECORD_SCHEMA_VERSION, GateRecord, LegRun, LegSpec, verify,
};

fn leg(id: &str, boots: bool, hermetic: bool, boot_path: BootPath) -> LegSpec {
    LegSpec {
        id: id.into(),
        boots,
        hermetic,
        boot_path,
    }
}

fn composition(target: &str, legs: Vec<LegSpec>) -> DeclaredComposition {
    DeclaredComposition {
        gate_target: target.into(),
        legs,
    }
}

fn provenance_for(dir: &Path, label: &str, domain: &str) -> Provenance {
    let (img, layout, vmlinuz, initramfs) = triple(dir, label);
    let mut ps = params();
    ps.domain = domain.into();
    compose(label, ps, &img, &layout, &vmlinuz, &initramfs).expect("compose")
}

fn record_for(p: &Provenance, target: &str, legs: &[&str]) -> GateRecord {
    GateRecord {
        schema_version: GATE_RECORD_SCHEMA_VERSION,
        gate_target: target.into(),
        image_label: p.image_label.clone(),
        staged: p.produced.clone(),
        params: p.params.clone(),
        leg: legs.iter().map(|id| LegRun { id: (*id).into() }).collect(),
    }
}

#[test]
fn a_matching_record_over_a_booting_composition_verifies() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let p = provenance_for(tmp.path(), "abc1234", "box.test");
    let decl = composition(
        "boot-gate-ceremony",
        vec![
            leg("dryrun", true, false, BootPath::DirectKernel),
            leg("bake_repro", false, false, BootPath::DirectKernel),
        ],
    );
    let rec = record_for(&p, "boot-gate-ceremony", &["dryrun", "bake_repro"]);
    verify(&rec, &p, &decl, classify(&p.params.domain)).expect("verifies");
}

#[test]
fn a_composition_with_no_booting_leg_can_never_satisfy_the_gate() {
                                                                            
    let tmp = tempfile::tempdir().expect("tempdir");
    let p = provenance_for(tmp.path(), "abc1234", "box.test");
    let decl = composition(
        "boot-gate-paperwork",
        vec![leg("bake_repro", false, false, BootPath::DirectKernel)],
    );
    let rec = record_for(&p, "boot-gate-paperwork", &["bake_repro"]);
    let e = verify(&rec, &p, &decl, classify(&p.params.domain)).expect_err("refuses");
    assert_eq!(e.id.token(), "gate-composition-unsatisfiable");
}

#[test]
fn a_hash_mismatched_record_refuses_naming_both_sides() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let p = provenance_for(tmp.path(), "abc1234", "box.test");
    let decl = composition(
        "boot-gate-ceremony",
        vec![leg("dryrun", true, false, BootPath::DirectKernel)],
    );
    let mut rec = record_for(&p, "boot-gate-ceremony", &["dryrun"]);
    let other = hex_of(0x99);
    rec.staged.img = other.clone();
    let e = verify(&rec, &p, &decl, classify(&p.params.domain)).expect_err("refuses");
    assert_eq!(e.id.token(), "gate-record-mismatch");
    assert!(
        e.detail.contains(&other) && e.detail.contains(&p.produced.img),
        "both sides named: {}",
        e.detail
    );
                                                                                             
    let mut wrong_label = record_for(&p, "boot-gate-ceremony", &["dryrun"]);
    wrong_label.image_label = "deadbeef".into();
    assert_eq!(
        verify(&wrong_label, &p, &decl, classify(&p.params.domain))
            .expect_err("refuses")
            .id
            .token(),
        "gate-record-mismatch"
    );
    let mut wrong_params = record_for(&p, "boot-gate-ceremony", &["dryrun"]);
    wrong_params.params.image_version += 1;
    assert_eq!(
        verify(&wrong_params, &p, &decl, classify(&p.params.domain))
            .expect_err("refuses")
            .id
            .token(),
        "gate-record-mismatch"
    );
}

#[test]
fn a_reduced_leg_run_never_greens_a_full_composition_and_the_refusal_names_both_sets() {
                                                                                              
                                                                                        
    let tmp = tempfile::tempdir().expect("tempdir");
    let p = provenance_for(tmp.path(), "abc1234", "box.test");
    let decl = composition(
        "boot-gate",
        vec![
            leg("dryrun", true, false, BootPath::DirectKernel),
            leg("rescue_smoke", true, false, BootPath::SeabiosInstalledDisk),
            leg("restore_smoke", true, false, BootPath::SeabiosInstalledDisk),
        ],
    );
    let reduced = record_for(&p, "boot-gate", &["dryrun"]);
    let e = verify(&reduced, &p, &decl, classify(&p.params.domain)).expect_err("refuses");
    assert_eq!(e.id.token(), "gate-record-mismatch");
    assert!(
        e.detail.contains("rescue_smoke") && e.detail.contains("restore_smoke"),
        "the legs that never ran are named: {}",
        e.detail
    );
    assert!(
        e.detail.contains("dryrun"),
        "the executed set is named too: {}",
        e.detail
    );
    let extra = record_for(
        &p,
        "boot-gate",
        &["dryrun", "rescue_smoke", "restore_smoke", "invented"],
    );
    let e = verify(&extra, &p, &decl, classify(&p.params.domain)).expect_err("refuses");
    assert!(e.detail.contains("invented"), "{}", e.detail);
}

#[test]
fn a_real_domain_image_refuses_until_a_hermetic_installed_disk_composition_exists() {
                                                                                               
                                                                                            
                                  
    let tmp = tempfile::tempdir().expect("tempdir");
    let p = provenance_for(tmp.path(), "abc1234", "rezepte.example.org");
    assert_eq!(classify(&p.params.domain), DomainClass::Real);
                                                        
    let today = composition(
        "boot-gate",
        vec![
            leg("dryrun", true, false, BootPath::DirectKernel),
            leg("rescue_smoke", true, false, BootPath::SeabiosInstalledDisk),
        ],
    );
    let rec = record_for(&p, "boot-gate", &["dryrun", "rescue_smoke"]);
    let e = verify(&rec, &p, &today, DomainClass::Real).expect_err("refuses");
    assert_eq!(e.id.token(), "real-domain-gate-unavailable");
    assert!(
        e.cure().as_str().contains("Q7"),
        "the cure names the cross-stream debt: {}",
        e.cure().as_str()
    );
                                                                                             
                                                                               
    let kernel_only = composition(
        "boot-gate-acme",
        vec![leg("acme_lifecycle", true, true, BootPath::DirectKernel)],
    );
    let rec = record_for(&p, "boot-gate-acme", &["acme_lifecycle"]);
    assert_eq!(
        verify(&rec, &p, &kernel_only, DomainClass::Real)
            .expect_err("refuses")
            .id
            .token(),
        "real-domain-gate-unavailable"
    );
                                                         
    let after_q7 = composition(
        "boot-gate-ceremony",
        vec![leg(
            "installed_disk",
            true,
            true,
            BootPath::SeabiosInstalledDisk,
        )],
    );
    let rec = record_for(&p, "boot-gate-ceremony", &["installed_disk"]);
    verify(&rec, &p, &after_q7, DomainClass::Real).expect("a hermetic installed-disk gate passes");
                                                                                                
                          
    let t = provenance_for(tmp.path(), "def5678", "box.test");
    let rec = record_for(&t, "boot-gate", &["dryrun", "rescue_smoke"]);
    verify(&rec, &t, &today_for("boot-gate"), DomainClass::Test).expect("test domain passes");
}

fn today_for(target: &str) -> DeclaredComposition {
    composition(
        target,
        vec![
            leg("dryrun", true, false, BootPath::DirectKernel),
            leg("rescue_smoke", true, false, BootPath::SeabiosInstalledDisk),
        ],
    )
}

                                                                                                    

use orchard::ceremony::leg_registry::{
    LegOpts, REGISTRY, Selector, composition_of, dryrun_runtime_opts, leg as registered_leg,
    recipe_of, selectors_of,
};

fn makefile() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Makefile"))
        .expect("read the orchard Makefile")
}

#[test]
fn builder_setters_never_touch_the_network_mode() {
                                                                                               
                                                                                          
                                                             
    for start in [true, false] {
        let base = orchard::deploy::dryrun::DryrunOpts {
            restrict_net: start,
            ..dryrun_runtime_opts()
        };
        let after = base.clone().with_http_probe(9443, "/healthz");
        assert_eq!(
            after.restrict_net, start,
            "with_http_probe must not change the network mode"
        );
    }
}

/// A deliberately NON-hermetic constructor. It exists so the derivation arm has a case where the
/// leg's ACTUAL mode differs from the builder's CAPABILITY — every registered leg is hermetic
/// today, so without this the arm could not tell an actual-mode predicate from a capability one,
                                                    
fn non_hermetic_fixture_opts() -> orchard::deploy::dryrun::DryrunOpts {
    orchard::deploy::dryrun::DryrunOpts {
        restrict_net: false,
        ..dryrun_runtime_opts()
    }
}

#[test]
fn the_predicate_is_the_legs_actual_mode_not_the_builders_capability() {
    use orchard::ceremony::leg_registry::GateLeg;
                                                                                                 
                                                                                  
    let open = GateLeg {
        id: "fixture_open_net",
        test_binary: "fixture",
        boot_path: BootPath::DirectKernel,
        opts: LegOpts::Dryrun(non_hermetic_fixture_opts),
    };
    assert!(open.boots());
    assert!(
        !open.hermetic(),
        "a leg whose own constructor leaves the guest on open NAT is NOT hermetic, however          capable the builder is"
    );
    let closed = GateLeg {
        id: "fixture_closed_net",
        test_binary: "fixture",
        boot_path: BootPath::DirectKernel,
        opts: LegOpts::Dryrun(dryrun_runtime_opts),
    };
    assert!(
        closed.hermetic(),
        "and the arm is live in the other direction"
    );
                                                                                            
                                 
    let no_guest = GateLeg {
        id: "fixture_no_guest",
        test_binary: "fixture",
        boot_path: BootPath::DirectKernel,
        opts: LegOpts::NoGuest,
    };
    assert!(!no_guest.boots() && !no_guest.hermetic());
}

#[test]
fn every_registered_leg_derives_its_mode_from_its_own_constructor() {
                                                                                               
                                                                                           
    assert!(!REGISTRY.is_empty(), "an empty registry proves nothing");
    for l in REGISTRY {
        let spec = l.spec();
        assert_eq!(spec.id, l.id);
        assert_eq!(spec.boots, !matches!(l.opts, LegOpts::NoGuest));
                                                                                             
        let expected = match l.opts {
            LegOpts::NoGuest => false,
            LegOpts::Dryrun(make) => make().restrict_net,
            LegOpts::DebianE2e(make) => make().restrict_net,
        };
        assert_eq!(
            spec.hermetic, expected,
            "{}: the derived mode must be the leg's own",
            l.id
        );
    }
}

#[test]
fn a_hermetic_seabios_installed_disk_leg_exists_today() {
                                                                                                 
                                                                                                  
                                                                                                 
                                                                                       
    let l = registered_leg("installed_disk_boots_through_seabios_to_working_runtime")
        .expect("registered");
    let spec = l.spec();
    assert!(spec.boots, "the leg boots the image");
    assert_eq!(spec.boot_path, BootPath::SeabiosInstalledDisk);
    assert!(
        spec.hermetic,
        "the installed-disk leg boots hermetically since the si land; if this flipped, a \
         real-domain gate has no satisfier and the gate refuses unconditionally"
    );
}

#[test]
fn the_recipe_parser_classifies_every_cargo_test_line_or_hard_fails() {
                                                                                                
                                                                                               
                
    let mf = makefile();
    for target in ["boot-gate", "boot-gate-ceremony", "boot-gate-acme"] {
        let recipe = recipe_of(&mf, target).unwrap_or_else(|| panic!("no target {target}"));
        let sels = selectors_of(&recipe)
            .unwrap_or_else(|e| panic!("{target}: every cargo test line must classify: {e}"));
        assert!(!sels.is_empty(), "{target} runs no cargo test at all");
    }
                                                                                                 
                    
    let sels = selectors_of(&recipe_of(&mf, "boot-gate").expect("boot-gate")).expect("classify");
    assert!(
        sels.iter().any(|s| matches!(s, Selector::Named { .. })),
        "boot-gate name-filters some legs"
    );
    assert!(
        sels.iter()
            .any(|s| matches!(s, Selector::WholePackageIgnored { .. })),
        "boot-gate runs one whole-package ignored set (the image-builder bakes)"
    );
    assert!(
        sels.iter()
            .any(|s| matches!(s, Selector::AllExceptSkipped { .. })),
        "boot-gate skip-filters the prod-e2e binary"
    );
                                                    
    for bad in [
        "cargo test -p orchard --test deploy_dryrun -- --nocapture some_leg".to_string(),
        "cargo test --test deploy_dryrun -- --ignored some_leg".to_string(),
        "cargo test -p orchard --test -- --ignored".to_string(),
        "cargo test -p orchard --test x -- --ignored --frobnicate".to_string(),
        "cargo test -p orchard --test x -- --ignored a --skip b".to_string(),
    ] {
        assert!(
            selectors_of(std::slice::from_ref(&bad)).is_err(),
            "must hard-fail, not skip: {bad}"
        );
    }
}

#[test]
fn the_ceremony_target_declares_an_enumerable_booting_composition() {
                                                                                                   
                                       
    let mf = makefile();
    let comp = composition_of(&mf, "boot-gate-ceremony").expect("derivable");
    assert_eq!(comp.gate_target, "boot-gate-ceremony");
                                                                                                 
                                                                                             
                                                                              
    let legs_only = composition_of(&mf, "boot-gate-ceremony-legs").expect("derivable");
    for l in &legs_only.legs {
        assert!(
            comp.legs.contains(l),
            "the delegated leg `{}` is part of the parent composition",
            l.id
        );
    }
    assert!(
        comp.legs.len() > legs_only.legs.len(),
        "and the parent adds its own leg on top"
    );
    assert!(
        comp.legs.iter().any(|l| l.boots),
        "the must-boot rule: the ceremony gate boots the produced bytes"
    );
    for l in &comp.legs {
        assert!(
            registered_leg(&l.id).is_some(),
            "every declared leg is registered: {}",
            l.id
        );
    }
                                                                                           
                                                                                                
                                                                                                 
                                                                                  
    let e = composition_of(&mf, "boot-gate").expect_err("not enumerable from the recipe");
    assert!(
        e.contains("registry does not carry") || e.contains("ignored set"),
        "the refusal says WHAT it could not resolve: {e}"
    );
                                                                                                
              
    let unregistered =
        "t:\n\tcargo test -p orchard --test deploy_dryrun -- --ignored not_a_registered_leg\n";
    assert!(
        composition_of(unregistered, "t")
            .expect_err("unregistered leg")
            .contains("registry does not carry")
    );
    let whole_package = "t:\n\tcargo test -p recipes-image-builder -- --ignored\n";
    assert!(
        composition_of(whole_package, "t")
            .expect_err("whole-package invocation")
            .contains("ignored set")
    );
    let skip_filtered =
        "t:\n\tcargo test -p orchard --test deploy_prod_e2e -- --ignored --skip something\n";
    assert!(
        composition_of(skip_filtered, "t")
            .expect_err("skip-filtered invocation")
            .contains("ignored set")
    );
}

#[test]
fn a_renamed_ceremony_leg_breaks_the_derivation_rather_than_shrinking_it() {
                                                                                           
                                                                                               
                           
    let mf = makefile().replace(
        "dryrun_boots_to_working_runtime",
        "dryrun_boots_to_working_runtime_RENAMED",
    );
    let e = composition_of(&mf, "boot-gate-ceremony-legs").expect_err("a renamed leg breaks it");
    assert!(e.contains("registry does not carry"), "{e}");
}

                                                                                                    

use orchard::ceremony::gate_record::{
    GATE_TARGET_ENV, adopt_gate_record, emit_leg_pass, gate_record_path, profile_gate_record_path,
    read_gate_record, s10_precondition,
};
use orchard::ceremony::probes::ProbeResult;

/// The emission arms mutate a process-global env var, so they run one at a time.
fn emit_guard() -> std::sync::MutexGuard<'static, ()> {
    static M: std::sync::Mutex<()> = std::sync::Mutex::new(());
    M.lock().unwrap_or_else(|e| e.into_inner())
}

fn with_gate_target<T>(target: Option<&str>, f: impl FnOnce() -> T) -> T {
    unsafe {
        match target {
            Some(t) => std::env::set_var(GATE_TARGET_ENV, t),
            None => std::env::remove_var(GATE_TARGET_ENV),
        }
    }
    let out = f();
    unsafe {
        std::env::remove_var(GATE_TARGET_ENV);
    }
    out
}

#[test]
fn a_leg_outside_a_gate_target_emits_nothing_and_that_is_fail_closed() {
                                                                                            
                                                                             
    let _serial = emit_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (img, layout, vmlinuz, initramfs) = triple(tmp.path(), "abc1234");
    let p = compose("abc1234", params(), &img, &layout, &vmlinuz, &initramfs).expect("compose");
    write(&img, &p).expect("write");
    let emitted = with_gate_target(None, || {
        emit_leg_pass(&img, "dryrun_boots_to_working_runtime")
    })
    .expect("no target is not an error");
    assert!(!emitted, "nothing emitted without a gate target");
    assert!(!gate_record_path(&img).exists(), "no record file appears");
}

#[test]
fn legs_append_merge_into_one_record_and_a_second_run_of_a_leg_is_idempotent() {
    let _serial = emit_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (img, layout, vmlinuz, initramfs) = triple(tmp.path(), "abc1234");
    let p = compose("abc1234", params(), &img, &layout, &vmlinuz, &initramfs).expect("compose");
    write(&img, &p).expect("write");
    with_gate_target(Some("boot-gate-ceremony"), || {
        for id in [
            "dryrun_boots_to_working_runtime",
            "installed_disk_boots_through_seabios_to_working_runtime",
            "dryrun_boots_to_working_runtime",
        ] {
            assert!(emit_leg_pass(&img, id).expect("emit"));
        }
    });
    let rec = read_gate_record(&gate_record_path(&img)).expect("read");
    assert_eq!(rec.gate_target, "boot-gate-ceremony");
    assert_eq!(rec.image_label, "abc1234");
    assert_eq!(
        rec.staged, p.produced,
        "the record binds the image's own hashes"
    );
    assert_eq!(rec.params, p.params, "and the image's own build parameters");
    assert_eq!(
        rec.leg.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(),
        vec![
            "dryrun_boots_to_working_runtime",
            "installed_disk_boots_through_seabios_to_working_runtime"
        ],
        "a leg re-run appends no second row"
    );
}

#[test]
fn a_record_never_blends_two_gate_runs() {
                                                                                              
                                                                                                 
                  
    let _serial = emit_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (img, layout, vmlinuz, initramfs) = triple(tmp.path(), "abc1234");
    let p = compose("abc1234", params(), &img, &layout, &vmlinuz, &initramfs).expect("compose");
    write(&img, &p).expect("write");
    with_gate_target(Some("boot-gate-ceremony"), || {
        emit_leg_pass(&img, "dryrun_boots_to_working_runtime").expect("first")
    });
    let e = with_gate_target(Some("boot-gate"), || {
        emit_leg_pass(&img, "rescue_bundle_activates_on_corrupt_persist")
            .expect_err("a different target refuses")
    });
    assert_eq!(e.id.token(), "gate-record-mismatch");
    assert!(e.detail.contains("boot-gate-ceremony"), "{}", e.detail);
}

#[test]
fn the_s10_precondition_reads_the_profile_copy_not_the_out_dir_drop_point() {
                                                                                                  
    let _serial = emit_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).expect("mk");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Makefile"),
        repo.join("Makefile"),
    )
    .expect("copy the real Makefile — the composition comes from the real recipe");
    let out = tmp.path().join("out");
    std::fs::create_dir_all(&out).expect("mk");
    let (img, layout, vmlinuz, initramfs) = triple(&out, "abc1234");
    let p = compose("abc1234", params(), &img, &layout, &vmlinuz, &initramfs).expect("compose");
    write(&img, &p).expect("write");
    with_gate_target(Some("boot-gate-ceremony"), || {
        for l in composition_of(&makefile(), "boot-gate-ceremony")
            .expect("derivable")
            .legs
        {
            emit_leg_pass(&img, &l.id).expect("emit");
        }
    });
    let records_dir = tmp.path().join("boxes/alpha.d");
    std::fs::create_dir_all(&records_dir).expect("mk");
                                                                        
    match s10_precondition(Some(&img), Some(&records_dir), &repo, "boot-gate-ceremony") {
        ProbeResult::Unmet(why) => assert!(why.contains("gate-record"), "{why}"),
        other => panic!("an unadopted record must be not-ready, got {other:?}"),
    }
    adopt_gate_record(&img, &records_dir).expect("adopt");
    assert!(profile_gate_record_path(&records_dir).exists());
    assert_eq!(
        s10_precondition(Some(&img), Some(&records_dir), &repo, "boot-gate-ceremony"),
        ProbeResult::Met,
        "the adopted record satisfies S10"
    );
                                                                                                    
    std::fs::remove_file(gate_record_path(&img)).expect("rm");
    assert_eq!(
        s10_precondition(Some(&img), Some(&records_dir), &repo, "boot-gate-ceremony"),
        ProbeResult::Met
    );
                                                                                         
    assert!(matches!(
        s10_precondition(None, Some(&records_dir), &repo, "boot-gate-ceremony"),
        ProbeResult::Unevaluable(_)
    ));
    assert!(matches!(
        s10_precondition(Some(&img), None, &repo, "boot-gate-ceremony"),
        ProbeResult::Unevaluable(_)
    ));
                                                                              
    assert!(matches!(
        s10_precondition(Some(&img), Some(&records_dir), &repo, "boot-gate"),
        ProbeResult::Unmet(_)
    ));
}

#[test]
fn a_stale_gate_record_refusal_names_the_files_to_delete() {
                                                                                                
                                                                                                  
    let _serial = emit_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).expect("mk");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Makefile"),
        repo.join("Makefile"),
    )
    .expect("Makefile");
    let out = tmp.path().join("out");
    std::fs::create_dir_all(&out).expect("mk");
                                
    let (img, layout, vmlinuz, initramfs) = triple(&out, "aaa11111");
    let p = compose("aaa11111", params(), &img, &layout, &vmlinuz, &initramfs).expect("compose");
    write(&img, &p).expect("write");
    with_gate_target(Some("boot-gate-ceremony"), || {
        for l in composition_of(&makefile(), "boot-gate-ceremony")
            .expect("derivable")
            .legs
        {
            emit_leg_pass(&img, &l.id).expect("emit");
        }
    });
    let records_dir = tmp.path().join("boxes/alpha.d");
    std::fs::create_dir_all(&records_dir).expect("mk");
    adopt_gate_record(&img, &records_dir).expect("adopt");
                                                                                                    
    let (img2, layout2, vmlinuz2, initramfs2) = triple(&out, "bbb22222");
    let p2 = compose(
        "bbb22222",
        params(),
        &img2,
        &layout2,
        &vmlinuz2,
        &initramfs2,
    )
    .expect("compose");
    write(&img2, &p2).expect("write");
    match s10_precondition(Some(&img2), Some(&records_dir), &repo, "boot-gate-ceremony") {
        ProbeResult::Unmet(why) => {
            assert!(
                why.contains(&profile_gate_record_path(&records_dir).display().to_string()),
                "cure names the records-dir record: {why}"
            );
            assert!(
                why.contains(&gate_record_path(&img2).display().to_string()),
                "cure names the image record: {why}"
            );
        }
        other => panic!("a stale record must refuse with the recovery cure, got {other:?}"),
    }
}

#[test]
fn an_env_prefixed_invocation_still_classifies() {
                                                                                                   
                                                                               
    let sels = selectors_of(&[
        "@out=$$(RECIPES_GATE_TARGET=boot-gate-ceremony cargo test -p orchard --test deploy_dryrun \
         -- --ignored --nocapture dryrun_boots_to_working_runtime 2>&1); \\"
            .to_string(),
    ])
    .expect("classifies");
    assert_eq!(
        sels,
        vec![Selector::Named {
            test_binary: "deploy_dryrun".into(),
            names: vec!["dryrun_boots_to_working_runtime".into()],
        }]
    );
}

#[test]
fn the_real_domain_predicate_needs_all_three_properties_together() {
                                                                                           
                                                                                                  
                                                                                                 
    use orchard::ceremony::gate_record::satisfies_real_domain;
    let ok = leg("installed", true, true, BootPath::SeabiosInstalledDisk);
    assert!(satisfies_real_domain(std::slice::from_ref(&ok)));
    for missing in [
                                                                           
        leg("open_net", true, false, BootPath::SeabiosInstalledDisk),
                                                                                           
        leg("kernel_only", true, true, BootPath::DirectKernel),
                                                          
        leg("no_boot", false, true, BootPath::SeabiosInstalledDisk),
                                                                                        
        leg("prod_e2e", true, true, BootPath::ProdE2e),
    ] {
        assert!(
            !satisfies_real_domain(std::slice::from_ref(&missing)),
            "{} must not satisfy the real-domain rule on its own",
            missing.id
        );
    }
                                                                                               
    let mixed = vec![
        leg("open_net", true, false, BootPath::SeabiosInstalledDisk),
        leg("kernel_only", true, true, BootPath::DirectKernel),
        ok.clone(),
    ];
    assert!(satisfies_real_domain(&mixed));
    assert!(
        !satisfies_real_domain(&[]),
        "an empty composition satisfies nothing"
    );
}

#[test]
fn the_e2e_fixture_never_names_a_gate_target_containing_itself() {
                                                                                                   
                                                                                                
                                                                                         
    let fixture = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/deploy_ceremony_e2e.rs"),
    )
    .expect("read the e2e fixture");
    let declared = fixture
        .lines()
        .find_map(|l| l.trim().strip_prefix("gate_target = \\\""))
        .and_then(|r| r.split('\\').next())
        .expect("the fixture profile declares a gate_target");
    let mf = makefile();
    let comp = composition_of(&mf, declared)
        .unwrap_or_else(|e| panic!("the fixture's gate target must be derivable: {e}"));
    assert!(
        !comp
            .legs
            .iter()
            .any(|l| registered_leg(&l.id).is_some_and(|g| g.test_binary == "deploy_ceremony_e2e")),
        "the fixture's gate target `{declared}` contains the e2e leg — that recurses"
    );
                                                                                 
    assert!(
        comp.legs.iter().any(|l| l.boots),
        "{declared} boots something"
    );
                                                                                                
    let parent = composition_of(&mf, "boot-gate-ceremony").expect("derivable");
    assert!(
        parent
            .legs
            .iter()
            .any(|l| registered_leg(&l.id).is_some_and(|g| g.test_binary == "deploy_ceremony_e2e")),
        "the parent target runs the e2e"
    );
}

/// The full battery must not invoke the e2e either: `make boot-gate` is the battery the e2e's
/// ceremony would re-enter.
#[test]
fn the_full_battery_does_not_invoke_the_ceremony_e2e() {
    let mf = makefile();
    let recipe = recipe_of(&mf, "boot-gate").expect("boot-gate");
    for line in &recipe {
        assert!(
            !line.contains("deploy_ceremony_e2e"),
            "make boot-gate invokes the ceremony e2e, which re-enters it: {line}"
        );
    }
}

/// FAC-GC-16 shape 4b's driven half. `PathWriteId` makes a non-path id at a `write_atomic` call a
/// compile error; what the type does NOT decide is which path-write id each variant carries, and a
/// one-way mis-map (both variants to the same id) is invisible to the construction-site census.
/// `an_unwritable_profile_path_refuses_on_the_path_not_on_the_r44_content_rule`
/// (`ceremony_interview.rs`) drives the Profile direction through the interview; this drives both
/// variants at the write itself, exact-set over the closed enum.
#[test]
fn each_path_write_class_carries_its_own_path_write_refusal_id() {
    use orchard::ceremony::gate_record::{PathWriteId, write_atomic};
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let sealed = tmp.path().join("sealed");
    std::fs::create_dir_all(&sealed).expect("mk sealed");
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o555)).expect("seal");

                                                                                                    
                                                                                   
    if std::fs::write(sealed.join("probe"), "x").is_ok() {
        let _ = std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755));
        panic!(
            "a 0o555 dir is still writable here (running as root, or a mount that ignores the \
             mode), so this arm cannot express an unwritable path"
        );
    }

    let observed: Vec<(PathWriteId, String)> = [PathWriteId::Sidecar, PathWriteId::Profile]
        .into_iter()
        .map(|class| {
            let e = write_atomic(&sealed.join("out.toml"), "body = 1\n", class)
                .expect_err("a sealed directory cannot be written");
            (class, e.id.token().to_string())
        })
        .collect();
    let _ = std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755));

    assert_eq!(
        observed,
        vec![
            (PathWriteId::Sidecar, "sidecar-unwritable".to_string()),
            (PathWriteId::Profile, "profile-unwritable".to_string()),
        ],
        "each write class must carry its own remedy; a shared id hands a sidecar failure the \
         profile's remedy"
    );
}
