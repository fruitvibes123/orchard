                                                                                            
                                                                                                        
//! which would otherwise surface only as an OOM or a dead env deep inside a KVM gate — or worse, as a
//! green gate measuring the wrong thing:
//!
//!   1. The manifest validates through the same §4.1 bake gate as every tenant manifest.
//!   2. The cgroup budget clears box-init's OWN admission predicate — `Σ + BOX_RESERVE ≤ MemTotal`
//!      against the REAL 512 MiB reserve and a realistic MemTotal, with margin.
//!   3. The engine leaf holds the measured TEXT-lane working set resident.
//!   4. The engine env carries exactly what creatine reads TODAY — and NOT the two vars it cannot act
//!      on yet, because a baked-but-dead env is indistinguishable at the gate from a working one.
//!   5. The pin profile for this manifest is the PRODUCTION VL pair, with a payload large enough that
                                                                       
//!   6. EVERY shipped tenant manifest — not just this one — clears the admission predicate.
//!
//! Check 2/6 exist because this is the class of defect that reaches production silently: nothing in
//! `make verify` evaluated box-init's predicate, so a manifest citing the wrong reserve constant looked
                                                                          

use recipes_image_builder::config;
use recipes_image_builder::models::Models;
use std::path::Path;

const PROD: &str = include_str!("../prod-cotenant.toml");
                                                                                                       
/// real path or the test would validate a profile the bake never reads.
const PROD_MANIFEST: &str = "crates/image-builder/prod-cotenant.toml";

/// The prod box's NOMINAL RAM.
const PROD_BOX_MIB: u64 = 2048;
/// box-init's own-footprint reserve — **512 MiB**, read from `fruit-basket/crates/box-init/src/cgroup.rs:27`
/// (`BOX_RESERVE_BYTES`). An earlier revision of this test hardcoded 256 and therefore "verified" a
                                                                                                       
/// test must be updated with it — there is no cross-repo import to do it automatically.
const BOX_RESERVE_MIB: u64 = 512;
/// `MemTotal` is total USABLE RAM — always strictly below the nominal VM size (kernel image, memmap,
/// reserved e820 regions come off the top). Asserting against the NOMINAL size is exactly the mistake
                           
///
/// MEASURED per box size by booting this box's own kernel. Fail-closed: a manifest written for a size
/// with no measurement here is an ERROR, never an interpolation — this number must not be guessed.
fn measured_memtotal_mib(box_mib: u64) -> u64 {
    match box_mib {
                                                                                                         
        2048 => 1939,
                                                                                 
        1536 => 1439,
        other => panic!(
            "no MEASURED MemTotal for a {other} MiB box. Boot the box kernel at -m {other}, read \
             MemTotal, and add it here — do NOT interpolate or fall back to the nominal size, which is \
             the defect this table exists to prevent"
        ),
    }
}

/// The prod box's MemTotal, for the prod-specific assertions below.
const PROD_MEMTOTAL_MIB: u64 = 1939;

/// Every shipped tenant manifest and the box RAM it is WRITTEN FOR. Budgeting the 1536 MiB bench
                                                                                                     
const TENANT_MANIFESTS: [(&str, u64); 4] = [
    ("prod-cotenant.toml", 2048),
    ("dha-tenant.toml", 2048),
    ("hotswap-tenant.toml", 1536),
    ("toy-tenant.toml", 2048),
];

const MIB: u64 = 1024 * 1024;

fn prod() -> fb_manifest::ValidatedManifest {
    fb_manifest::parse_and_validate(PROD, &config::os_identities())
        .expect("the prod co-tenant manifest must validate through the §4.1 bake gate")
}

fn models() -> Models {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root");
    Models::load(root).expect("models.toml must load + validate")
}

fn engine_env(vm: &fb_manifest::ValidatedManifest) -> Vec<(String, String)> {
    let m = vm.manifest();
    let engine = m
        .resource_domain
        .as_ref()
        .and_then(|rd| rd.engine.as_ref())
        .expect("the prod manifest must declare a resource_domain engine");
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

#[test]
fn prod_manifest_validates_and_names_creatine_as_the_engine() {
    let vm = prod();
    let engine = vm
        .manifest()
        .resource_domain
        .as_ref()
        .and_then(|rd| rd.engine.as_ref())
        .expect("resource_domain.engine");
    assert_eq!(engine.service, "creatine");
}

/// The budget must satisfy box-init's OWN admission predicate at the prod box size. If it does not, the
/// box refuses the resource domain at boot — a failure that would otherwise appear only in a gate run.
#[test]
fn the_cgroup_budget_fits_the_2gib_prod_box() {
    let vm = prod();
    let m = vm.manifest();
    let rd = m.resource_domain.as_ref().expect("resource_domain");
    let sigma_mib = rd.memory_max.0 / MIB;

                                                                                                   
                                                                                                        
                               
    assert!(
        sigma_mib + BOX_RESERVE_MIB <= PROD_MEMTOTAL_MIB,
        "box-init enforces Σ + BOX_RESERVE ≤ MemTotal: Σ={sigma_mib} + {BOX_RESERVE_MIB} = {} MiB \
         exceeds the ~{PROD_MEMTOTAL_MIB} MiB MemTotal of a {PROD_BOX_MIB} MiB box — box-init would \
         refuse the resource domain and fatal(), boot-looping the target",
        sigma_mib + BOX_RESERVE_MIB
    );
                                                                                                    
                                                                                                      
    let headroom = PROD_MEMTOTAL_MIB - (sigma_mib + BOX_RESERVE_MIB);
    assert!(
        headroom >= 64,
        "Σ={sigma_mib} MiB + reserve leaves only {headroom} MiB under MemTotal — too close to the \
         admission ceiling to survive MemTotal varying with kernel/firmware"
    );

    let engine = rd.engine.as_ref().expect("resource_domain.engine");
    assert!(
        engine.memory_max.0 < rd.memory_max.0,
        "cap-coherence §4.1: the engine leaf must be strictly below Σ"
    );

                                                                                                       
                                                                                                            
                                                                                                        
                                                                                                           
                                                                                      
    let text_lane_working_set_mib = 1_147;                                                   
    assert!(
        engine.memory_max.0 / MIB >= text_lane_working_set_mib,
        "engine leaf {} MiB is below the measured text-lane working set (~{text_lane_working_set_mib} \
         MiB) — the text lane would churn the weights plane back through verity",
        engine.memory_max.0 / MIB
    );
}

/// The env contract: exactly what creatine reads today, and NOTHING it cannot act on. The absent pair is
/// the load-bearing half — baking `CREATINE_MMPROJ_PATH`/`CREATINE_TOWER_CACHE` before the serve wire
/// exists would make the prod manifest LOOK vision-capable while the binary ignores both, which is
/// precisely the "gate greens describe a different artifact" failure this cycle exists to close.
#[test]
fn the_engine_env_carries_only_what_creatine_reads_today() {
    let env = engine_env(&prod());
    let get = |k: &str| {
        env.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
    };

    assert_eq!(
        get("CREATINE_MODEL_PATH"),
        Some("/models/model.gguf"),
        "the canonical in-volume name keeps this env constant across model swaps"
    );
    assert_eq!(
        get("CREATINE_LOWMEM"),
        Some("1"),
        "mmap-backed weights are what make the file plane evictable under the engine cap"
    );
                                                                                                    
    assert_eq!(
        get("CREATINE_BIND"),
        Some("unix:/run/creatine/creatine.sock")
    );
    assert!(
        get("CREATINE_MODEL").is_some_and(|m| !m.is_empty()),
        "creatine rejects a request whose model id != its CREATINE_MODEL"
    );

    for dead in ["CREATINE_MMPROJ_PATH", "CREATINE_TOWER_CACHE"] {
        assert!(
            get(dead).is_none(),
            "{dead} is baked but creatine-serve has no mmproj load path (main.rs → \
             families::load_engine → Qwen2Engine::load, single-GGUF). A dead env reads as a working \
             one at the gate — it lands with creatine's vision-oracle envelope, not before"
        );
    }
}

                                                                                                        
/// enough that the built image exceeds the 2 GiB guest. A profile silently reverted to a bench fixture
/// would leave both gates green while proving nothing about prod margins — the exact defect §13.1 names.
#[test]
fn the_prod_profile_pins_the_vl_pair_and_clears_the_image_over_ram_premise() {
    let models = models();
    let profile = models
        .profile_for_manifest(Some(Path::new(PROD_MANIFEST)))
        .expect("the prod co-tenant manifest must have a models.toml pin profile");

    let mmproj = profile.weights.mmproj.as_ref().expect(
        "the PRODUCTION profile must pin the vision projector — the pair is what sizes the image",
    );
    assert!(
        mmproj.file.contains("mmproj"),
        "the projector pin must actually be an mmproj artifact: {}",
        mmproj.file
    );

                                                                                                   
                                                                                                   
                                                                                                              
                                                                         
    let payload_mib = profile.weights.payload_bytes() / MIB;
    assert!(
        payload_mib >= 1_700,
        "the prod payload is only {payload_mib} MiB — too small to make the image unbufferable in a \
         {PROD_BOX_MIB} MiB guest (whole premise)"
    );
}

/// EVERY shipped tenant manifest must clear box-init's admission predicate — each against the box size
/// it is actually written for.
///
                                                                                                        
/// and against NOMINAL RAM rather than MemTotal. Nothing in `make verify` evaluated the predicate, so it
/// was invisible until the target boot-looped.
///
/// TWO gaps closed after audit R2, both of which R2 mutation-proved were open:
                                                                                                    
///     1536 MiB VM — admitting a Σ up to 1.54× that box's real ceiling. Sizes are now per-manifest.
                                                                                                   
///     fifth manifest failed OPEN. The list is now cross-checked against the crate directory.
#[test]
fn every_shipped_manifest_clears_box_inits_admission_predicate() {
                                                                                                       
                                                    
      
                                                                                                     
                                                                                                    
                                                                                                         
                                                                                                       
                                                                                               
      
                                                                                                    
                                                        
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut on_disk: Vec<String> = std::fs::read_dir(crate_dir)
        .expect("read the image-builder crate dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".toml"))
        .filter(|n| {
            std::fs::read_to_string(crate_dir.join(n)).is_ok_and(|toml| {
                fb_manifest::parse_and_validate(&toml, &config::os_identities()).is_ok()
            })
        })
        .collect();
    on_disk.sort();
    let mut covered: Vec<String> = TENANT_MANIFESTS
        .iter()
        .map(|(n, _)| (*n).to_string())
        .collect();
    covered.sort();
    assert_eq!(
        on_disk, covered,
        "the tenant-manifest table is stale. EVERY .toml in the crate that validates as a tenant \
         manifest must be budgeted against the box size it targets — an uncovered manifest fails \
         OPEN (audit; name-independent membership per)"
    );

    let mut checked = 0;
    for (name, box_mib) in TENANT_MANIFESTS {
        let toml = std::fs::read_to_string(crate_dir.join(name))
            .unwrap_or_else(|e| panic!("read {name}: {e}"));
        let vm = fb_manifest::parse_and_validate(&toml, &config::os_identities())
            .unwrap_or_else(|e| panic!("{name} must validate through the §4.1 bake gate: {e:?}"));
        let Some(rd) = vm.manifest().resource_domain.as_ref() else {
            continue;                                    
        };
        checked += 1;
        let memtotal = measured_memtotal_mib(box_mib);
        let sigma_mib = rd.memory_max.0 / MIB;
        assert!(
            sigma_mib + BOX_RESERVE_MIB <= memtotal,
            "{name} (written for a {box_mib} MiB box): Σ={sigma_mib} MiB + the {BOX_RESERVE_MIB} MiB \
             box-init reserve = {} MiB exceeds that box's MEASURED MemTotal of {memtotal} MiB. \
             box-init would refuse the resource domain (cgroup.rs:114) and fatal() — the target \
             BOOT-LOOPS. Size Σ against MemTotal minus the REAL reserve, never against nominal RAM",
            sigma_mib + BOX_RESERVE_MIB
        );
        if let Some(engine) = rd.engine.as_ref() {
            assert!(
                engine.memory_max.0 < rd.memory_max.0,
                "{name}: cap-coherence §4.1 — the engine leaf must be strictly below Σ"
            );
        }
    }
    assert!(
        checked >= 3,
        "expected at least 3 manifests with a resource_domain, walked {checked} — did the list go stale?"
    );
}

                                                                                                     
                                                                                                 
                                                                                                
                                                                                            
                                                         

/// Defect 1 — an EMPTY `mtls_paths` rendered `acl is_android_api` with NO criterion, which haproxy
/// rejects fatally (`missing fetch method in ACL expression ''`). Assert allowlist-style over EVERY
/// emitted acl: each must carry a criterion, so this catches the whole class rather than one name.
#[test]
fn every_rendered_acl_carries_a_criterion() {
    let m = prod();
                                                                                              
                                                                                                    
                                                                                                        
                                                       
    let cfg = config::haproxy_config(
        &m.manifest().edge,
        &fb_manifest::PlaceholderCtx {
            domain: "prod.test".into(),
            source_date_epoch: 0,
        },
    )
    .expect("the prod co-tenant edge must render — every throttle rule declares paths");
    let mut seen = 0usize;
    for line in cfg.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("acl ") else {
            continue;
        };
        seen += 1;
        let mut it = rest.split_whitespace();
        let name = it.next().unwrap_or_default();
        let criterion = it.next().unwrap_or_default();
        assert!(
            !name.is_empty() && !criterion.is_empty(),
            "haproxy would refuse `acl {name}` — an acl with no criterion is parse-fatal \
             (the 2026-07-25 produced-bytes defect); full line: {line:?}"
        );
    }
    assert!(seen > 0, "expected the render to emit acls at all");
    assert!(
        cfg.contains("acl is_android_api path_beg"),
        "the mTLS gate must render with its path_beg criterion"
    );
}

/// Defect 2 — haproxy's `bind *:443` names `/persist/acme/<domain>/full.pem`, and NOTHING created it:
/// the manifest declared no `bootstrap-acme-cert` boot hook, so the file was absent and the bind was
/// fatal (`unable to stat SSL certificate`). Tie the two together: if the render depends on the cert,
/// the manifest must declare the hook that writes it.
///
                                                                                       
/// prod-cotenant-only assertion, which left the very defect it describes live on `dha-tenant`,
/// `hotswap-tenant` and `toy-tenant` — all three bound a cert none of them created. A single-manifest
/// guard for a whole-class defect reads as coverage while providing none, and the sibling mTLS-acl
/// guard was already class-shaped, so this was the odd one out.
///
                                                                                                 
/// real as the sibling census test that asserts that table EQUALS the on-disk validated manifest set
/// (the `n.contains("tenant")` census at line ~257). A new manifest that census refuses is what keeps
/// this table honest; do not read this loop as auto-discovering shipped manifests on its own.
#[test]
fn every_bound_cert_has_a_boot_hook_that_creates_it() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    for (name, _) in TENANT_MANIFESTS {
        let toml = std::fs::read_to_string(crate_dir.join(name))
            .unwrap_or_else(|e| panic!("read {name}: {e}"));
        let m = fb_manifest::parse_and_validate(&toml, &config::os_identities())
            .unwrap_or_else(|e| panic!("{name} must validate through the §4.1 bake gate: {e:?}"));
        let cfg = config::haproxy_config(
            &m.manifest().edge,
            &fb_manifest::PlaceholderCtx {
                domain: "prod.test".into(),
                source_date_epoch: 0,
            },
        )
        .unwrap_or_else(|e| panic!("{name}'s edge must render: {e}"));
                                                                                                      
                                                         
        if !cfg.contains("/persist/acme/prod.test/full.pem") {
            continue;
        }
        checked += 1;
        let hooks: Vec<&str> = m
            .manifest()
            .boot_hooks
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        assert!(
            hooks.contains(&"bootstrap-acme-cert"),
            "{name}: the render binds an acme cert but no boot hook creates it — haproxy would be \
             parse-fatal on a fresh box and crash-loop under s6 forever. hooks present: {hooks:?}"
        );
    }
    assert!(
        checked >= 4,
        "expected every shipped tenant manifest to bind a TLS cert and be checked here; only \
         {checked} were — a vacuous pass would hide exactly the defect this guards"
    );
}
