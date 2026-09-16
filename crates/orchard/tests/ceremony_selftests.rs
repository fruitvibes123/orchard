                                                                                                 
//! the REAL surfaces they quantify over — the clap enums/flag surfaces (recursive walk, aliases
                                                                                            
                                                                                         
//! (`ceremony-seed-*`, driven by `make ceremony-seeds`, each expecting a red).
//!
//! Rides `make verify` via `cargo test --workspace`.

use std::collections::{BTreeMap, BTreeSet};

use clap::{CommandFactory, Parser};

use orchard::ceremony::classify::{
    FlagClass, GLOBAL_BENIGN_FLAGS, VerbClass, VerbId, class_of_short_token, class_of_token,
    flag_table, is_no_op_exit_token, table_flags_of, verb_class, walk_long_flags,
};
use orchard::ceremony::param::{
    DefaultWithSource, ParamClass, ParamValues, probe_firmware, probe_key_file, probe_out_dir,
};
use orchard::ceremony::probes::{ProbeCtx, ProbeResult};
use orchard::ceremony::spine::{
    ExecutorClass, GateClass, PreconditionSetId, Program, SPINE, StepId, spine_modeled_verbs,
};
use orchard::cli::Cli;
use orchard::deploy::profile::PROFILE_KEYS;

                                                                                                   

fn parse(argv: &[&str]) -> orchard::cli::OrchardCmd {
    let mut full = vec!["orchard"];
    full.extend_from_slice(argv);
    Cli::try_parse_from(full)
        .unwrap_or_else(|e| panic!("parse {argv:?}: {e}"))
        .command
}

fn ctx_fixture() -> (tempfile::TempDir, ProbeCtx) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("orchard");
    std::fs::create_dir_all(root.join("crates/image-builder")).expect("mk root");
    let ctx = ProbeCtx::from_paths(
        root.clone(),
        tmp.path().join("store"),
        root.join("repo-manifest.toml"),
    );
    (tmp, ctx)
}

fn plausible(name: &str) -> String {
    match name {
        "image_version" | "port" => "22".to_string(),
        "tenant_artifacts" => "binary:recipes-app,config:service-manifest".to_string(),
        "firmware" => "seabios".to_string(),
        other => format!("val-{other}"),
    }
}

/// Plausible values for every declared param of a step.
fn values_for(step: &orchard::ceremony::spine::Step) -> ParamValues {
    let mut v = ParamValues::default();
    for p in step.params {
        v.insert(p.name, plausible(p.name));
    }
    v
}

                                                                                                   

                                                                              
/// `ceremony-seed-unclassified-verb` demonstrates the red build). This arm grounds the VALUES on
/// the two finding-cited cases plus the full read-only complement, driven through real parses.
#[test]
fn verb_classification_values_hold() {
                                                                             
    let read_only: &[&[&str]] = &[
        &["derive-rescue-offline", "--image", "/x.img"],
        &["status", "h", "--ssh-identity", "/k"],
        &["doctor"],
        &["market", "verify"],
        &["market", "outdated"],
        &["market", "store", "status"],
    ];
    for argv in read_only {
        assert_eq!(
            verb_class(&parse(argv)),
            VerbClass::ReadOnly,
            "{argv:?} must be READ-ONLY"
        );
    }
                                                                            
    assert_eq!(
        verb_class(&parse(&["market", "store", "prune"])),
        VerbClass::Writing
    );
                                                                                               
                                                  
    for argv in [
        vec!["vendor"],
        vec!["prime"],
        vec!["sync-pins"],
        vec!["refresh-apk-lock"],
        vec!["market", "upgrade", "--source", "x"],
        vec!["market", "store", "migrate"],
        vec!["build", "--domain", "box.test"],
        vec!["generate-keys"],
        vec!["dryrun"],
                                                                                         
        vec!["run", "boxes/alpha.toml"],
    ] {
        assert_eq!(
            verb_class(&parse(&argv)),
            VerbClass::Writing,
            "{argv:?} must be WRITING"
        );
    }
}

                                                                                                   

#[test]
fn flag_classification_is_total_over_the_walked_surfaces() {
    for verb in spine_modeled_verbs() {
        let walked = walk_long_flags(verb.command_path());
        let walked_longs: BTreeSet<&str> = walked
            .iter()
            .map(|f| f.long.as_str())
            .filter(|l| !GLOBAL_BENIGN_FLAGS.contains(l))
            .collect();
        let table: BTreeSet<&str> = table_flags_of(verb);
        let missing: Vec<_> = walked_longs.difference(&table).collect();
        let stale: Vec<_> = table.difference(&walked_longs).collect();
        assert!(
            missing.is_empty() && stale.is_empty(),
            "flag table vs walked surface for {verb:?}:\n  unclassified (add to flag_table): \
             {missing:?}\n  stale (not on the surface): {stale:?}"
        );
                                                               
        for f in &walked {
            for a in &f.aliases {
                assert!(
                    class_of_token(verb, a).is_some(),
                    "{verb:?}: alias --{a} (of --{}) does not resolve to a class",
                    f.long
                );
            }
        }
    }
                                                                    
    assert_eq!(
        class_of_token(VerbId::MarketUpgrade, "yes"),
        Some(FlagClass::ConsentBearing),
        "--yes must resolve through its canonical --commit"
    );
                                                                                                
                                                                                                 
                                                                              
    assert_eq!(
        class_of_token(VerbId::Run, "commit"),
        Some(FlagClass::ConsentBearing),
        "run --commit must classify ConsentBearing"
    );
    assert_eq!(
        class_of_token(VerbId::Run, "wipe-confirmed"),
        Some(FlagClass::MandatoryDestructiveToken),
        "run --wipe-confirmed must classify MandatoryDestructiveToken"
    );
}

/// Delta v3.5 §6 row E5 / §7 Q-typed-token: every destructive token the interview can require an
/// operator to type is a `run` flag that sets `wipe_confirmed`.
///
/// What it claims: for each `(verb, flag, MandatoryDestructiveToken)` row of `flag_table()` whose
/// verb is a SPINE step's verb — the rows `required_typed_tokens` quantifies over — `orchard run
/// <profile> --<flag>` parses and the parsed `Run` carries `wipe_confirmed`. The token set is
/// derived from the table and the spine, not hand-listed, so a second such row that `run` cannot
/// take reddens this arm. It matters because `conduct` maps the typed set onto
/// `RunInvocation.wipe_confirmed` by the literal `--wipe-confirmed` (delta §0.4): a second token
/// would be required of the operator, accepted by the interview and then carried by nothing. What
/// it does NOT claim: that `run` refuses a token outside the set (the parser's own domain), nor
/// anything about the OTHER flag classes. Blind spots, named: a destructive spine step whose verb
/// is `None` declares no token and is outside the derivation; the interview's own emission is
/// `required_typed_tokens`' arms.
#[test]
fn every_destructive_token_a_spine_step_owes_parses_as_run_and_sets_wipe_confirmed() {
    let spine_verbs: BTreeSet<VerbId> = SPINE.iter().filter_map(|s| s.verb).collect();
    let tokens: Vec<&str> = flag_table()
        .iter()
        .filter(|(v, _, c)| spine_verbs.contains(v) && *c == FlagClass::MandatoryDestructiveToken)
        .map(|(_, flag, _)| *flag)
        .collect();
                                                                                             
    assert!(
        !tokens.is_empty(),
        "no spine step's verb carries a MandatoryDestructiveToken row, so this arm proves nothing"
    );
    for flag in tokens {
        let argv = ["run", "boxes/p.toml", &format!("--{flag}")].map(String::from);
        let cmd = Cli::try_parse_from(std::iter::once("orchard".to_string()).chain(argv))
            .unwrap_or_else(|e| {
                panic!("`orchard run <profile> --{flag}` is required of the operator and does not parse: {e}")
            })
            .command;
        match cmd {
            orchard::cli::OrchardCmd::Run { wipe_confirmed, .. } => assert!(
                wipe_confirmed,
                "`--{flag}` parses on run without setting wipe_confirmed, which is the field \
                 `conduct` carries"
            ),
            _ => panic!("`run --{flag}` parsed as another verb"),
        }
    }
}

                                                                                                  
                                                                                          
/// `class_of_token(...).unwrap_or_else(|| panic!(...))`, so a `Some(Benign)` fallback makes BOTH
/// vacuous at once — an unclassified composed flag would then be silently accepted as harmless.
/// `make ceremony-seeds` seed 1 does not catch it either (its `--yes` resolves through the real
/// alias branch, which the revert leaves intact). Nothing asserted the NEGATIVE direction; this
/// arm does, over the whole verb domain.
#[test]
fn class_of_token_refuses_an_unclassified_token_for_every_verb() {
    for verb in spine_modeled_verbs() {
                                                                                               
                                                                                                
                                                                                                
                                                                                        
        let flags = table_flags_of(verb);
        let &known = flags
            .iter()
            .next()
            .unwrap_or_else(|| panic!("{verb:?} has no classified flags; the table lookup broke"));
        assert!(
            class_of_token(verb, known).is_some(),
            "{verb:?}: the classified flag --{known} must resolve"
        );
                                                                                                  
                                                       
        for token in [
            "definitely-not-a-flag-xyzzy",
            "--definitely-not-a-flag-xyzzy",
            "definitely-not-a-flag-xyzzy=value",
            "",
        ] {
            assert_eq!(
                class_of_token(verb, token),
                None,
                "{verb:?}: the unclassified token {token:?} resolved to a class. The composition \
                 gate's two arms reach the class through `unwrap_or_else(panic)`, so a fallback \
                 class makes both vacuous and lets an unclassified flag compose"
            );
        }
    }
}

/// D-FH2-3: `GLOBAL_BENIGN_FLAGS` must equal the real clap global surface (every root arg with
/// `global = true`) plus clap's auto help/version, so a new global or a dropped one cannot leave
/// the list classifying a verb-local flag Benign without a red build.
#[test]
fn global_benign_flags_equals_the_clap_global_surface() {
    let root = Cli::command();
    let mut derived: BTreeSet<&str> = root
        .get_arguments()
        .filter(|a| a.is_global_set())
        .filter_map(|a| a.get_long())
        .collect();
                                                                                         
    derived.insert("help");
    derived.insert("version");
    let declared: BTreeSet<&str> = GLOBAL_BENIGN_FLAGS.iter().copied().collect();
    assert_eq!(
        derived,
        declared,
        "GLOBAL_BENIGN_FLAGS drifted from the clap global surface.\n  \
         in clap not in the const: {:?}\n  in the const not in clap: {:?}",
        derived.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&derived).collect::<Vec<_>>(),
    );
}

                                                                                          
/// unchecked. `class_of_short_token` resolves a short token through the verb's real clap surface
/// (`get_short`) to its long name and classifies that. No verb DECLARES a short option today (clap's
/// auto `-h`/`-V` are not in `get_arguments()`), so every single-dash token is unclassified here and
/// the gate refuses it — the get_short resolution is what would classify a benign short flag a verb
/// gains later, instead of refusing it.
#[test]
fn short_tokens_are_unclassified_until_a_verb_declares_one() {
                                                                                                    
    for tok in ["-h", "-y", "-V"] {
        assert_eq!(
            class_of_short_token(VerbId::Build, tok),
            None,
            "{tok}: build declares no short option, so it does not resolve to a class"
        );
    }
                                                                      
    assert_eq!(class_of_short_token(VerbId::Build, "--domain"), None);
    assert_eq!(class_of_short_token(VerbId::Build, "box.test"), None);
                                                                                                     
                                                                                                  
                                       
    assert_eq!(
        class_of_token(VerbId::Build, "domain"),
        Some(FlagClass::Benign)
    );
}

                                                                                                     

#[test]
fn compositions_stay_inside_declared_surfaces_and_forbidden_classes_are_never_composed() {
    for step in SPINE.iter() {
        let values = values_for(step);
        for inv in (step.compose)(&values) {
            match inv.program {
                Program::External(p) => {
                    assert!(
                        ["docker", "make"].contains(&p),
                        "{:?}: external program {p:?} is not allowlisted",
                        step.id
                    );
                }
                Program::SelfExe => {
                    let verb = step.verb.unwrap_or_else(|| {
                        panic!("{:?}: SelfExe composition without a bound verb", step.id)
                    });
                                                                        
                    let path = verb.command_path();
                    assert!(
                        inv.args.len() >= path.len()
                            && inv.args[..path.len()].iter().zip(path).all(|(a, p)| a == p),
                        "{:?}: argv {:?} does not start with {path:?}",
                        step.id,
                        inv.args
                    );
                    for tok in &inv.args {
                        assert!(
                            !is_no_op_exit_token(verb, tok),
                            "{:?}: composed token {tok} is a no-op-and-exit-0 flag: \
                             the child would exit 0 without running the verb, leaving the step \
                             recorded DONE with nothing produced",
                            step.id
                        );
                        if let Some(stripped) = tok.strip_prefix("--") {
                            let class = class_of_token(verb, stripped).unwrap_or_else(|| {
                                panic!(
                                    "{:?}: composed flag {tok} is not on {verb:?}'s classified \
                                     surface",
                                    step.id
                                )
                            });
                            assert!(
                                matches!(class, FlagClass::Benign | FlagClass::ForwardablePin),
                                "{:?}: composed flag {tok} has forbidden class {class:?} \
                                 (consent-bearing/guard-disabling/destructive tokens are \
                                 never composed)",
                                step.id
                            );
                        } else if tok.starts_with('-') && tok != "-" {
                                                                                            
                                                                                                    
                                                                                               
                                                                                                       
                            let class = class_of_short_token(verb, tok).unwrap_or_else(|| {
                                panic!(
                                    "{:?}: composed single-dash token {tok} is not a classified \
                                     short flag on {verb:?}; composers emit long flags",
                                    step.id
                                )
                            });
                            assert!(
                                matches!(class, FlagClass::Benign | FlagClass::ForwardablePin),
                                "{:?}: composed short flag {tok} has forbidden class {class:?}",
                                step.id
                            );
                        }
                    }
                }
            }
        }
    }
}

                                                                              
/// parameter the step does not declare. `ParamValues::get` records every queried name in an
/// interior-mutable access log, reached by `compose(&values)` and by `ProbeCtx::value` inside a
/// precondition/done-probe; the arm asserts accessed ⊆ declared. The composer-only form could not
                                                                                                
/// covering preconditions + done-probes closes it (the same generator as the mutation M-G,
/// `P_DOMAIN` removed from S7 while `compose_s7` still reads it).
///
/// Preconditions run over the step's PLAUSIBLE values with the network seam, so a value-gated read
/// (one behind a presence check) is taken and logged without an SSH attempt (FAC-GC-12, closes
/// P-G). Done-probes run over the same plausible values, so a value-gated read there is logged too
/// (D-FH2-4, closes P-G2).
#[test]
fn no_step_clause_reads_an_undeclared_parameter() {
    for step in SPINE.iter() {
        let declared: BTreeSet<String> = step.params.iter().map(|p| p.name.to_string()).collect();
        let check = |accessed: BTreeSet<String>, clause: &str| {
            let undeclared: Vec<String> = accessed
                .into_iter()
                .filter(|n| !declared.contains(n))
                .collect();
            assert!(
                undeclared.is_empty(),
                "{:?}: {clause} read UNDECLARED parameter(s) {undeclared:?} — declare them in the \
                 step's params or stop reading them",
                step.id
            );
        };
                                                                            
        let values = values_for(step);
        let _ = (step.compose)(&values);
        check(values.accessed_names(), "compose");
                                                                                                  
                                                                                      
        for pre in step.preconditions {
            let (_tmp, base) = ctx_fixture();
            let ctx = base.with_values(values_for(step)).with_network_seam();
            let _ = (pre.run)(&ctx);
            check(ctx.accessed_names(), pre.id);
        }
                                                                                                  
                                                                                                 
                           
        if let Some(done) = step.artifact_present {
            let (_tmp, base) = ctx_fixture();
            let ctx = base.with_values(values_for(step)).with_network_seam();
            let values = values_for(step);
            let _ = (done.run)(&ctx, &values);
            let mut accessed = ctx.accessed_names();
            accessed.extend(values.accessed_names());
            check(accessed, done.id);
        }
    }
}

                                                                                                 
/// over ADVERSARIAL values (not one fixture) and asserts no consent/guard/destructive token ever
/// composes. `--rust`/`--kernel` (the whole-toolchain re-pin) and `--commit`/`--yes` (consent)
/// must never appear.
#[test]
fn s6_composition_rejects_non_artifact_kinds_over_adversarial_values() {
    let s6 = SPINE
        .iter()
        .find(|s| s.id == StepId::S6TenantRepin)
        .expect("S6");
    let verb = s6.verb.expect("S6 verb");
                                                                                         
                                                                                                   
                                                                                                 
                                                                                     
    for (adversarial, want) in [
        ("commit:x", 0),
        ("yes:x", 0),
        ("rust:1.99.0", 0),
        ("kernel:6.99", 0),
        ("all:x", 0),
        ("binary:recipes-app,rust:1.99.0,commit:x", 1),
        ("source:grape-src", 1),
        ("binary:a,config:b,source:c", 3),
    ] {
        let mut values = ParamValues::default();
        values.insert("tenant_artifacts", adversarial.to_string());
        let invs = (s6.compose)(&values);
        assert_eq!(
            invs.len(),
            want,
            "{adversarial:?}: composed {} invocations, expected {want}",
            invs.len()
        );
        for inv in &invs {
            for tok in &inv.args {
                if let Some(flag) = tok.strip_prefix("--") {
                                                                                 
                    let class = class_of_token(verb, flag)
                        .unwrap_or_else(|| panic!("{adversarial:?}: composed unknown flag {tok}"));
                    assert_eq!(
                        class,
                        FlagClass::Benign,
                        "{adversarial:?}: composed a non-Benign flag {tok} ({class:?})"
                    );
                    assert!(
                        ["--source", "--binary", "--config"].contains(&tok.as_str()),
                        "{adversarial:?}: composed {tok}, not one of --source/--binary/--config"
                    );
                }
            }
        }
    }
}

                                                                                              
/// reads option-form tokens as flags. The composer must not pass a raw unvalidated value: it
/// prepends `--` (closes the `-f<mk>`/`--eval=` shapes, grounded on GNU Make 4.4.1) and falls back
/// to the safe default for any value that is not argv-positional-safe (closes `VAR=value`, which
/// survives `--`). The enforcing layer is `P_GATE_TARGET`'s `probe_argv_positional`, checked
/// separately below.
#[test]
fn s8_gate_composition_never_passes_a_raw_unsafe_make_arg() {
    let s8 = SPINE
        .iter()
        .find(|s| s.id == StepId::S8BootGate)
        .expect("S8");
                                                                                                    
                                                                                                
    let dflt = orchard::ceremony::spine::CEREMONY_GATE_TARGET.to_string();
                                                          
    for (target, want) in [
        (None, vec!["--".to_string(), dflt.clone()]),
        (
            Some("custom-gate"),
            vec!["--".to_string(), "custom-gate".to_string()],
        ),
                                                                                      
        (Some("-f/tmp/fake.mk"), vec!["--".to_string(), dflt.clone()]),
        (
            Some("--eval=$(shell x)"),
            vec!["--".to_string(), dflt.clone()],
        ),
        (Some("IMG=/evil"), vec!["--".to_string(), dflt.clone()]),
        (Some("a b"), vec!["--".to_string(), dflt.clone()]),
    ] {
        let mut values = ParamValues::default();
        if let Some(t) = target {
            values.insert("gate_target", t.to_string());
        }
        let invs = (s8.compose)(&values);
        assert_eq!(invs.len(), 1, "{target:?}: one make invocation");
        assert_eq!(
            invs[0].program,
            Program::External("make"),
            "{target:?}: S8 composes make"
        );
        assert_eq!(
            invs[0].args, want,
            "{target:?}: unsafe target must not reach make raw"
        );
    }
}

                                                                                  
/// `CEREMONY_GATE_TARGET`, and it is the reduced legs composition — never the old `boot-gate`, which
/// emitted no record and left S10 unsatisfiable. The interview default and S8's composed fallback
/// both name it; PR_GATE_RECORD's fallback reads the same const by construction.
#[test]
fn the_default_gate_target_is_one_satisfiable_value() {
    use orchard::ceremony::param::DefaultWithSource;
    use orchard::ceremony::spine::CEREMONY_GATE_TARGET;
    let s8 = SPINE
        .iter()
        .find(|s| s.id == StepId::S8BootGate)
        .expect("S8");
    let gate_param = s8
        .params
        .iter()
        .find(|p| p.name == "gate_target")
        .expect("S8 declares gate_target");
    assert_eq!(
        gate_param.default,
        DefaultWithSource::Builtin(CEREMONY_GATE_TARGET),
        "the interview default is the one const",
    );
    let invs = (s8.compose)(&ParamValues::default());
    assert_eq!(
        invs[0].args,
        vec!["--".to_string(), CEREMONY_GATE_TARGET.to_string()],
        "absent gate_target composes make -- <const>",
    );
    assert_eq!(CEREMONY_GATE_TARGET, "boot-gate-ceremony-legs");
    assert_ne!(
        CEREMONY_GATE_TARGET, "boot-gate",
        "never the unsatisfiable boot-gate",
    );
}

                                                                                                   
/// does not. The type enforces it per-declaration; this holds it as a SET over the whole spine, so a
/// future declared-but-underived default (the class that let S6 compose zero invocations and record
/// DONE) is a red build. `box_login_identity` is the one Derived param; `tenant_artifacts` was
/// re-scoped to `Required` (operator-supplied, no false-derive promise).
#[test]
fn fac_gc_3_a_default_has_a_producer_iff_it_is_derived() {
    use orchard::ceremony::param::DefaultWithSource;
    let mut derived = 0;
    for step in SPINE.iter() {
        for p in step.params {
            let is_derived = matches!(
                p.default,
                DefaultWithSource::Derived(..) | DefaultWithSource::FromContext(..)
            );
            assert_eq!(
                is_derived,
                p.default.derivation().is_some(),
                "{}: a derivation exists iff the default is Derived/FromContext",
                p.name,
            );
            if is_derived {
                derived += 1;
            }
        }
    }
    assert!(
        derived >= 1,
        "at least one Derived default must exist, else the arm is vacuous"
    );
    let ta = SPINE
        .iter()
        .flat_map(|s| s.params.iter())
        .find(|p| p.name == "tenant_artifacts")
        .expect("tenant_artifacts param");
    assert_eq!(
        ta.default,
        DefaultWithSource::Required,
        "tenant_artifacts is operator-supplied (Required), not a Derived promise nothing keeps",
    );
}

                                                                                            

/// Every spine parameter, deduped by name (the spine declares some at two steps).
fn spine_params() -> BTreeMap<&'static str, &'static orchard::ceremony::param::ParamRecord> {
    let mut m = BTreeMap::new();
    for step in SPINE.iter() {
        for p in step.params {
            m.entry(p.name).or_insert(p);
        }
    }
    m
}

/// The declared read edges of the whole spine: (consumer name, read name), deduped.
fn read_edges() -> BTreeSet<(&'static str, &'static str)> {
    spine_params()
        .values()
        .flat_map(|p| p.default.reads().iter().map(move |r| (p.name, *r)))
        .collect()
}

/// C-a: a producer's declared read names a spine parameter. A read naming nothing the spine
/// declares can never be populated, so its producer would resolve `None` at every site.
#[test]
fn every_declared_read_names_a_spine_parameter() {
    let params = spine_params();
    let edges = read_edges();
    for (consumer, read) in &edges {
        assert!(
            params.contains_key(read),
            "`{consumer}` declares a read of `{read}`, which no spine step declares"
        );
    }
    assert!(
        !edges.is_empty(),
        "the spine declares no read edge, so this arm and its siblings assert nothing"
    );
}

/// C-b: depth-1. A declared read names a parameter with NO derivation of its own, which is the
/// property `resolve_values` pass 2 relies on (producers read pass-1 base values) and the property
/// that makes the ask-order deferral terminate.
#[test]
fn every_declared_read_names_a_parameter_without_a_derivation() {
    let params = spine_params();
    let edges = read_edges();
    for (consumer, read) in &edges {
        let Some(p) = params.get(read) else {
            continue;                               
        };
        assert!(
            p.default.derivation().is_none(),
            "`{consumer}` reads `{read}`, which is itself producer-backed; the graph must stay \
             depth-1 (pass 2 hands producers the pass-1 set, and the ask-order deferral assumes \
             reads release)"
        );
    }
    assert!(
        !edges.is_empty(),
        "the spine declares no read edge, so this arm asserts nothing"
    );
}

/// C-c: co-declaration. A step declaring a producer-backed parameter declares each of its reads,
/// so the input is in the same ask list at that step's slot or an earlier one — the premise the
/// inputs-first ordering needs.
#[test]
fn a_step_declaring_a_producer_backed_param_declares_its_reads() {
    let mut checked = 0usize;
    for step in SPINE.iter() {
        let declared: BTreeSet<&str> = step.params.iter().map(|p| p.name).collect();
        for p in step.params {
            for read in p.default.reads() {
                checked += 1;
                assert!(
                    declared.contains(read),
                    "{:?} declares `{}`, whose producer reads `{read}`, and does not declare \
                     `{read}`",
                    step.id,
                    p.name
                );
            }
        }
    }
    assert!(
        checked >= 1,
        "no step declares a producer-backed parameter, so this arm asserts nothing"
    );
}

/// C-d: reads-honesty + resolvability. Each producer, run over a view built from its OWN declared
/// reads and nothing else, asks only declared names (the view logs misses too) and resolves. An
                                                                                                
/// silent-no-op class.
#[test]
fn every_producer_asks_only_its_declared_reads_and_resolves() {
    use orchard::ceremony::param::DerivationInputs;
    let (_tmp, ctx) = ctx_fixture();
    let mut checked = 0usize;
    for (name, p) in spine_params() {
        let Some(d) = p.default.derivation() else {
            continue;
        };
        checked += 1;
        let declared: BTreeSet<&str> = d.reads.iter().copied().collect();
        let inputs = DerivationInputs::for_reads(d.reads, ctx.repo_root(), |r| {
            declared.contains(r).then_some("val.pub")
        });
        let out = (d.f)(&inputs);
        let asked = inputs.asked_names();
        let undeclared: Vec<&String> = asked
            .iter()
            .filter(|a| !declared.contains(a.as_str()))
            .collect();
        assert!(
            undeclared.is_empty(),
            "`{name}`'s producer read {undeclared:?}, which its `reads` does not declare — the \
             view returns None there, so the default silently stops resolving"
        );
        assert!(
            out.is_some(),
            "`{name}`'s producer returned None over a fully-populated view of its own declared \
             reads, so the shown derivation never happens"
        );
    }
    assert!(
        checked >= 1,
        "no producer-backed parameter exists, so this arm asserts nothing"
    );
}

                                                                                                 
/// whitespace refuse; real make targets and docker refs pass.
#[test]
fn argv_positional_safe_rejects_option_and_assignment_forms() {
    use orchard::ceremony::param::{argv_positional_safe, probe_argv_positional};
    for bad in [
        "",
        "-f/tmp/x.mk",
        "--eval=x",
        "VAR=value",
        "a b",
        "a\tb",
        "a\nb",
        "-",
        "a=b",
    ] {
        assert!(!argv_positional_safe(bad), "{bad:?} must be rejected");
    }
    for good in [
        "boot-gate",
        "recipes-imgbuild:dev",
        "registry.example.com:5000/repo/name:tag",
        "sha256@abc",
        "boot-gate-lifecycle",
    ] {
        assert!(argv_positional_safe(good), "{good:?} must pass");
    }
                                                                                
    let (_tmp, ctx) = ctx_fixture();
    assert!(matches!(
        probe_argv_positional(&ctx, "VAR=value"),
        orchard::ceremony::probes::ProbeResult::Unmet(_)
    ));
    assert!(matches!(
        probe_argv_positional(&ctx, "boot-gate"),
        orchard::ceremony::probes::ProbeResult::Met
    ));
}

                                                                                                   

/// Task 5 landed the C4 schema extension: nothing is pending — every spine param resolves
/// against a real profile key. A future param without a key must extend the schema, not this
/// list.
const PENDING_C4_KEYS: &[&str] = &[];

#[test]
fn every_param_resolves_against_the_profile_schema() {
    for step in SPINE.iter() {
        for p in step.params {
            assert!(
                PROFILE_KEYS.contains(&p.name) || PENDING_C4_KEYS.contains(&p.name),
                "{:?}: param {} has no C4 profile key (add the key in Task 5's schema extension \
                 or fix the name)",
                step.id,
                p.name
            );
        }
    }
}

                                                                                    
/// ceremony — a spine param (resolved by `resolve_values`), a C5 context key, or `schema_version`
/// (the skew refusal, `refusal.rs`). A new profile key the ceremony reads on no path reddens here,
/// so a persisted-but-dropped key cannot ship silently. `runtime_hostkey_fingerprint` fell through
/// both consumption and disclosure until it joined S10's params.
#[test]
fn every_profile_key_is_consumed_by_the_ceremony() {
                                                                                               
                                                                      
    const CEREMONY_NON_PARAM_KEYS: &[&str] = &[
        "repo_root",
        "artifact_store",
        "repo_manifest",
        "schema_version",
    ];
    for key in PROFILE_KEYS {
        let is_param = SPINE.iter().flat_map(|s| s.params).any(|p| p.name == *key);
        assert!(
            is_param || CEREMONY_NON_PARAM_KEYS.contains(key),
            "profile key `{key}` is neither a spine param nor a ceremony-consumed context key: the \
             ceremony drops it silently on the install path. Declare it as a param and \
             compose it, or add it to the consumed set with its consumer named."
        );
    }
}

                                                                                                   

#[test]
fn param_classes_are_coherent_across_steps() {
                                                                              
    let mut seen: BTreeMap<&str, (ParamClass, &str)> = BTreeMap::new();
    for step in SPINE.iter() {
        for p in step.params {
            let entry = (p.class, p.explain);
            if let Some(prev) = seen.get(p.name) {
                assert_eq!(
                    *prev, entry,
                    "param {} declared differently across steps",
                    p.name
                );
            } else {
                seen.insert(p.name, entry);
            }
        }
    }
                                                              
    assert_eq!(
        seen.get("image_version").map(|(c, _)| *c),
        Some(ParamClass::Judgment)
    );
                                                                                    
    assert!(
        seen.values()
            .filter(|(c, _)| *c == ParamClass::Identity)
            .count()
            >= 10
    );
}

                                                                                                   

#[test]
fn gate_classes_match_the_verbs_consent_surfaces() {
    for step in SPINE.iter() {
        match step.gate {
            GateClass::VerbOwned => {
                let verb = step.verb.expect("a verb-owned gate needs a verb");
                assert!(
                    flag_table()
                        .iter()
                        .any(|(v, _, c)| *v == verb && *c == FlagClass::ConsentBearing),
                    "{:?}: gate VerbOwned but {verb:?} has no consent-bearing flag",
                    step.id
                );
            }
            GateClass::SpineSupplied => {
                if let Some(verb) = step.verb {
                    assert!(
                        !flag_table()
                            .iter()
                            .any(|(v, _, c)| *v == verb && *c == FlagClass::ConsentBearing),
                        "{:?}: gate SpineSupplied but {verb:?} owns a consent flag — the gate \
                         model must be VerbOwned",
                        step.id
                    );
                }
            }
            GateClass::None => {}
        }
    }
}

                                                                                                   

#[test]
fn external_steps_are_probe_gated_and_s8_is_the_conditional_executor() {
    for step in SPINE.iter() {
        if step.executor == ExecutorClass::ExternalChecklist {
            assert!(
                !step.preconditions.is_empty(),
                "{:?}: an external-checklist step needs at least one gating probe",
                step.id
            );
        }
    }
    let conditional: Vec<StepId> = SPINE
        .iter()
        .filter(|s| matches!(s.executor, ExecutorClass::InternalWhere(_)))
        .map(|s| s.id)
        .collect();
    assert_eq!(conditional, vec![StepId::S8BootGate]);
    let ExecutorClass::InternalWhere(set) = SPINE
        .iter()
        .find(|s| s.id == StepId::S8BootGate)
        .expect("S8")
        .executor
    else {
        panic!("S8 executor shape");
    };
    assert_eq!(set, PreconditionSetId::S8GateComposition);
}

                                                                                                   

#[test]
fn probes_run_over_the_read_only_context() {
                                                                                               
                                                                 
    let (_tmp, ctx) = ctx_fixture();
    assert!(ctx.repo_root().ends_with("orchard"));
    assert!(ctx.profile().is_none());
    for step in SPINE.iter() {
        for pr in step.preconditions {
            let _ = (pr.run)(&ctx);                                        
        }
        for p in step.params {
            let _ = (p.probe)(&ctx, "probe-value");
        }
        if let Some(done) = step.artifact_present {
            let _ = (done.run)(&ctx, &ParamValues::default());
        }
    }
}

                                                                                            

#[test]
fn key_path_params_take_existing_paths_never_raw_material() {
    let (tmp, ctx) = ctx_fixture();
                                               
    let ProbeResult::Unmet(cure) = probe_key_file(&ctx, "-----BEGIN OPENSSH PRIVATE KEY-----\nabc")
    else {
        panic!("raw key material must be Unmet");
    };
    assert!(cure.contains("PATH"), "{cure}");
                                                       
    assert!(matches!(
        probe_key_file(&ctx, "/no/such/key"),
        ProbeResult::Unmet(_)
    ));
    let key = tmp.path().join("k.pub");
    std::fs::write(&key, "ssh-ed25519 AAAA t").expect("write key");
    assert_eq!(
        probe_key_file(&ctx, key.to_str().expect("utf8")),
        ProbeResult::Met
    );
                                                               
    for step in SPINE.iter() {
        for p in step.params {
            if p.name.ends_with("_pubkey") || p.name.ends_with("_identity") {
                assert!(
                    std::ptr::fn_addr_eq(
                        p.probe,
                        probe_key_file as fn(&ProbeCtx, &str) -> ProbeResult
                    ),
                    "{}: key-path params use probe_key_file",
                    p.name
                );
            }
        }
    }
}

                                                                                                   

/// Extract `<name>` placeholder tokens from a pathspec where `name` is a bare
/// lowercase-underscore identifier (a step-parameter reference). Descriptive strings with spaces
/// or other content inside `<…>` are not parameter references and are skipped.
fn placeholder_tokens(pathspec: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = pathspec.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<'
            && let Some(close) = pathspec[i + 1..].find('>')
        {
            let inner = &pathspec[i + 1..i + 1 + close];
            if !inner.is_empty() && inner.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
                out.push(inner.to_string());
            }
            i += 1 + close + 1;
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn declared_writes_are_well_formed_and_the_vocabulary_is_honest() {
    use orchard::ceremony::spine::WriteClass;
                                                                     
    assert!(!WriteClass::RunLocal.observable());
    assert!(!WriteClass::None.observable());
    for c in [
        WriteClass::Record,
        WriteClass::HostShared,
        WriteClass::RepoTree,
        WriteClass::Store,
        WriteClass::TargetBox,
    ] {
        assert!(c.observable(), "{c:?} must be observable");
    }
    for step in SPINE.iter() {
        let declared: BTreeSet<&str> = step.params.iter().map(|p| p.name).collect();
        for w in step.writes {
            assert!(!w.pathspec.is_empty(), "{:?}: empty pathspec", step.id);
            if w.class == WriteClass::RepoTree {
                assert!(
                    !w.pathspec.starts_with('/'),
                    "{:?}: repo-tree pathspec {} must be checkout-relative",
                    step.id,
                    w.pathspec
                );
            }
                                                                                
                                                                                                  
                                                                                                
                                                                                                   
                                                                                       
            for tok in placeholder_tokens(w.pathspec) {
                assert!(
                    declared.contains(tok.as_str()),
                    "{:?}: write pathspec {:?} names <{tok}>, which the step does not declare — \
                     use a declared parameter placeholder or descriptive text",
                    step.id,
                    w.pathspec
                );
            }
        }
                                                                                                
                                    
        if step.writes.iter().any(|w| w.class.observable())
            && let Some(verb) = step.verb
        {
            let argv: Vec<&str> = match verb {
                VerbId::GenerateKeys => vec!["generate-keys"],
                VerbId::Prime => vec!["prime"],
                VerbId::Vendor => vec!["vendor"],
                VerbId::MarketUpgrade => vec!["market", "upgrade", "--source", "x"],
                VerbId::Build => vec!["build", "--domain", "box.test"],
                VerbId::Prod => vec!["prod", "1.2.3.4", "--pubkey", "/k", "--ssh-identity", "/k"],
                                                                                                    
                VerbId::Guide | VerbId::Run => {
                    unreachable!("{verb:?} owns no spine step, so it never appears as step.verb")
                }
            };
            assert_eq!(
                verb_class(&parse(&argv)),
                VerbClass::Writing,
                "{:?} declares observable writes but {verb:?} is not WRITING",
                step.id
            );
        }
    }
}

                                                                                                   

#[test]
fn firmware_probe_is_exactly_the_v1_coverage_bound() {
    let (_tmp, ctx) = ctx_fixture();
    assert_eq!(probe_firmware(&ctx, "seabios"), ProbeResult::Met);
    assert_eq!(probe_firmware(&ctx, "seabios-gpt"), ProbeResult::Met);
    let ProbeResult::Unmet(cure) = probe_firmware(&ctx, "uefi") else {
        panic!("uefi must refuse toward S10");
    };
    assert!(cure.contains("signed-USB"), "{cure}");
    assert!(matches!(
        probe_firmware(&ctx, "ovmf"),
        ProbeResult::Unmet(_)
    ));
}

                                                                                   

#[test]
fn out_dir_probe_refuses_a_path_under_the_repo_root() {
    let (tmp, ctx) = ctx_fixture();
    let inside = ctx.repo_root().join("out");
    let ProbeResult::Unmet(cure) = probe_out_dir(&ctx, inside.to_str().expect("utf8")) else {
        panic!("an out_dir under the repo root must refuse");
    };
    assert!(cure.contains("repo root"), "{cure}");
    let outside = tmp.path().join("out");
    std::fs::create_dir_all(&outside).expect("mk out");
    assert_eq!(
        probe_out_dir(&ctx, outside.to_str().expect("utf8")),
        ProbeResult::Met
    );
}

                                                                                               
/// refuse. The one-sided `canonicalize().unwrap_or(raw)` compared the symlink-resolved root
/// against the raw (symlinked, non-existent) candidate and admitted it. Reverting `probe_out_dir`
/// to the one-sided form reddens here.
#[test]
fn out_dir_probe_refuses_a_missing_path_under_a_symlinked_repo_root() {
    let tmp = tempfile::tempdir().expect("tempdir");
                                                                           
    let real_root = tmp.path().join("real/orchard");
    std::fs::create_dir_all(real_root.join("crates/image-builder")).expect("mk root");
    #[cfg(unix)]
    std::os::unix::fs::symlink(tmp.path().join("real"), tmp.path().join("link")).expect("symlink");
    let ctx = ProbeCtx::from_paths(
        real_root.clone(),
        tmp.path().join("store"),
        real_root.join("repo-manifest.toml"),
    );
                                                                                   
    let via_link = tmp.path().join("link/orchard/out");
    let ProbeResult::Unmet(_) = probe_out_dir(&ctx, via_link.to_str().expect("utf8")) else {
        panic!("a missing out_dir under a symlinked root must refuse");
    };
                                                                       
    let direct = real_root.join("out");
    assert!(matches!(
        probe_out_dir(&ctx, direct.to_str().expect("utf8")),
        ProbeResult::Unmet(_)
    ));
                                                
    let outside = tmp.path().join("elsewhere/out");
    std::fs::create_dir_all(outside.parent().expect("parent")).expect("mk");
    assert_eq!(
        probe_out_dir(&ctx, outside.to_str().expect("utf8")),
        ProbeResult::Met
    );
}

                                                                                                   

#[test]
fn spine_order_and_derived_verb_subset_hold() {
    let ids: Vec<StepId> = SPINE.iter().map(|s| s.id).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(
        ids, sorted,
        "SPINE rows run in step order (the ask/run order)"
    );
    assert_eq!(ids.len(), 11);
    assert_eq!(
        spine_modeled_verbs(),
        BTreeSet::from([
            VerbId::GenerateKeys,
            VerbId::Prime,
            VerbId::Vendor,
            VerbId::MarketUpgrade,
            VerbId::Build,
            VerbId::Prod,
                                                                                      
            VerbId::Guide,
            VerbId::Run,
        ]),
        "the derived spine-modeled subset (guide/run join with their verbs)"
    );
    for step in SPINE.iter() {
        assert!(!step.title.is_empty() && !step.explain.is_empty() && !step.produces.is_empty());
    }
}

                                                                                                   
                                                                            
                                                                                                   

use orchard::ceremony::porcelain::{
    EXIT_CLASSES, EXIT_CODE_TABLE, PORCELAIN_FIELDS, PORCELAIN_KINDS, PORCELAIN_STATUS,
    PorcelainRecord, exit_code, refusal_record, result_record,
};
use orchard::ceremony::refusal::{Refusal, RefusalId, TypedCure};

/// A test condition whose `cure` is a fixed string: the walk builds a `Derived` refusal through the
/// real `Refusal::typed` path (no free string reaches a `Derived` id).
struct FixedCure(&'static str);

impl TypedCure for FixedCure {
    fn cure(&self) -> String {
        self.0.to_string()
    }
}

                                                                                                   

/// The cure text a composed operator render carries, read the way an operator reads it: everything
/// after the `\n  cure: ` label to the end. `None` when the label is absent — the caller decides
/// whether that is the failure, so the label's absence and an empty cure are DIFFERENT reds.
fn rendered_cure(render: &str) -> Option<&str> {
    render.split_once("\n  cure: ").map(|(_, tail)| tail)
}

                                                                                                  
/// total match inside `refusal_ids!` (a variant without a cure source cannot build); this walk is
/// the render half, and R7 measured the old walk covering only one of the two branches that render
/// — it built every id `with_cure_extra`, which 1 of the production `Refusal::new` sites uses, so
/// emptying the branch the others take stayed green.
///
/// Domain: a `CureSource::Static` id x BOTH `cure()` branches; a
/// `CureSource::Derived` id x its one meaningful branch (the extra IS the cure), plus a check that
/// building it with no extra trips the non-empty assert. Asserted per cell: the branch reached is
/// the branch intended (arm sanity first, so a cell cannot pass vacuously from the wrong branch),
/// `cure()` composes exactly as documented, and the COMPOSED Display carries that same text after
/// the `cure:` LABEL — not the label alone, which is what `refusal (x): d\n  cure: ` satisfies with
/// a blank.
#[test]
fn ac13_every_refusal_renders_a_nonempty_cure() {
    use orchard::ceremony::refusal::CureSource;
    assert!(!RefusalId::ALL.is_empty());
    let mut cells = 0usize;
    let mut expected_cells = 0usize;
                                                                                                 
                                                                                            
    let derived_extra = "the derived remedy for this id";
    for id in RefusalId::ALL {
        assert!(!id.token().is_empty());
        match id.cure_source() {
            CureSource::Static(template) => {
                assert!(!template.trim().is_empty(), "{id:?}: empty cure template");
                expected_cells += 2;
                for (branch, r) in [
                    ("no-extra", Refusal::new(*id, "detail-text")),
                    (
                        "with-extra",
                        Refusal::new(*id, "detail-text").with_cure_extra("specific"),
                    ),
                ] {
                    assert_eq!(
                        r.cure_extra().is_some(),
                        branch == "with-extra",
                        "{id:?} [{branch}]: the walk built the wrong branch"
                    );
                    let cure = r.cure().as_str().to_string();
                    let expected = if branch == "with-extra" {
                        format!("{template} (specific)")
                    } else {
                        template.to_string()
                    };
                    assert_eq!(
                        cure, expected,
                        "{id:?} [{branch}]: cure() drifted from `template` / `template (extra)`"
                    );
                    assert_rendered_cure(*id, branch, &r, &cure);
                    cells += 1;
                }
            }
            CureSource::Derived => {
                expected_cells += 1;
                                                                                                  
                                                  
                let prev_hook = std::panic::take_hook();
                std::panic::set_hook(Box::new(|_| {}));
                let no_extra = std::panic::catch_unwind(|| Refusal::new(*id, "d").cure());
                std::panic::set_hook(prev_hook);
                assert!(
                    no_extra.is_err(),
                    "{id:?} [derived]: a derived-source refusal built with no extra must trip the \
                     non-empty cure assert"
                );
                let r = Refusal::typed(*id, "detail-text", &FixedCure(derived_extra));
                let cure = r.cure().as_str().to_string();
                assert_eq!(
                    cure, derived_extra,
                    "{id:?} [derived]: cure() must render the typed condition's cure"
                );
                assert_rendered_cure(*id, "derived", &r, &cure);
                cells += 1;
            }
        }
    }
                                                                                                  
    assert_eq!(
        cells, expected_cells,
        "the cure walk did not cover every id's intended cure branches"
    );
}

                                                                                                    
                                                                                                   
/// `  cure: ` with nothing after).
fn assert_rendered_cure(id: RefusalId, branch: &str, r: &Refusal, cure: &str) {
    let render = r.to_string();
    assert!(
        render.contains(id.token()),
        "{id:?} [{branch}]: the render does not name the id: {render}"
    );
    let shown = rendered_cure(&render).unwrap_or_else(|| {
        panic!("{id:?} [{branch}]: the render carries no `cure:` line at all: {render}")
    });
    assert!(
        !shown.trim().is_empty(),
        "{id:?} [{branch}]: the render's cure line is BLANK after the label: {render:?}"
    );
    assert_eq!(
        shown, cure,
        "{id:?} [{branch}]: the rendered cure text is not the cure the refusal carries"
    );
}

                                                                                        

/// The flag tokens a template spells, each with the `orchard <verb>` in scope at that point (the
/// nearest one to its left in the same template, if any). Reading rule, stated because it is the
/// model this checker enforces rather than a grammar of English: words are whitespace-separated,
/// `a/b` reads as two tokens, and the prose punctuation and inline-code backticks around a token
/// are not part of it.
fn cure_flags(template: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut scope: Option<String> = None;
    let words: Vec<&str> = template.split_whitespace().collect();
    for (i, w) in words.iter().enumerate() {
        if let Some(v) = verb_after(&words, i) {
            scope = Some(v);
        }
        for piece in w.split('/') {
            let t =
                piece.trim_matches(|c: char| !c.is_ascii_alphanumeric() && !"-_<>.$".contains(c));
            if t.starts_with("--") && t.len() > 2 {
                out.push((t.to_string(), scope.clone()));
            }
        }
    }
    out
}

/// The verb an `orchard` introduces at `i`. Only an `orchard` OPENING an inline-code span reads as
/// an invocation: the templates spell every invocation that way, and unquoted prose about the tool
/// ("one WRITING orchard invocation per host", "upgrade orchard, or …") is not one.
fn verb_after(words: &[&str], i: usize) -> Option<String> {
    if !words[i].starts_with('`') || words[i].trim_start_matches('`') != "orchard" {
        return None;
    }
    let next = words
        .get(i + 1)?
        .trim_end_matches('`')
        .trim_end_matches([',', '.', ';']);
    (!next.is_empty() && next.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        .then(|| next.to_string())
}

fn cure_verbs(template: &str) -> Vec<String> {
    let words: Vec<&str> = template.split_whitespace().collect();
    (0..words.len())
        .filter_map(|i| verb_after(&words, i))
        .collect()
}

/// Tokens naming a sidecar of the placeholder image the templates call `<img>`.
fn cure_image_sidecars(template: &str) -> Vec<String> {
    template
        .split_whitespace()
        .map(|w| w.trim_matches(|c: char| !c.is_ascii_alphanumeric() && !"-_<>.".contains(c)))
        .filter(|t| t.starts_with("<img>."))
        .map(String::from)
        .collect()
}

/// Tokens shaped like a run-records directory (`<something>.d`), whatever precedes them.
fn cure_records_paths(template: &str) -> Vec<String> {
    let mut out = Vec::new();
    for w in template.split_whitespace() {
        for piece in w.split('/') {
            let t =
                piece.trim_matches(|c: char| !c.is_ascii_alphanumeric() && !"-_<>.".contains(c));
            if t.ends_with(".d") && t.len() > 2 {
                out.push(t.to_string());
            }
        }
    }
    out
}

                                                                                             
/// gates its EXISTENCE, not its content: a flag, verb or path claim inside one was owned only
/// where some past finding left a `contains("…")` assertion at that refusal's own call site.
///
/// What this checker enforces: every `--flag` a cure template spells exists on the real clap
/// surface (verb-scoped when an `orchard <verb>` precedes it in the same template, else anywhere
/// on the tree); every `orchard <verb>` names a real subcommand; no template spells a run-records
/// directory (the real one is resolved and rides `cure_extra` via `records_dir_cure`); and the
/// gate-record sidecar name is the one `gate_record_path` produces. The extracted sets are FROZEN,
/// so a template that gains or loses a claim reddens here and is re-checked at that point.
///
/// Blind spots, named: a flag that exists but on a verb no `orchard <verb>` in that template
/// scopes it to; a claim phrased without its token ("pass the target flag"); the cross-reference
                                                                                   
#[test]
fn every_flag_verb_and_records_path_a_cure_names_exists_on_the_surface() {
    use orchard::ceremony::classify::walk_long_flags;
    use orchard::ceremony::gate_record::{gate_record_path, provenance_path};
    use orchard::ceremony::records::records_dir_of;
    use std::path::Path;

                                                                                           
                 
    let sample = "run `orchard build --dha-weights-gguf/--dha-mmproj-gguf <path>`, or fix \
                  --repo-root; upgrade orchard, one orchard invocation per host, or restore \
                  boxes/<name>.d/";
    assert_eq!(
        cure_flags(sample)
            .iter()
            .map(|(f, v)| (f.as_str(), v.as_deref()))
            .collect::<Vec<_>>(),
        vec![
            ("--dha-weights-gguf", Some("build")),
            ("--dha-mmproj-gguf", Some("build")),
            ("--repo-root", Some("build")),
        ],
        "the flag scanner does not read the sample the way the checker claims"
    );
    assert_eq!(
        cure_verbs(sample),
        vec!["build".to_string()],
        "an unquoted `orchard` is prose about the tool and must not read as a verb claim"
    );
    assert_eq!(cure_records_paths(sample), vec!["<name>.d".to_string()]);
    assert!(
        cure_flags("pass the target flag").is_empty(),
        "a claim phrased without its token is invisible here — the named blind spot"
    );

    let whole_surface: BTreeSet<String> = walk_long_flags(&[])
        .into_iter()
        .flat_map(|f| std::iter::once(f.long).chain(f.aliases))
        .collect();
    assert!(
        whole_surface.contains("target") && !whole_surface.contains("box-target"),
        "the walked surface is not the real one: {whole_surface:?}"
    );
    let subcommands: BTreeSet<String> = Cli::command()
        .get_subcommands()
        .map(|c| c.get_name().to_string())
        .collect();

                                                                                          
                                       
    let sidecar_names: BTreeSet<String> = [
        gate_record_path(Path::new("<img>.img")),
        provenance_path(Path::new("<img>.img")),
    ]
    .iter()
    .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(String::from))
    .collect();
    assert_eq!(
        sidecar_names.len(),
        2,
        "the sidecar derivation collapsed: {sidecar_names:?}"
    );

    let mut flags = BTreeSet::new();
    let mut verbs = BTreeSet::new();
    let mut records_paths = BTreeSet::new();
    let mut sidecar_claims = 0usize;
    for id in RefusalId::ALL {
                                                                                                    
                                                           
        let template = match id.cure_source() {
            orchard::ceremony::refusal::CureSource::Static(t) => t,
            orchard::ceremony::refusal::CureSource::Derived => "",
        };
        for (flag, scope) in cure_flags(template) {
            let name = flag.trim_start_matches("--").to_string();
            let allowed: BTreeSet<String> = match &scope {
                Some(verb) => walk_long_flags(&[verb.as_str()])
                    .into_iter()
                    .flat_map(|f| std::iter::once(f.long).chain(f.aliases))
                    .chain(GLOBAL_BENIGN_FLAGS.iter().map(|g| (*g).to_string()))
                    .collect(),
                None => whole_surface.clone(),
            };
            assert!(
                allowed.contains(&name),
                "{id:?}: the cure tells the operator to pass `{flag}`, which is not on the {} \
                 surface",
                scope.as_deref().unwrap_or("orchard")
            );
            flags.insert(flag);
        }
        for verb in cure_verbs(template) {
            assert!(
                subcommands.contains(&verb),
                "{id:?}: the cure names `orchard {verb}`, which is not a subcommand"
            );
            verbs.insert(verb);
        }
        records_paths.extend(cure_records_paths(template));
        for token in cure_image_sidecars(template) {
            assert!(
                sidecar_names.contains(&token),
                "{id:?}: the cure tells the operator to copy `{token}`, which no emitter produces; \
                 the derived sidecar names are {sidecar_names:?}"
            );
            sidecar_claims += 1;
        }
    }

                                                                                                   
                                                                         
    assert_eq!(
        flags,
        BTreeSet::from(
            [
                "--artifact-store",
                "--context",
                "--dha-mmproj-gguf",
                "--dha-weights-gguf",
                "--image-version",
                "--repo-manifest",
                "--repo-root",
                "--target",
            ]
            .map(String::from)
        ),
        "the flags spelled across the cure templates changed"
    );
    assert_eq!(
        verbs,
        BTreeSet::from(["build", "guide", "run"].map(String::from)),
        "the verbs spelled across the cure templates changed"
    );
                                                                                            
                                                                                                   
                                                  
    assert!(
        records_paths.is_empty(),
        "a cure template spells a run-records directory ({records_paths:?}); the real one is \
         `records_dir_of` at open, rendered into cure_extra"
    );
    assert!(
        records_dir_of(Path::new("/state/records"), Path::new("boxes/alpha.toml"))
            .ends_with("alpha.d"),
        "the `<name>.d` shape this arm scans for is not the shape records_dir_of produces"
    );
    assert_eq!(
        sidecar_claims, 1,
        "the gate-record sidecar claim moved; this arm checked {sidecar_claims} templates for it"
    );
}

                                                                                               
/// every field PRESENT is in the locked vocabulary — a SUBSET check, so dropping
/// `refusal_record`'s `.field("cure", …)` passes it, and
/// `print_context_porcelain_refusal_still_emits_both_records` counts records by kind while its
/// message names the cure. Nothing asserted the field is REQUIRED. This arm asserts the exact key
/// SEQUENCE (both directions redden: a dropped field and a new one) and the joint truth across the
/// two renderers — the machine record's cure is the same text the operator's stderr shows, for
/// every id in both branches.
#[test]
fn refusal_records_carry_the_exact_field_set_and_the_rendered_cure() {
    use orchard::ceremony::refusal::CureSource;
    let mut cells = 0usize;
    let mut expected_cells = 0usize;
    for id in RefusalId::ALL {
                                                                            
                                                                                     
        let branches: Vec<(&str, Refusal)> = match id.cure_source() {
            CureSource::Static(_) => vec![
                ("no-extra", Refusal::new(*id, "detail-text")),
                (
                    "with-extra",
                    Refusal::new(*id, "detail-text").with_cure_extra("specific"),
                ),
            ],
            CureSource::Derived => vec![(
                "derived",
                Refusal::typed(
                    *id,
                    "detail-text",
                    &FixedCure("the derived remedy for this id"),
                ),
            )],
        };
        expected_cells += branches.len();
        for (branch, r) in branches {
            let rec = refusal_record(&r);
            assert_eq!(rec.kind, "refusal", "{id:?} [{branch}]: wrong record kind");
            let keys: Vec<&str> = rec.fields.iter().map(|(k, _)| *k).collect();
            assert_eq!(
                keys,
                ["id", "detail", "cure"],
                "{id:?} [{branch}]: the refusal record's field sequence changed. A porcelain \
                 consumer branches on `cure=`; dropping it leaves the subset check green. Re-freeze this sequence consciously"
            );
            let value = |k: &str| {
                rec.fields
                    .iter()
                    .find(|(key, _)| *key == k)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_else(|| panic!("{id:?} [{branch}]: no {k} field"))
            };
            assert_eq!(value("id"), id.token());
            assert_eq!(value("detail"), "detail-text");
            assert!(
                !value("cure").trim().is_empty(),
                "{id:?} [{branch}]: the record's cure value is empty"
            );
                                                                                           
            let render = r.to_string();
            let shown = rendered_cure(&render)
                .unwrap_or_else(|| panic!("{id:?} [{branch}]: no cure line: {render}"));
            assert_eq!(
                value("cure"),
                shown,
                "{id:?} [{branch}]: the porcelain record's cure and the stderr render's cure \
                 disagree — one of the two renderers dropped or changed it"
            );
            cells += 1;
        }
    }
    assert_eq!(cells, expected_cells);
}

                                                                                                   

#[test]
fn ac9_exit_code_mapping_matches_the_frozen_table() {
                                                                                      
    let mapped: Vec<(&str, i32)> = EXIT_CLASSES
        .iter()
        .map(|c| (c.token(), exit_code(c)))
        .collect();
    let mut sorted_mapped = mapped.clone();
    sorted_mapped.sort_by_key(|(_, code)| *code);
    assert_eq!(
        sorted_mapped.as_slice(),
        EXIT_CODE_TABLE,
        "exit_code drifted from EXIT_CODE_TABLE"
    );
                                                                                   
    let codes: BTreeSet<i32> = mapped.iter().map(|(_, c)| *c).collect();
    assert_eq!(codes.len(), mapped.len(), "duplicate exit codes");
    assert_eq!(
        exit_code(&orchard::ceremony::porcelain::ExitClass::Success),
        0
    );
    assert_ne!(
        exit_code(&orchard::ceremony::porcelain::ExitClass::RefusalWithCure),
        exit_code(&orchard::ceremony::porcelain::ExitClass::Crash)
    );
                                                                                               
                             
    for c in EXIT_CLASSES {
        assert!(PORCELAIN_STATUS.contains(&c.status()));
    }
                                                                                      
                                                                                          
                                                                                                 
    for (token, code) in EXIT_CODE_TABLE {
        assert!(
            (0..=255).contains(code),
            "exit code {code} for {token} does not fit the process-exit u8 range"
        );
    }
}

#[test]
fn ac9_porcelain_vocabulary_is_locked_and_enforced() {
                                                                                              
                                                                                           
    let r = Refusal::new(RefusalId::ContextUnresolvable, "d");
    for rec in [
        refusal_record(&r),
        result_record(
            "vendor",
            &orchard::ceremony::porcelain::ExitClass::RefusalWithCure,
        ),
    ] {
        assert!(PORCELAIN_KINDS.contains(&rec.kind));
        for (k, _) in &rec.fields {
            assert!(PORCELAIN_FIELDS.contains(k));
        }
    }
                                                                    
    let rec = PorcelainRecord::new("detail").field("detail", "a\tb\nc\\d");
    let line = rec.render();
    assert!(!line.contains('\n'));
    assert_eq!(line, "detail\tdetail=a\\tb\\nc\\\\d");
                                                                
    assert!(std::panic::catch_unwind(|| PorcelainRecord::new("bogus-kind")).is_err());
    assert!(
        std::panic::catch_unwind(|| PorcelainRecord::new("result").field("bogus-field", "v"))
            .is_err()
    );
}

                                                                                                   

                                                                                        
                                                                                            
                                                                                              
                                                                                              
                                                                                               
                                                                                              
                                                                                              
                                                                                    
                                                                                              
                                                                         
                                                                                                 
                                         
                                                                                       
                                                                                               
                

                                                                                         
/// `EXIT_CODE_TABLE` code is DISCLOSED in `known_shadows`, never silent. This arm asserts every
/// actual overlap is declared and every declared shadow is a real overlap — the exemption's own
/// precondition (know your collisions) is now checked.
#[test]
fn exempt_exit_codes_disclose_every_ceremony_shadow() {
    use orchard::ceremony::porcelain::{EXIT_CODE_TABLE, VERB_OWNED_EXIT_SITES};
    let ceremony_codes: BTreeSet<i32> = EXIT_CODE_TABLE.iter().map(|(_, c)| *c).collect();
    for site in VERB_OWNED_EXIT_SITES {
        let actual: BTreeSet<i32> = site
            .codes
            .iter()
            .copied()
            .filter(|c| ceremony_codes.contains(c))
            .collect();
        let declared: BTreeSet<i32> = site.known_shadows.iter().copied().collect();
        assert_eq!(
            actual, declared,
            "{}: shadow set drifted — actual overlap with the ceremony table {actual:?} != \
             declared known_shadows {declared:?}",
            site.verb
        );
    }
}

                                                                                                   

fn spawn_orchard(
    cwd: &std::path::Path,
    home: &std::path::Path,
    envs: &[(&str, &str)],
    args: &[&str],
) -> (i32, String, String) {
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_orchard"));
    c.current_dir(cwd)
        .env_remove("FRUIT_ARTIFACT_STORE")
        .env_remove("ORCHARD_LOCK_TOKEN")
        .env_remove("RECIPES_DHA_WEIGHTS_GGUF")
        .env_remove("RECIPES_DHA_MMPROJ_GGUF")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
                                                                
        .env("ORCHARD_LOCK_DIR", home.join(".ceremony-lock"))
        .args(args);
    for (k, v) in envs {
        c.env(k, v);
    }
    let out = c.output().expect("spawn orchard");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A refusal through the real binary exits with the MAPPED code and prints the cure — the
                                                          
#[test]
fn refusals_exit_with_the_mapped_code_and_a_cure() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("orchard");
    std::fs::create_dir_all(root.join("crates/image-builder")).expect("mk root");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("mk home");
    let (code, _, stderr) = spawn_orchard(
        &root,
        &home,
        &[],
        &["--artifact-store", "/no/such/store", "vendor"],
    );
    assert_eq!(
        code,
        exit_code(&orchard::ceremony::porcelain::ExitClass::RefusalWithCure),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("refusal (context-unresolvable)"),
        "{stderr}"
    );
                                                                                                   
                                                                                                  
                                                                                                   
                                                                                                 
                                                  
    let cure_line = stderr
        .split_once("\n  cure: ")
        .map(|(_, tail)| tail.lines().next().unwrap_or(""))
        .unwrap_or_else(|| panic!("no `cure:` line on stderr at all: {stderr}"));
    assert!(
        !cure_line.trim().is_empty(),
        "the refusal's cure line is BLANK after the label — a cureless refusal reached the \
         operator: {stderr:?}"
    );
    let committed_template = match RefusalId::ContextUnresolvable.cure_source() {
        orchard::ceremony::refusal::CureSource::Static(t) => t,
        orchard::ceremony::refusal::CureSource::Derived => {
            panic!("ContextUnresolvable is a static-template id")
        }
    };
    assert_eq!(
        cure_line, committed_template,
        "the operator's cure text is not this id's committed template: {stderr:?}"
    );
}

                                                                                       
/// least one locked-vocabulary record, ending with the result record whose exit field matches
/// the process exit code.
#[test]
fn porcelain_verbs_emit_locked_records() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("orchard");
    std::fs::create_dir_all(root.join("crates/image-builder")).expect("mk root");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("mk home");
    let plain = tmp.path().join("plain");
    std::fs::create_dir_all(&plain).expect("mk plain");

                                                                                                  
                                               
    type Case<'a> = (Vec<&'a str>, &'a std::path::Path, Vec<(&'a str, &'a str)>);
    let cases: Vec<Case> = vec![
        (
            vec!["vendor", "--porcelain", "--store", "/no/such/store"],
            root.as_path(),
            vec![],
        ),
        (vec!["prime", "--porcelain"], plain.as_path(), vec![]),
        (
            vec!["generate-keys", "--porcelain", "--regenerate-master-key"],
            plain.as_path(),
            vec![],
        ),
        (
            vec!["build", "--porcelain", "--domain", "box.test"],
            root.as_path(),
            vec![("RECIPES_DHA_WEIGHTS_GGUF", "/nonexistent.gguf")],
        ),
        (
            vec!["market", "upgrade", "--porcelain", "--source", "x"],
            plain.as_path(),
            vec![],
        ),
        (
            vec![
                "prod",
                "--porcelain",
                "203.0.113.1",
                "--pubkey",
                "/no/such/key.pub",
                "--ssh-identity",
                "/no/such/key",
            ],
            plain.as_path(),
            vec![],
        ),
    ];
    for (args, cwd, envs) in cases {
        let (code, stdout, stderr) = spawn_orchard(cwd, &home, &envs, &args);
        let records: Vec<&str> = stdout
            .lines()
            .filter(|l| {
                PORCELAIN_KINDS
                    .iter()
                    .any(|k| l.starts_with(&format!("{k}\t")))
            })
            .collect();
        assert!(
            !records.is_empty(),
            "{args:?}: no porcelain records\nstdout: {stdout}\nstderr: {stderr}"
        );
        let last = records.last().expect("nonempty");
        assert!(
            last.starts_with("result\t"),
            "{args:?}: last record is {last}"
        );
        assert!(
            last.contains(&format!("exit={code}")),
            "{args:?}: result record {last} vs process exit {code}"
        );
        let status_ok = PORCELAIN_STATUS
            .iter()
            .any(|s| last.contains(&format!("status={s}")));
        assert!(status_ok, "{args:?}: {last}");
    }
}

                                                                                               
/// silently lose the flag with nothing red. For each spine-modeled non-interactive verb: WITH
/// `--porcelain` a `result\t` record appears; WITHOUT it, no `result\t` record appears. A verb
/// that stopped being recognized would emit no result line WITH the flag and redden here.
/// (Per-verb STEP records — the run face's step/detail lines — land with the `run` verb in
/// Task 6; this arm pins the flag-recognition coverage that exists now.)
#[test]
fn porcelain_flag_is_load_bearing_for_every_spine_modeled_verb() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let plain = tmp.path().join("plain");
    std::fs::create_dir_all(&plain).expect("mk");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("mk home");
                                                                                                 
    let base_argv: &[&[&str]] = &[
        &["generate-keys", "--regenerate-master-key"],
        &["prime"],
        &["vendor"],
        &["build", "--domain", "box.test"],
        &["market", "upgrade", "--source", "x"],
        &[
            "prod",
            "203.0.113.1",
            "--pubkey",
            "/no/such/key.pub",
            "--ssh-identity",
            "/no/such/key",
        ],
                                                                                           
                                                                                          
                                 
        &["run", "/no/such/profile.toml"],
    ];
    let has_result = |args: &[&str]| -> bool {
        let (_, stdout, _) = spawn_orchard(&plain, &home, &[], args);
        stdout.lines().any(|l| l.starts_with("result\t"))
    };
    for base in base_argv {
                                                                                               
                                                                                           
        let mut with: Vec<&str> = base.to_vec();
        with.push("--porcelain");
        assert!(
            has_result(&with),
            "{base:?}: WITH --porcelain emits no result record — the verb lost porcelain \
             recognition (porcelain_of)"
        );
        assert!(
            !has_result(base),
            "{base:?}: WITHOUT --porcelain emits a result record — the tail is not gated on the \
             flag"
        );
    }
}

                                                                                                    

                                                                                               
/// declared over a step PRODUCT must name a producer at or before the step that declares it —
/// otherwise the runner would evaluate it before the thing exists. `CeremonyImmutable` names no
/// producer and is what admission evaluates.
#[test]
fn precondition_subjects_precede_their_consumers() {
    use orchard::ceremony::probes::SubjectOrigin;
    let order = |id: orchard::ceremony::spine::StepId| {
        SPINE
            .iter()
            .position(|s| s.id == id)
            .expect("step in spine")
    };
    let mut immutable = 0usize;
    for step in SPINE.iter() {
        for probe in step.preconditions {
            match probe.subject {
                SubjectOrigin::CeremonyImmutable => immutable += 1,
                SubjectOrigin::StepProduct(producer) => assert!(
                    order(producer) <= order(step.id),
                    "{}'s precondition {} names producer {:?}, which runs AFTER it",
                    step.id.token(),
                    probe.id,
                    producer
                ),
            }
        }
    }
    assert!(
        immutable > 0,
        "at least one precondition is admission-evaluable, or the admission probe set is \
         vacuous and this arm proves nothing"
    );
}

/// Every declared input identity is either re-derivable by the runner or on the DEFERRED list
/// with its owning task. An identity in neither is a silent permanent SKIP: `step_done` skips a
/// non-derivable identity by design (the record stands), so an unimplemented resolver would
                                                    
#[test]
fn every_input_identity_resolves_or_is_declared_deferred() {
    use orchard::ceremony::admission::{IDENTITIES_DEFERRED, Measured, identity_value};
    let (_tmp, ctx) = ctx_fixture();
    let mut values = ParamValues::default();
    values.insert("tenant_source_ref", "f0ad0fc");
    let measured = Measured {
        dirty: vec![],
        head: Some("deadbeef".into()),
    };
    for step in SPINE.iter() {
        for id in step.input_identities {
            let deferred = IDENTITIES_DEFERRED.iter().any(|(d, _)| *d == id.id);
                                                                                               
                                                                                                  
                                                                                              
                                                                      
            let known = matches!(
                id.id,
                "containerfile"
                    | "pins.toml"
                    | "consume-pins.toml"
                    | "ceremony-head"
                    | "tenant_source_ref"
                    | "handoff-tree-hash"
            );
            assert!(
                known || deferred,
                "input identity `{}` (step {}) has no resolver arm and is not on \
                 IDENTITIES_DEFERRED",
                id.id,
                step.id.token()
            );
            if known {
                                                                                            
                if id.id == "ceremony-head" {
                    assert_eq!(
                        identity_value(id.id, &ctx, &values, &measured).as_deref(),
                        Some("deadbeef")
                    );
                }
                if id.id == "tenant_source_ref" {
                    assert_eq!(
                        identity_value(id.id, &ctx, &values, &measured).as_deref(),
                        Some("f0ad0fc")
                    );
                }
            }
        }
    }
    for (id, _) in IDENTITIES_DEFERRED {
        assert!(
            SPINE
                .iter()
                .any(|s| s.input_identities.iter().any(|i| i.id == *id)),
            "DEFERRED identity `{id}` is not declared by any step — stale entry"
        );
    }
}

                                                                                               
/// to re-supply it with. Derived from the spine and the real clap surface, so a new
/// Judgment-class parameter without a `run` flag is a red test rather than a value that can
/// never be re-supplied (and would therefore refuse every run forever).
#[test]
fn every_judgment_parameter_has_a_run_flag() {
    use orchard::ceremony::classify::walk_long_flags;
    use orchard::ceremony::param::ParamClass;
    let flags: BTreeSet<String> = walk_long_flags(&["run"])
        .into_iter()
        .map(|f| f.long)
        .collect();
    let mut judgment = BTreeSet::new();
    for step in SPINE.iter() {
        for p in step.params {
            if p.class == ParamClass::Judgment {
                judgment.insert(p.name);
            }
        }
    }
    assert!(
        !judgment.is_empty(),
        "no judgment-class parameter exists, so this arm proves nothing — the judgment class has no domain"
    );
    for name in &judgment {
        let flag = name.replace('_', "-");
        assert!(
            flags.contains(&flag),
            "judgment parameter `{name}` has no `orchard run --{flag}` to re-supply it; the flags on run are {flags:?}"
        );
    }
                                                                                             
                                                                                            
    for name in &judgment {
        assert_eq!(
            name.replace('_', "-").replace('-', "_"),
            **name,
            "parameter name `{name}` does not round-trip through the flag spelling"
        );
    }
}

/// An empty answer on a judgment parameter supplies its shown builtin default, which takes the
/// same probe path a typed answer takes (`interview::query`).
///
/// Scoped to Judgment. An IDENTITY builtin is a display token, not a value — `manifest`'s
/// `(pinned reference tenant)` fails `probe_existing_file` by design; an empty answer there
/// resolves to `Unset` and never reaches a probe.
#[test]
fn every_judgment_builtin_default_passes_its_own_probe() {
    let (_tmp, ctx) = ctx_fixture();
    let mut checked = 0usize;
    for step in SPINE.iter() {
        for p in step.params {
            if p.class != ParamClass::Judgment {
                continue;
            }
            let DefaultWithSource::Builtin(v) = p.default else {
                continue;
            };
            checked += 1;
            match (p.probe)(&ctx, v) {
                ProbeResult::Met => {}
                ProbeResult::Unmet(why) | ProbeResult::Unevaluable(why) => panic!(
                    "judgment parameter `{}` shows the builtin default {v:?}, an empty answer \
                     supplies it, and its own probe then refuses it: {why}",
                    p.name
                ),
            }
        }
    }
    assert!(
        checked > 0,
        "no judgment parameter carries a builtin default, so this arm proves nothing"
    );
}

/// The ceremony `run` face exposes no step-selection flag (spec §3): the spine order and the
/// done-probes decide what runs, never an operator-chosen subset.
#[test]
fn the_run_face_exposes_no_step_selector() {
    use orchard::ceremony::classify::walk_long_flags;
    for f in walk_long_flags(&["run"]) {
        let name = f.long.as_str();
        assert!(
            !(name.contains("step") || name.contains("only") || name.contains("skip")),
            "`orchard run` must expose no step-selection flag, found --{name}"
        );
    }
}

                                                                                  
/// `requires_clean_tree` must name exactly the steps whose verb refuses dirt. That property is
/// checkable rather than asserted: a verb refuses dirt iff it carries the `--allow-dirty`
                                                                 
#[test]
fn clean_tree_steps_are_exactly_the_allow_dirty_verbs() {
    use orchard::ceremony::classify::{FlagClass, class_of_token};
    let mut clean_tree = Vec::new();
    let mut allow_dirty = Vec::new();
    for step in SPINE.iter() {
        if step.requires_clean_tree {
            clean_tree.push(step.id.token());
        }
        if let Some(verb) = step.verb
            && class_of_token(verb, "allow-dirty") == Some(FlagClass::GuardDisabling)
        {
            allow_dirty.push(step.id.token());
        }
    }
    assert_eq!(
        clean_tree, allow_dirty,
        "the clean-tree step set must equal the set whose verb carries the GuardDisabling \
         --allow-dirty escape hatch"
    );
    assert!(
        !clean_tree.is_empty(),
        "no step needs a clean tree, so the commit gate has no firing point and this arm proves \
         nothing"
    );
}

                                                                                                    

                                                                                               
/// spine field the guide contradicts is a red test rather than a stale sentence.
#[test]
fn the_guide_command_table_agrees_with_the_spine_render() {
    use orchard::ceremony::derive::spine_command_rows;
    let full = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../orchard_guide.md"),
    )
    .expect("read orchard_guide.md");
                                                                                           
                                                                                                  
                                                                                                
                                     
    let start = full
        .find("## 10. Command reference")
        .expect("guide has a §10");
    let end = full[start..]
        .find("\n## 11.")
        .map(|i| start + i)
        .unwrap_or(full.len());
    let guide = &full[start..end];
    let rows = spine_command_rows();
    assert!(!rows.is_empty(), "an empty render proves nothing");
                                                                                                     
                                                                                                   
                                                                               
                                                                                                    
                                                                                   
                                                                                                     
                                                                                                    
                                                                                             
    let mut in_fence = false;
    let mut guide_commands: Vec<Vec<String>> = Vec::new();
    for l in guide.lines() {
        if l.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence || !l.trim_start().starts_with('|') {
            continue;
        }
        let Some(cell) = l.split('|').nth(1) else {
            continue;
        };
        let cell = cell.trim().trim_matches('`');
        let words: Vec<String> = cell.split_whitespace().map(str::to_string).collect();
        if words.first().map(String::as_str) == Some("orchard") {
            guide_commands.push(words);
        }
    }
    for row in &rows {
        let inv: Vec<&str> = row.invocation.split_whitespace().collect();
        assert!(
            guide_commands
                .iter()
                .any(|g| { g.len() >= inv.len() && g.iter().zip(&inv).all(|(a, b)| a == b) }),
            "§10 has no command row that IS `{}` (word-boundary match; a longer command with the \
             same prefix does not count). §10 commands: {guide_commands:?}",
            row.invocation
        );
    }
}

                                                                                       
/// `orchard <verb>` true from any checkout, so a surface that still says `cargo run -p orchard`
/// or names an absolute `target/release` path hands the operator a form that only works from one
/// directory.
#[test]
fn derived_surfaces_carry_one_invocation_form() {
    use orchard::ceremony::derive::{
        BANNED_INVOCATION_FORMS, build_next_steps, spine_command_rows,
    };
    let img = std::path::Path::new("/tmp/recipes-image-abc.img");
                                                                                              
                                                                            
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut surfaces: Vec<String> = Vec::new();
    for domain in ["box.test", "rezepte.example.org"] {
        surfaces.extend(build_next_steps(img, domain, &repo_root));
    }
    surfaces.extend(spine_command_rows().into_iter().map(|r| r.invocation));
    surfaces.push(orchard::deploy::epilogue::next_steps(&build_next_steps(
        img, "box.test", &repo_root,
    )));
    assert!(!surfaces.is_empty());
    for s in &surfaces {
        for banned in BANNED_INVOCATION_FORMS {
            assert!(
                !s.contains(banned),
                "a derived surface carries the banned invocation form {banned:?}: {s}"
            );
        }
    }
}

                                                                                               
/// only when THAT gate's declared composition is hermetic-and-installed-disk. The oracle is the
/// Makefile the fixture writes, never `real_domain_gate`'s own answer — the prior arm branched on
                                                                                         
/// composition carrying the installed-disk leg must name the gate; the SAME Makefile with that leg
                                                                                             
/// over the whole registry, not the composition) reddens the reduced fixture: the registry keeps
/// the leg the recipe dropped, so a registry scan still answers `Some` and the debt case never
/// fires. Also holds the P1 High: never a bare `orchard dryrun` for a real-domain image.
#[test]
fn the_post_build_hint_names_a_real_domain_gate_only_when_the_composition_satisfies_it() {
    use orchard::ceremony::derive::build_next_steps;
    let img = std::path::Path::new("/tmp/recipes-image-abc.img");
    let target = orchard::ceremony::spine::CEREMONY_GATE_TARGET;
                                                                                                   
    let makefile = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Makefile"),
    )
    .expect("read the repo Makefile");

                                                                                                      
                                      
    let sat = tempfile::tempdir().expect("tempdir");
    std::fs::write(sat.path().join("Makefile"), &makefile).expect("write Makefile");
    let hint_sat = build_next_steps(img, "rezepte.example.org", sat.path()).join("\n");
    assert!(
        !hint_sat.contains("orchard dryrun"),
        "never a bare dryrun for a real-domain image: {hint_sat}"
    );
    assert!(
        hint_sat.contains(&format!("make {target}")),
        "a satisfying composition makes the hint name the gate: {hint_sat}"
    );
    assert!(
        !hint_sat.contains("Q7"),
        "a satisfying composition is not the debt case: {hint_sat}"
    );

                                                                                                     
                                                                                                      
                           
    let reduced: String = makefile
        .lines()
        .filter(|l| !l.contains("installed_disk_boots_through_seabios_to_working_runtime"))
        .collect::<Vec<_>>()
        .join("\n");
    let not = tempfile::tempdir().expect("tempdir");
    std::fs::write(not.path().join("Makefile"), reduced).expect("write Makefile");
    let hint_not = build_next_steps(img, "rezepte.example.org", not.path()).join("\n");
    assert!(
        hint_not.contains("Q7"),
        "a non-satisfying composition names the debt: {hint_not}"
    );
    assert!(
        hint_not.lines().all(|l| l.trim_start().starts_with('#')),
        "with no usable gate the hint offers no command to run: {hint_not}"
    );

                                                                                                    
                         
    let test = build_next_steps(img, "box.test", sat.path()).join("\n");
    assert!(test.contains(&format!("make {target}")), "{test}");
    assert!(!test.contains("orchard dryrun"), "{test}");
}

                                                                                                
/// model are named, so a new hint cannot join them silently.
#[test]
fn the_derived_surface_exclusions_are_a_frozen_exact_set() {
    use orchard::ceremony::derive::DERIVED_SURFACE_EXCLUSIONS;
    assert_eq!(
        DERIVED_SURFACE_EXCLUSIONS,
        &[
            "generate_keys_secure_boot_next_steps",
            "sign_sb_next_steps",
            "orchard sync-pins",
            "orchard refresh-apk-lock",
            "orchard update-cert-fingerprints",
            "orchard market store status",
            "orchard market store prune",
        ],
        "the exclusion set is frozen; adding a row is a deliberate act with its reason"
    );
}

/// The shim and the real binary share ONE workspace `target/`, so a shim `[[bin]] name` of
/// `orchard` overwrites the binary it is supposed to exec — and then execs itself, forever.
/// Measured: that is exactly what happened the first time the shim crate was added, and a
/// `--version` from outside a checkout printed the shim's refusal instead of a version. Cargo
/// does not refuse the collision, so this arm does.
#[test]
fn the_shim_artifact_never_collides_with_the_binary_it_execs() {
    let shim = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../orchard-shim/Cargo.toml"),
    )
    .expect("read the shim manifest");
    let parsed: toml::Table = toml::from_str(&shim).expect("parses");
    let bins = parsed
        .get("bin")
        .and_then(|b| b.as_array())
        .expect("the shim declares [[bin]]");
    assert_eq!(bins.len(), 1, "one shim artifact");
    let name = bins[0]
        .get("name")
        .and_then(|n| n.as_str())
        .expect("the bin is named");
    assert_ne!(
        name, "orchard",
        "the shim artifact must not be named `orchard`: both crates build into one \
         target/release, so it would overwrite the binary it execs"
    );
                                                                                         
    let real = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("read the orchard manifest");
    assert!(
        real.contains("name = \"orchard\""),
        "the real crate is still `orchard`"
    );
                                                                                     
                                                                                             
}

                                                                                       
/// surfaces the 2026-07 pass left out. The rule is the C4-2026-07 one recorded in
                                                                                                
/// the operator does about it.
///
/// HONEST TRIPWIRE, coverage stated: it drives the REAL binary over one cheap refusing argv per
/// verb and asserts the stderr carries an actionable next step. It cannot judge whether the step
/// is the RIGHT one — that is review and the fresh-audit's — and it reaches only the refusal each
/// argv triggers, not every refusal those verbs can raise. What it does hold is the regression it
/// exists for: a refusal that degrades to a bare statement of what went wrong.
#[test]
fn o1_the_extended_verbs_refuse_with_an_actionable_next_step() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("mk");
                                                                                               
                                                                                            
    const ACTIONABLE: &[&str] = &[
        "orchard ",
        "make ",
        "cargo ",
        "pass ",
        "set ",
        "run ",
        "add ",
        "remove ",
        "fix ",
        "check ",
        "supply ",
        "point ",
        "populate ",
        "re-run",
        "rerun",
        "create ",
        "use ",
    ];
    let cases: &[(&str, &[&str])] = &[
        (
            "market upgrade",
            &["market", "upgrade", "--source", "no-such-artifact"],
        ),
        ("market store prune", &["market", "store", "prune"]),
        ("market verify", &["market", "verify"]),
        (
            "status",
            &["status", "203.0.113.1", "--ssh-identity", "/no/such/key"],
        ),
    ];
    for (label, argv) in cases {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_orchard"))
            .current_dir(tmp.path())
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("ORCHARD_LOCK_DIR", tmp.path().join("lock"))
            .env_remove("FRUIT_ARTIFACT_STORE")
            .env_remove("ORCHARD_LOCK_TOKEN")
            .args(*argv)
            .output()
            .expect("spawn");
        assert!(
            !out.status.success(),
            "{label}: this argv must refuse, or the arm proves nothing"
        );
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            ACTIONABLE.iter().any(|a| text.to_lowercase().contains(a)),
            "{label}: the refusal states no action the operator can take:\n{text}"
        );
    }
}

                                                                                                   
                                                                         
                                                                                                   

/// The crate root read at RUN time. The compile-time `env!` form bakes the BUILD tree's path into
/// the binary, so a stale binary scans a tree nobody is editing
                                                                                           
/// scanning nothing.
fn crate_root_at_runtime() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect(
        "CARGO_MANIFEST_DIR is unset: this census has no source tree to scan and must not pass",
    ))
}

/// Every `*.rs` under `<crate>/<sub>`, recursively, as `/`-joined paths relative to the crate
/// root, sorted. Reading a directory that is not there is a red, not an empty scan.
fn rust_sources_under(sub: &str) -> Vec<String> {
    let root = crate_root_at_runtime();
    let mut out = Vec::new();
    let mut stack = vec![root.join(sub)];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
            panic!(
                "read {}: {e} — the census cannot scan nothing",
                dir.display()
            )
        });
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let rel = path
                    .strip_prefix(&root)
                    .expect("under the crate root")
                    .to_str()
                    .expect("utf-8 path")
                    .replace('\\', "/");
                out.push(rel);
            }
        }
    }
    out.sort();
    out
}

/// One `RefusalId::<Variant>` occurrence: its 1-based line and the variant name.
type IdOccurrence = (usize, String);

/// The `RefusalId::<Variant>` occurrences in one source, split into the ones this scanner counts
/// as construction sites and the ones it drops as comment text.
///
/// The MODEL, stated because it is what the census enforces and not a Rust lexer: an occurrence
/// counts unless the first non-whitespace characters of its line are `//`. Trailing comments,
/// block-comment bodies and string literals are therefore COUNTED — that direction over-counts
/// and reddens, so it is the safe one. The unsafe direction is a variant reached without the
/// `RefusalId::` prefix; the `use`-import route is refused separately below, and the
/// local-binding route (`let id = RefusalId::X;` used at two sites) still moves the count and so
/// still reddens, though it attributes the sites to the binding line.
fn refusal_id_occurrences(src: &str) -> (Vec<IdOccurrence>, Vec<IdOccurrence>) {
    let (mut code, mut commented) = (Vec::new(), Vec::new());
    for (n, line) in src.lines().enumerate() {
        let in_comment_line = line.trim_start().starts_with("//");
        let mut rest = line;
        while let Some(at) = rest.find("RefusalId::") {
            rest = &rest[at + "RefusalId::".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            if in_comment_line {
                commented.push((n + 1, name));
            } else {
                code.push((n + 1, name));
            }
        }
    }
    (code, commented)
}

                                                                                                  
/// remedy class, and the property that keeps it that way is a HUMAN judgment at each construction
/// site: does this failure belong to that class. No checker owns that judgment (peeler D26), so
/// this arm owns the thing a checker can own — the SET. It freezes the multiset
/// {(source file, RefusalId variant) -> construction-token count} over `crates/orchard/src`, and
/// prints the involved rows' construction-site LINES when the set moves, scanned
/// from the tree at re-freeze time.
///
/// What it claims: the set changed. What it does NOT claim: that any cure is true at its site.
/// That claim's owner is the construction (one id, one remedy class) and the driven per-class pins.
///
/// Domain: every `*.rs` under `src`, minus `ceremony/refusal.rs` (the declaration site) and minus
/// the crate's inline `*_tests.rs` modules. Blind spots are named on `refusal_id_occurrences`.
#[test]
fn refusal_construction_sites_match_the_frozen_class_table() {
                                                      
    const FROZEN: &[(&str, &str, usize)] = &[
        ("src/ceremony/admission.rs", "CeremonyTreeDirty", 1),
        ("src/ceremony/admission.rs", "JudgmentNotResupplied", 1),
        ("src/ceremony/admission.rs", "ParameterInvalid", 1),
        ("src/ceremony/admission.rs", "PreconditionUnmet", 1),
        ("src/ceremony/admission.rs", "ProfileTargetMissing", 1),
        ("src/ceremony/admission.rs", "RequiredParamMissing", 1),
        ("src/ceremony/admission.rs", "TargetMismatch", 1),
        ("src/ceremony/admission.rs", "TargetNotTyped", 1),
        ("src/ceremony/consent.rs", "ConsentGateOwed", 3),
        ("src/ceremony/consent.rs", "SiblingContentUnrecognized", 1),
        ("src/ceremony/disclosure.rs", "GitStateUnreadable", 1),
        ("src/ceremony/gate_commit.rs", "CeremonyCommitRefused", 2),
        ("src/ceremony/gate_commit.rs", "CommitPreviewEmpty", 1),
        ("src/ceremony/gate_commit.rs", "CommitVerifyFailed", 1),
        ("src/ceremony/gate_commit.rs", "GateContentMoved", 1),
        ("src/ceremony/gate_commit.rs", "GateRecordDropped", 1),
        ("src/ceremony/gate_commit.rs", "GateSettleFailed", 1),
        ("src/ceremony/gate_commit.rs", "GateTreeDeltaExceedsOwed", 1),
        ("src/ceremony/gate_commit.rs", "GitStateUnreadable", 2),
        (
            "src/ceremony/gate_commit.rs",
            "InternalInvariantViolated",
            1,
        ),
        ("src/ceremony/gate_commit.rs", "PartialCommitBlocked", 1),
        ("src/ceremony/gate_commit.rs", "RepositoryFormUnmodelled", 1),
        (
            "src/ceremony/gate_record.rs",
            "GateCompositionUnsatisfiable",
            1,
        ),
        ("src/ceremony/gate_record.rs", "GateRecordMismatch", 6),
        ("src/ceremony/gate_record.rs", "GateRecordMissing", 3),
        ("src/ceremony/gate_record.rs", "GateRecordSchemaSkew", 1),
        ("src/ceremony/gate_record.rs", "ProfileUnwritable", 1),
        ("src/ceremony/gate_record.rs", "ProvenanceUnusable", 5),
        (
            "src/ceremony/gate_record.rs",
            "RealDomainGateUnavailable",
            1,
        ),
        ("src/ceremony/gate_record.rs", "SidecarUnwritable", 4),
        ("src/ceremony/interview.rs", "InternalInvariantViolated", 2),
        ("src/ceremony/interview.rs", "InterviewNotInteractive", 1),
        ("src/ceremony/interview.rs", "ProfileAnswerInvalid", 2),
        ("src/ceremony/interview.rs", "ProfileUnwritable", 1),
        ("src/ceremony/interview.rs", "ProfileWriteRefused", 1),
        ("src/ceremony/lock.rs", "LockHeld", 1),
        ("src/ceremony/lock.rs", "LockUnavailable", 4),
        ("src/ceremony/lock.rs", "RunnerLivenessLost", 4),
        ("src/ceremony/records.rs", "DeclaredPathUnhashable", 3),
        ("src/ceremony/records.rs", "GitStateUnreadable", 1),
        ("src/ceremony/records.rs", "InternalInvariantViolated", 4),
        ("src/ceremony/records.rs", "RecordsSchemaOutdated", 1),
        ("src/ceremony/records.rs", "RecordsUnreadable", 2),
        ("src/ceremony/records.rs", "RecordsUnwritable", 4),
        ("src/ceremony/records.rs", "UnmergedOwedPath", 1),
        ("src/ceremony/runner.rs", "DestructiveTokenNotTyped", 1),
        ("src/ceremony/runner.rs", "GateRecordMissing", 1),
        ("src/ceremony/runner.rs", "GitStateUnreadable", 2),
        ("src/ceremony/runner.rs", "InternalInvariantViolated", 2),
        ("src/ceremony/runner.rs", "PreconditionUnmet", 2),
        ("src/ceremony/runner.rs", "RepoManifestUnusable", 2),
        ("src/ceremony/runner.rs", "RequiredParamMissing", 1),
        ("src/ceremony/runner.rs", "StepFailed", 2),
        ("src/ceremony/runner.rs", "StepInputMissing", 2),
        ("src/deploy/context.rs", "ContextConflict", 1),
        ("src/deploy/context.rs", "ContextFileInvalid", 3),
        ("src/deploy/context.rs", "ContextNotUtf8", 1),
        ("src/deploy/context.rs", "ContextUnresolvable", 3),
        ("src/deploy/context.rs", "ProfileContextPathRelative", 1),
        ("src/main.rs", "ProfileSchemaSkew", 1),
        ("src/main.rs", "WeightsEnvRefused", 1),
    ];
                                                                                               
                                                               
    const FROZEN_COMMENTED: &[(&str, &str)] = &[];

                                                                                                   
    let fixture = r#"
let a = Refusal::new(RefusalId::LockUnavailable, "x");
// a commented-out construction: Refusal::new(RefusalId::LockHeld, "y")
/// doc prose naming RefusalId::StepFailed
    //! module prose naming RefusalId::StepFailed
write_atomic(p, b, RefusalId::SidecarUnwritable)?;
let two = (RefusalId::LockHeld, RefusalId::StepFailed);
"#;
    let (code, commented) = refusal_id_occurrences(fixture);
    assert_eq!(
        code.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>(),
        [
            "LockUnavailable",
            "SidecarUnwritable",
            "LockHeld",
            "StepFailed"
        ],
        "the scanner does not read its own fixture the way this census claims"
    );
    assert_eq!(
        commented
            .iter()
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>(),
        ["LockHeld", "StepFailed", "StepFailed"],
        "a construction on a comment line must not count as a site"
    );

                                                                                                   
    let all = rust_sources_under("src");
    assert!(
        all.len() >= 40,
        "the walk found {} sources under src; the tree it is meant to scan is larger, so this is \
         a walk failure and not a clean tree",
        all.len()
    );
    assert!(
        all.contains(&"src/ceremony/refusal.rs".to_string()),
        "the declaration site must be REACHED and then skipped, not missed by the walk"
    );
    let scanned: Vec<&String> = all
        .iter()
        .filter(|p| *p != "src/ceremony/refusal.rs" && !p.ends_with("_tests.rs"))
        .collect();

    let known: BTreeMap<String, RefusalId> = RefusalId::ALL
        .iter()
        .map(|id| (format!("{id:?}"), *id))
        .collect();
    let root = crate_root_at_runtime();
    let mut measured: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut measured_lines: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    let mut measured_commented: BTreeSet<(String, String)> = BTreeSet::new();
    for rel in &scanned {
        let text = std::fs::read_to_string(root.join(rel)).expect("read a scanned source");
        for line in text.lines() {
            assert!(
                !(line.trim_start().starts_with("use ") && line.contains("RefusalId::")),
                "{rel}: a `use` of a RefusalId VARIANT lets a site spell it without the \
                 `RefusalId::` prefix, which this census cannot see. Import the enum, not its \
                 variants: {line}"
            );
        }
        let (code, commented) = refusal_id_occurrences(&text);
        for (line, name) in code {
            assert!(
                known.contains_key(&name),
                "{rel}:{line}: `RefusalId::{name}` is not a variant of the enum. A path that is \
                 not a variant (an associated const, a typo, a renamed variant) makes the count \
                 for this file meaningless"
            );
            *measured.entry(((*rel).clone(), name.clone())).or_default() += 1;
            measured_lines
                .entry(((*rel).clone(), name))
                .or_default()
                .push(line);
        }
        for (_, name) in commented {
            measured_commented.insert(((*rel).clone(), name));
        }
    }

                                                                                                   
    let frozen_commented: BTreeSet<(String, String)> = FROZEN_COMMENTED
        .iter()
        .map(|(f, v)| ((*f).to_string(), (*v).to_string()))
        .collect();
    assert_eq!(
        measured_commented, frozen_commented,
        "the comment-line occurrences moved. These are the occurrences the census DROPS, so a \
         change here changes what the counts below mean"
    );

                                                                                                   
                                                                                                
                                                                                                
                                
    let constructed: BTreeSet<&str> = measured.keys().map(|(_, v)| v.as_str()).collect();
    let declared: BTreeSet<&str> = known.keys().map(String::as_str).collect();
    assert_eq!(
        constructed, declared,
        "a declared RefusalId has no construction site"
    );

                                                                                                   
    let frozen: BTreeMap<(String, String), usize> = FROZEN
        .iter()
        .map(|(f, v, n)| (((*f).to_string(), (*v).to_string()), *n))
        .collect();
    assert_eq!(
        frozen.len(),
        FROZEN.len(),
        "the frozen table holds a duplicate (file, variant) row"
    );
    if measured != frozen {
        let mut report = String::from(
            "the RefusalId construction-site multiset moved. Re-read each changed row's SITES \
             below and confirm the id's remedy is true at each, then re-freeze this table:\n",
        );
        for key in frozen
            .keys()
            .chain(measured.keys())
            .collect::<BTreeSet<_>>()
        {
            let (was, now) = (
                frozen.get(key).copied().unwrap_or(0),
                measured.get(key).copied().unwrap_or(0),
            );
            if was != now {
                let lines = measured_lines
                    .get(key)
                    .map(|v| format!("{v:?}"))
                    .unwrap_or_else(|| "[]".to_string());
                report.push_str(&format!(
                    "  {} {}: {was} -> {now}  sites {lines}\n",
                    key.0, key.1
                ));
            }
        }
        panic!("{report}");
    }
    assert_eq!(
        measured.values().sum::<usize>(),
        106,
        "the total construction-token count moved without a row changing, which cannot happen \
         unless this arm's own arithmetic is wrong"
    );
}

                                                                                     
/// convention survived in a clap help line and in comments after the templates were fixed. Both
/// spellings of that retired convention are enumerable tokens, so a source-byte scan owns them:
/// the allowlist is the exact set of lines permitted to hold each, and both directions redden (a
/// new site, and a lost allowlisted line).
///
/// What it claims: these two TOKENS appear nowhere but the allowlisted true-negation lines. What
/// it does NOT claim: that no location claim is wrong. A paraphrase carrying no token is outside
/// it — the standing WATCH, disclosed, and the reason Arm 3 keeps its own records-path check over
/// the cure templates.
///
/// The needles and the allowlisted lines are assembled from fragments so this file does not
/// itself hold the tokens it scans the tree for.
#[test]
fn the_retired_records_location_convention_stays_deleted() {
    const BESIDE: &str = concat!("beside the ", "profile");
    const BOXES_D: &str = concat!("boxes/<", "name>.d");
    const BESIDE_ALLOWED: &[(&str, &str)] = &[];
    const BOXES_D_ALLOWED: &[(&str, &str)] = &[(
        "src/ceremony/records.rs",
        concat!(
            "/// where the records live rather than a static `boxes/<",
            "name>.d/` convention that drifted when the"
        ),
    )];

                                                                                                   
    let hits = |text: &str, needle: &str| -> Vec<String> {
        text.lines()
            .filter(|l| l.contains(needle))
            .map(|l| l.trim().to_string())
            .collect()
    };
    let fixture = concat!(
        "/// its run records live in `boxes/<",
        "name>.d/`.\n",
        "// the copy beside the ",
        "profile is what S8 reads\n",
        "// the copy beside the box is not this claim\n"
    );
    assert_eq!(
        hits(fixture, BESIDE).len(),
        1,
        "the scanner misses its own fixture line"
    );
    assert_eq!(
        hits(fixture, BOXES_D).len(),
        1,
        "the scanner misses its own fixture line"
    );
    assert!(
        hits("// records beside the box\n", BESIDE).is_empty(),
        "a different phrase must not read as this token"
    );

    let root = crate_root_at_runtime();
    let sources: Vec<String> = rust_sources_under("src");
    let tests: Vec<String> = rust_sources_under("tests");
    assert!(
        tests.len() >= 20 && sources.len() >= 40,
        "the walk found {} src and {} tests sources; that is a walk failure, not a clean tree",
        sources.len(),
        tests.len()
    );
    let mut beside_found: BTreeSet<(String, String)> = BTreeSet::new();
    let mut boxes_d_found: BTreeSet<(String, String)> = BTreeSet::new();
    for rel in sources.iter().chain(tests.iter()) {
        let text = std::fs::read_to_string(root.join(rel)).expect("read a scanned source");
        for line in hits(&text, BESIDE) {
            beside_found.insert((rel.clone(), line));
        }
        if rel.starts_with("src/") {
            for line in hits(&text, BOXES_D) {
                boxes_d_found.insert((rel.clone(), line));
            }
        }
    }

    let expect = |rows: &[(&str, &str)]| -> BTreeSet<(String, String)> {
        rows.iter()
            .map(|(f, l)| ((*f).to_string(), (*l).to_string()))
            .collect()
    };
    assert_eq!(
        beside_found,
        expect(BESIDE_ALLOWED),
        "the retired records-location phrasing moved. Every line holding it must be a TRUE \
         NEGATION on the allowlist; a claim that the records live there is the defect"
    );
    assert_eq!(
        boxes_d_found,
        expect(BOXES_D_ALLOWED),
        "the retired checkout-relative records path moved. The resolved dir is what a refusal \
         renders (`records_dir_cure`); a help line or comment naming that shape is the \
         defect"
    );
}

/// One `toml::to_string_pretty` occurrence: the enclosing fn's name and the trimmed line.
type SerializeSite = (String, String, String);

/// The `toml::to_string_pretty` occurrences in one source, with the fn each sits in.
///
/// The MODEL, stated because it is what the arm below enforces and not a Rust parser: a line counts
/// unless its first non-whitespace characters are `//`, and its enclosing fn is the nearest
/// PRECEDING line whose trimmed text starts with `fn ` after any `pub`/`pub(crate)`/`async`/`const`
/// prefix. A hit before the first such line is attributed to `(top level)`. Block-comment bodies and
/// string literals COUNT — that direction over-counts and reddens, so it is the safe one.
fn toml_pretty_sites(rel: &str, src: &str) -> Vec<SerializeSite> {
    let mut out = Vec::new();
    let mut enclosing = "(top level)".to_string();
    for line in src.lines() {
        let t = line.trim_start();
        let mut head = t;
        for prefix in [
            "pub(crate) ",
            "pub ",
            "async ",
            "const ",
            "unsafe ",
            "extern ",
        ] {
            head = head.strip_prefix(prefix).unwrap_or(head);
        }
        if let Some(rest) = head.strip_prefix("fn ") {
            enclosing = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
        }
        if t.starts_with("//") {
            continue;
        }
        if t.contains("toml::to_string_pretty") {
            out.push((rel.to_string(), enclosing.clone(), t.trim_end().to_string()));
        }
    }
    out
}

/// FAC-GC-16 shape 5, the hunt's admissible fallback (`code-phaseR-r6-cures-factory-hunt.md`
/// §Shape 5) for the residue shape 4a leaves: shape 4a routed the six TOML serialize hand-offs
/// through `encode_owned`, and nothing makes a SEVENTH one do the same.
///
/// Two halves, each with its own model.
/// - DRIVEN: `encode_owned` maps a real `toml::ser::Error` to `InternalInvariantViolated`.
/// - FREEZE: the source text under `crates/orchard/src` holds exactly one `toml::to_string_pretty`
///   occurrence, inside `encode_owned`. Exact-set equality, so a new hand-off and a lost chokepoint
///   both redden and force a conscious re-freeze.
///
/// What it claims: those two measured facts. What it does NOT claim: that a serialize failure at an
/// arbitrary site carries the encode id. Blind spots, from the hunt plus this scanner's own model: a
/// `Result<String, toml::ser::Error>` travelling to a distant `map_err` (`records.rs`'s persist
/// closure is that shape, and its signature is what routes it); any OTHER serializer
/// (`toml::to_string`, a hand-built `Serializer`, serde_json); the `write_atomic` path, which is a
/// write and not a serialize; a call emitted by a macro, bound through a fn pointer, or spelled
/// through a `use` rename; and everything outside `crates/orchard/src`.
#[test]
fn the_one_toml_serialize_chokepoint_under_src_constructs_the_encode_id() {
                                                              
    const FROZEN: &[(&str, &str, &str)] = &[(
        "src/ceremony/refusal.rs",
        "encode_owned",
        "toml::to_string_pretty(value).map_err(|e| {",
    )];

                                                                                                     
                                                                                                  
                                
    let refusal = orchard::ceremony::refusal::encode_owned(&42u32, "the probe artifact")
        .expect_err("a bare integer is not a TOML document, so this must refuse");
    assert_eq!(
        refusal.id.token(),
        "internal-invariant-violated",
        "the chokepoint's serialize failure must carry the internal-invariant id, not a path- or \
         image-shaped remedy: {}",
        refusal.detail
    );
    assert!(
        refusal.detail.contains("the probe artifact"),
        "the detail names the artifact the caller supplied: {}",
        refusal.detail
    );

                                                                                                   
    let fixture = concat!(
        "pub fn encode_owned<T>(v: &T) -> R {\n",
        "    toml::to_string_pretty(v).map_err(|e| x)\n",
        "}\n",
        "fn elsewhere() {\n",
        "    // a commented hand-off: toml::to_string_pretty(&x)\n",
        "    let s = toml::to_string(&x);\n",
        "    let t = toml::to_string_pretty(&x).unwrap();\n",
        "}\n",
    );
    let seen = toml_pretty_sites("fx.rs", fixture);
    assert_eq!(
        seen.iter().map(|(_, f, _)| f.as_str()).collect::<Vec<_>>(),
        ["encode_owned", "elsewhere"],
        "the scanner does not read its own fixture the way this arm claims"
    );
    assert!(
        toml_pretty_sites("fx.rs", "    // toml::to_string_pretty(&x)\n").is_empty(),
        "a commented hand-off must not count as a site"
    );
    assert!(
        toml_pretty_sites("fx.rs", "    let s = toml::to_string(&x);\n").is_empty(),
        "a different serializer must not read as this one"
    );

                                                                                                     
    let all = rust_sources_under("src");
    assert!(
        all.len() >= 40,
        "the walk found {} sources under src; that is a walk failure and not a clean tree",
        all.len()
    );
    let root = crate_root_at_runtime();
    let mut measured: Vec<SerializeSite> = Vec::new();
    for rel in &all {
        let text = std::fs::read_to_string(root.join(rel)).expect("read a scanned source");
        measured.extend(toml_pretty_sites(rel, &text));
    }
    measured.sort();
    let frozen: Vec<SerializeSite> = FROZEN
        .iter()
        .map(|(f, n, l)| ((*f).to_string(), (*n).to_string(), (*l).to_string()))
        .collect();
    assert_eq!(
        measured, frozen,
        "the TOML serialize hand-offs under src moved. Every one of them must route through \
         `encode_owned`, so a serialize failure carries the internal-invariant id instead of a \
         path- or image-shaped remedy. Re-point the new site at \
         `encode_owned`, or re-freeze this row with the reason"
    );
}

type CommitSite = (String, String, String);

/// Every `GitCommit::commit` call under `crates/orchard/src`, with the fn it sits in and its
/// argument list normalized to one line (runs of whitespace collapsed to one space, a trailing
/// comma dropped).
///
/// The MODEL, stated because it is what the arm below enforces and not a Rust parser: a line whose
/// text holds `.commit(` opens a call, and the argument text is gathered forward until the round
/// brackets balance. Bracket counting ignores no string or char literal, so a bracket inside an
/// argument literal would mis-gather — that direction changes the row and reddens, which is the
/// safe one. A line whose first non-whitespace characters are `//` is skipped. The enclosing fn is
/// the nearest preceding line whose trimmed text starts with `fn ` after any
/// `pub`/`pub(crate)`/`async`/`const`/`unsafe`/`extern` prefix.
fn commit_call_sites(rel: &str, src: &str) -> Vec<CommitSite> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut enclosing = "(top level)".to_string();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        let mut head = t;
        for prefix in [
            "pub(crate) ",
            "pub ",
            "async ",
            "const ",
            "unsafe ",
            "extern ",
        ] {
            head = head.strip_prefix(prefix).unwrap_or(head);
        }
        if let Some(rest) = head.strip_prefix("fn ") {
            enclosing = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
        }
        if t.starts_with("//") {
            continue;
        }
        let Some(at) = line.find(".commit(") else {
            continue;
        };
        let mut depth = 0i32;
        let mut args = String::new();
        'gather: for (j, text) in lines.iter().enumerate().skip(i) {
            let from = if j == i { at + ".commit".len() } else { 0 };
            for c in text[from..].chars() {
                match c {
                    '(' => {
                        depth += 1;
                        if depth == 1 {
                            continue;
                        }
                    }
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break 'gather;
                        }
                    }
                    _ => {}
                }
                args.push(c);
            }
            args.push(' ');
        }
        let args = args.split_whitespace().collect::<Vec<_>>().join(" ");
        out.push((
            rel.to_string(),
            enclosing.clone(),
            args.trim_end_matches(',').to_string(),
        ));
    }
    out
}

                                                                                                  
/// else. The seam's `no_verify` parameter is a bare `bool` with no type to hold that scope, and the
/// non-ceremony call site (`market upgrade`'s) is not driven by any arm — the CLI would have to run
/// a whole upgrade to reach it — so this is a FREEZE over the call sites, not a driven arm.
///
/// What it claims: `crates/orchard/src` holds exactly these `.commit(` calls with exactly these
/// argument lists, so a flipped literal and a new call site both redden and force a conscious
/// re-freeze. What it does NOT claim: that no code can skip the hooks — the name says frozen
/// call sites, not "only the ceremony", because a freeze compares content and models no grammar. Blind spots, named: a call
/// spelled `GitCommit::commit(&g, …)` rather than as a method; the flag bound to a variable or
/// threaded through a wrapper (the argument text changes, so the row still reddens, but the freeze
/// then holds a name and not a value); a call emitted by a macro; and everything outside
/// `crates/orchard/src`. The ceremony no longer uses this seam (R16: the gate constructs its commit
/// through git plumbing, `ceremony::gate_commit`), so every remaining call site runs the host's
/// hooks.
#[test]
fn the_commit_call_sites_under_src_are_frozen_with_their_hook_policy_flag() {
                                                        
    const FROZEN: &[(&str, &str, &str)] = &[
        (
            "src/deploy/git_commit.rs",
            "shell_git_pathspec_scopes_the_commit",
            "repo.path(), &[repo.path().join(\"consume-pins.toml\")], msg, CommitOpts::default()",
        ),
        (
            "src/deploy/git_commit.rs",
            "shell_git_runs_the_hosts_hooks_unless_no_verify_is_set",
            "repo.path(), std::slice::from_ref(&target), \"hooked\", CommitOpts::default()",
        ),
        (
            "src/deploy/git_commit.rs",
            "shell_git_runs_the_hosts_hooks_unless_no_verify_is_set",
            "repo.path(), &[target], \"unhooked\", CommitOpts { no_verify: true }",
        ),
        (
            "src/deploy/git_commit.rs",
            "shell_git_fails_closed_outside_a_repo",
            "dir.path(), &[dir.path().join(\"x\")], \"msg\", CommitOpts::default()",
        ),
        (
            "src/main.rs",
            "run_deploy",
            "&root, &cplan.orchard, &message, CommitOpts::default()",
        ),
    ];

                                                                                                   
    let fixture = concat!(
        "fn one() {\n",
        "    seam.commit(repo, paths, msg, true)?;\n",
        "}\n",
        "pub fn two() {\n",
        "    // seam.commit(repo, paths, msg, true)\n",
        "    ShellGit\n",
        "        .commit(\n",
        "            repo.path(),\n",
        "            &[p],\n",
        "            msg,\n",
        "            false,\n",
        "        )\n",
        "        .unwrap();\n",
        "}\n",
    );
    let seen = commit_call_sites("fx.rs", fixture);
    assert_eq!(
        seen,
        vec![
            (
                "fx.rs".to_string(),
                "one".to_string(),
                "repo, paths, msg, true".to_string()
            ),
            (
                "fx.rs".to_string(),
                "two".to_string(),
                "repo.path(), &[p], msg, false".to_string()
            ),
        ],
        "the scanner does not read its own fixture the way this freeze claims: a one-line call, a \
         call whose arguments wrap over five lines, and a commented call"
    );
    assert!(
        commit_call_sites("fx.rs", "    // seam.commit(r, p, m, true);\n").is_empty(),
        "a commented call must not count as a site"
    );
    assert!(
        commit_call_sites("fx.rs", "    let c = record.committed(x);\n").is_empty(),
        "a different method must not read as this one"
    );

                                                                                                     
    let all = rust_sources_under("src");
    assert!(
        all.len() >= 40,
        "the walk found {} sources under src; that is a walk failure and not a clean tree",
        all.len()
    );
    for required in ["src/main.rs", "src/ceremony/runner.rs"] {
        assert!(
            all.contains(&required.to_string()),
            "the walk missed {required}, so this freeze would scan the call sites it exists for \
             not at all and pass"
        );
    }
    let root = crate_root_at_runtime();
    let mut measured: Vec<CommitSite> = Vec::new();
    for rel in &all {
        let text = std::fs::read_to_string(root.join(rel)).expect("read a scanned source");
        measured.extend(commit_call_sites(rel, &text));
    }
    measured.sort();
    let mut frozen: Vec<CommitSite> = FROZEN
        .iter()
        .map(|(f, n, a)| ((*f).to_string(), (*n).to_string(), (*a).to_string()))
        .collect();
    frozen.sort();
    assert_eq!(
        measured, frozen,
        "the `GitCommit::commit` call sites under src moved. `--no-verify` is the CEREMONY gate \
         commit's alone — the witness pair, not the host's hook chain, is its content contract \
         (F5) — and every other caller runs the host's hooks. Read the new or changed site \
         against that scope, then re-freeze this list"
    );
}

/// One `Command::new("git")` spawn under `src`: (file, enclosing fn).
type GitSpawnSite = (String, String);

/// The enclosing fn name walk `commit_call_sites` uses, factored for the spawn census.
fn enclosing_fn_of(lines: &[&str], upto: usize) -> String {
    let mut enclosing = "(top level)".to_string();
    for line in lines.iter().take(upto + 1) {
        let t = line.trim_start();
        let mut head = t;
        for prefix in [
            "pub(crate) ",
            "pub(in crate::ceremony) ",
            "pub ",
            "async ",
            "const ",
            "unsafe ",
            "extern ",
        ] {
            head = head.strip_prefix(prefix).unwrap_or(head);
        }
        if let Some(rest) = head.strip_prefix("fn ") {
            enclosing = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
        }
    }
    enclosing
}

/// Every `Command::new("git")` construction in `src`, with the fn it sits in. Commented lines do not
/// count; a different program does not read as this one.
fn git_spawn_sites(rel: &str, src: &str) -> Vec<GitSpawnSite> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        if !line.contains("Command::new(\"git\")") {
            continue;
        }
        out.push((rel.to_string(), enclosing_fn_of(&lines, i)));
    }
    out
}

/// Every `git_output(` call's argument list in one source, with the fn it sits in: the ARGV of the
/// build-side git reads, whose flag lives at the caller and not at the spawn.
fn git_output_calls(rel: &str, src: &str) -> Vec<CommitSite> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if t.starts_with("//") {
            continue;
        }
                                        
        if t.contains("fn git_output(") {
            continue;
        }
        let Some(at) = line.find("git_output(") else {
            continue;
        };
        let mut depth = 0i32;
        let mut args = String::new();
        'gather: for (j, text) in lines.iter().enumerate().skip(i) {
            let from = if j == i { at + "git_output".len() } else { 0 };
            for c in text[from..].chars() {
                match c {
                    '(' => {
                        depth += 1;
                        if depth == 1 {
                            continue;
                        }
                    }
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break 'gather;
                        }
                    }
                    _ => {}
                }
                args.push(c);
            }
            args.push(' ');
        }
        let args = args.split_whitespace().collect::<Vec<_>>().join(" ");
        out.push((
            rel.to_string(),
            enclosing_fn_of(&lines, i),
            args.trim_end_matches(',').to_string(),
        ));
    }
    out
}

/// §3.9 (iii): the SPAWN-SITE CENSUS that closes the set P-LAST quantifies over. Property P-LAST
/// ("after a gate's identity read, no git command the run or a step child issues refreshes or writes
/// the index until the next gate's own settle") is a claim about a set of git invocations; this arm
/// freezes that set so a new one cannot join it silently.
///
/// What it claims: `crates/orchard/src` constructs `Command::new("git")` at exactly these (file, fn)
/// sites, and `build_image` reads git through exactly these `git_output` argument lists. A new spawn
/// site, a moved one, or a dropped `--no-optional-locks` in a frozen argv all redden and force a
/// conscious re-freeze with a disposition. What it does NOT claim: that no other code can spawn git —
/// a freeze compares content and models no grammar. Blind spots, named: a spawn built through a
/// helper that takes the program name as a value; a spawn spelled `process::Command::new(prog)` with
/// `prog` bound elsewhere; a macro-emitted spawn; a flag passed as a variable rather than a literal;
/// and everything outside `crates/orchard/src`. The rows marked `#[cfg(test)]` are fixture builders,
/// frozen so a new production site cannot hide among them. The per-site behaviour is driven where it
/// can be: `git_dirty_paths` and the run's post-gate reads by
/// `no_git_read_after_the_gates_identity_read_writes_the_index_in_the_run`, `diff_stat` by
/// `the_s6_diff_stat_read_never_refreshes_the_index`, `git_clean` by
/// `the_doctors_working_tree_read_never_refreshes_the_index`. `build_image`'s status read is reachable
/// only through a container build, so its argv row here is its only mechanism.
#[test]
fn the_git_spawn_sites_under_src_are_frozen_with_their_index_disposition() {
                                                                                                 
                                                        
    const FROZEN_SPAWNS: &[(&str, &str)] = &[
                                                                                                      
                                                     
        ("src/ceremony/gate_commit.rs", "ceremony_git"),
                                                                     
        ("src/ceremony/gate_commit_tests.rs", "git"),
                                                                                            
        ("src/deploy/build_image.rs", "git_output"),
                                                                             
        ("src/deploy/doctor.rs", "git_clean"),
                                                            
        ("src/deploy/doctor.rs", "git"),
        ("src/deploy/doctor.rs", "settle"),
                                                                                          
        ("src/deploy/git_commit.rs", "run"),
                                                    
        ("src/deploy/git_commit.rs", "git_show_head"),
                                                                                       
        ("src/deploy/git_commit.rs", "diff_stat"),
                                
        ("src/deploy/git_commit.rs", "test_repo"),
        ("src/deploy/git_commit.rs", "git_stdout"),
                                              
        ("src/deploy/store_admin.rs", "worktree_checkouts"),
                               
        ("src/deploy/store_admin.rs", "run_git"),
    ];
    const FROZEN_GIT_OUTPUT_ARGV: &[(&str, &str, &str)] = &[
        (
            "src/deploy/build_image.rs",
            "build_image",
            "&opts.repo_root, &[\"--no-optional-locks\", \"status\", \"--porcelain\"]",
        ),
        (
            "src/deploy/build_image.rs",
            "build_image",
            "&opts.repo_root, &[\"rev-parse\", \"HEAD\"]",
        ),
        (
            "src/deploy/build_image.rs",
            "build_image",
            "&opts.repo_root, &[\"show\", \"-s\", \"--format=%ct\", \"HEAD\"]",
        ),
    ];

                                                                                                   
    let fixture = concat!(
        "fn one() {\n",
        "    let out = Command::new(\"git\").arg(\"-C\").output();\n",
        "}\n",
        "pub(in crate::ceremony) fn two() {\n",
        "    // let x = Command::new(\"git\");\n",
        "    let mut cmd = std::process::Command::new(\"git\");\n",
        "}\n",
        "fn three() {\n",
        "    let out = Command::new(\"gitk\").output();\n",
        "}\n",
    );
    assert_eq!(
        git_spawn_sites("fx.rs", fixture),
        vec![
            ("fx.rs".to_string(), "one".to_string()),
            ("fx.rs".to_string(), "two".to_string()),
        ],
        "the scanner does not read its own fixture the way this freeze claims: a plain spawn, a \
         qualified spawn inside a `pub(in ...)` fn, a commented spawn, and a spawn of a DIFFERENT \
         program"
    );
    let argv_fixture = concat!(
        "fn caller() {\n",
        "    let a = git_output(&root, &[\"status\"])?;\n",
        "    // git_output(&root, &[\"commented\"])\n",
        "    let b = git_output(\n",
        "        &root,\n",
        "        &[\"show\", \"HEAD\"],\n",
        "    )?;\n",
        "}\n",
        "pub(crate) fn git_output(repo_root: &Path, args: &[&str]) -> R {\n",
        "}\n",
    );
    assert_eq!(
        git_output_calls("fx.rs", argv_fixture),
        vec![
            (
                "fx.rs".to_string(),
                "caller".to_string(),
                "&root, &[\"status\"]".to_string()
            ),
            (
                "fx.rs".to_string(),
                "caller".to_string(),
                "&root, &[\"show\", \"HEAD\"]".to_string()
            ),
        ],
        "the argv scanner does not read its own fixture the way this freeze claims: a one-line \
         call, a commented call, a wrapped call, and the DEFINITION (not a call)"
    );

                                                                                                     
    let all = rust_sources_under("src");
    assert!(
        all.len() >= 40,
        "the walk found {} sources under src; that is a walk failure and not a clean tree",
        all.len()
    );
    for required in [
        "src/ceremony/gate_commit.rs",
        "src/ceremony/admission.rs",
        "src/deploy/build_image.rs",
    ] {
        assert!(
            all.contains(&required.to_string()),
            "the walk missed {required}, so this freeze would scan the sites it exists for not at \
             all and pass"
        );
    }
    let root = crate_root_at_runtime();
    let mut spawns: Vec<GitSpawnSite> = Vec::new();
    let mut argv: Vec<CommitSite> = Vec::new();
    for rel in &all {
        let text = std::fs::read_to_string(root.join(rel)).expect("read a scanned source");
        spawns.extend(git_spawn_sites(rel, &text));
        if rel == "src/deploy/build_image.rs" {
            argv.extend(git_output_calls(rel, &text));
        }
    }
    spawns.sort();
    let mut frozen: Vec<GitSpawnSite> = FROZEN_SPAWNS
        .iter()
        .map(|(f, n)| ((*f).to_string(), (*n).to_string()))
        .collect();
    frozen.sort();
    assert_eq!(
        spawns, frozen,
        "the `Command::new(\"git\")` sites under src moved. Every one is a member of the set P-LAST \
         quantifies over: read the new or changed site's index effect against the §3.9 table, give \
         it its flag, then re-freeze this list"
    );
    let mut frozen_argv: Vec<CommitSite> = FROZEN_GIT_OUTPUT_ARGV
        .iter()
        .map(|(f, n, a)| ((*f).to_string(), (*n).to_string(), (*a).to_string()))
        .collect();
    frozen_argv.sort();
    argv.sort();
    assert_eq!(
        argv, frozen_argv,
        "build_image's git reads moved. The S7 status read carries `--no-optional-locks` at the \
         CALLER, and no arm can drive it (the read sits inside a container build), so this argv is \
         its only mechanism"
    );

                                                                                                    
    let ceremony: Vec<&GitSpawnSite> = spawns
        .iter()
        .filter(|(f, _)| f.starts_with("src/ceremony/"))
        .collect();
    assert_eq!(
        ceremony,
        vec![
            &(
                "src/ceremony/gate_commit.rs".to_string(),
                "ceremony_git".to_string()
            ),
            &(
                "src/ceremony/gate_commit_tests.rs".to_string(),
                "git".to_string()
            ),
        ],
        "a ceremony git command is constructed outside `ceremony_git`, so its child inherits the \
         GIT_* environment §3.11 strips. The second row is the §3.3 arms' fixture builder, compiled \
         only under `#[cfg(test)]`; a new PRODUCTION constructor reds here"
    );
}

                                                                                                
/// and the renderer arms derive their expected rows from the same map, so a re-word there passes
/// every deriving arm (the R12 floor record's M-9). This freeze holds the two speakable phrases as
/// literals; a re-word or a ROTATION reds here and forces a conscious re-freeze. Measured before
/// widening: with only the two speakable phrases frozen, swapping the `Ambiguous` and `Interrupted`
/// bodies left the whole suite green (the headless-stop arm derives its expected phrases from the
/// same map and dedups on the class, so only a COLLISION reddened).
///
/// What it claims: `DirtClass::ALL` holds exactly these variants in this order, each with exactly
/// this phrase. What it does NOT claim: that a phrase is true of its class — that judgment lives at
/// the declaration and in the driven arms that render each.
#[test]
fn the_cause_phrases_are_frozen() {
    use orchard::ceremony::records::DirtClass;
    const FROZEN: &[(&str, &str)] = &[
        ("CleanOrRecorded", "recorded by this run"),
        ("PriorRunRecorded", "recorded by a prior run"),
        ("Interrupted", "a prior run interrupted mid-write"),
        ("Ambiguous", "unrecorded"),
    ];
    let measured: Vec<(String, String)> = DirtClass::ALL
        .iter()
        .map(|c| (format!("{c:?}"), c.cause_phrase().to_string()))
        .collect();
    let frozen: Vec<(String, String)> = FROZEN
        .iter()
        .map(|(v, p)| ((*v).to_string(), (*p).to_string()))
        .collect();
    assert_eq!(
        measured, frozen,
        "the class-to-cause-phrase map moved. Both consumers (the headless stop's cause list and \
         every disclosure row's class column) render these strings at the operator; re-read \
         the new phrase against its class, then re-freeze this list"
    );
}

/// CT-4 (D-R12-5, FAC-GC-14 face 1): the three `DirtClass` payload maps are pairwise INJECTIVE over
/// `DirtClass::ALL`. `commit_message` groups by class equality after a `section_order` sort, and the
/// headless-stop cause list dedups on the class; both read as one section per class and one phrase
/// per class only while the maps stay injective. The R11 probe that measured this is promoted here.
///
/// What it claims: `section_order`, `class_heading` and `cause_phrase` are each injective over
/// `DirtClass::ALL` on this tree. What it does NOT claim: that any ordinal, heading or phrase is
/// TRUE of its class. That judgment lives at the declaration and in the driven arms that render
/// each (`the_commit_message_sections_follow_section_order_and_keep_input_order_within_a_section`,
/// `the_headless_unspeakable_stop_names_the_subset_and_each_present_cause_once`).
#[test]
fn the_dirt_class_payload_maps_are_pairwise_injective() {
    use orchard::ceremony::consent::class_heading;
    use orchard::ceremony::records::DirtClass;

                                                                                                 
                                                
    let variants: Vec<String> = DirtClass::ALL.iter().map(|c| format!("{c:?}")).collect();
    let distinct_variants: BTreeSet<&String> = variants.iter().collect();
    assert_eq!(
        distinct_variants.len(),
        variants.len(),
        "DirtClass::ALL lists a variant twice: {variants:?}"
    );

    let maps: [(&str, Vec<String>); 3] = [
        (
            "section_order",
            DirtClass::ALL
                .iter()
                .map(|c| c.section_order().to_string())
                .collect(),
        ),
        (
            "class_heading",
            DirtClass::ALL
                .iter()
                .map(|c| class_heading(*c).to_string())
                .collect(),
        ),
        (
            "cause_phrase",
            DirtClass::ALL
                .iter()
                .map(|c| c.cause_phrase().to_string())
                .collect(),
        ),
    ];
    for (name, values) in maps {
        let distinct: BTreeSet<&String> = values.iter().collect();
        assert_eq!(
            distinct.len(),
            values.len(),
            "{name} maps two DirtClass variants to one value, so the class-keyed grouping and \
             dedup can no longer read one-per-class: {:?}",
            DirtClass::ALL
                .iter()
                .map(|c| format!("{c:?}"))
                .zip(values.iter())
                .collect::<Vec<_>>()
        );
    }
}

use proc_macro2::{Delimiter, TokenStream, TokenTree};

/// What the token walk measured in one ceremony source.
#[derive(Debug, Default)]
struct DeployCensus {
    /// Item paths after `crate::deploy::`, as spelled (a variant path is its own row).
    items: Vec<String>,
    /// `(item path, alias ident)` for `as`-bound matches inside a `use` item.
    aliases: Vec<(String, String)>,
    /// Fail-closed shapes: a module-level alias, an alias inside a brace list, a bare module
    /// reference, a path suffix the matcher cannot follow (glob, turbofish).
    errors: Vec<String>,
    /// `deploy` idents the canonical matcher did not consume (a relative path, a `crate::{…}`
    /// group, any spelling that lexes the ident outside `crate :: deploy ::`).
    unconsumed: usize,
}

/// Lex one source and walk its token trees. Comments vanish in the lexer; doc comments and string
/// literals lex as literals, never `Ident`s, so prose naming deploy cannot enter the census. A
/// source that does not lex fails closed.
fn census_file(src: &str) -> Result<DeployCensus, String> {
    let ts: TokenStream = src.parse().map_err(|e| format!("does not lex: {e}"))?;
    let mut c = DeployCensus::default();
    walk_tokens(ts, &mut c);
    Ok(c)
}

fn path_sep(toks: &[TokenTree], i: usize) -> bool {
    matches!(toks.get(i), Some(TokenTree::Punct(p)) if p.as_char() == ':')
        && matches!(toks.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == ':')
}

fn walk_tokens(ts: TokenStream, c: &mut DeployCensus) {
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    let mut in_use = false;
    let mut i = 0usize;
    while i < toks.len() {
        match &toks[i] {
            TokenTree::Ident(id) if *id == "use" => {
                in_use = true;
                i += 1;
            }
            TokenTree::Punct(p) if p.as_char() == ';' => {
                in_use = false;
                i += 1;
            }
            TokenTree::Ident(id)
                if *id == "crate"
                    && path_sep(&toks, i + 1)
                    && matches!(toks.get(i + 3), Some(TokenTree::Ident(d)) if d.to_string().trim_start_matches("r#") == "deploy") =>
            {
                i = deploy_suffix(&toks, i + 4, in_use, c);
            }
            TokenTree::Ident(id) if id.to_string().trim_start_matches("r#") == "deploy" => {
                c.unconsumed += 1;
                i += 1;
            }
            TokenTree::Group(g) => {
                walk_tokens(g.stream(), c);
                i += 1;
            }
            _ => i += 1,
        }
    }
}

/// The path after a matched `crate :: deploy` head: `:: seg` repeated, a use-tree brace group
/// after `::`, then an optional `as <alias>` when inside a `use` item. Returns the index after
/// the consumed suffix.
fn deploy_suffix(toks: &[TokenTree], mut j: usize, in_use: bool, c: &mut DeployCensus) -> usize {
    let mut segs: Vec<String> = Vec::new();
    while path_sep(toks, j) {
        match toks.get(j + 2) {
            Some(TokenTree::Ident(s)) if *s != "as" => {
                segs.push(s.to_string());
                j += 3;
            }
            Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => {
                brace_members(g.stream(), &segs, c);
                return j + 3;
            }
            _ => {
                c.errors.push(format!(
                    "a `::` after `crate::deploy::{}` is followed by neither an ident nor a \
                     brace group (glob and turbofish spellings are not censusable — name the item)",
                    segs.join("::")
                ));
                return j + 2;
            }
        }
    }
    let mut alias = None;
    if in_use
        && matches!(toks.get(j), Some(TokenTree::Ident(a)) if *a == "as")
        && let Some(TokenTree::Ident(a)) = toks.get(j + 1)
    {
        alias = Some(a.to_string());
        j += 2;
    }
    if segs.is_empty() {
        c.errors.push(
            "a bare `crate::deploy` names the module, not an item (D-R12-1: name the item)"
                .to_string(),
        );
        return j;
    }
    let path = segs.join("::");
    match alias {
        Some(a) if segs.len() < 2 => c.errors.push(format!(
            "`crate::deploy::{path} as {a}` aliases at the module level, so every descendant \
             becomes reachable with no `deploy` token at the use site. Name the item (D-R12-1)"
        )),
        Some(a) => {
            c.aliases.push((path.clone(), a));
            c.items.push(path);
        }
        None => c.items.push(path),
    }
    j
}

/// A use-tree brace group's comma-separated members, each joined onto the prefix. `self` yields
/// the prefix; a nested brace recurses; an aliased member is a fail-closed error (it hides which
/// item the list admits).
fn brace_members(ts: TokenStream, prefix: &[String], c: &mut DeployCensus) {
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    for member in toks.split(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == ',')) {
        if member.is_empty() {
            continue;
        }
        if member.len() == 1 && matches!(&member[0], TokenTree::Ident(s) if *s == "self") {
            if prefix.is_empty() {
                c.errors.push(
                    "`self` in a root brace list names the module, not an item (D-R12-1)"
                        .to_string(),
                );
            } else {
                c.items.push(prefix.join("::"));
            }
            continue;
        }
        let mut segs = prefix.to_vec();
        let mut j = 0usize;
        loop {
            match member.get(j) {
                Some(TokenTree::Ident(s)) if *s == "as" => {
                    c.errors.push(
                        "an alias inside a brace list hides which item it admits (D-R12-1: name \
                         the item on its own `use` line)"
                            .to_string(),
                    );
                    return;
                }
                Some(TokenTree::Ident(s)) => {
                    segs.push(s.to_string());
                    j += 1;
                }
                Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => {
                    brace_members(g.stream(), &segs, c);
                    break;
                }
                _ => {
                    c.errors
                        .push(format!("unparsable brace-list member {member:?}"));
                    return;
                }
            }
            if path_sep(member, j) {
                j += 2;
                continue;
            }
            if let Some(extra) = member.get(j) {
                if matches!(extra, TokenTree::Ident(s) if *s == "as") {
                    c.errors.push(
                        "an alias inside a brace list hides which item it admits (D-R12-1: name \
                         the item on its own `use` line)"
                            .to_string(),
                    );
                } else {
                    c.errors
                        .push(format!("unparsable brace-list member {member:?}"));
                }
                return;
            }
            if segs.len() > prefix.len() {
                c.items.push(segs.join("::"));
            }
            break;
        }
    }
}

/// CT-7 / D-R12-4, the MECHANIZE rung of the borrowed-contract closure: an IMPORT CENSUS over the
/// ceremony sources' bytes. The split rule (D-R12-1) is that the ceremony may borrow MECHANISM from
/// `deploy::` and may not borrow a DECISION or a DISCLOSURE; that rule is a human judgment at each
/// introduction, so this arm owns the thing a checker can own — the SET of `crate::deploy::` items
/// the ceremony sources reference. Both directions redden: a new item, and a retired one, each
/// forcing a conscious re-freeze at the introducing commit.
///
/// What it claims: the ceremony sources reference exactly these deploy items, and carry exactly
/// these alias bindings. What it does NOT claim: that any referenced item is mechanism rather than
/// a decision — that reading is the design rule, and this floor does not make it.
///
                                                                                               
/// the canonical `crate::deploy::<item>` matcher did not consume FAILS the census, so a relative
/// path, a `crate::{deploy::…}` group, or any line shape `cargo fmt` emits can only produce a red,
/// never a silent pass. The identifier comparison normalizes the raw-ident spelling (`r#deploy`
                                                                                                    
/// is total. Blind spots that remain are the module system, not the lexer: a deploy item reached
/// through a re-export by some other module (the path then names that module, not `crate::deploy`);
/// a macro that GLUES the path from tokens none of which is the ident `deploy`; and everything
/// outside `crates/orchard/src/ceremony`.
#[test]
fn the_ceremony_imports_exactly_the_frozen_deploy_item_set() {
                                                                                                     
                                                                                                   
                                                                                         
    const FROZEN_ITEMS: &[&str] = &[
        "build_image::DEFAULT_OUT_DIR",
        "build_image::default_kernel_xz",
        "build_image::default_syslinux_src",
        "build_image::validate_net",
        "context::ARTIFACT_STORE_ENV",
        "context::ResolvedContext",
        "dryrun::DryrunOpts",
        "dryrun::qemu::user_netdev_arg",
        "git_commit::EditOutcome::Aborted",
        "git_commit::EditOutcome::Edited",
        "git_commit::edit_message_with",
        "prod_e2e::DebianE2eOpts",
        "prod_e2e::debian_user_netdev_arg",
        "prod_orchestrate::DEFAULT_PROVISIONING_USER",
        "prod_orchestrate::DEFAULT_RECONNECT_USER",
        "profile::Profile",
        "profile::ip_cross_check",
        "profile::scan_for_forbidden_content",
        "stage_stream::hash_file_chunked",
    ];
                                                                                   
                                                                                                
                                                                                                  
                                                  
    const FROZEN_ALIASES: &[(&str, &str, &str)] = &[(
        "src/ceremony/preflight.rs",
        "prod_orchestrate::DEFAULT_PROVISIONING_USER",
        "CLOUD_USER",
    )];

                                                                                                   
                                                                                                
                                                                                                   
                                                       
    let fixture = concat!(
        "use crate::deploy::profile::{Profile, ip_cross_check};\n",
        "use crate::deploy::git_commit::{\n",
        "    self,\n",
        "    GitCommit,\n",
        "};\n",
        "// use crate::deploy::git_commit::consent_from;\n",
        "/// doc prose naming deploy and crate::deploy::x\n",
        "fn f(flags: &u8) { let _c = crate::deploy::git_commit::consent_from(flags); }\n",
        "fn g() { let _m = crate::deploy::git_commit::EditOutcome::Aborted; }\n",
        "fn h() { let _s = \"crate::deploy::in_a_string\"; }\n",
    );
    let measured_fixture = census_file(fixture).expect("the fixture lexes");
    assert_eq!(
        measured_fixture.unconsumed, 0,
        "every canonical spelling is consumed; comments and literals are invisible"
    );
    assert!(
        measured_fixture.errors.is_empty(),
        "the fixture holds no fail-closed shape: {:?}",
        measured_fixture.errors
    );
    let items_set: BTreeSet<&str> = measured_fixture.items.iter().map(String::as_str).collect();
    let want: BTreeSet<&str> = [
        "profile::Profile",
        "profile::ip_cross_check",
        "git_commit",
        "git_commit::GitCommit",
        "git_commit::consent_from",
        "git_commit::EditOutcome::Aborted",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        items_set, want,
        "the walk does not read its own fixture the way this census claims: a wrapped brace \
         list, a `self` member, a disallowed item, a variant path, and the dropped comment"
    );
                                                                                        
                                                        
    let relative = census_file("use super::super::deploy::git_commit::diff_stat;\n").expect("lex");
    assert_eq!(
        relative.unconsumed, 1,
        "a relative deploy path is an unconsumed ident (MB-2's shape)"
    );
    let crate_grouped = census_file("use crate::{deploy::git_commit::diff_stat};\n").expect("lex");
    assert_eq!(
        crate_grouped.unconsumed, 1,
        "a crate-level brace group hides the canonical head (MB-4's shape)"
    );
    let module_alias = census_file("use crate::deploy::git_commit as gc;\n").expect("lex");
    assert!(
        module_alias
            .errors
            .iter()
            .any(|e| e.contains("module level")),
        "a one-segment alias is a module-level refusal (MB-5's shape): {:?}",
        module_alias.errors
    );
    let root_alias = census_file("use crate::deploy as dep;\n").expect("lex");
    assert!(
        root_alias
            .errors
            .iter()
            .any(|e| e.contains("names the module")),
        "the root alias is a bare-module refusal (zero segments): {:?}",
        root_alias.errors
    );
    let brace_alias =
        census_file("use crate::deploy::git_commit::{diff_stat as d};\n").expect("lex");
    assert!(
        brace_alias
            .errors
            .iter()
            .any(|e| e.contains("alias inside a brace list")),
        "an alias inside a brace list is refused: {:?}",
        brace_alias.errors
    );
    let cast = census_file("fn f() { let _x = crate::deploy::a::B as u8; }\n").expect("lex");
    assert!(
        cast.aliases.is_empty() && cast.errors.is_empty(),
        "a cast outside a `use` item is not an alias binding: {:?} {:?}",
        cast.aliases,
        cast.errors
    );
                                                                                        
                                                                         
    let raw_head = census_file("use crate::r#deploy::git_commit::diff_stat;\n").expect("lex");
    assert_eq!(
        raw_head.unconsumed, 0,
        "a raw-ident deploy head is consumed"
    );
    assert!(
        raw_head.items.iter().any(|i| i == "git_commit::diff_stat"),
        "the raw-ident borrow's item is captured: {:?}",
        raw_head.items
    );
    let raw_bare = census_file("fn f() { let _ = r#deploy::x(); }\n").expect("lex");
    assert_eq!(
        raw_bare.unconsumed, 1,
        "a bare raw-ident `deploy` still counts as an unconsumed ident"
    );

                                                                                                   
    let all = rust_sources_under("src/ceremony");
    assert!(
        all.len() >= 20,
        "the walk found {} sources under src/ceremony; the module it is meant to scan is larger, \
         so this is a walk failure and not a clean tree",
        all.len()
    );
    for required in [
        "src/ceremony/runner.rs",
        "src/ceremony/consent.rs",
        "src/ceremony/disclosure.rs",
    ] {
        assert!(
            all.contains(&required.to_string()),
            "the walk missed {required}, so the census would scan the commit path's own sources \
             not at all and pass"
        );
    }

                                                                                                    
    let root = crate_root_at_runtime();
    let mut measured: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut aliases: BTreeSet<(String, String, String)> = BTreeSet::new();
    for rel in &all {
        let text = std::fs::read_to_string(root.join(rel)).expect("read a scanned source");
        let c = census_file(&text).unwrap_or_else(|e| panic!("{rel}: {e}"));
        assert_eq!(
            c.unconsumed, 0,
            "{rel}: {} `deploy` ident(s) outside the canonical `crate::deploy::<item>` spelling. \
             The split rule (D-R12-1): the ceremony may borrow MECHANISM, never a DECISION or a \
             DISCLOSURE, and every borrow is censused by its canonical spelling — re-spell the \
             path as `crate::deploy::…`",
            c.unconsumed
        );
        assert!(
            c.errors.is_empty(),
            "{rel}: fail-closed deploy-path shape(s): {:#?}",
            c.errors
        );
        for token in c.items {
            measured.entry(token).or_default().insert((*rel).clone());
        }
        for (path, alias) in c.aliases {
            aliases.insert(((*rel).clone(), path, alias));
        }
    }

                                                                                                    
    let frozen: BTreeSet<&str> = FROZEN_ITEMS.iter().copied().collect();
    assert_eq!(
        frozen.len(),
        FROZEN_ITEMS.len(),
        "the frozen item list holds a duplicate row"
    );
    let seen: BTreeSet<&str> = measured.keys().map(String::as_str).collect();
    if seen != frozen {
        let added: Vec<String> = seen
            .difference(&frozen)
            .map(|t| format!("  + {t}  at {:?}", measured[*t]))
            .collect();
        let gone: Vec<String> = frozen
            .difference(&seen)
            .map(|t| format!("  - {t}"))
            .collect();
        panic!(
            "the ceremony's `crate::deploy::` item set moved. The split rule (D-R12-1): the \
             ceremony may borrow MECHANISM, and may not borrow a DECISION or a DISCLOSURE. Read \
             each added item against that rule, then re-freeze this list.\n{}\n{}",
            added.join("\n"),
            gone.join("\n")
        );
    }
    let frozen_aliases: BTreeSet<(String, String, String)> = FROZEN_ALIASES
        .iter()
        .map(|(f, p, a)| ((*f).to_string(), (*p).to_string(), (*a).to_string()))
        .collect();
    assert_eq!(
        aliases, frozen_aliases,
        "the ceremony's `crate::deploy` alias bindings moved. An alias renames an item this \
         census already counts; a new one is where descendants could hide from it. Read the \
         binding, then re-freeze"
    );
}
