                                                                                                  
//! is driven through the SAME `Interviewer` seam the operator drives, with a scripted answer
//! list; the pty arms drive the real binary through `script(1)`.

#[allow(dead_code)]
#[path = "common/shell_split.rs"]
mod shell_split;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use orchard::ceremony::Utf8PathBuf;
use orchard::ceremony::admission::{
    Measured, PlannedStep, RunInvocation, admit_with, plan_of, required_present_params,
    resolve_values,
};
use orchard::ceremony::interview::{
    AskItem, Conducted, EmptyAnswer, Interviewer, TargetOutcome, apply_answers, ask_set, conduct,
    empty_answer, execute_authorized_run, guide_child_env, query, render_profile,
    required_typed_tokens, resolve_target,
};
use orchard::ceremony::lock::acquire_at;
use orchard::ceremony::param::{DefaultWithSource, ParamClass, ParamRecord};
use orchard::ceremony::probes::{DoneResult, ProbeCtx};
use orchard::ceremony::records::{RunRecords, StepRecord};
use orchard::ceremony::runner::{ChildCall, ChildCwd, ChildOutcome, Executor};
use orchard::ceremony::spine::{Program, SPINE, StepId};
use orchard::deploy::context::{ContextSources, ResolvedContext, ValueSource};
use orchard::deploy::profile::{Profile, load_str};

/// Build a `Utf8PathBuf` from a test path (tmp paths are UTF-8).
fn u8(p: impl AsRef<Path>) -> Utf8PathBuf {
    Utf8PathBuf::from(p.as_ref().to_str().expect("utf8 test path"))
}

/// A scripted operator: answers in order, and records everything the interview said.
struct Scripted {
    answers: Vec<String>,
    said: String,
    prompts: Vec<String>,
}

impl Scripted {
    fn new(answers: &[&str]) -> Self {
        Scripted {
            answers: answers.iter().map(|s| (*s).to_string()).collect(),
            said: String::new(),
            prompts: Vec::new(),
        }
    }
}

impl Interviewer for Scripted {
    fn ask(&mut self, prompt: &str) -> Option<String> {
        self.prompts.push(prompt.to_string());
        if self.answers.is_empty() {
            return None;
        }
        Some(self.answers.remove(0))
    }
    fn say(&mut self, text: &str) {
        self.said.push_str(text);
    }
}

struct Fx {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    ctx: ResolvedContext,
}

fn fixture() -> Fx {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("orchard");
    std::fs::create_dir_all(&root).expect("root");
    let store = tmp.path().join("artifact-store");
    std::fs::create_dir_all(&store).expect("store");
    let ctx = ResolvedContext {
        repo_root: u8(&root),
        artifact_store: u8(&store),
        repo_manifest: u8(root.join("repo-manifest.toml")),
        sources: ContextSources {
            repo_root: ValueSource::Flag,
            artifact_store: ValueSource::Flag,
            repo_manifest: ValueSource::Flag,
            context_file: None,
        },
    };
    Fx {
        _tmp: tmp,
        root,
        ctx,
    }
}

/// A plausible, PROBE-VALID answer for every ceremony parameter, with the files its probes
/// require materialized under the fixture. Keeps the interview arms about the interview rather
/// than about assembling twenty answers by hand.
fn answers_for(fx: &Fx, items: &[AskItem]) -> Vec<String> {
    answers_for_base(fx._tmp.path(), items)
}

/// The param->answer mapping over a base dir. The ac15 pty script derives its answers from this plus
                                                                                     
/// positional script.
fn answers_for_base(base: &std::path::Path, items: &[AskItem]) -> Vec<String> {
    items
        .iter()
        .map(|i| fixture_answer(base, i.param.name))
        .collect()
}

/// One home for the per-parameter fixture answer, so the positional script and the by-name
/// interview arm cannot diverge on what a parameter is answered with.
fn fixture_answer(base: &std::path::Path, name: &str) -> String {
    let key = base.join("k.pub");
    if !key.exists() {
        std::fs::write(&key, "ssh-ed25519 AAAA fixture\n").expect("key fixture");
    }
                                                                                              
                             
    let private = base.join("k");
    if !private.exists() {
        std::fs::write(&private, "fixture private key\n").expect("private key fixture");
    }
    let manifest = base.join("manifest.toml");
    if !manifest.exists() {
        std::fs::write(&manifest, "# fixture\n").expect("manifest fixture");
    }
    match name {
        "container_image" => "recipes-imgbuild:dev".to_string(),
        "keys_dir" => base.join("keys").display().to_string(),
        "tenant_source_ref" => "f0ad0fc".to_string(),
        "tenant_repo" => "recipes".to_string(),
        "tenant_artifacts" => "binary:recipes-app".to_string(),
        "domain" => "box.test".to_string(),
        "net" => "mode=dhcp".to_string(),
        "firmware" => "seabios".to_string(),
        "image_version" => "3".to_string(),
        "out_dir" => base.join("images").display().to_string(),
        "operator_pubkey" | "recovery_pubkey" | "ssh_identity" | "box_login_identity" => {
            key.display().to_string()
        }
        "manifest" => manifest.display().to_string(),
        "gate_target" => "boot-gate-ceremony".to_string(),
        "port" => "22".to_string(),
        "host_fingerprint" => "SHA256:fixture".to_string(),
        "provisioning_user" => "debian".to_string(),
                                                                                            
                                                   
        _ => String::new(),
    }
}

fn plan_all_pending() -> Vec<PlannedStep> {
    SPINE
        .iter()
        .map(|s| PlannedStep {
            id: s.id,
            done: DoneResult::NotDone("fixture".into()),
        })
        .collect()
}

fn plan_with_done(done: &[StepId]) -> Vec<PlannedStep> {
    SPINE
        .iter()
        .map(|s| PlannedStep {
            id: s.id,
            done: if done.contains(&s.id) {
                DoneResult::Done
            } else {
                DoneResult::NotDone("fixture".into())
            },
        })
        .collect()
}

                                                                                                    

#[test]
fn the_ask_set_is_judgment_every_run_plus_identity_of_not_done_steps() {
    let profile = Profile::default();
    let all = ask_set(&plan_all_pending(), &profile);
    let names: Vec<&str> = all.iter().map(|i| i.param.name).collect();
    assert!(
        !names.contains(&"ip"),
        "the target is confirmed at its own prompt, never as an ordinary parameter"
    );
    assert!(
        names.contains(&"image_version"),
        "the judgment value is asked"
    );
    assert!(
        names.contains(&"domain"),
        "an identity value of a pending step is asked"
    );
                                                                                         
                                                                                                 
                         
    let mut seen = std::collections::BTreeSet::new();
    for n in &names {
        assert!(seen.insert(*n), "{n} asked twice");
    }
    let spine_order: Vec<&str> = SPINE
        .iter()
        .flat_map(|s| s.params.iter().map(|p| p.name))
        .filter(|n| *n != "ip")
        .collect();
    let mut expected: Vec<&str> = Vec::new();
    for n in spine_order {
        if !expected.contains(&n) {
            expected.push(n);
        }
    }
    assert_eq!(
        names, expected,
        "ask order is spine order, producer inputs first"
    );

                                                                                               
    let done_all: Vec<StepId> = SPINE.iter().map(|s| s.id).collect();
    let converged = ask_set(&plan_with_done(&done_all), &profile);
    assert_eq!(
        converged.iter().map(|i| i.param.name).collect::<Vec<_>>(),
        vec!["image_version"],
        "a converged profile is asked only what is re-decided every run"
    );

                                                                                                    
                                                                                                   
                                                                                          
    let mixed = ask_set(&plan_with_done(&[StepId::S9BoxPreflight]), &profile);
    let mixed_names: Vec<&str> = mixed.iter().map(|i| i.param.name).collect();
    for name in ["ssh_identity", "host_fingerprint"] {
        assert!(
            mixed_names.contains(&name),
            "{name} is a Required param of the not-done S10 and must be asked even though the done \
             S9 also declares it: {mixed_names:?}"
        );
    }
}

#[test]
fn the_ask_set_offers_every_param_the_gate_can_demand() {
                                                                                                     
                                                                                                  
                                                                                                     
                                                                                                 
                                                                                                      
                                                
    use orchard::ceremony::admission::required_present_params;
    let profile = Profile::default();
    let plans =
        std::iter::once(plan_all_pending()).chain(SPINE.iter().map(|s| plan_with_done(&[s.id])));
    for plan in plans {
        let offered: std::collections::BTreeSet<&str> = ask_set(&plan, &profile)
            .iter()
            .map(|i| i.param.name)
            .collect();
        for (_step, p) in required_present_params(&plan) {
            assert!(
                offered.contains(p.name),
                "the admission gate can demand `{}` for this plan but ask_set does not offer it",
                p.name
            );
        }
    }
}

#[test]
fn guide_child_env_carries_the_lock_token_and_the_guide_ppid() {
                                                                                                  
                                                       
    assert_eq!(
        guide_child_env("tok-xyz", 4321),
        vec![
            ("ORCHARD_LOCK_TOKEN".to_string(), "tok-xyz".to_string()),
            ("ORCHARD_CEREMONY_PPID".to_string(), "4321".to_string()),
        ]
    );
}

#[test]
fn a_resolvable_value_is_shown_with_its_source_and_kept_by_an_empty_answer() {
                                                                                    
    let profile = Profile {
        domain: Some("box.test".into()),
        ..Default::default()
    };
    let items = ask_set(&plan_all_pending(), &profile);
    let domain = items
        .iter()
        .find(|i| i.param.name == "domain")
        .expect("asked");
    assert_eq!(
        domain.current.as_ref().map(|(v, s)| (v.as_str(), *s)),
        Some(("box.test", "profile"))
    );
    let fx = fixture();
    let ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    let ea = empty_answer(domain, &ctx);
    assert!(
        domain
            .render(&ea)
            .contains("current: box.test  (from the profile)")
    );
    let mut io = Scripted::new(&[""]);
    assert_eq!(
        query(&mut io, domain, &ctx).as_deref(),
        Some("box.test"),
        "an empty answer keeps the current value"
    );
}

#[test]
fn a_query_re_prompts_with_the_probes_own_cure_until_the_answer_validates() {
                                                                                      
                                                               
    let fx = fixture();
    let ctx = ProbeCtx::new(&fx.ctx, None);
    let item = AskItem {
        step: StepId::S7ImageBuild,
        param: SPINE
            .iter()
            .flat_map(|s| s.params.iter())
            .find(|p| p.name == "out_dir")
            .expect("out_dir"),
        current: None,
    };
    let inside = fx.root.join("inside").display().to_string();
    let outside = fx._tmp.path().join("images").display().to_string();
    let mut io = Scripted::new(&[inside.as_str(), outside.as_str()]);
    assert_eq!(
        query(&mut io, &item, &ctx).as_deref(),
        Some(outside.as_str())
    );
    assert!(
        io.said.contains("repo root"),
        "the re-prompt carries the probe's own cure: {}",
        io.said
    );
    assert_eq!(io.prompts.len(), 2, "it asked again rather than accepting");
}

#[test]
fn a_required_value_cannot_be_left_empty() {
    let fx = fixture();
    let ctx = ProbeCtx::new(&fx.ctx, None);
    let item = AskItem {
        step: StepId::S7ImageBuild,
        param: SPINE
            .iter()
            .flat_map(|s| s.params.iter())
            .find(|p| p.name == "domain")
            .expect("domain"),
        current: None,
    };
    let mut io = Scripted::new(&["", "box.test"]);
    assert_eq!(query(&mut io, &item, &ctx).as_deref(), Some("box.test"));
    assert!(io.said.contains("required"), "{}", io.said);
}

#[test]
fn what_an_empty_answer_does_is_decided_by_the_parameters_class() {
                                                                                               
                                                                                                
                                                     
    let fx = fixture();
    let ctx = ProbeCtx::new(&fx.ctx, None);
    let (mut judgment, mut required, mut identity_builtin, mut identity_derived) =
        (0usize, 0usize, 0usize, 0usize);
    let mut seen = BTreeSet::new();
    for step in SPINE.iter() {
        for param in step.params {
            if !seen.insert(param.name) {
                continue;
            }
            let item = AskItem {
                step: step.id,
                param,
                current: None,
            };
            let ea = empty_answer(&item, &ctx);
            match (param.class, param.default) {
                (_, DefaultWithSource::Required) => {
                    required += 1;
                    assert_eq!(
                        ea,
                        EmptyAnswer::Reprompt,
                        "`{}` has no default to fall back on, so an empty answer must re-prompt",
                        param.name
                    );
                }
                (ParamClass::Judgment, _) => {
                    judgment += 1;
                    let EmptyAnswer::Accept(v, _) = &ea else {
                        panic!(
                            "judgment `{}` resolved an empty answer to {ea:?}; the run's gate reads \
                             the key from the typed invocation, so anything but Accept refuses the \
                             guided run it just authorized",
                            param.name
                        )
                    };
                    assert!(
                        !v.is_empty(),
                        "judgment `{}` accepts an EMPTY value, which the child's clap parse refuses",
                        param.name
                    );
                    if param.name == "image_version" {
                        assert_eq!(v, "0", "the spine's builtin serial is what Enter supplies");
                    }
                }
                (ParamClass::Identity, DefaultWithSource::Builtin(_)) => {
                    identity_builtin += 1;
                    assert_eq!(
                        ea,
                        EmptyAnswer::Unset,
                        "identity builtin `{}` stays unset and the verb applies its builtin after \
                         the merge",
                        param.name
                    );
                }
                (ParamClass::Identity, _) => {
                                                                                          
                                                                                              
                                                                                       
                    identity_derived += 1;
                    assert_eq!(
                        ea,
                        EmptyAnswer::Reprompt,
                        "identity `{}` with a runtime default that does not resolve here reprompts",
                        param.name
                    );
                }
            }
        }
    }
                                                                               
    assert!(
        judgment > 0 && required > 0 && identity_builtin > 0 && identity_derived > 0,
        "the spine no longer populates all four arms (judgment {judgment}, required {required}, \
         identity builtin {identity_builtin}, identity derived {identity_derived}), so this arm \
         proves less than it claims"
    );
}

                                                                                                   

#[test]
fn accepting_the_displayed_target_never_rewrites_it_and_a_re_point_needs_its_own_action() {
    assert_eq!(
        resolve_target(Some("203.0.113.5"), "203.0.113.5", None),
        TargetOutcome::Unchanged("203.0.113.5".into())
    );
    assert_eq!(
        resolve_target(None, "203.0.113.5", None),
        TargetOutcome::FirstRun("203.0.113.5".into())
    );
                                                                                             
    for retyped in [None, Some(""), Some("203.0.113.5"), Some("198.51.100.0")] {
        assert_eq!(
            resolve_target(Some("203.0.113.5"), "198.51.100.9", retyped),
            TargetOutcome::RePointDeclined {
                stored: "203.0.113.5".into(),
                confirmed: "198.51.100.9".into()
            },
            "retyped {retyped:?} must not re-point"
        );
    }
    assert_eq!(
        resolve_target(Some("203.0.113.5"), "198.51.100.9", Some("198.51.100.9")),
        TargetOutcome::RePointed("198.51.100.9".into())
    );
}

                                                                                                   

#[test]
fn the_required_tokens_are_derived_from_the_pending_destructive_steps() {
    assert_eq!(
        required_typed_tokens(&plan_all_pending()),
        vec!["--wipe-confirmed".to_string()]
    );
                                                       
    assert!(required_typed_tokens(&plan_with_done(&[StepId::S10ProdInstall])).is_empty());
}

#[test]
fn judgment_values_ride_the_argv_not_only_the_profile() {
                                                                                                  
                               
    let mut judgment = BTreeMap::new();
    judgment.insert("image_version".to_string(), "7".to_string());
    let ctx = seam_ctx();
    let inv = RunInvocation {
        profile_path: u8("boxes/alpha.toml"),
        target: Some("203.0.113.5".to_string()),
        judgment,
        wipe_confirmed: true,
        ..Default::default()
    };
    let mut expected = vec![
        "run".to_string(),
        "boxes/alpha.toml".into(),
        "--target".into(),
        "203.0.113.5".into(),
        "--image-version".into(),
        "7".into(),
        "--wipe-confirmed".into(),
    ];
    expected.extend(ctx.forward_flags());
    assert_eq!(inv.argv(&ctx), expected);
}

#[test]
fn argv_carries_repo_form_dir_only_when_the_directory_is_set() {
                                                                                               
                                                   
    let ctx = seam_ctx();
    let set = RunInvocation {
        profile_path: u8("boxes/alpha.toml"),
        target: Some("203.0.113.5".to_string()),
        repo_form_dir: Some(u8("custom/dir")),
        ..Default::default()
    }
    .argv(&ctx);
    let pos = set
        .iter()
        .position(|a| a == "--repo-form-dir")
        .expect("the flag is present when the directory is set");
    assert_eq!(set.get(pos + 1).map(String::as_str), Some("custom/dir"));
    let unset = RunInvocation {
        profile_path: u8("boxes/alpha.toml"),
        target: Some("203.0.113.5".to_string()),
        ..Default::default()
    }
    .argv(&ctx);
    assert!(
        !unset.iter().any(|a| a == "--repo-form-dir"),
        "no flag when the directory is empty: {unset:?}"
    );
}

#[test]
fn argv_pins_the_child_to_the_resolved_context() {
                                                                                                    
                                                                                           
                                                                                            
                                                                  
    use orchard::deploy::context::{ContextSources, ResolvedContext, ValueSource};
    let ctx = ResolvedContext {
        repo_root: "/srv/checkout-A".into(),
        artifact_store: "/srv/checkout-A/store".into(),
        repo_manifest: "/srv/checkout-A/repo-manifest.toml".into(),
        sources: ContextSources {
            repo_root: ValueSource::Flag,
            artifact_store: ValueSource::Flag,
            repo_manifest: ValueSource::Flag,
            context_file: None,
        },
    };
    let inv = RunInvocation {
        profile_path: u8("/x/boxes/p.toml"),
        target: Some("203.0.113.5".to_string()),
        ..Default::default()
    };
    let child = inv.argv(&ctx);
                                                                                               
    let tail = ctx.forward_flags();
    assert!(
        child.ends_with(&tail),
        "the context flags are the argv's tail: {child:?}"
    );
    let run_portion = &child[..child.len() - tail.len()];
                                                                    
    for (flag, val) in [
        ("--repo-root", "/srv/checkout-A"),
        ("--artifact-store", "/srv/checkout-A/store"),
        ("--repo-manifest", "/srv/checkout-A/repo-manifest.toml"),
    ] {
        let i = child
            .iter()
            .position(|a| a == flag)
            .unwrap_or_else(|| panic!("child argv missing {flag}: {child:?}"));
        assert_eq!(
            child.get(i + 1).map(String::as_str),
            Some(val),
            "{flag} must carry its resolved value: {child:?}"
        );
    }
                                                                                                      
    assert!(
        !run_portion
            .iter()
            .any(|a| a == "--repo-root" || a == "--artifact-store" || a == "--repo-manifest"),
        "the run-portion must not itself carry context globals: {run_portion:?}"
    );
}

/// Delta v3.5 §6 row E1 + v3.6 §5 row G1: the composed `run` argv, parsed back by clap, carries
/// every field of the invocation it was composed from and the three resolved context paths, at
/// both settings of the regime flag.
///
/// What it claims: over an invocation with `target`, one judgment entry, `commit`,
/// `wipe_confirmed` and a non-ASCII relative `repo_form_dir`, and a context whose three paths are
/// non-ASCII, at `porcelain: false` and at `porcelain: true`,
/// `Cli::try_parse_from(["orchard"] + inv.argv(&ctx))` parses and the resulting `Run` field set
/// and the four globals each equal the value the argv was composed from; and the `--porcelain`
/// token is in the argv exactly when the field is set. The oracle is clap over the rendered
/// tokens compared to the sources; no expectation here is produced by the composer. The `Run`
/// destructure names every field, so a new `Run` field is a compile error until this arm states
/// whether the composer emits it. What it does NOT claim: the token ORDER (clap accepts several),
/// the behaviour of a spawned child (`ceremony_utf8_argv.rs` drives the binary), the shell
/// rendering of the argv as a printed command
/// (`the_printed_commands_word_split_back_to_the_composed_argv`), or anything about a judgment key
/// with no `Run` field. Blind spots, named: a judgment key whose `_`→`-` spelling is not a `run`
/// flag would fail the parse here rather than being compared; `--context` is asserted absent
/// because the composer emits it never, which is a claim about this argv and not about the verb's
/// surface.
#[test]
fn the_composed_run_argv_parses_back_to_the_invocations_fields_and_the_context() {
    use clap::Parser as _;

    for porcelain in [false, true] {
        let ctx = ResolvedContext {
            repo_root: Utf8PathBuf::from("/srv/naïve-café"),
            artifact_store: Utf8PathBuf::from("/srv/naïve-café/store"),
            repo_manifest: Utf8PathBuf::from("/srv/naïve-café/repo-manifest.toml"),
            sources: ContextSources {
                repo_root: ValueSource::Flag,
                artifact_store: ValueSource::Flag,
                repo_manifest: ValueSource::Flag,
                context_file: None,
            },
        };
        let mut judgment = BTreeMap::new();
        judgment.insert("image_version".to_string(), "3".to_string());
        let inv = RunInvocation {
            profile_path: u8("boxes/béta.toml"),
            target: Some("203.0.113.5".to_string()),
            judgment,
            commit: true,
            wipe_confirmed: true,
            porcelain,
            repo_form_dir: Some(u8("boxes/audited-förm")),
        };

                                                                                             
                   
        let argv = inv.argv(&ctx);
        assert!(
            argv.iter().any(|a| !a.is_ascii()),
            "no argv token carries a non-ASCII scalar, so the encoding claim is untested: {argv:?}"
        );
        assert_eq!(
            argv.iter().any(|a| a == "--porcelain"),
            porcelain,
            "the composed argv carries --porcelain iff the field is set: {argv:?}"
        );

        let mut full = vec!["orchard".to_string()];
        full.extend(argv.iter().cloned());
        let cli = orchard::cli::Cli::try_parse_from(&full)
            .unwrap_or_else(|e| panic!("the composed argv does not parse: {e}\n{argv:?}"));

        assert_eq!(cli.repo_root.as_ref(), Some(&ctx.repo_root));
        assert_eq!(cli.artifact_store.as_ref(), Some(&ctx.artifact_store));
        assert_eq!(cli.repo_manifest.as_ref(), Some(&ctx.repo_manifest));
        assert_eq!(cli.context, None, "the composer emits no --context");
        assert!(!cli.print_context, "the composer emits no --print-context");

                                                                                                 
                                         
        let orchard::cli::OrchardCmd::Run {
            profile,
            target,
            image_version,
            commit,
            wipe_confirmed,
            porcelain: parsed_porcelain,
            repo_form_dir,
        } = cli.command
        else {
            panic!("the composed argv is not a `run`: {argv:?}");
        };
        assert_eq!(profile, inv.profile_path);
        assert_eq!(target, inv.target);
        assert_eq!(
            image_version.map(|v| v.to_string()),
            inv.judgment.get("image_version").cloned(),
            "the judgment entry rides the argv under its `_`→`-` flag name"
        );
        assert_eq!(commit, inv.commit);
        assert_eq!(wipe_confirmed, inv.wipe_confirmed);
        assert_eq!(
            parsed_porcelain, inv.porcelain,
            "the composer emits --porcelain iff the field is set"
        );
        assert_eq!(repo_form_dir, inv.repo_form_dir);
    }
}

                                                                                                    
  
                                                                                                    
                                                                                             
                                                                                       

/// The token classes §2.3's rule separates: the five that must be quoted to survive the paste, and
/// one wholly inside the bare set `[A-Za-z0-9_./:=+@%,-]`.
const QUOTE_CLASSES: &[(&str, &str)] = &[
    ("a space", "My Box"),
    ("a single quote", "it's-mine"),
    ("a dollar", "$HOME"),
    ("a tab", "a\tb"),
    ("a non-ASCII scalar", "naïve-café"),
    ("wholly in the bare set", "audited-form"),
];

/// Read the reader itself, so row G2's comparison is not vacuous.
///
/// What it claims: over a hand-written quoted line, `shell_split` returns the hand-written token
/// list; over the same values left unquoted it returns more tokens or an expanded `$HOME`; and an
/// empty quoted token comes back as one token. No expectation here is produced by the composer.
/// What it does NOT claim: that `/bin/sh`'s splitting is POSIX-conformant — the reader IS the host
/// shell, so this arm measures the reader against a hand literal and not the shell against a
/// standard. Blind spots, named: one quoted line and one unquoted line, not the grammar of shell
/// words; the reader's fail-closed branches (a non-zero exit, stderr output, a missing NUL
/// terminator) are not driven here.
#[test]
fn the_shell_reader_splits_a_hand_written_line_into_its_hand_written_tokens() {
    use shell_split::shell_split;

                                                                                     
    assert_eq!(
        shell_split("orchard run 'My Box/a.toml' --target 'it'\\''s' --repo-root '/srv/$HOME'"),
        vec![
            "run".to_string(),
            "My Box/a.toml".into(),
            "--target".into(),
            "it's".into(),
            "--repo-root".into(),
            "/srv/$HOME".into(),
        ],
        "the reader does not return the shell's own word splitting of a quoted line"
    );
                                                                                                  
                                                   
    let unquoted = shell_split("orchard run My Box/a.toml --repo-root /srv/$HOME");
    assert!(
        unquoted.len() > 4 || !unquoted.contains(&"/srv/$HOME".to_string()),
        "the reader does not perform the shell's field splitting and expansion: {unquoted:?}"
    );
                                                                                              
    assert_eq!(shell_split("orchard run '' --commit").len(), 3);
}

/// Delta v3.6 §5 row G2: over an invocation and a context whose values carry a space, a `'`, a
/// `$`, a tab and a non-ASCII scalar, the shell's own word splitting of the printed resume and
/// admit commands yields exactly `argv(ctx)` and `admit_argv(ctx)`, and clap parses the result
/// back to the invocation and the context.
///
/// What it claims, per token class of [`QUOTE_CLASSES`]: the class's value rides the invocation's
/// `--target` and `--repo-form-dir` and the context's three paths; `/bin/sh` splits
/// `resume_command`'s output into exactly `argv(ctx)` and `admit_command`'s into exactly
/// `admit_argv(ctx)`, token by token; clap over the split resume yields the invocation's every
/// `Run` field and the context's three globals, and over the split admit yields the `Admit` pair;
/// and for the one class wholly inside the bare set the rendered token is bare, not quoted. The
/// oracles are `/bin/sh` and clap, both outside the crate. What it does NOT claim: that
/// `shell_word`'s bare set is the right set (delta §6 Q-quote-set decides it; this arm measures
/// that whatever is quoted round-trips and that a bare-set value stays bare), that a token
/// carrying a newline survives a porcelain record's one-line form (FOLD7G § Directing-session
/// read's residual), or anything about a shell other than the host's. Blind spots, named: the
/// reader is `/bin/sh`, so a host whose `/bin/sh` is not POSIX-conformant measures that shell; the
/// classes are five samples, not the complement of the bare set; the printed command is read
/// whole here, not cut out of a cure (`ceremony_runner.rs`'s `resume_in` does that).
#[test]
fn the_printed_commands_word_split_back_to_the_composed_argv() {
    use clap::Parser as _;
    use shell_split::shell_split;

    for (label, value) in QUOTE_CLASSES {
        let root = format!("/srv/{value}/orchard");
        let ctx = ResolvedContext {
            repo_root: Utf8PathBuf::from(root.clone()),
            artifact_store: Utf8PathBuf::from(format!("{root}/store")),
            repo_manifest: Utf8PathBuf::from(format!("{root}/repo-manifest.toml")),
            sources: ContextSources {
                repo_root: ValueSource::Flag,
                artifact_store: ValueSource::Flag,
                repo_manifest: ValueSource::Flag,
                context_file: None,
            },
        };
        let mut judgment = BTreeMap::new();
        judgment.insert("image_version".to_string(), "3".to_string());
        let inv = RunInvocation {
            profile_path: u8("boxes/alpha.toml"),
            target: Some((*value).to_string()),
            judgment,
            commit: true,
            wipe_confirmed: true,
            porcelain: true,
            repo_form_dir: Some(u8(format!("boxes/{value}"))),
        };

        let argv = inv.argv(&ctx);
        let admit_argv = inv.admit_argv(&ctx);
                                                                                                   
                                           
        assert!(
            argv.iter().filter(|t| t.contains(*value)).count() >= 4,
            "{label}: the class value does not reach the composed argv: {argv:?}"
        );

        let resume = inv.resume_command(&ctx);
        let admit = inv.admit_command(&ctx);
        assert_eq!(
            shell_split(&resume),
            argv,
            "{label}: the shell's split of the printed resume command is not argv(ctx): {resume:?}"
        );
        assert_eq!(
            shell_split(&admit),
            admit_argv,
            "{label}: the shell's split of the printed admit command is not admit_argv(ctx): \
             {admit:?}"
        );

        let full: Vec<String> = std::iter::once("orchard".to_string())
            .chain(shell_split(&resume))
            .collect();
        let cli = orchard::cli::Cli::try_parse_from(&full)
            .unwrap_or_else(|e| panic!("{label}: the printed resume command does not parse: {e}"));
        assert_eq!(cli.repo_root.as_ref(), Some(&ctx.repo_root), "{label}");
        assert_eq!(
            cli.artifact_store.as_ref(),
            Some(&ctx.artifact_store),
            "{label}"
        );
        assert_eq!(
            cli.repo_manifest.as_ref(),
            Some(&ctx.repo_manifest),
            "{label}"
        );
        let orchard::cli::OrchardCmd::Run {
            profile,
            target,
            image_version,
            commit,
            wipe_confirmed,
            porcelain,
            repo_form_dir,
        } = cli.command
        else {
            panic!("{label}: the printed resume command is not a `run`: {resume:?}");
        };
        assert_eq!(profile, inv.profile_path, "{label}");
        assert_eq!(target, inv.target, "{label}");
        assert_eq!(
            image_version.map(|v| v.to_string()),
            inv.judgment.get("image_version").cloned(),
            "{label}"
        );
        assert_eq!(commit, inv.commit, "{label}");
        assert_eq!(wipe_confirmed, inv.wipe_confirmed, "{label}");
        assert_eq!(porcelain, inv.porcelain, "{label}");
        assert_eq!(repo_form_dir, inv.repo_form_dir, "{label}");

        let full_admit: Vec<String> = std::iter::once("orchard".to_string())
            .chain(shell_split(&admit))
            .collect();
        let admit_cli = orchard::cli::Cli::try_parse_from(&full_admit)
            .unwrap_or_else(|e| panic!("{label}: the printed admit command does not parse: {e}"));
        assert_eq!(
            admit_cli.repo_root.as_ref(),
            Some(&ctx.repo_root),
            "{label}"
        );
        let orchard::cli::OrchardCmd::Admit {
            box_profile,
            repo_form_dir: admit_dir,
        } = admit_cli.command
        else {
            panic!("{label}: the printed admit command is not an `admit`: {admit:?}");
        };
        assert_eq!(box_profile, inv.profile_path, "{label}");
        assert_eq!(admit_dir, inv.repo_form_dir, "{label}");

                                                                                                   
                                                                                
        if *label == "wholly in the bare set" {
            let bare = format!("--repo-form-dir boxes/{value} ");
            assert!(
                resume.contains(&bare),
                "{label}: a value inside the bare set was quoted: {resume:?}"
            );
            assert!(
                !resume.contains('\''),
                "{label}: the printed command carries a quote for a line that needs none: \
                 {resume:?}"
            );
        }
    }
}

                                                                                                      
  
                                                                                            
                                                                                                   
                                                                                                   
                           
  
                                                                                                     
                                                                                                   
                                                             

/// Records every call and answers from a scripted outcome list; an empty list answers `Ok`.
#[derive(Default)]
struct RecordingExec {
    calls: Vec<ChildCall>,
    outcomes: Vec<ChildOutcome>,
}

impl Executor for RecordingExec {
    fn run(&mut self, call: &ChildCall, _sink: &mut dyn FnMut(&str)) -> ChildOutcome {
        self.calls.push(call.clone());
        if self.outcomes.is_empty() {
            return ChildOutcome::Ok;
        }
        self.outcomes.remove(0)
    }
}

/// Literal paths, so the argv oracle below can be written out by hand.
fn seam_ctx() -> ResolvedContext {
    ResolvedContext {
        repo_root: Utf8PathBuf::from("/fix/checkout-A"),
        artifact_store: Utf8PathBuf::from("/fix/checkout-A/store"),
        repo_manifest: Utf8PathBuf::from("/fix/checkout-A/repo-manifest.toml"),
        sources: ContextSources {
            repo_root: ValueSource::Flag,
            artifact_store: ValueSource::Flag,
            repo_manifest: ValueSource::Flag,
            context_file: None,
        },
    }
}

fn seam_conducted() -> Conducted {
    Conducted {
        invocation: RunInvocation {
            profile_path: Utf8PathBuf::from("boxes/alpha.toml"),
            target: Some("203.0.113.5".to_string()),
            ..Default::default()
        },
    }
}

/// The authorize argv followed by the three context flags of [`seam_ctx`].
fn seam_expected_args() -> Vec<String> {
    strs(&[
        "run",
        "boxes/alpha.toml",
        "--target",
        "203.0.113.5",
        "--repo-root",
        "/fix/checkout-A",
        "--artifact-store",
        "/fix/checkout-A/store",
        "--repo-manifest",
        "/fix/checkout-A/repo-manifest.toml",
    ])
}

fn strs(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn the_authorized_run_spawn_is_composed_at_the_seam_with_the_lock_held() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock = acquire_at(&tmp.path().join("lock"), "guide", None).expect("acquire");
    let ctx = seam_ctx();
    let conducted = seam_conducted();
    let mut exec = RecordingExec::default();

    execute_authorized_run(&conducted, &ctx, Some(&lock), &mut exec).expect("the scripted Ok");

                                                                                      
    assert_eq!(
        exec.calls.len(),
        1,
        "one spawn per authorized run: {:?}",
        exec.calls
    );
    let call = &exec.calls[0];
    assert_eq!(call.program, Program::SelfExe, "the guide's own binary");
    assert_eq!(
        call.args,
        seam_expected_args(),
        "the authorize argv plus the resolved context flags"
    );
    assert_eq!(
        call.env,
        vec![
            ("ORCHARD_LOCK_TOKEN".to_string(), lock.token().to_string()),
            (
                "ORCHARD_CEREMONY_PPID".to_string(),
                std::process::id().to_string()
            ),
        ],
        "the child joins the guide's lock and arms its death signal against the guide"
    );
    assert_eq!(
        call.cwd,
        ChildCwd::Inherit,
        "the child's relative-path base is the guide's, not an invented directory"
    );
    assert!(call.inherit_stdio, "the run gets the real descriptors");
}

#[test]
fn the_authorized_run_maps_ok_to_ok_and_a_failure_to_the_pointer_line() {
    let ctx = seam_ctx();
    let conducted = seam_conducted();
    let mut exec = RecordingExec {
        calls: Vec::new(),
        outcomes: vec![
            ChildOutcome::Ok,
            ChildOutcome::Failed("x exited 7".to_string()),
        ],
    };

    let ok = execute_authorized_run(&conducted, &ctx, None, &mut exec);
    let failed = execute_authorized_run(&conducted, &ctx, None, &mut exec);

                                                                                                
                                                                                    
    assert_eq!(
        exec.calls.len(),
        2,
        "both runs reached the executor: {:?}",
        exec.calls
    );
    assert_eq!(ok, Ok(()));
    assert_eq!(
        failed,
        Err("the ceremony run failed (x exited 7) — its own output above says why".to_string()),
        "the operator is pointed at the child's own output, not handed a bare detail"
    );
}

#[test]
fn the_authorized_run_spawn_exports_nothing_when_the_guide_holds_no_lock() {
    let ctx = seam_ctx();
    let conducted = seam_conducted();
    let mut exec = RecordingExec::default();

    execute_authorized_run(&conducted, &ctx, None, &mut exec).expect("the scripted Ok");

    assert_eq!(
        exec.calls.len(),
        1,
        "one spawn per authorized run: {:?}",
        exec.calls
    );
    let call = &exec.calls[0];
    assert_eq!(
        call.env,
        Vec::<(String, String)>::new(),
        "no lock, so no join token and no ppid"
    );
                                                                                     
    assert_eq!(call.args, seam_expected_args());
    assert_eq!(call.program, Program::SelfExe);
}

                                                                                                    

#[test]
fn the_written_profile_carries_no_destructive_intent_key_material_or_typed_token() {
    let profile = Profile {
        ip: Some("203.0.113.5".into()),
        domain: Some("box.test".into()),
        ..Default::default()
    };
    let text = render_profile(&profile).expect("renders");
    for forbidden in [
        "wipe_confirmed",
        "--wipe-confirmed",
        "-----BEGIN",
        "allow_dirty",
        "restore_from",
    ] {
        assert!(
            !text.contains(forbidden),
            "profile carries {forbidden}:\n{text}"
        );
    }
                                                                               
    let smuggled = Profile {
        domain: Some("--wipe-confirmed".into()),
        ..profile.clone()
    };
    let e = render_profile(&smuggled).expect_err("refuses");
    assert_eq!(e.id.token(), "profile-write-refused");
}

#[test]
fn an_answer_that_does_not_fit_its_keys_type_refuses_at_the_write() {
    let mut answers = BTreeMap::new();
    answers.insert("image_version".to_string(), "not-a-number".to_string());
    let e = apply_answers(&Profile::default(), &answers).expect_err("refuses");
    assert_eq!(e.id.token(), "profile-answer-invalid");
    answers.insert("image_version".to_string(), "7".to_string());
    let p = apply_answers(&Profile::default(), &answers).expect("applies");
    assert_eq!(p.image_version, Some(7));
}

                                                                                                    

fn conduct_fixture(
    fx: &Fx,
    profile: &Profile,
    answers: &[&str],
) -> (Option<Conducted>, Scripted, PathBuf) {
                                                                                                 
                          
    let profile_path = fx._tmp.path().join("boxes/alpha.toml");
    let records = RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
    let mut io = Scripted::new(answers);
    let out = conduct(
        &mut io,
        &u8(&profile_path),
        profile,
        &fx.ctx,
        &records,
        &Default::default(),
        None,
    )
    .expect("no refusal")
    .authorized();
    (out, io, profile_path)
}

#[test]
fn an_abandoned_interview_writes_nothing_and_authorizes_nothing() {
    let fx = fixture();
                                                    
    let (out, _io, path) = conduct_fixture(&fx, &Profile::default(), &[]);
    assert!(out.is_none());
    assert!(
        !path.exists(),
        "no profile is written on an abandoned interview"
    );
}

#[test]
fn a_declined_re_point_leaves_the_profile_file_untouched() {
                                                                                                
    let fx = fixture();
    let profile_path = fx._tmp.path().join("boxes/alpha.toml");
    std::fs::create_dir_all(profile_path.parent().expect("parent")).expect("mk");
    let original = "ip = \"203.0.113.5\"\ndomain = \"box.test\"\n";
    std::fs::write(&profile_path, original).expect("seed");
    let profile = orchard::deploy::profile::load_str(original).expect("parses");
    let records = RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
                                                                                       
                                                                                
    let mut io = Scripted::new(&["198.51.100.9", ""]);
    let out = conduct(
        &mut io,
        &u8(&profile_path),
        &profile,
        &fx.ctx,
        &records,
        &Default::default(),
        None,
    )
    .expect("no refusal")
    .authorized();
    assert!(
        out.is_none(),
        "a declined re-point does not authorize a run"
    );
    assert_eq!(
        std::fs::read_to_string(&profile_path).expect("read"),
        original,
        "the profile file is byte-unchanged"
    );
    assert!(
        io.said.contains("still names 203.0.113.5"),
        "the operator is told what the profile still names: {}",
        io.said
    );
}

#[test]
fn a_completed_interview_writes_the_profile_before_authorizing_and_forwards_what_was_typed() {
    let fx = fixture();
    let profile = Profile::default();
    let profile_path = fx._tmp.path().join("boxes/alpha.toml");
    let records = RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
    let items = ask_set(&plan_all_pending(), &profile);
                                                                         
    let mut answers = vec!["203.0.113.5".to_string()];                         
    answers.extend(answers_for(&fx, &items));
    answers.push("--wipe-confirmed".to_string());                                 
    let refs: Vec<&str> = answers.iter().map(String::as_str).collect();
    let mut io = Scripted::new(&refs);
    let conducted = conduct(
        &mut io,
        &u8(&profile_path),
        &profile,
        &fx.ctx,
        &records,
        &Default::default(),
        None,
    )
    .expect("no refusal")
    .authorized()
    .expect("conducted");
                                                                                      
    let written = std::fs::read_to_string(&profile_path).expect("written");
    assert!(written.contains("ip = \"203.0.113.5\""), "{written}");
    assert!(written.contains("domain = \"box.test\""), "{written}");
    assert!(written.contains("image_version = 3"), "{written}");
                                                             
    assert!(
        !written.contains("wipe"),
        "the typed token is not stored:\n{written}"
    );
    let mut expected = vec![
        "run".to_string(),
        profile_path.display().to_string(),
        "--target".into(),
        "203.0.113.5".into(),
        "--image-version".into(),
        "3".into(),
        "--wipe-confirmed".into(),
    ];
    expected.extend(fx.ctx.forward_flags());
    assert_eq!(conducted.invocation.argv(&fx.ctx), expected);
}

#[test]
fn the_guide_run_seam_forwards_repo_form_dir_only_when_set() {
                                                                                                
                                                     
    let driven = |dir: Option<&Utf8PathBuf>| -> Vec<String> {
        let fx = fixture();
        let profile = Profile::default();
        let profile_path = fx._tmp.path().join("boxes/alpha.toml");
        let records =
            RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
        let items = ask_set(&plan_all_pending(), &profile);
        let mut answers = vec!["203.0.113.5".to_string()];
        answers.extend(answers_for(&fx, &items));
        answers.push("--wipe-confirmed".to_string());
        let refs: Vec<&str> = answers.iter().map(String::as_str).collect();
        let mut io = Scripted::new(&refs);
        let conducted = conduct(
            &mut io,
            &u8(&profile_path),
            &profile,
            &fx.ctx,
            &records,
            &Default::default(),
            dir,
        )
        .expect("no refusal")
        .authorized()
        .expect("conducted");
        conducted.invocation.argv(&fx.ctx)
    };
    let with = driven(Some(&u8("custom/repo-form")));
    let pos = with
        .iter()
        .position(|a| a == "--repo-form-dir")
        .expect("the child argv carries the flag when the guide set it");
    assert_eq!(
        with.get(pos + 1).map(String::as_str),
        Some("custom/repo-form")
    );
    let without = driven(None);
    assert!(
        !without.iter().any(|a| a == "--repo-form-dir"),
        "no flag in the child argv when unset: {without:?}"
    );
}

                                                                                                
                                                                                                    
/// or a typed confirmation"), and it used to render for a filesystem failure too: an operator
/// whose profile dir was read-only was told their ANSWERS were forbidden. The write sites now
/// construct `ProfileUnwritable`, whose remedy is the path.
///
/// Both `ProfileUnwritable` sites are driven: the dir that cannot be created, and the dir that
/// exists and cannot be written. The composed cure is asserted whole, so a template edit that
                                              
///
/// A REGRESSION PIN, not the closure (D-W22-2): the closure is the 4-way split of
                                                                    
/// `the_written_profile_carries_no_destructive_intent_key_material_or_typed_token` keeps holding it.
#[test]
fn an_unwritable_profile_path_refuses_on_the_path_not_on_the_r44_content_rule() {
    use std::os::unix::fs::PermissionsExt;
    const CURE: &str = "check the named path's ownership, permissions and free space";

    let fx = fixture();
    let profile = Profile::default();
    let items = ask_set(&plan_all_pending(), &profile);
    let mut answers = vec!["203.0.113.5".to_string()];
    answers.extend(answers_for(&fx, &items));
    answers.push("--wipe-confirmed".to_string());
    let refs: Vec<&str> = answers.iter().map(String::as_str).collect();

    let sealed = fx._tmp.path().join("sealed");
    std::fs::create_dir_all(&sealed).expect("mk sealed");
    let existing = sealed.join("existing");
    std::fs::create_dir_all(&existing).expect("mk existing");
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o555)).expect("seal");
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o555)).expect("seal");

                                                                                              
                                                                                         
    let probe = std::fs::write(sealed.join("probe"), "x").is_err();
    if !probe {
        let _ = std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755));
        panic!(
            "a 0o555 dir is still writable here (running as root, or a mount that ignores the \
             mode), so this arm cannot express an unwritable profile path"
        );
    }

    for (site, profile_path) in [
                                                                                               
        ("dir cannot be created", sealed.join("new/alpha.toml")),
                                                                                           
        ("dir cannot be written", existing.join("alpha.toml")),
    ] {
        let records =
            RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
        let mut io = Scripted::new(&refs);
        let e = conduct(
            &mut io,
            &u8(&profile_path),
            &profile,
            &fx.ctx,
            &records,
            &Default::default(),
            None,
        )
        .expect_err("an unwritable profile path refuses");
        assert_eq!(
            e.id.token(),
            "profile-unwritable",
            "{site}: a filesystem failure is not a content refusal: {e}"
        );
                                                                                                 
                                                                     
        assert!(
            e.detail
                .contains(&profile_path.parent().expect("parent").display().to_string()),
            "{site}: the refusal names the path that failed: {}",
            e.detail
        );
        assert!(
            io.said.contains("target"),
            "{site}: the interview never ran, so the write is not what refused"
        );
        let render = e.to_string();
        let cure = render
            .lines()
            .find_map(|l| l.trim_start().strip_prefix("cure: "))
            .unwrap_or_else(|| panic!("{site}: no cure line: {render}"));
        assert_eq!(cure, CURE, "{site}: the composed cure moved: {render}");
        assert!(
            !render.contains("identity only"),
            "{site}: the render blames the operator's ANSWERS for a path failure: {render}"
        );
        assert!(
            !profile_path.exists(),
            "{site}: a refused write must leave no profile behind"
        );
    }

    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755)).expect("unseal");
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).expect("unseal");
}

#[test]
fn an_authorize_answer_that_is_not_the_token_leaves_it_unsupplied() {
                                                                                                
                                                                       
    let fx = fixture();
    let profile = Profile {
        domain: Some("box.test".into()),
        net: Some("mode=dhcp".into()),
        out_dir: Some(fx._tmp.path().join("images")),
        ..Default::default()
    };
    let items = ask_set(&plan_all_pending(), &profile);
                                                                                       
    let mut answers = vec!["203.0.113.5".to_string()];
    answers.extend(answers_for(&fx, &items));
    answers.push("yes".to_string());                 
    let refs: Vec<&str> = answers.iter().map(String::as_str).collect();
    let (out, io, _) = {
        let profile_path = fx._tmp.path().join("boxes/alpha.toml");
        let records =
            RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
        let mut io = Scripted::new(&refs);
        let out = conduct(
            &mut io,
            &u8(&profile_path),
            &profile,
            &fx.ctx,
            &records,
            &Default::default(),
            None,
        )
        .expect("no refusal")
        .authorized();
        (out, io, profile_path)
    };
    let conducted = out.expect("conducted");
    assert!(
        !conducted
            .invocation
            .argv(&fx.ctx)
            .contains(&"--wipe-confirmed".to_string()),
        "an approximate answer is not an authorization: {:?}",
        conducted.invocation.argv(&fx.ctx)
    );
    assert!(io.said.contains("not the token"), "{}", io.said);
}

#[test]
fn a_second_interview_re_offers_a_steps_identity_when_its_judgment_is_re_decided() {
                                                                                                    
                                                                                                
                                                                                                    
                                                                                          
    let fx = fixture();
    let profile = Profile {
        ip: Some("203.0.113.5".into()),
        domain: Some("box.test".into()),
        ..Default::default()
    };
    let mut records =
        RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
                                                                                       
    let recorded = RunInvocation {
        profile_path: u8(fx._tmp.path().join("boxes/alpha.toml")),
        judgment: BTreeMap::from([("image_version".to_string(), "3".to_string())]),
        ..Default::default()
    };
    let recorded_values = resolve_values(&recorded, &profile, &fx.ctx);
    for step in SPINE.iter() {
        let mut params = BTreeMap::new();
        for p in step.params {
            if let Some(v) = recorded_values.get(p.name) {
                params.insert(p.name.to_string(), v.to_string());
            }
        }
        records
            .record_step(StepRecord {
                step: step.id.token().to_string(),
                run_id: records.run_id().to_string(),
                params,
                input_identities: Default::default(),
                produced: Default::default(),
            })
            .expect("record");
    }
    let asked_over = |values: &orchard::ceremony::param::ParamValues| -> Vec<&'static str> {
        let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone())).with_values(values.clone());
        let plan = plan_of(&probe_ctx, values, &records, &Default::default());
        ask_set(&plan, &profile)
            .iter()
            .map(|i| i.param.name)
            .collect()
    };
                                                                                                 
    let kept = asked_over(&recorded_values);
    assert!(
        !kept.contains(&"domain"),
        "keeping the judgment value leaves S7 settled: {kept:?}"
    );
                                                                                
    let redecided = RunInvocation {
        profile_path: u8(fx._tmp.path().join("boxes/alpha.toml")),
        judgment: BTreeMap::from([("image_version".to_string(), "4".to_string())]),
        ..Default::default()
    };
    let bumped = asked_over(&resolve_values(&redecided, &profile, &fx.ctx));
    assert!(
        bumped.contains(&"domain"),
        "re-deciding image_version un-settles S7, re-offering its identity: {bumped:?}"
    );
    assert!(
        bumped.contains(&"image_version"),
        "the judgment value is re-decided every run: {bumped:?}"
    );
}

                                                                                         

                                                                                               
/// re-computes the ask set as answers arrive, so a positional script cannot address it. An
/// unmapped prompt panics: a new prompt is a red, never a silent empty answer.
struct ByName {
    answers: BTreeMap<String, String>,
    asked: Vec<String>,
}

/// The prompt's subject: `domain [box.test]: ` -> `domain`; `--wipe-confirmed: ` -> the token.
fn prompt_key(prompt: &str) -> String {
    let p = prompt.trim_end();
    let p = p.strip_suffix(':').unwrap_or(p).trim_end();
    match p.rfind(" [") {
        Some(i) if p.ends_with(']') => p[..i].to_string(),
        _ => p.to_string(),
    }
}

impl Interviewer for ByName {
    fn ask(&mut self, prompt: &str) -> Option<String> {
        let key = prompt_key(prompt);
        self.asked.push(key.clone());
                                                                                             
                              
        assert!(
            self.asked.iter().filter(|a| **a == key).count() <= 3,
            "the interview re-prompted `{key}` three times — the fixture answer does not validate"
        );
        Some(
            self.answers
                .get(&key)
                .unwrap_or_else(|| {
                    panic!(
                        "the interview asked `{key}` and the arm answers nothing \
                     for it; add it to `by_name_answers`"
                    )
                })
                .clone(),
        )
    }
    fn say(&mut self, _text: &str) {}
}

/// An operator who presses Enter the FIRST time each SPINE-PARAMETER prompt is put, then answers by
/// name. The target, the re-point and the typed tokens always delegate: an empty first-run target
/// abandons the interview before the ask loop, and an empty token is its own arm
/// (`an_authorize_answer_that_is_not_the_token_leaves_it_unsupplied`).
///
/// Inactive (`EmptyFirst::new(inner, false)`) it is a pass-through to `inner`.
struct EmptyFirst {
    inner: ByName,
    enter_at: BTreeSet<&'static str>,
    entered: Vec<String>,
}

impl EmptyFirst {
    fn new(inner: ByName, active: bool) -> Self {
        let enter_at = if active {
            SPINE
                .iter()
                .flat_map(|s| s.params.iter().map(|p| p.name))
                .collect()
        } else {
            BTreeSet::new()
        };
        EmptyFirst {
            inner,
            enter_at,
            entered: Vec::new(),
        }
    }

    /// Enter at the named prompt keys only; every other prompt goes straight to `inner`.
    fn at(inner: ByName, keys: &[&'static str]) -> Self {
        EmptyFirst {
            inner,
            enter_at: keys.iter().copied().collect(),
            entered: Vec::new(),
        }
    }
}

impl Interviewer for EmptyFirst {
    fn ask(&mut self, prompt: &str) -> Option<String> {
        let key = prompt_key(prompt);
        if self.enter_at.contains(&key.as_str()) && !self.entered.contains(&key) {
            self.entered.push(key.clone());
            self.inner.asked.push(key);
            return Some(String::new());
        }
        self.inner.ask(prompt)
    }
    fn say(&mut self, text: &str) {
        self.inner.say(text);
    }
}

/// Every prompt key the arm can answer: every spine parameter, the two target prompts, and every
/// destructive token the spine declares. Derived from `SPINE` and `required_typed_tokens`, never a
/// hand list, so a new parameter or token arrives as an answer rather than a panic.
fn by_name_answers(
    base: &Path,
    target: &str,
    overrides: &[(&str, &str)],
) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for step in SPINE.iter() {
        for p in step.params {
            m.insert(p.name.to_string(), fixture_answer(base, p.name));
        }
    }
    m.insert("target".to_string(), target.to_string());
    m.insert("re-point to".to_string(), target.to_string());
    for token in required_typed_tokens(&plan_all_pending()) {
        m.insert(token.clone(), token);
    }
    for (k, v) in overrides {
        m.insert((*k).to_string(), (*v).to_string());
    }
    m
}

/// A converged profile's records: every spine step recorded done at the values that profile
/// resolves to with nothing typed.
fn record_every_step_done(fx: &Fx, profile: &Profile, profile_path: &Path) -> RunRecords {
    let mut records =
        RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
    let inv = RunInvocation {
        profile_path: u8(profile_path),
        ..Default::default()
    };
    let values = resolve_values(&inv, profile, &fx.ctx);
    for step in SPINE.iter() {
        let mut params = BTreeMap::new();
        for p in step.params {
            if let Some(v) = values.get(p.name) {
                params.insert(p.name.to_string(), v.to_string());
            }
        }
        records
            .record_step(StepRecord {
                step: step.id.token().to_string(),
                run_id: records.run_id().to_string(),
                params,
                input_identities: Default::default(),
                produced: Default::default(),
            })
            .expect("record");
    }
    records
}

/// The invocation the forwarded argv composes, parsed by the REAL clap surface. The
                                                           
/// totality is `ceremony_selftests::every_judgment_parameter_has_a_run_flag`.
fn run_invocation_of(argv: &[String]) -> RunInvocation {
    use clap::Parser as _;
    let mut full = vec!["orchard".to_string()];
    full.extend(argv.iter().cloned());
    let cli = orchard::cli::Cli::try_parse_from(&full)
        .unwrap_or_else(|e| panic!("the forwarded argv does not parse as an invocation: {e}"));
    match cli.command {
        orchard::cli::OrchardCmd::Run {
            profile,
            target,
            image_version,
            commit,
            wipe_confirmed,
            ..
        } => {
            let mut judgment = BTreeMap::new();
            if let Some(v) = image_version {
                judgment.insert("image_version".to_string(), v.to_string());
            }
            RunInvocation {
                profile_path: profile,
                target,
                judgment,
                commit,
                wipe_confirmed,
                ..Default::default()
            }
        }
        _ => panic!("the interview forwarded a non-run invocation: {argv:?}"),
    }
}

/// One case's inputs. `settled` names the steps the PRE-answer plan must read done, so a case
/// cannot degenerate into "everything is not-done anyway" and pass vacuously.
struct Case<'a> {
    name: &'a str,
    before: Profile,
    seeded: bool,
    target: &'a str,
    overrides: &'a [(&'a str, &'a str)],
    settled: &'a [StepId],
    expect_destructive: bool,
    /// Press Enter at the first ask of every spine parameter (the empty-answer domain).
    enter_first: bool,
}

/// What one case observed: the interview's own product (the authorize argv rides
/// `Conducted::invocation`), the profile it left on disk, and the prompt keys it put — with the
/// subset that was answered by pressing Enter.
struct Covered {
    run_argv: Vec<String>,
    written: Profile,
    asked: Vec<String>,
    entered: Vec<String>,
}

/// One case of the relation: drive the whole interview, then derive what the run it authorized
/// demands and check the interview put every one of those to the operator.
fn the_interview_covers_the_run_it_authorizes(spec: Case) -> Covered {
    let Case {
        name: case,
        before,
        seeded,
        target,
        overrides,
        settled,
        expect_destructive,
        enter_first,
    } = spec;
    let fx = fixture();
    let profile_path = fx._tmp.path().join("boxes/alpha.toml");
    let records = if seeded {
        record_every_step_done(&fx, &before, &profile_path)
    } else {
        RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records")
    };
                                                                                                  
                                                                                                    
    let pre_inv = RunInvocation {
        profile_path: u8(&profile_path),
        ..Default::default()
    };
    let pre_values = resolve_values(&pre_inv, &before, &fx.ctx);
    let pre_ctx = ProbeCtx::new(&fx.ctx, Some(before.clone())).with_values(pre_values.clone());
    let pre_plan = plan_of(&pre_ctx, &pre_values, &records, &Measured::default());
    for id in settled {
        assert!(
            pre_plan.iter().any(|p| p.id == *id && p.is_done()),
            "{case}: {} must read DONE before the answers, or the case proves nothing",
            id.token()
        );
    }

    let mut io = EmptyFirst::new(
        ByName {
            answers: by_name_answers(fx._tmp.path(), target, overrides),
            asked: Vec::new(),
        },
        enter_first,
    );
    let conducted = conduct(
        &mut io,
        &u8(&profile_path),
        &before,
        &fx.ctx,
        &records,
        &Measured::default(),
        None,
    )
    .expect("no refusal")
    .authorized()
    .expect("the interview authorized a run");

                                                                                        
    let written = std::fs::read_to_string(&profile_path).expect("the profile was written");
    let after = load_str(&written).expect("the written profile parses");
    let argv = conducted.invocation.argv(&fx.ctx);
    let inv = run_invocation_of(&argv);
    let values = resolve_values(&inv, &after, &fx.ctx);
    let run_ctx = ProbeCtx::new(&fx.ctx, Some(after.clone())).with_values(values.clone());
    let plan_after = plan_of(&run_ctx, &values, &records, &Measured::default());

    let demanded = required_present_params(&plan_after);
                                                                                  
    assert!(
        !demanded.is_empty(),
        "{case}: the authorized run demands no Required param, so the superset check is empty"
    );
    for (step, p) in &demanded {
        assert!(
            io.inner.asked.iter().any(|a| a == p.name),
            "{case}: the run this interview authorized demands `{}` for the not-done {} and the \
             interview never put it to the operator. Asked: {:?}",
            p.name,
            step.token(),
            io.inner.asked
        );
    }
    let tokens = required_typed_tokens(&plan_after);
    assert!(
        !expect_destructive || !tokens.is_empty(),
        "{case}: this case exists to exercise a run that reaches a destructive step, and the \
         authorized run reaches none"
    );
    for t in &tokens {
        assert!(
            io.inner.asked.iter().any(|a| a == t),
            "{case}: the run this interview authorized requires `{t}` typed live and the interview \
             never offered it. Asked: {:?}",
            io.inner.asked
        );
    }
                                                                                                   
                                                                                                     
    let _ = admit_with(&inv, &fx.ctx, &after, &records, Measured::default()).unwrap_or_else(|e| {
        panic!(
            "{case}: the run the interview authorized is refused by its own admission gate: {} :: \
             {} :: argv {:?}",
            e.id.token(),
            e.detail,
            argv
        )
    });
    Covered {
        run_argv: argv,
        written: after,
        asked: io.inner.asked,
        entered: io.entered,
    }
}

#[test]
fn the_interview_offers_every_param_and_token_the_run_it_authorizes_demands() {
                                                                                                
                                                                                                 
                                                                                                   
                                                                                                
                                                                                                
                                                                                             
    let converged = Profile {
        ip: Some("203.0.113.5".into()),
        domain: Some("box.test".into()),
        image_version: Some(3),
        ..Default::default()
    };
                                                                                              
    the_interview_covers_the_run_it_authorizes(Case {
        name: "first run",
        before: Profile::default(),
        seeded: false,
        target: "203.0.113.5",
        overrides: &[],
        settled: &[],
        expect_destructive: true,
        enter_first: false,
    });
                                                                                                    
                                                                                                  
                                                                                          
    the_interview_covers_the_run_it_authorizes(Case {
        name: "re-decided judgment",
        before: converged.clone(),
        seeded: true,
        target: "203.0.113.5",
        overrides: &[("image_version", "4")],
        settled: &[
            StepId::S7ImageBuild,
            StepId::S9BoxPreflight,
            StepId::S10ProdInstall,
        ],
        expect_destructive: false,
        enter_first: false,
    });
                                                                                             
                                                                               
    the_interview_covers_the_run_it_authorizes(Case {
        name: "re-point",
        before: converged,
        seeded: true,
        target: "198.51.100.9",
        overrides: &[],
        settled: &[StepId::S9BoxPreflight, StepId::S10ProdInstall],
        expect_destructive: true,
        enter_first: false,
    });
}

/// The token following `flag` in an argv, or `None` when the flag is absent or trails the argv.
/// The pair must be ADJACENT: a flag with its value dropped reads as `None` here rather than
/// picking up whatever token follows.
fn flag_value_at(argv: &[String], flag: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .cloned()
}

#[test]
fn pressing_enter_at_every_prompt_supplies_the_judgment_default_on_both_transports() {
                                                                                               
                                                                                                 
                                                                             
    let covered = the_interview_covers_the_run_it_authorizes(Case {
        name: "accepted defaults",
        before: Profile::default(),
        seeded: false,
        target: "203.0.113.5",
        overrides: &[],
        settled: &[],
        expect_destructive: true,
        enter_first: true,
    });

                                                                                                   
                                                                                       
    assert!(
        covered.entered.iter().any(|k| k == "image_version"),
        "the judgment prompt was never answered with Enter: {:?}",
        covered.entered
    );
    for key in &covered.asked {
        let is_param = SPINE
            .iter()
            .flat_map(|s| s.params.iter())
            .any(|p| p.name == key);
        assert!(
            !is_param || covered.entered.iter().any(|e| e == key),
            "`{key}` was asked but never answered with Enter, so this case does not cover it"
        );
    }

                                                                                              
       
    assert_eq!(
        flag_value_at(&covered.run_argv, "--image-version").as_deref(),
        Some("0"),
        "an empty answer on the judgment parameter must supply the shown default to the run: {:?}",
        covered.run_argv
    );
                                                                   
    assert_eq!(
        covered.written.image_version,
        Some(0),
        "the accepted default is stored as well as forwarded"
    );
                                                                                                  
                                                                                
    assert_eq!(
        covered.written.firmware, None,
        "an empty answer on an optional identity parameter writes nothing"
    );
}

/// The spine's record for one parameter name, looked up rather than hand-copied.
fn spine_param(name: &str) -> &'static ParamRecord {
    SPINE
        .iter()
        .flat_map(|s| s.params.iter())
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("the spine declares no `{name}`"))
}

                                                                                                    
/// declared input resolves, and a written `.pub` file so the resolved value passes its own probe.
fn derived_identity_fixture(fx: &Fx, pub_stem: &str) -> (PathBuf, PathBuf, Profile) {
    let base = fx._tmp.path();
    let pubkey = base.join(format!("{pub_stem}.pub"));
    std::fs::write(&pubkey, "ssh-ed25519 AAAA fixture\n").expect("pubkey fixture");
    let profile = Profile {
        operator_pubkey: Some(pubkey.clone()),
        ..Default::default()
    };
    (base.join(pub_stem), pubkey, profile)
}

#[test]
fn a_derived_identity_default_resolves_at_the_prompt_and_lands_in_the_profile() {
                                                                          
                                                                                                    
                                                                                             
    let fx = fixture();
    let profile_path = fx._tmp.path().join("boxes/alpha.toml");
    let (derived, _pubkey, before) = derived_identity_fixture(&fx, "k");
    std::fs::write(&derived, "fixture private key\n").expect("private key fixture");

                                                                                                 
                        
    let inv = RunInvocation {
        profile_path: u8(&profile_path),
        ..Default::default()
    };
    let values = resolve_values(&inv, &before, &fx.ctx);
    let ctx = ProbeCtx::new(&fx.ctx, Some(before.clone())).with_values(values);
    let item = AskItem {
        step: StepId::S10ProdInstall,
        param: spine_param("box_login_identity"),
        current: None,
    };
    assert_eq!(
        empty_answer(&item, &ctx),
        EmptyAnswer::Accept(derived.display().to_string(), "derived"),
        "a resolvable Derived identity default is offered as its resolved value"
    );

    let records = RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
    let mut io = EmptyFirst::at(
        ByName {
            answers: by_name_answers(fx._tmp.path(), "203.0.113.5", &[]),
            asked: Vec::new(),
        },
        &["box_login_identity"],
    );
    let conducted = conduct(
        &mut io,
        &u8(&profile_path),
        &before,
        &fx.ctx,
        &records,
        &Measured::default(),
        None,
    )
    .expect("no refusal")
    .authorized()
    .expect("the interview authorized a run");

                                                                                                     
                                                                                     
    assert_eq!(io.entered, vec!["box_login_identity".to_string()]);
    assert_eq!(
        io.inner
            .asked
            .iter()
            .filter(|k| *k == "box_login_identity")
            .count(),
        1,
        "the resolved default passed its prompt-time probe: {:?}",
        io.inner.asked
    );

    let written = std::fs::read_to_string(&profile_path).expect("the profile was written");
    let after = load_str(&written).expect("the written profile parses");
    assert_eq!(
        after.box_login_identity.as_deref(),
        Some(derived.as_path()),
        "the accepted derivation is written to the profile"
    );
                                                                                           
    let run_inv = run_invocation_of(&conducted.invocation.argv(&fx.ctx));
    admit_with(&run_inv, &fx.ctx, &after, &records, Measured::default()).unwrap_or_else(|e| {
        panic!(
            "the run the interview authorized is refused by its own admission gate: {} :: {}",
            e.id.token(),
            e.detail
        )
    });
}

#[test]
fn a_derived_identity_default_takes_the_prompt_probe_and_re_prompts_when_it_fails() {
                                                                                            
                                                                                  
    let fx = fixture();
    let profile_path = fx._tmp.path().join("boxes/alpha.toml");
    let (derived, pubkey, before) = derived_identity_fixture(&fx, "absent");
    assert!(
        !derived.exists(),
        "the derived target must be absent, or this arm proves nothing"
    );
                                                                                          
                                                                                                
    let pubkey_answer = pubkey.display().to_string();

                                                                                                    
                                                                        
    let inv = RunInvocation {
        profile_path: u8(&profile_path),
        ..Default::default()
    };
    let values = resolve_values(&inv, &before, &fx.ctx);
    let ctx = ProbeCtx::new(&fx.ctx, Some(before.clone())).with_values(values);
    let item = AskItem {
        step: StepId::S10ProdInstall,
        param: spine_param("box_login_identity"),
        current: None,
    };
    assert_eq!(
        empty_answer(&item, &ctx),
        EmptyAnswer::Accept(derived.display().to_string(), "derived"),
        "the producer resolves; only its target is missing"
    );

    let records = RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
    let mut io = EmptyFirst::at(
        ByName {
            answers: by_name_answers(
                fx._tmp.path(),
                "203.0.113.5",
                &[("operator_pubkey", pubkey_answer.as_str())],
            ),
            asked: Vec::new(),
        },
        &["box_login_identity"],
    );
    let conducted = conduct(
        &mut io,
        &u8(&profile_path),
        &before,
        &fx.ctx,
        &records,
        &Measured::default(),
        None,
    )
    .expect("no refusal")
    .authorized()
    .expect("the interview authorized a run");

    assert_eq!(
        io.inner
            .asked
            .iter()
            .filter(|k| *k == "box_login_identity")
            .count(),
        2,
        "a resolved default whose probe fails is re-put, not accepted: {:?}",
        io.inner.asked
    );
    let typed = fx._tmp.path().join("k.pub");
    let written = std::fs::read_to_string(&profile_path).expect("the profile was written");
    let after = load_str(&written).expect("the written profile parses");
    assert_eq!(
        after.box_login_identity.as_deref(),
        Some(typed.as_path()),
        "what the operator typed at the re-prompt is what lands, never the unprobed derivation"
    );
    let run_inv = run_invocation_of(&conducted.invocation.argv(&fx.ctx));
    admit_with(&run_inv, &fx.ctx, &after, &records, Measured::default()).unwrap_or_else(|e| {
        panic!(
            "the re-answered run is refused by its own admission gate: {} :: {}",
            e.id.token(),
            e.detail
        )
    });
}

                                                                                               
/// reads `operator_pubkey`, asked earlier in this same pass. The two arms above both seed
/// `operator_pubkey` into the profile, so neither exercises a pass-level resolve ctx.
///
/// Asserts over the whole interview, not `empty_answer` alone: the default resolves at its own
/// prompt (asked once, answered by Enter), and the written profile holds the derivation, not what
/// a by-name re-prompt would have typed.
#[test]
fn a_first_run_resolves_a_derived_identity_against_an_answer_from_the_same_pass() {
    let fx = fixture();
    let base = fx._tmp.path();
    let profile_path = base.join("boxes/alpha.toml");
    let before = Profile::default();
    assert!(
        before.operator_pubkey.is_none(),
        "a FIRST run: nothing the producer reads is in the profile, or this arm is the seeded case"
    );

    let answers = by_name_answers(base, "203.0.113.5", &[]);
    let typed_pubkey = answers
        .get("operator_pubkey")
        .expect("the fixture answers operator_pubkey")
        .clone();
    let derived = base.join("k");
    assert_eq!(
        typed_pubkey,
        base.join("k.pub").display().to_string(),
        "the derivation below is `operator_pubkey` minus `.pub`"
    );
    assert!(
        derived.exists(),
        "the derived target must exist, or the prompt-time probe fails and this arm measures the \
         re-prompt path instead"
    );

    let records = RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
    let mut io = EmptyFirst::at(
        ByName {
            answers,
            asked: Vec::new(),
        },
        &["box_login_identity"],
    );
    let conducted = conduct(
        &mut io,
        &u8(&profile_path),
        &before,
        &fx.ctx,
        &records,
        &Measured::default(),
        None,
    )
    .expect("no refusal")
    .authorized()
    .expect("the interview authorized a run");

                                                                                                  
                                                                                            
    let at = |k: &str| io.inner.asked.iter().position(|a| a == k);
    let op = at("operator_pubkey").expect("operator_pubkey was asked");
    let bl = at("box_login_identity").expect("box_login_identity was asked");
    assert!(
        op < bl,
        "operator_pubkey is asked before box_login_identity: {:?}",
        io.inner.asked
    );
                                                                        
    assert_eq!(io.entered, vec!["box_login_identity".to_string()]);
    assert_eq!(
        io.inner
            .asked
            .iter()
            .filter(|k| *k == "box_login_identity")
            .count(),
        1,
        "the derived default resolved at its prompt, so Enter settled it: {:?}",
        io.inner.asked
    );

    let written = std::fs::read_to_string(&profile_path).expect("the profile was written");
    let after = load_str(&written).expect("the written profile parses");
    assert_eq!(
        after.box_login_identity.as_deref(),
        Some(derived.as_path()),
        "the derivation from the same-pass answer is what landed; the by-name fallback a re-prompt \
         would have taken types {typed_pubkey}"
    );
    let run_inv = run_invocation_of(&conducted.invocation.argv(&fx.ctx));
    admit_with(&run_inv, &fx.ctx, &after, &records, Measured::default()).unwrap_or_else(|e| {
        panic!(
            "the run the first-run interview authorized is refused by its own admission gate: \
             {} :: {}",
            e.id.token(),
            e.detail
        )
    });
}

                                                                                        
                                                                                               
/// spine declares it AFTER `box_login_identity`. The producer must still resolve over THIS run's
/// answer: the written profile pairs the new pubkey with the new private key. P4 measured the
/// stale pairing (new pubkey, old private key), which surfaces only at the Leg-B reconnect.
#[test]
fn a_derived_identity_resolves_against_an_answer_a_later_step_declares() {
    let fx = fixture();
    let base = fx._tmp.path();
    let profile_path = base.join("boxes/alpha.toml");
    for name in ["old.pub", "old", "new.pub", "new"] {
        std::fs::write(base.join(name), "ssh-ed25519 AAAA fixture\n").expect("key fixture");
    }
    let (old_pub, old_priv) = (base.join("old.pub"), base.join("old"));
    let (new_pub, new_priv) = (base.join("new.pub"), base.join("new"));
    let before = Profile {
        operator_pubkey: Some(old_pub.clone()),
        ..Default::default()
    };

                                                                                                 
                                                                                     
    let s10 = SPINE
        .iter()
        .find(|s| s.id == StepId::S10ProdInstall)
        .expect("S10");
    let declared_at = |n: &str| {
        s10.params
            .iter()
            .position(|p| p.name == n)
            .unwrap_or_else(|| panic!("S10 declares {n}"))
    };
    assert!(
        declared_at("box_login_identity") < declared_at("operator_pubkey"),
        "S10's param list puts the consumer first; the reorder is what fixes the ask order"
    );

                                                                                         
    let inv = RunInvocation {
        profile_path: u8(&profile_path),
        ..Default::default()
    };
    let values = resolve_values(&inv, &before, &fx.ctx);
    let mut records =
        RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
    let s7 = SPINE
        .iter()
        .find(|s| s.id == StepId::S7ImageBuild)
        .expect("S7");
    let mut params = BTreeMap::new();
    for p in s7.params {
        if let Some(v) = values.get(p.name) {
            params.insert(p.name.to_string(), v.to_string());
        }
    }
    records
        .record_step(StepRecord {
            step: StepId::S7ImageBuild.token().to_string(),
            run_id: records.run_id().to_string(),
            params,
            input_identities: Default::default(),
            produced: Default::default(),
        })
        .expect("record s7");

                                                                                                
                                                
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(before.clone())).with_values(values.clone());
    let plan = plan_of(&probe_ctx, &values, &records, &Measured::default());
    assert!(
        plan.iter()
            .any(|p| p.id == StepId::S7ImageBuild && p.is_done()),
        "S7 must read done at the profile's own values, or this is not the P4 configuration"
    );
    let pre_answer: Vec<&str> = ask_set(&plan, &before)
        .iter()
        .map(|i| i.param.name)
        .collect();
    assert!(
        pre_answer.contains(&"operator_pubkey") && pre_answer.contains(&"box_login_identity"),
        "both the input and the consumer are asked in this plan: {pre_answer:?}"
    );

    let mut io = EmptyFirst::at(
        ByName {
            answers: by_name_answers(
                base,
                "203.0.113.5",
                &[("operator_pubkey", &new_pub.display().to_string())],
            ),
            asked: Vec::new(),
        },
        &["box_login_identity"],
    );
    let conducted = conduct(
        &mut io,
        &u8(&profile_path),
        &before,
        &fx.ctx,
        &records,
        &Measured::default(),
        None,
    )
    .expect("no refusal")
    .authorized()
    .expect("the interview authorized a run");

    let at = |k: &str| {
        io.inner
            .asked
            .iter()
            .position(|a| a == k)
            .unwrap_or_else(|| panic!("{k} was asked: {:?}", io.inner.asked))
    };
    assert!(
        at("operator_pubkey") < at("box_login_identity"),
        "the declared input is asked before its consumer: {:?}",
        io.inner.asked
    );
                                                                                            
                                                                              
    assert_eq!(io.entered, vec!["box_login_identity".to_string()]);
    assert_eq!(
        io.inner
            .asked
            .iter()
            .filter(|k| *k == "box_login_identity")
            .count(),
        1,
        "the derived default settled at its prompt: {:?}",
        io.inner.asked
    );

    let written = std::fs::read_to_string(&profile_path).expect("the profile was written");
    let after = load_str(&written).expect("the written profile parses");
    assert_eq!(
        after.operator_pubkey.as_deref(),
        Some(new_pub.as_path()),
        "this run's answer is what landed"
    );
    assert_eq!(
        after.box_login_identity.as_deref(),
        Some(new_priv.as_path()),
        "the reconnect identity is derived from THIS run's pubkey; P4's pairing writes {} instead",
        old_priv.display()
    );
    let run_inv = run_invocation_of(&conducted.invocation.argv(&fx.ctx));
    admit_with(&run_inv, &fx.ctx, &after, &records, Measured::default()).unwrap_or_else(|e| {
        panic!(
            "the run the interview authorized is refused by its own admission gate: {} :: {}",
            e.id.token(),
            e.detail
        )
    });
}

/// The inputs-before-consumer relation, quantified over the plan domain rather than the one
/// configuration Arm P4 drives: all-pending, each single step done (the state that moves a param
/// from an early declarer to a later one), and all-done.
#[test]
fn every_declared_input_is_asked_before_its_consumer_in_every_plan() {
    let profile = Profile::default();
    let all_done: Vec<StepId> = SPINE.iter().map(|s| s.id).collect();
    let plans = std::iter::once(plan_all_pending())
        .chain(SPINE.iter().map(|s| plan_with_done(&[s.id])))
        .chain(std::iter::once(plan_with_done(&all_done)));
    let mut pairs = 0usize;
    for plan in plans {
        let items = ask_set(&plan, &profile);
        let names: Vec<&str> = items.iter().map(|i| i.param.name).collect();
        for (idx, item) in items.iter().enumerate() {
            for read in item.param.default.reads() {
                                                                                                 
                                                                                                 
                let Some(at) = names.iter().position(|n| n == read) else {
                    continue;
                };
                pairs += 1;
                assert!(
                    at < idx,
                    "`{}` reads `{read}`, which this plan asks AFTER it: {names:?}",
                    item.param.name
                );
            }
        }
    }
    assert!(
        pairs >= 1,
        "no (consumer, in-list input) pair exists in any plan, so this arm asserts nothing"
    );
                                                                                                
                                            
    let s7_done: Vec<&str> = ask_set(&plan_with_done(&[StepId::S7ImageBuild]), &profile)
        .iter()
        .map(|i| i.param.name)
        .collect();
    let at = |n: &str| {
        s7_done
            .iter()
            .position(|x| *x == n)
            .unwrap_or_else(|| panic!("{n} is asked in the S7-done plan: {s7_done:?}"))
    };
    assert!(
        at("operator_pubkey") < at("box_login_identity"),
        "the S7-done plan asks the input first: {s7_done:?}"
    );
}

#[test]
fn enter_on_a_stored_judgment_value_forwards_the_stored_value() {
                                                                                                  
                                                                                                 
                             
    let fx = fixture();
    let profile_path = fx._tmp.path().join("boxes/alpha.toml");
    let converged = Profile {
        ip: Some("203.0.113.5".into()),
        domain: Some("box.test".into()),
        image_version: Some(3),
        ..Default::default()
    };
    let records = record_every_step_done(&fx, &converged, &profile_path);
    let mut io = ByName {
        answers: by_name_answers(
            fx._tmp.path(),
            "203.0.113.5",
            &[("image_version", "")],                                
        ),
        asked: Vec::new(),
    };
    let conducted = conduct(
        &mut io,
        &u8(&profile_path),
        &converged,
        &fx.ctx,
        &records,
        &Measured::default(),
        None,
    )
    .expect("no refusal")
    .authorized()
    .expect("the interview authorized a run");

                                                                                                 
                                                                                         
    assert_eq!(
        io.asked,
        vec!["target".to_string(), "image_version".to_string()],
        "a converged profile is asked only its judgment value"
    );
    assert_eq!(
        flag_value_at(&conducted.invocation.argv(&fx.ctx), "--image-version").as_deref(),
        Some("3"),
        "Enter on a stored judgment value forwards THAT value: {:?}",
        conducted.invocation.argv(&fx.ctx)
    );
                                                                                    
    let written = std::fs::read_to_string(&profile_path).expect("the profile was written");
    let after = load_str(&written).expect("the written profile parses");
    let inv = run_invocation_of(&conducted.invocation.argv(&fx.ctx));
    let admitted =
        admit_with(&inv, &fx.ctx, &after, &records, Measured::default()).unwrap_or_else(|e| {
            panic!(
                "the re-confirmed run is refused: {} :: {}",
                e.id.token(),
                e.detail
            )
        });
    assert!(
        admitted
            .plan
            .iter()
            .any(|p| p.id == StepId::S7ImageBuild && p.is_done()),
        "re-confirming the recorded judgment value leaves S7 settled"
    );
}

                                                                                                    

fn orchard_bin() -> &'static str {
    env!("CARGO_BIN_EXE_orchard")
}

#[test]
fn ac10_the_interview_refuses_a_non_interactive_stdin_with_its_own_signature() {
                                                                                          
                                                                                              
                                                          
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = std::process::Command::new(orchard_bin())
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("ORCHARD_LOCK_DIR", tmp.path().join("lock"))
        .args(["guide", "boxes/alpha.toml"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "refusal-with-cure: {stderr}");
    assert!(
        stderr.contains("interview-not-interactive"),
        "the interview's own id: {stderr}"
    );
    assert!(
        stderr.contains("orchard run"),
        "the cure names the unattended route: {stderr}"
    );
    assert!(
        !stderr.contains("passphrase"),
        "not the passphrase gate's message: {stderr}"
    );
}

/// Drive a command under a real pty with a scripted answer file. GROUNDED on util-linux
/// `script(1)` (2.42.2, the version the plan probed): the child gets a tty on BOTH descriptors,
/// answers arrive in order, and answer-file EOF is a clean read-EOF rather than a hang.
fn under_pty(dir: &Path, envs: &[(&str, &str)], argv: &[&str], answers: &str) -> (i32, String) {
    let answer_file = dir.join("answers");
    std::fs::write(&answer_file, answers).expect("write answers");
    let quoted: Vec<String> = argv
        .iter()
        .map(|a| format!("'{}'", a.replace('\'', "'\\''")))
        .collect();
    let transcript = dir.join("transcript");
    let mut cmd = std::process::Command::new("script");
    cmd.current_dir(dir)
        .args([
            "-q",
            "-e",
            "-c",
            &quoted.join(" "),
            &transcript.display().to_string(),
        ])
        .stdin(std::process::Stdio::from(
            std::fs::File::open(&answer_file).expect("open answers"),
        ));
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn script(1)");
    let text = std::fs::read_to_string(&transcript).unwrap_or_default();
                                                                                                 
                                                    
    (out.status.code().unwrap_or(-1), text.replace("\r\n", "\n"))
}

#[test]
fn ac15_a_pty_driven_interview_writes_the_profile_and_authorizes_nothing_on_eof() {
                                                                                            
                                                                                                 
                                                                                            
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("orchard");
                                                                                            
                                       
    std::fs::create_dir_all(repo.join("crates/image-builder")).expect("mk");
    std::fs::create_dir_all(tmp.path().join("artifact-store")).expect("mk");
    let key = tmp.path().join("k.pub");
    std::fs::write(&key, "ssh-ed25519 AAAA fixture\n").expect("key");
    let manifest = tmp.path().join("manifest.toml");
    std::fs::write(&manifest, "# fixture\n").expect("manifest");
    let profile = tmp.path().join("boxes/alpha.toml");
                                                                                        
                                                                                                   
                                                       
    let items = ask_set(&plan_all_pending(), &Profile::default());
    let mut answer_lines = vec!["203.0.113.5".to_string()];
    answer_lines.extend(answers_for_base(tmp.path(), &items));
    let answers = format!("{}\n", answer_lines.join("\n"));
    let (code, transcript) = under_pty(
        tmp.path(),
        &[
            ("HOME", &tmp.path().display().to_string()),
            (
                "ORCHARD_LOCK_DIR",
                &tmp.path().join("lock").display().to_string(),
            ),
            (
                "FRUIT_ARTIFACT_STORE",
                &tmp.path().join("artifact-store").display().to_string(),
            ),
        ],
        &[
            orchard_bin(),
            "--repo-root",
            &repo.display().to_string(),
            "guide",
            &profile.display().to_string(),
        ],
        &answers,
    );
    assert_eq!(code, 0, "the interview ended cleanly:\n{transcript}");
    assert!(
        transcript.contains("the profile was written, the run was not authorized"),
        "EOF at the authorize (after the profile write) reports the profile written, not \
         authorized:\n{transcript}"
    );
                                                                                       
    assert!(
        transcript.contains("the deployment domain baked into the image"),
        "the parameter's own explanation is rendered:\n{transcript}"
    );
                                                                                         
    let written = std::fs::read_to_string(&profile).expect("the profile was written");
    assert!(written.contains("ip = \"203.0.113.5\""), "{written}");
    assert!(written.contains("domain = \"box.test\""), "{written}");
    assert!(written.contains("image_version = 3"), "{written}");
    assert!(
        !written.contains("wipe"),
        "no typed intent stored:\n{written}"
    );
                                                                                                  
                                                                                         
    let records_dir = orchard::ceremony::records::records_dir_of(
        &tmp.path().join(".local/state/orchard/records"),
        &profile,
    );
    assert!(
        !records_dir.join("steps.toml").exists(),
        "no ceremony executed"
    );
}

                                                                                                   

/// Spawn `orchard admit` with the process CWD at `cwd`, feeding `input` to the authorize prompt.
/// `repo_form_dir` is passed as `--repo-form-dir` when `Some`.
fn admit_from_cwd(
    cwd: &Path,
    repo_root: &Path,
    profile: &Path,
    repo_form_dir: Option<&str>,
    input: &str,
) -> (bool, String) {
    use std::io::Write as _;
    let home = repo_root.join("../home");
    std::fs::create_dir_all(home.join(".config")).expect("mk home");
    let store = repo_root.join("../store");
    std::fs::create_dir_all(&store).expect("mk store");
    let mut args: Vec<std::ffi::OsString> = vec![
        "--repo-root".into(),
        repo_root.as_os_str().into(),
        "--artifact-store".into(),
        store.as_os_str().into(),
        "admit".into(),
        "--box".into(),
        profile.as_os_str().into(),
    ];
    if let Some(dir) = repo_form_dir {
        args.push("--repo-form-dir".into());
        args.push(dir.into());
    }
    let mut child = std::process::Command::new(orchard_bin())
        .current_dir(cwd)
        .args(&args)
        .env_remove("FRUIT_ARTIFACT_STORE")
        .env_remove("ORCHARD_LOCK_TOKEN")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", home.join(".state"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn orchard admit");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

                                                                                           
/// checkout. Driven with the process CWD OUTSIDE the checkout, which is the only vantage that
/// separates `repo_root.join(dir)` from a bare relative `dir`: the shipped arm
/// `ceremony_declared_space::orchard_admit_writes_only_after_the_authorize_and_ratifies_the_sorted_key_set`
/// passes an ABSOLUTE `--repo-form-dir` from the harness CWD, where the two resolve alike.
///
/// Three legs: a relative flag value, no flag at all (the `boxes/repo-form` default), and an
/// absolute flag value used as given. Each asserts both directions: the file exists under the
/// checkout (or at the absolute path) AND the CWD-relative path was not created.
///
/// What it claims: where THIS run's `admit` wrote. It does not claim the gate's own read resolves
/// the same way; that is `ceremony_declared_space::ratified_file_bases_under_repo_root_and_an_absolute_override_survives`.
#[test]
fn orchard_admit_bases_its_key_directory_under_the_checkout_from_a_foreign_cwd() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("repo");
                                                                                      
    std::fs::create_dir_all(root.join("crates/image-builder")).expect("mk repo");
    for args in [
        vec!["init", "-q", "-b", "main", "."],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
    ] {
        let out = std::process::Command::new("git")
            .current_dir(&root)
            .args(&args)
            .output()
            .expect("git");
        assert!(out.status.success(), "git {args:?}");
    }
    std::fs::write(root.join("repo-manifest.toml"), "schema-version = 1\n").expect("manifest");
    let profile = tmp.path().join("alpha.toml");
    std::fs::write(&profile, "ip = \"203.0.113.5\"\ndomain = \"box.test\"\n").expect("profile");
    let foreign = tmp.path().join("foreign-cwd");
    std::fs::create_dir_all(&foreign).expect("mk foreign cwd");

                                         
    let (ok, text) = admit_from_cwd(&foreign, &root, &profile, Some("custom/dir"), "admit\n");
    assert!(ok, "leg 1: admit did not exit 0:\n{text}");
    let under_checkout = root.join("custom/dir/executing.keys");
                                                                                               
    assert!(
        text.contains(&format!("wrote {}", under_checkout.display())),
        "leg 1: the run does not name the written path under the checkout:\n{text}"
    );
    assert!(
        !std::fs::read_to_string(&under_checkout)
            .expect("leg 1: no executing.keys under the checkout")
            .is_empty(),
        "leg 1: the written declared space is empty"
    );
    assert!(
        !foreign.join("custom").exists(),
        "leg 1: admit created a key directory relative to the process CWD"
    );

                                                     
    let (ok, text) = admit_from_cwd(&foreign, &root, &profile, None, "admit\n");
    assert!(ok, "leg 2: admit did not exit 0:\n{text}");
    let default_file = root.join("boxes/repo-form/executing.keys");
    assert!(
        text.contains(&format!("wrote {}", default_file.display())),
        "leg 2: the default directory is not under the checkout:\n{text}"
    );
    assert!(default_file.exists(), "leg 2: no default-directory file");
    assert!(
        !foreign.join("boxes").exists(),
        "leg 2: the default directory was created relative to the process CWD"
    );

                                                         
    let abs = tmp.path().join("abs-ratified");
    let (ok, text) = admit_from_cwd(
        &foreign,
        &root,
        &profile,
        Some(abs.to_str().expect("utf-8 tmp path")),
        "admit\n",
    );
    assert!(ok, "leg 3: admit did not exit 0:\n{text}");
    let abs_file = abs.join("executing.keys");
    assert!(
        text.contains(&format!("wrote {}", abs_file.display())),
        "leg 3: the absolute directory did not survive the join:\n{text}"
    );
    assert!(
        abs_file.exists(),
        "leg 3: no file at the absolute directory"
    );
    assert!(
        !root.join(abs.strip_prefix("/").expect("absolute")).exists(),
        "leg 3: the absolute directory was re-based under the checkout"
    );
}

                                                                                                   

                                                                                                
/// and `the_guide_run_seam_forwards_repo_form_dir_only_when_set` read the composed argv as a
/// vector of strings; neither hands it to a parser, and both other conduct call sites pass an
/// empty directory, so no argv in this suite carries the flag through clap. `RunInvocation::argv`
/// ends with the resolved context flags
/// (`argv_pins_the_child_to_the_resolved_context`), so the spelling the guide emits is
/// the spelling the child receives.
///
/// This arm parses the conducted argv with the real `Cli` and reads the field it binds to. The
/// arity of `run --repo-form-dir` is outside what
/// `ceremony_selftests::flag_classification_is_total_over_the_walked_surfaces` compares: it walks
/// long names and aliases, not whether a long takes a value.
///
/// Blind spot: `main.rs`'s two `repo_form_dir` hops (the Guide route into `conduct`, the Run route
/// into `RunInvocation`) are in the binary and no arm drives them.
#[test]
fn the_guides_composed_argv_parses_as_a_run_carrying_the_repo_form_dir() {
    use clap::Parser as _;

    let conducted_argv = |dir: Option<&Utf8PathBuf>| -> Vec<String> {
        let fx = fixture();
        let profile = Profile::default();
        let profile_path = fx._tmp.path().join("boxes/alpha.toml");
        let records =
            RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
        let items = ask_set(&plan_all_pending(), &profile);
        let mut answers = vec!["203.0.113.5".to_string()];
        answers.extend(answers_for(&fx, &items));
        answers.push("--wipe-confirmed".to_string());
        let refs: Vec<&str> = answers.iter().map(String::as_str).collect();
        let mut io = Scripted::new(&refs);
        let conducted = conduct(
            &mut io,
            &u8(&profile_path),
            &profile,
            &fx.ctx,
            &records,
            &Default::default(),
            dir,
        )
        .expect("no refusal")
        .authorized()
        .expect("conducted");
        conducted.invocation.argv(&fx.ctx)
    };

    let parsed_dir = |argv: &[String]| -> Option<Utf8PathBuf> {
        let mut full = vec!["orchard".to_string()];
        full.extend(argv.iter().cloned());
        let cli = orchard::cli::Cli::try_parse_from(&full)
            .unwrap_or_else(|e| panic!("the guide's argv does not parse as an invocation: {e}"));
        match cli.command {
            orchard::cli::OrchardCmd::Run { repo_form_dir, .. } => repo_form_dir,
            _ => panic!("the guide composed a non-run invocation: {argv:?}"),
        }
    };

    let with = conducted_argv(Some(&u8("custom/repo-form")));
                                                                                             
    assert!(
        with.iter().any(|a| a == "--repo-form-dir"),
        "the composed argv carries no flag to parse: {with:?}"
    );
    assert_eq!(
        parsed_dir(&with).as_ref().map(Utf8PathBuf::as_str),
        Some("custom/repo-form"),
        "`run` binds the guide's directory to its own `repo_form_dir`"
    );

    let without = conducted_argv(None);
    assert_eq!(
        parsed_dir(&without),
        None,
        "an unset guide directory leaves the child's `repo_form_dir` unset"
    );
}
