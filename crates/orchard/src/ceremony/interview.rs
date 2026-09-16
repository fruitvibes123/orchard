                                                                                            
//! profile, disclose, authorize once, then hand to C3.
//!
//! The whole decision layer is pure and armed without a terminal — the ask set, the per-query
//! render, the re-point rule, the profile the answers compose, and the argv the authorize
//! forwards. [`Interviewer`] is the only I/O, so the pty arms drive the SAME code the operator
//! does rather than a parallel path.

use std::collections::BTreeMap;

use super::Utf8PathBuf;
use super::admission::{
    Measured, PlannedStep, RunInvocation, plan_of, profile_value, resolve_values,
};
use super::emit::emit_stdout;
use super::gate_record::PathWriteId;
use super::lock::CeremonyLock;
use super::param::{DefaultWithSource, DerivationInputs, ParamClass, ParamRecord};
use super::probes::{ProbeCtx, ProbeResult};
use super::records::RunRecords;
use super::refusal::{Refusal, RefusalId, encode_owned};
use super::runner::{ChildCall, ChildCwd, ChildOutcome, Executor, staged_image_of};
use super::spine::{Program, SPINE, StepId};
use crate::deploy::context::ResolvedContext;
use crate::deploy::profile::Profile;

/// The one I/O seam. `ask` returns one line of operator input, or `None` at EOF.
pub trait Interviewer {
    fn ask(&mut self, prompt: &str) -> Option<String>;
    fn say(&mut self, text: &str);
}

                                                                                            
/// passphrase gate keeps its own message welded to its own call site (`deploy/tty.rs`): the two
/// gates protect different things, and a shared message would make a removed gate masquerade as
/// the other one still working.
pub fn require_interactive_stdin() -> Result<(), Refusal> {
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() {
        return Ok(());
    }
    Err(Refusal::new(
        RefusalId::InterviewNotInteractive,
        "the guided interview asks questions, and stdin is not a terminal (a pipe, a redirect, \
         or a CI runner)",
    ))
}

/// One thing the interview will put to the operator.
#[derive(Debug, Clone)]
pub struct AskItem {
    /// The step whose ask slot this parameter consumed, in spine order: for identity params the
    /// first NOT-DONE declaring step (a done step's identity params are not asked); for judgment
    /// params the first declaring step, done or not (judgment is asked every run).
    pub step: StepId,
    pub param: &'static ParamRecord,
    /// The value already resolvable, with where it came from. `Some` ⇒ the operator CONFIRMS
    /// (empty input keeps it); `None` ⇒ the operator supplies it.
    pub current: Option<(String, &'static str)>,
}

impl AskItem {
                                                                                 
    pub fn render(&self, ea: &EmptyAnswer) -> String {
        let mut s = format!("{}\n  {}\n", self.param.name, self.param.explain);
        match ea {
            EmptyAnswer::Keep(v, src) => s.push_str(&format!("  current: {v}  (from the {src})\n")),
            EmptyAnswer::Accept(v, src) => s.push_str(&format!(
                "  default: {v} ({src}; an empty answer supplies it for this run)\n"
            )),
            EmptyAnswer::Unset | EmptyAnswer::Reprompt => {
                s.push_str(&format!("  default: {}\n", default_token(self.param)))
            }
        }
        s
    }

    fn prompt(&self, ea: &EmptyAnswer) -> String {
        match ea {
            EmptyAnswer::Keep(v, _) | EmptyAnswer::Accept(v, _) => {
                format!("{} [{v}]: ", self.param.name)
            }
            _ => format!("{}: ", self.param.name),
        }
    }
}

fn default_token(p: &ParamRecord) -> String {
    use super::param::DefaultWithSource::*;
    match p.default {
        Builtin(v) => format!("{v} (builtin)"),
        FromContext(t, _) => format!("{t} (resolved from context)"),
        Derived(t, _) => format!("{t} (derived)"),
        Required => "(none — required)".to_string(),
    }
}

                                                                                                  
/// IDENTITY parameters of NOT-DONE steps, in spine order, each carrying any value already
/// resolvable so the operator confirms rather than retypes. A done step's identity parameters are
/// not asked: their values are already bound into the record that made the step done. A
                                                                                          
/// reaches the derivation at the consumer's prompt.
pub fn ask_set(plan: &[PlannedStep], profile: &Profile) -> Vec<AskItem> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for step in SPINE.iter() {
        let done = plan.iter().any(|p| p.id == step.id && p.is_done());
        for param in step.params {
                                                                                        
                                                         
            if param.name == "ip" {
                continue;
            }
            let judgment = param.class == ParamClass::Judgment;
                                                                                                  
                                                                                        
                                                                                                    
                                                                                                   
                                                                          
            if done && !judgment {
                continue;
            }
            if !seen.insert(param.name) {
                continue;
            }
                                                                                           
                                                                                   
            out.push(AskItem {
                step: step.id,
                param,
                current: profile_value(profile, param.name).map(|v| (v, "profile")),
            });
        }
    }
    order_inputs_first(out)
}

                                                                                        
/// present in this list are emitted. Reads name resolver-less params (depth-1, ceremony_selftests),
/// so held items release. A leftover under a violated depth-1 appends in input order; membership is
                                        
fn order_inputs_first(items: Vec<AskItem>) -> Vec<AskItem> {
    let in_list: std::collections::BTreeSet<&'static str> =
        items.iter().map(|i| i.param.name).collect();
    let ready = |item: &AskItem, emitted: &std::collections::BTreeSet<&'static str>| {
        item.param
            .default
            .reads()
            .iter()
            .all(|r| emitted.contains(r) || !in_list.contains(r))
    };
    let mut out: Vec<AskItem> = Vec::new();
    let mut emitted: std::collections::BTreeSet<&'static str> = std::collections::BTreeSet::new();
    let mut held: Vec<AskItem> = Vec::new();
    for item in items {
        if ready(&item, &emitted) {
            emitted.insert(item.param.name);
            out.push(item);
            while let Some(i) = held.iter().position(|h| ready(h, &emitted)) {
                let h = held.remove(i);
                emitted.insert(h.param.name);
                out.push(h);
            }
        } else {
            held.push(item);
        }
    }
    out.extend(held);
    out
}

                                
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetOutcome {
    /// No stored `ip` yet: the confirmed target becomes the stored one (the first-run carve-out).
    FirstRun(String),
    /// The confirmed target equals the stored one. The profile is NOT rewritten.
    Unchanged(String),
    /// The operator re-typed the new target at the distinct re-point prompt.
    RePointed(String),
    /// A differing target was confirmed but the re-point was not completed. The profile stays
    /// untouched and the run does not proceed against a target the profile does not name.
    RePointDeclined { stored: String, confirmed: String },
}

/// Decide the target outcome. `retyped` is what the operator entered at the SEPARATE re-point
/// prompt, which only runs when the confirmed target differs from the stored one — accepting a
/// displayed target unchanged can never reach this and so can never rewrite the profile.
pub fn resolve_target(
    stored: Option<&str>,
    confirmed: &str,
    retyped: Option<&str>,
) -> TargetOutcome {
    let Some(stored) = stored else {
        return TargetOutcome::FirstRun(confirmed.to_string());
    };
    if stored == confirmed {
        return TargetOutcome::Unchanged(confirmed.to_string());
    }
    match retyped {
        Some(r) if r == confirmed => TargetOutcome::RePointed(confirmed.to_string()),
        _ => TargetOutcome::RePointDeclined {
            stored: stored.to_string(),
            confirmed: confirmed.to_string(),
        },
    }
}

                                                                                                      
/// the guide already holds) and the guide's own pid (so `run` arms its parent-death kill against the
                                                                                                 
/// site so the export is unit-armed the way the runner's `child_env` is, rather than asserted
                                           
pub fn guide_child_env(lock_token: &str, guide_pid: u32) -> Vec<(String, String)> {
    vec![
        (
            super::lock::LOCK_TOKEN_ENV.to_string(),
            lock_token.to_string(),
        ),
        (
            super::lock::CEREMONY_PPID_ENV.to_string(),
            guide_pid.to_string(),
        ),
    ]
}

                                                                                                   
/// Composition and application live in one lib function so the arm and production run the same
                                                           
/// `inherit_stdio: true` gives the run the real descriptors; `ChildCwd::Inherit` keeps the child's
                                                                                          
                                                            
pub fn execute_authorized_run(
    conducted: &Conducted,
    ctx: &ResolvedContext,
    lock: Option<&CeremonyLock>,
    exec: &mut dyn Executor,
) -> Result<(), String> {
    let call = ChildCall {
        step: SPINE[0].id,
        program: Program::SelfExe,
        args: conducted.invocation.argv(ctx),
        env: lock
            .map(|l| guide_child_env(l.token(), std::process::id()))
            .unwrap_or_default(),
        cwd: ChildCwd::Inherit,
        inherit_stdio: true,
    };
    match exec.run(&call, &mut |line| emit_stdout(&format!("{line}\n"))) {
        ChildOutcome::Ok => Ok(()),
        ChildOutcome::Failed(detail) => Err(format!(
            "the ceremony run failed ({detail}) — its own output above says why"
        )),
    }
}

                                                                                        
                                                                                          
/// classification, never a hand list.
pub fn required_typed_tokens(plan: &[PlannedStep]) -> Vec<String> {
    use super::classify::{FlagClass, flag_table};
    let mut out = Vec::new();
    for step in SPINE.iter() {
        if !step.destructive() || plan.iter().any(|p| p.id == step.id && p.is_done()) {
            continue;
        }
        let Some(verb) = step.verb else { continue };
        for (v, flag, class) in flag_table() {
            if *v == verb && *class == FlagClass::MandatoryDestructiveToken {
                let token = format!("--{flag}");
                if !out.contains(&token) {
                    out.push(token);
                }
            }
        }
    }
    out
}

/// Apply the collected answers onto a profile. Values land by their PARAMETER NAME, which is the
                                                                                             
/// name→field map that a new key could escape.
pub fn apply_answers(
    profile: &Profile,
    answers: &BTreeMap<String, String>,
) -> Result<Profile, Refusal> {
    let mut value = serde_json::to_value(profile).map_err(|e| {
        Refusal::new(
            RefusalId::InternalInvariantViolated,
            format!("serialize the profile: {e}"),
        )
    })?;
    let obj = value.as_object_mut().ok_or_else(|| {
        Refusal::new(
            RefusalId::InternalInvariantViolated,
            "the profile is not a table",
        )
    })?;
    for (k, v) in answers {
        if v.is_empty() {
            continue;
        }
                                                                                                 
                                                                                      
        let typed = match k.as_str() {
            "port" | "image_version" | "schema_version" => {
                v.parse::<u64>().map(serde_json::Value::from).map_err(|_| {
                    Refusal::new(
                        RefusalId::ProfileAnswerInvalid,
                        format!("`{k}` takes a number and the answer was {v:?}"),
                    )
                })?
            }
            _ => serde_json::Value::String(v.clone()),
        };
        obj.insert(k.clone(), typed);
    }
    serde_json::from_value(value).map_err(|e| {
        Refusal::new(
            RefusalId::ProfileAnswerInvalid,
            format!("the collected answers do not compose a valid profile: {e}"),
        )
    })
}

                                                                                                 
/// bytes about to be written, not on the struct, so it sees exactly what lands on disk.
pub fn render_profile(profile: &Profile) -> Result<String, Refusal> {
    let text = encode_owned(profile, "the profile")?;
    if let Some(found) = crate::deploy::profile::scan_for_forbidden_content(&text) {
        return Err(Refusal::new(
            RefusalId::ProfileWriteRefused,
            format!("the profile about to be written carries {found}"),
        ));
    }
    Ok(text)
}

/// What an empty answer at this item does. Computed once per ask; the render, the prompt, and the
/// empty-input branch read this one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmptyAnswer {
    /// Enter keeps the shown current value (src = where it came from).
    Keep(String, &'static str),
    /// Enter supplies the shown default as this run's answer (judgment only).
    Accept(String, &'static str),
                                                                                   
    Unset,
    /// No fallback exists; the prompt repeats.
    Reprompt,
}

/// Resolves what an empty answer means for this item. A Derived or FromContext default of EITHER
/// class resolves through its own producer, so the resolved value takes the prompt-time probe; an
/// unresolvable one returns `Reprompt`. A Builtin identity default stays `Unset`.
pub fn empty_answer(item: &AskItem, ctx: &ProbeCtx) -> EmptyAnswer {
    if let Some((v, src)) = &item.current {
        return EmptyAnswer::Keep(v.clone(), src);
    }
    match (item.param.class, &item.param.default) {
        (_, DefaultWithSource::Required) => EmptyAnswer::Reprompt,
        (ParamClass::Judgment, DefaultWithSource::Builtin(v)) => {
            EmptyAnswer::Accept((*v).to_string(), "builtin")
        }
        (ParamClass::Identity, DefaultWithSource::Builtin(_)) => EmptyAnswer::Unset,
                                                                                                
                                                                                                   
                                                                                        
        (_, d) => match d.derivation() {
            Some(deriv) => {
                let inputs =
                    DerivationInputs::for_reads(deriv.reads, ctx.repo_root(), |r| ctx.value(r));
                match (deriv.f)(&inputs) {
                    Some(v) => EmptyAnswer::Accept(v, source_word(d)),
                    None => EmptyAnswer::Reprompt,
                }
            }
            None => EmptyAnswer::Reprompt,
        },
    }
}

fn source_word(d: &DefaultWithSource) -> &'static str {
    match d {
        DefaultWithSource::Builtin(_) => "builtin",
        DefaultWithSource::FromContext(..) => "resolved from context",
        DefaultWithSource::Derived(..) => "derived",
        DefaultWithSource::Required => "required",
    }
}

                                                                                     
/// probe's cure on failure. `None` ⇒ the operator ended input (EOF), which the caller treats as
/// an abandoned interview, never as an empty answer.
pub fn query(io: &mut dyn Interviewer, item: &AskItem, ctx: &ProbeCtx) -> Option<String> {
    let ea = empty_answer(item, ctx);
    io.say(&item.render(&ea));
    loop {
        let raw = io.ask(&item.prompt(&ea))?;
        let mut answer = raw.trim().to_string();
        if answer.is_empty() {
            match &ea {
                EmptyAnswer::Keep(v, _) => return Some(v.clone()),
                                                                                    
                EmptyAnswer::Unset => return Some(String::new()),
                EmptyAnswer::Reprompt => {
                    io.say("  this value is required — there is no default to fall back on\n");
                    continue;
                }
                                                                                                    
                EmptyAnswer::Accept(v, _) => answer = v.clone(),
            }
        }
        match (item.param.probe)(ctx, &answer) {
            ProbeResult::Met => return Some(answer),
            ProbeResult::Unmet(cure) | ProbeResult::Unevaluable(cure) => {
                io.say(&format!("  {cure}\n"));
            }
        }
    }
}

/// What the interview produced: the invocation the authorize forwards to the C3 child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conducted {
    pub invocation: RunInvocation,
}

                                                                                        
/// happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conclusion {
    /// The interview reached the authorize and forwards this run.
    Authorized(Conducted),
                                                                                                 
    Abandoned { profile_written: bool },
}

impl Conclusion {
    /// The authorized run, or `None` on any abandon.
    pub fn authorized(self) -> Option<Conducted> {
        match self {
            Conclusion::Authorized(c) => Some(c),
            Conclusion::Abandoned { .. } => None,
        }
    }
}

                                                                                              
/// prompt: an abandoned interview writes nothing and authorizes nothing.
pub fn conduct(
    io: &mut dyn Interviewer,
    profile_path: &Utf8PathBuf,
    profile: &Profile,
    resolved_ctx: &ResolvedContext,
    records: &RunRecords,
    measured: &Measured,
    repo_form_dir: Option<&Utf8PathBuf>,
) -> Result<Conclusion, Refusal> {
    let mut answers: BTreeMap<String, String> = BTreeMap::new();
                                                                                                   
                                                                            
    let inv = RunInvocation {
        profile_path: profile_path.clone(),
        repo_form_dir: repo_form_dir.cloned(),
        ..Default::default()
    };
                                                                                                 
                                                                                              
                                                                                     
    let stored = profile_value(profile, "ip");
    io.say(
        "\ntarget\n  the box this ceremony installs onto; confirmed every run, and cross-checked \
         against the profile\n",
    );
    let prompt = match &stored {
        Some(v) => format!("target [{v}]: "),
        None => "target: ".to_string(),
    };
    let Some(raw) = io.ask(&prompt) else {
        return Ok(Conclusion::Abandoned {
            profile_written: false,
        });
    };
    let confirmed = match raw.trim() {
        "" => match &stored {
            Some(v) => v.clone(),
            None => {
                io.say("  the target is required\n");
                return Ok(Conclusion::Abandoned {
                    profile_written: false,
                });
            }
        },
        t => t.to_string(),
    };
    let outcome = if stored.as_deref() == Some(confirmed.as_str()) || stored.is_none() {
        resolve_target(stored.as_deref(), &confirmed, None)
    } else {
        io.say(&format!(
            "  this differs from the profile's stored target ({}).\n  Re-pointing a profile at a \
             different box is its own action: RE-TYPE the new target to confirm, or leave empty \
             to keep the profile as it is.\n",
            stored.as_deref().unwrap_or("(none)")
        ));
        let Some(retyped) = io.ask("re-point to: ") else {
            return Ok(Conclusion::Abandoned {
                profile_written: false,
            });
        };
        resolve_target(stored.as_deref(), &confirmed, Some(retyped.trim()))
    };
    let target = match &outcome {
        TargetOutcome::FirstRun(t) | TargetOutcome::RePointed(t) => {
            answers.insert("ip".to_string(), t.clone());
            t.clone()
        }
        TargetOutcome::Unchanged(t) => t.clone(),
        TargetOutcome::RePointDeclined { stored, confirmed } => {
            io.say(&format!(
                "  the re-point was not confirmed: the profile still names {stored}, and this \
                 ceremony will not run against {confirmed}. Nothing was written.\n"
            ));
            return Ok(Conclusion::Abandoned {
                profile_written: false,
            });
        }
    };
                                                                                        
                                                                                                        
                                                                                                  
                                  
    let bound = SPINE.iter().map(|s| s.params.len()).sum::<usize>() + 1;
    let mut updated = apply_answers(profile, &answers)?;
    for _ in 0..bound {
        let values = resolve_values(&inv, &updated, resolved_ctx);
        let probe_ctx = ProbeCtx::new(resolved_ctx, Some(updated.clone()))
            .with_values(values.clone())
            .with_run_paths(staged_image_of(records), records.dir().to_path_buf());
        let plan = plan_of(&probe_ctx, &values, records, measured);
        let pending: Vec<AskItem> = ask_set(&plan, &updated)
            .into_iter()
            .filter(|item| !answers.contains_key(item.param.name))
            .collect();
        if pending.is_empty() {
            break;
        }
        for item in pending {
                                                                                                   
                                                                                                   
               
            let so_far = apply_answers(profile, &answers)?;
            let so_far_values = resolve_values(&inv, &so_far, resolved_ctx);
            let item_ctx = ProbeCtx::new(resolved_ctx, Some(so_far))
                .with_values(so_far_values)
                .with_run_paths(staged_image_of(records), records.dir().to_path_buf());
            let Some(answer) = query(io, &item, &item_ctx) else {
                return Ok(Conclusion::Abandoned {
                    profile_written: false,
                });
            };
            answers.insert(item.param.name.to_string(), answer);
        }
        updated = apply_answers(profile, &answers)?;
    }
                                                                                                
    let text = render_profile(&updated)?;
    if let Some(dir) = profile_path.as_path().parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            Refusal::new(
                RefusalId::ProfileUnwritable,
                format!("create {}: {e}", dir.display()),
            )
        })?;
    }
                                                                                                 
                                                                   
    super::gate_record::write_atomic(profile_path.as_path(), &text, PathWriteId::Profile)?;
    io.say(&format!("\nprofile written: {}\n", profile_path.as_str()));
                                                                                               
                                                                                      
                                                                                                 
                                                                     
    let values = resolve_values(&inv, &updated, resolved_ctx);
    let probe_ctx = ProbeCtx::new(resolved_ctx, Some(updated.clone()))
        .with_values(values.clone())
        .with_run_paths(staged_image_of(records), records.dir().to_path_buf());
    let plan = plan_of(&probe_ctx, &values, records, measured);
    let mut typed = Vec::new();
    for token in required_typed_tokens(&plan) {
        io.say(&format!(
            "\nthis run reaches a step that erases the target's whole disk. To authorize it, type \
             {token} exactly; leave empty to run up to that step and stop there.\n"
        ));
        let Some(answer) = io.ask(&format!("{token}: ")) else {
                                                                                                
            return Ok(Conclusion::Abandoned {
                profile_written: true,
            });
        };
        match answer.trim() {
            "" => {}
            a if a == token => typed.push(token.clone()),
            _ => io.say("  not the token; treating it as unsupplied\n"),
        }
    }
                                                                                               
                              
    let judgment: BTreeMap<String, String> = answers
        .iter()
        .filter(|(k, _)| is_judgment(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Ok(Conclusion::Authorized(Conducted {
        invocation: RunInvocation {
            profile_path: profile_path.clone(),
            target: Some(target),
            judgment,
            commit: false,
            wipe_confirmed: typed.iter().any(|t| t == "--wipe-confirmed"),
            porcelain: false,
            repo_form_dir: repo_form_dir.cloned(),
        },
    }))
}

fn is_judgment(name: &str) -> bool {
    SPINE.iter().any(|s| {
        s.params
            .iter()
            .any(|p| p.name == name && p.class == ParamClass::Judgment)
    })
}

#[cfg(test)]
mod order_inputs_first_tests {
    use super::*;
    use crate::ceremony::param::{Derivation, probe_non_empty};

    fn resolves(_: &DerivationInputs) -> Option<String> {
        Some("v".to_string())
    }

    const fn base(name: &'static str) -> ParamRecord {
        ParamRecord {
            name,
            explain: "",
            default: DefaultWithSource::Required,
            probe: probe_non_empty,
            class: ParamClass::Identity,
        }
    }

    const fn consumer(name: &'static str, reads: &'static [&'static str]) -> ParamRecord {
        ParamRecord {
            name,
            explain: "",
            default: DefaultWithSource::Derived("t", Derivation { reads, f: resolves }),
            probe: probe_non_empty,
            class: ParamClass::Identity,
        }
    }

    const P_BASE: ParamRecord = base("base");
    const P_OTHER: ParamRecord = base("other");
    const P_CONSUMER: ParamRecord = consumer("consumer", &["base"]);
    const P_CYCLE_A: ParamRecord = consumer("cycle-a", &["cycle-b"]);
    const P_CYCLE_B: ParamRecord = consumer("cycle-b", &["cycle-a"]);

    fn items(params: &[&'static ParamRecord]) -> Vec<AskItem> {
        params
            .iter()
            .map(|p| AskItem {
                step: StepId::S10ProdInstall,
                param: p,
                current: None,
            })
            .collect()
    }

    fn names(items: &[AskItem]) -> Vec<&'static str> {
        items.iter().map(|i| i.param.name).collect()
    }

    #[test]
    fn an_input_listed_after_its_consumer_is_emitted_before_it() {
        let out = order_inputs_first(items(&[&P_CONSUMER, &P_BASE, &P_OTHER]));
        assert_eq!(names(&out), vec!["base", "consumer", "other"]);
    }

    #[test]
    fn a_read_absent_from_the_list_leaves_its_consumer_in_place() {
        let out = order_inputs_first(items(&[&P_OTHER, &P_CONSUMER]));
        assert_eq!(
            names(&out),
            vec!["other", "consumer"],
            "a read answered elsewhere carries no order obligation"
        );
    }

    #[test]
    fn a_read_cycle_still_emits_every_item() {
        let out = order_inputs_first(items(&[&P_CYCLE_A, &P_CYCLE_B, &P_BASE]));
        let mut got = names(&out);
        got.sort_unstable();
        assert_eq!(
            got,
            vec!["base", "cycle-a", "cycle-b"],
            "a held item is appended, never dropped; an unasked param is its own refusal class \
             and order is the lesser invariant"
        );
    }
}
