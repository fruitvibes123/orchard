                                                                                         
//! hash-and-exec-verified at the gate; operator content is never committed, in the executing
//! checkout or any sibling.
//!
                                                                                   
//! - [`decide_executing_gate`] — the executing checkout's dirty DECLARED paths. Ambiguity beats
//!   the token: unrecorded or interrupted content stops EVERY regime with the external cure
//!   (settle or commit it yourself, then re-run), never a prompt; no typed token authorizes it.
                                                                                                  
                                                                                                 
                                                                                                
//!   ceremony output proceeds with its owed `git -C <sibling> commit` printed, and unrecognized
//!   content REFUSES before the overwriting step with an external cure.
//!
//! Recognition never consults the per-profile record set — it uses the shared content-addressed
//! store the same publish wrote (`records::sibling_output_recognized`).

use super::porcelain::{OwedKind, OwedStop};
use super::records::{DeclaredPathName, DirtClass};
use super::refusal::{Refusal, RefusalId};

/// The gate regime, derived by total match over `(unspeakable.is_empty(), is_tty, commit_token)`.
/// The prompt closure runs on exactly one arm (`Interactive`), so the property "the operator is
                                                                                   
enum GateRegime {
    /// Unspeakable content in the set (any tty/token): stop with the external cure. The interactive
    /// prompt never renders over unrecorded or interrupted content.
    UnspeakableStop,
    /// All-speakable set with the token: commit, no prompt.
    TokenRecorded,
    /// A terminal, all-speakable set, no token: disclose the record view, prompt y/e/N; `declined`
    /// is the stop the non-commit answer composes.
    Interactive { declined: StopSlot },
    /// All-speakable, no token, no terminal: print-only stop (slot A).
    HeadlessUnauthorized,
}

/// The non-commit stop a print-only or edit-abort gate composes. One slot: the interactive prompt
/// and the print-only stop only ever render over an all-speakable, no-token set (an unspeakable set
/// stops earlier at `UnspeakableStop`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopSlot {
    /// No token, all-speakable set.
    NoTokenRecorded,
}

/// Derive the regime. Eight explicit tuples, no wildcard, no guard. The four `(false, *, *)` rows
/// (unspeakable content present) all stop; no token or terminal reaches a prompt over them.
fn gate_regime(unspeakable_empty: bool, is_tty: bool, commit_token: bool) -> GateRegime {
    match (unspeakable_empty, is_tty, commit_token) {
        (false, false, false) => GateRegime::UnspeakableStop,
        (false, false, true) => GateRegime::UnspeakableStop,
        (false, true, true) => GateRegime::UnspeakableStop,
        (false, true, false) => GateRegime::UnspeakableStop,
        (true, false, true) => GateRegime::TokenRecorded,
        (true, true, true) => GateRegime::TokenRecorded,
        (true, true, false) => GateRegime::Interactive {
            declined: StopSlot::NoTokenRecorded,
        },
        (true, false, false) => GateRegime::HeadlessUnauthorized,
    }
}

/// What the gate decided about the executing checkout.
#[derive(Debug)]
pub enum GateDecision {
    /// Nothing dirty in the declared set.
    Proceed,
    /// Commit exactly these paths through the §3 construction, each with its classifier verdict;
    /// the verdict is what the commit message renders per class. `disclosure_shown` is true when the
    /// interactive prompt closure already emitted the composed disclosure (the note included), so
    /// the caller emits the discard note only on the token routes that bypassed the prompt (§3.6:
    /// each route emits once).
    Commit {
        paths: Vec<(DeclaredPathName, DirtClass)>,
        disclosure_shown: bool,
    },
    /// Commit after an interactive message edit; `declined` is the stop the edit-abort branch owes
                                                                                                
    /// fallback is total.
    EditThenCommit {
        paths: Vec<(DeclaredPathName, DirtClass)>,
        declined: StopSlot,
    },
    /// An operator action is owed; the run stops here with HEAD unchanged.
    Stop(Box<OwedStop>),
    /// The gate could not compose its disclosure; refuse (fail closed).
    Refuse(Box<Refusal>),
}

                                                                                                   
/// (the disclosure could not be composed) surfaces as `Refuse`, fail closed. `resume_with_commit`
                                                                                  
pub fn decide_executing_gate(
    dirt: &[(DeclaredPathName, DirtClass)],
    is_tty: bool,
    commit_token: bool,
    prompt: impl FnOnce() -> Result<char, Refusal>,
    resume: &str,
    resume_with_commit: &str,
) -> GateDecision {
    if dirt.is_empty() {
        return GateDecision::Proceed;
    }
                                                                                                 
                                                                                                  
                                         
    let unspeakable: Vec<&str> = dirt
        .iter()
        .filter(|(_, c)| !c.speakable())
        .map(|(p, _)| p.as_str())
        .collect();
    let paths: Vec<(DeclaredPathName, DirtClass)> =
        dirt.iter().map(|(p, c)| (p.clone(), *c)).collect();
    match gate_regime(unspeakable.is_empty(), is_tty, commit_token) {
        GateRegime::UnspeakableStop => {
                                                                                                   
                                                                                                   
                                                                                          
            let mut classes: Vec<DirtClass> = Vec::new();
            for (_, c) in dirt.iter().filter(|(_, c)| !c.speakable()) {
                if !classes.contains(c) {
                    classes.push(*c);
                }
            }
            let paths_of = |class: DirtClass| -> Vec<&str> {
                dirt.iter()
                    .filter(|(_, c)| *c == class && !c.speakable())
                    .map(|(p, _)| p.as_str())
                    .collect()
            };
            let causes = classes
                .iter()
                .map(|c| format!("{:?} ({})", paths_of(*c), c.cause_phrase()))
                .collect::<Vec<_>>()
                .join("; ");
            let cure_phrases = classes
                .iter()
                .map(|c| format!("{:?}: {}", paths_of(*c), c.unspeakable_cure_phrase()))
                .collect::<Vec<_>>()
                .join("; ");
            GateDecision::Stop(Box::new(OwedStop::new(
                OwedKind::ConsentGateStop,
                Refusal::new(
                    RefusalId::ConsentGateOwed,
                    format!(
                        "declared path(s) hold content this ceremony's records cannot speak for: \
                         {causes}; and no typed token authorizes committing content nobody reviewed"
                    ),
                )
                .with_cure_extra(format!("{cure_phrases}: {resume}")),
            )))
        }
        GateRegime::TokenRecorded => GateDecision::Commit {
            paths,
            disclosure_shown: false,
        },
        GateRegime::Interactive { declined } => match prompt() {
            Err(r) => GateDecision::Refuse(Box::new(r)),
            Ok(c) => match c.to_ascii_lowercase() {
                'y' => GateDecision::Commit {
                    paths,
                    disclosure_shown: true,
                },
                'e' => GateDecision::EditThenCommit { paths, declined },
                _ => GateDecision::Stop(slot_stop(declined, &paths, resume, resume_with_commit)),
            },
        },
        GateRegime::HeadlessUnauthorized => GateDecision::Stop(slot_stop(
            StopSlot::NoTokenRecorded,
            &paths,
            resume,
            resume_with_commit,
        )),
    }
}

/// The cure a print-only or edit-abort stop composes for a slot; one site, shared by
                                                                                             
/// unspeakable slots do not, because `--commit` is neutralized over unspeakable content.
fn slot_cure(slot: StopSlot, _resume: &str, resume_with_commit: &str) -> String {
    match slot {
        StopSlot::NoTokenRecorded => format!(
            "review the record view and commit them yourself, or re-run with --commit: \
             {resume_with_commit}"
        ),
    }
}

fn slot_path_list(paths: &[(DeclaredPathName, DirtClass)]) -> Vec<String> {
    paths.iter().map(|(p, _)| p.as_str().to_string()).collect()
}

/// The print-only stop text for the one slot (all-speakable, no token): HEAD is unchanged and the
/// operator carries no commit authorization.
pub(crate) fn slot_stop(
    slot: StopSlot,
    paths: &[(DeclaredPathName, DirtClass)],
    resume: &str,
    resume_with_commit: &str,
) -> Box<OwedStop> {
    let path_list = slot_path_list(paths);
    let detail = match slot {
        StopSlot::NoTokenRecorded => format!(
            "declared path(s) {path_list:?} are uncommitted and this run carries no commit \
             authorization, so HEAD is unchanged"
        ),
    };
    Box::new(OwedStop::new(
        OwedKind::ConsentGateStop,
        Refusal::new(RefusalId::ConsentGateOwed, detail).with_cure_extra(slot_cure(
            slot,
            resume,
            resume_with_commit,
        )),
    ))
}

/// The stop the ceremony owes when the interactive message edit aborts (no `$EDITOR`, editor
/// failed, or empty message): nothing was committed, HEAD is unchanged, and the cure is the same
                                               
pub(crate) fn edit_aborted_stop(
    declined: StopSlot,
    paths: &[(DeclaredPathName, DirtClass)],
    resume: &str,
    resume_with_commit: &str,
) -> Box<OwedStop> {
    let path_list = slot_path_list(paths);
    let detail = format!(
        "the message edit aborted (no $EDITOR, editor failed, or empty message); declared path(s) \
         {path_list:?} remain uncommitted and HEAD is unchanged"
    );
    Box::new(OwedStop::new(
        OwedKind::ConsentGateStop,
        Refusal::new(RefusalId::ConsentGateOwed, detail).with_cure_extra(slot_cure(
            declined,
            resume,
            resume_with_commit,
        )),
    ))
}

/// What the gate decided about one sibling checkout's declared paths.
#[derive(Debug)]
pub enum SiblingDecision {
    /// Nothing dirty, or every dirty declared path is recognized ceremony output. The owed
    /// commands (one per recognized path) are printed and the run proceeds.
    Proceed { owed: Vec<String> },
    /// Unrecognized content: refuse BEFORE the step that would overwrite it.
    Stop(Box<OwedStop>),
}

                                                                                            
/// verdict the caller obtained from the shared store; unrelated sibling dirt never reaches here
/// and never blocks.
pub fn decide_sibling(
    sibling_label: &str,
    dirty: &[(String, bool)],
    sibling_root: &std::path::Path,
    disclosure: &str,
) -> SiblingDecision {
    let unrecognized: Vec<&str> = dirty
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(p, _)| p.as_str())
        .collect();
    if !unrecognized.is_empty() {
        let mut detail = format!(
            "the {sibling_label} checkout has uncommitted change(s) at {unrecognized:?} that this \
             ceremony's own output does not account for, and the next step overwrites that path"
        );
        if !disclosure.is_empty() {
            detail.push('\n');
            detail.push_str(disclosure);
        }
        return SiblingDecision::Stop(Box::new(OwedStop::new(
            OwedKind::SiblingRefuseBeforeOverwrite,
            Refusal::new(RefusalId::SiblingContentUnrecognized, detail).with_cure_extra(format!(
                "review, then commit or stash the change in {} yourself",
                sibling_root.display()
            )),
        )));
    }
    SiblingDecision::Proceed {
        owed: dirty
            .iter()
            .map(|(p, _)| format!("git -C {} commit -- {p}", sibling_root.display()))
            .collect(),
    }
}

/// The ceremony's commit message: what ran, and each declared path it commits under a heading
/// naming that path's classifier verdict. Composed from the ceremony's own facts, never from a
/// scan of the tree. A prior-run path is attributed to a prior run, not to this run's steps
                     
pub fn commit_message(
    profile_name: &str,
    steps: &[&str],
    paths: &[(DeclaredPathName, DirtClass)],
) -> String {
    let subject = if steps.is_empty() {
        format!("ceremony({profile_name})")
    } else {
        format!("ceremony({profile_name}): {}", steps.join(" + "))
    };
    let mut s = format!("{subject}\n\n");
                                                                                                   
                                                                
    let mut rows: Vec<(DirtClass, &DeclaredPathName)> =
        paths.iter().map(|(p, c)| (*c, p)).collect();
    rows.sort_by_key(|(c, _)| c.section_order());
    let mut i = 0;
    while i < rows.len() {
        let class = rows[i].0;
        s.push_str(class_heading(class));
        s.push('\n');
        while i < rows.len() && rows[i].0 == class {
            s.push_str(&format!("  {}\n", rows[i].1));
            i += 1;
        }
    }
    s
}

/// The commit-message heading per class. A new class must decide its heading here to compile. The
/// heading names the classifier verdict, never a review act (the token-on-TTY corner).
pub fn class_heading(class: DirtClass) -> &'static str {
    match class {
        DirtClass::CleanOrRecorded => "Declared paths written by this ceremony run:",
        DirtClass::PriorRunRecorded => {
            "Declared paths finalized by a prior ceremony run (recorded content):"
        }
        DirtClass::Interrupted => {
            "Declared paths whose latest path record is open without finalize (interrupted write):"
        }
        DirtClass::Ambiguous => "Declared paths holding content no ceremony record speaks for:",
    }
}
