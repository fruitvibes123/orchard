                                                                       
//! records, one per line: `kind<TAB>key=value<TAB>…`, values escaping tab/newline/CR/backslash
//! by name and every other control or line/paragraph-separator char as `\u{...}` (allowlist —
                                                                                 
//! kind, field and status vocabularies are FROZEN committed lists; the constructors enforce
//! membership. Human prose may interleave in v1; a consumer selects record lines by `^<kind>\t` over the
//! locked kinds (the `run --porcelain` face pipes children and frames their output as `detail`
//! records, Task 6). The exit-surface tail that consumes these (class decision, stderr render,
                                                                                                
                         

use super::refusal::Refusal;

                                                               
pub const PORCELAIN_KINDS: &[&str] = &["result", "refusal", "step", "detail", "owed"];

                                                   
pub const PORCELAIN_FIELDS: &[&str] = &[
    "verb", "status", "exit", "id", "cure", "detail", "step", "action",
];

                                                                                             
/// both are distinct from a crash). `failed` = an operator-fixable verb error (a missing input,
                                                                           
pub const PORCELAIN_STATUS: &[&str] = &["ok", "refused", "owed", "failed", "crash"];

/// One porcelain record. `new`/`field` enforce the locked vocabularies, so a new kind or field
/// used without updating the lists is a loud panic in every test that renders it.
#[derive(Debug, Clone)]
pub struct PorcelainRecord {
    pub kind: &'static str,
    pub fields: Vec<(&'static str, String)>,
}

impl PorcelainRecord {
    pub fn new(kind: &'static str) -> Self {
        assert!(
            PORCELAIN_KINDS.contains(&kind),
            "porcelain kind {kind:?} is not in the locked vocabulary"
        );
        PorcelainRecord {
            kind,
            fields: Vec::new(),
        }
    }

    pub fn field(mut self, key: &'static str, value: impl Into<String>) -> Self {
        assert!(
            PORCELAIN_FIELDS.contains(&key),
            "porcelain field {key:?} is not in the locked vocabulary"
        );
        self.fields.push((key, value.into()));
        self
    }

    pub fn render(&self) -> String {
        let mut s = self.kind.to_string();
        for (k, v) in &self.fields {
                                                                                             
                                                                                                  
                                                                                              
                                                                                                 
                                                                                           
            let mut escaped = String::with_capacity(v.len());
            for c in v.chars() {
                match c {
                    '\\' => escaped.push_str("\\\\"),
                    '\t' => escaped.push_str("\\t"),
                    '\n' => escaped.push_str("\\n"),
                    '\r' => escaped.push_str("\\r"),
                    c if c.is_control() || c == '\u{2028}' || c == '\u{2029}' => {
                        escaped.push_str(&format!("\\u{{{:x}}}", c as u32));
                    }
                    c => escaped.push(c),
                }
            }
            s.push('\t');
            s.push_str(k);
            s.push('=');
            s.push_str(&escaped);
        }
        s
    }
}

                                                                                               
                                                                                
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    Success,
    RefusalWithCure,
    OperatorActionOwed(OwedKind),
    /// An operator-fixable verb error that is not a typed refusal (a missing pins.toml, a remote
                                                                                              
                                                                                           
    Failure,
    Crash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwedKind {
                                                                                      
    ConsentGateStop,
    /// Unrecognized content in a sibling declared path; refused before the overwriting step.
    SiblingRefuseBeforeOverwrite,
    /// An external-checklist step's probe is unmet; the instruction block was printed.
    ExternalChecklistStop,
    /// A destructive step reached without its typed flag; the resume command was printed.
    TypedGateStop,
}

                                                                                            
/// porcelain status say "owed", not "failed". It carries the refusal (id + cure + detail, so the
/// operator surface is identical to any other refusal) plus the owed KIND that selects the exit
/// code. `conclude` classes it before the plain-`Refusal` arm, so an owed stop can never be
/// reported as a bare refusal.
#[derive(Debug)]
pub struct OwedStop {
    pub kind: OwedKind,
    pub refusal: Refusal,
}

impl OwedStop {
    pub fn new(kind: OwedKind, refusal: Refusal) -> Self {
        OwedStop { kind, refusal }
    }
}

impl std::fmt::Display for OwedStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.refusal, f)
    }
}

impl std::error::Error for OwedStop {}

                                            
pub const EXIT_CLASSES: &[ExitClass] = &[
    ExitClass::Success,
    ExitClass::RefusalWithCure,
    ExitClass::OperatorActionOwed(OwedKind::ConsentGateStop),
    ExitClass::OperatorActionOwed(OwedKind::SiblingRefuseBeforeOverwrite),
    ExitClass::OperatorActionOwed(OwedKind::ExternalChecklistStop),
    ExitClass::OperatorActionOwed(OwedKind::TypedGateStop),
    ExitClass::Failure,
    ExitClass::Crash,
];

                                                                                             
/// `failed = 1` is the conventional error code; `crash = 101` matches Rust's panic-abort
/// convention (an internal fault, not an operator-fixable verb error).
pub const EXIT_CODE_TABLE: &[(&str, i32)] = &[
    ("success", 0),
    ("failed", 1),
    ("refusal-with-cure", 2),
    ("owed-consent-gate", 3),
    ("owed-sibling-refuse", 4),
    ("owed-external-checklist", 5),
    ("owed-typed-gate", 6),
    ("crash", 101),
];

impl ExitClass {
    pub fn token(self) -> &'static str {
        match self {
            ExitClass::Success => "success",
            ExitClass::Failure => "failed",
            ExitClass::Crash => "crash",
            ExitClass::RefusalWithCure => "refusal-with-cure",
            ExitClass::OperatorActionOwed(OwedKind::ConsentGateStop) => "owed-consent-gate",
            ExitClass::OperatorActionOwed(OwedKind::SiblingRefuseBeforeOverwrite) => {
                "owed-sibling-refuse"
            }
            ExitClass::OperatorActionOwed(OwedKind::ExternalChecklistStop) => {
                "owed-external-checklist"
            }
            ExitClass::OperatorActionOwed(OwedKind::TypedGateStop) => "owed-typed-gate",
        }
    }

    pub fn status(self) -> &'static str {
        match self {
            ExitClass::Success => "ok",
            ExitClass::RefusalWithCure => "refused",
            ExitClass::OperatorActionOwed(_) => "owed",
            ExitClass::Failure => "failed",
            ExitClass::Crash => "crash",
        }
    }
}

                                                                                               
/// crash; each owed stop is distinct.
pub fn exit_code(class: &ExitClass) -> i32 {
    match class {
        ExitClass::Success => 0,
        ExitClass::Failure => 1,
        ExitClass::RefusalWithCure => 2,
        ExitClass::OperatorActionOwed(OwedKind::ConsentGateStop) => 3,
        ExitClass::OperatorActionOwed(OwedKind::SiblingRefuseBeforeOverwrite) => 4,
        ExitClass::OperatorActionOwed(OwedKind::ExternalChecklistStop) => 5,
        ExitClass::OperatorActionOwed(OwedKind::TypedGateStop) => 6,
        ExitClass::Crash => 101,
    }
}

                                                                                              
/// own: `conclude` calls it and then renders. The `OwedStop` arm is what carries the
                                                                                                 
/// falls to the catch-all and reports as `failed`. Arm ORDER here is not load-bearing — an
/// `OwedStop` is not a `Refusal`, so the two arms are disjoint by type (measured: swapping them
/// changes nothing). Deleting the arm is what reddens
/// `ceremony_runner::an_owed_stop_concludes_as_operator_action_owed_not_as_a_bare_refusal`.
pub fn class_of_outcome(outcome: &Result<(), Box<dyn std::error::Error>>) -> ExitClass {
    match outcome {
        Ok(()) => ExitClass::Success,
        Err(e) if let Some(o) = e.downcast_ref::<OwedStop>() => {
            ExitClass::OperatorActionOwed(o.kind)
        }
        Err(e) if e.downcast_ref::<Refusal>().is_some() => ExitClass::RefusalWithCure,
        Err(_) => ExitClass::Failure,
    }
}

/// The result record every porcelain invocation ends with.
pub fn result_record(verb: &str, class: &ExitClass) -> PorcelainRecord {
    PorcelainRecord::new("result")
        .field("verb", verb)
        .field("status", class.status())
        .field("exit", exit_code(class).to_string())
}

/// The refusal record (precedes the result record on a refused porcelain run).
pub fn refusal_record(r: &Refusal) -> PorcelainRecord {
    PorcelainRecord::new("refusal")
        .field("id", r.id.token())
        .field("detail", r.detail.clone())
        .field("cure", r.cure().as_str())
}

/// A verb-owned exit-code site EXEMPT from the ExitClass mapping: a pre-existing documented
                                                                                            
                                                                                                
/// a ceremony code instead of the overlap being silent.
pub struct VerbOwnedExitSite {
    pub verb: &'static str,
    pub note: &'static str,
    pub codes: &'static [i32],
                                                                                              
    /// recorded here so the overlap is disclosed, never silent.
    pub known_shadows: &'static [i32],
}

pub const VERB_OWNED_EXIT_SITES: &[VerbOwnedExitSite] = &[
    VerbOwnedExitSite {
        verb: "OrchardCmd::Status",
        note: "status §2.5 honest codes",
        codes: &[0, 10, 11, 12, 13],
        known_shadows: &[0],
    },
    VerbOwnedExitSite {
        verb: "OrchardCmd::RotateKey",
        note: "rotate-key §3.2 honest codes",
        codes: &[0, 10, 11, 12, 13, 14],
        known_shadows: &[0],
    },
    VerbOwnedExitSite {
        verb: "MarketSub::Outdated",
        note: "--exit-drift documented codes; 1 shadows `failed` (a drift IS a failure-class exit)",
        codes: &[0, 1],
        known_shadows: &[0, 1],
    },
    VerbOwnedExitSite {
        verb: "StoreSub::Prune",
        note: "refused ⇒ 1, pre-existing; 1 shadows `failed` (a refused prune is a failure-class exit)",
        codes: &[0, 1],
        known_shadows: &[0, 1],
    },
];
