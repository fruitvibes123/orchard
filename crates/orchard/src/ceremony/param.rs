                                                                 
//! explanation, default with source, validation probe, class. The interview (C2) renders these;
                                                                                           

use std::collections::BTreeMap;

use super::probes::{ProbeCtx, ProbeResult};

                                                                                                
                                                                                                
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamClass {
    Identity,
    Judgment,
}

/// A derived default's producer with its declared read-set. The reads name BASE params only
/// (depth-1; ceremony_selftests owns it), and the producer receives exactly those values through a
/// `DerivationInputs` view. FAC-GC-3: a `Derived`/`FromContext` default carries this, so a
                                                                                                
/// resolved let S6 compose zero invocations and record DONE).
#[derive(Clone, Copy, Debug)]
pub struct Derivation {
    pub reads: &'static [&'static str],
    pub f: fn(&DerivationInputs) -> Option<String>,
}

/// The view a producer runs over: only its declared reads' values, plus the context repo root. No
/// profile and no other values, so an undeclared read has no channel that returns data (it yields
/// `None`, fail-closed to Reprompt/absent). `value` logs every asked name for the reads-honesty
             
pub struct DerivationInputs<'a> {
    values: BTreeMap<&'static str, &'a str>,
    repo_root: &'a std::path::Path,
    asked: std::cell::RefCell<std::collections::BTreeSet<String>>,
}

impl<'a> DerivationInputs<'a> {
    /// Build the view for a derivation: only `reads` get a value channel, looked up through
    /// `lookup`. An undeclared name is never populated, so a producer reading one gets `None`.
    pub fn for_reads(
        reads: &'static [&'static str],
        repo_root: &'a std::path::Path,
        lookup: impl Fn(&str) -> Option<&'a str>,
    ) -> Self {
        let mut values = BTreeMap::new();
        for r in reads {
            if let Some(v) = lookup(r) {
                values.insert(*r, v);
            }
        }
        DerivationInputs {
            values,
            repo_root,
            asked: std::cell::RefCell::new(std::collections::BTreeSet::new()),
        }
    }

    /// One declared input's value, logging the asked name whether hit or miss.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.asked.borrow_mut().insert(name.to_string());
        self.values.get(name).copied()
    }

    pub fn repo_root(&self) -> &std::path::Path {
        self.repo_root
    }

    /// The names any `value` was called with (reads-honesty selftest instrumentation).
    pub fn asked_names(&self) -> std::collections::BTreeSet<String> {
        self.asked.borrow().clone()
    }
}

                                                                                             
/// their source"). Equality is by variant + shown token, ignoring the producer fn pointer (whose
/// address is not a meaningful equality — hand-written rather than derived).
#[derive(Debug, Clone, Copy)]
pub enum DefaultWithSource {
    /// A builtin literal (shown verbatim).
    Builtin(&'static str),
    /// Resolved from the C5 context chain at admission by the carried derivation (the shown token
    /// names the value).
    FromContext(&'static str, Derivation),
    /// Derived from repo state or other resolved values at admission by the carried derivation (the
    /// shown token names the derivation).
    Derived(&'static str, Derivation),
    /// No default: the operator must supply it.
    Required,
}

impl DefaultWithSource {
    /// The derivation (read-set + producer) for a runtime-derived default, if any. `Builtin` and
    /// `Required` have none. The type makes a `Derived`/`FromContext` WITHOUT a derivation
    /// impossible.
    pub fn derivation(&self) -> Option<&Derivation> {
        match self {
            DefaultWithSource::FromContext(_, d) | DefaultWithSource::Derived(_, d) => Some(d),
            DefaultWithSource::Builtin(_) | DefaultWithSource::Required => None,
        }
    }

    /// The declared reads; empty for `Builtin`/`Required`. The ask-order reorder and the selftests
    /// read this.
    pub fn reads(&self) -> &'static [&'static str] {
        match self.derivation() {
            Some(d) => d.reads,
            None => &[],
        }
    }
}

impl PartialEq for DefaultWithSource {
    /// By variant + shown token. The producer fn pointer is intentionally not compared: fn-pointer
    /// addresses are not a meaningful equality, and the shown token identifies the derivation.
    fn eq(&self, other: &Self) -> bool {
        use DefaultWithSource::*;
        match (self, other) {
            (Builtin(a), Builtin(b)) => a == b,
            (FromContext(a, _), FromContext(b, _)) => a == b,
            (Derived(a, _), Derived(b, _)) => a == b,
            (Required, Required) => true,
            _ => false,
        }
    }
}

impl Eq for DefaultWithSource {}

                                                                                         
                                                        
#[derive(Clone, Copy)]
pub struct ParamRecord {
    pub name: &'static str,
    pub explain: &'static str,
    pub default: DefaultWithSource,
    pub probe: fn(&ProbeCtx, &str) -> ProbeResult,
    pub class: ParamClass,
}

impl std::fmt::Debug for ParamRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParamRecord")
            .field("name", &self.name)
            .field("class", &self.class)
            .finish()
    }
}

/// Collected parameter values a step composes from (name → value). `get` records every queried
/// name in `accessed` (interior-mutable), so a self-test can assert a `compose` reads only its
                                                                                       
/// that name is declared by another step or by none.
#[derive(Debug, Clone, Default)]
pub struct ParamValues {
    map: BTreeMap<&'static str, String>,
    accessed: std::cell::RefCell<std::collections::BTreeSet<String>>,
}

impl ParamValues {
    pub fn insert(&mut self, name: &'static str, value: impl Into<String>) {
        self.map.insert(name, value.into());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.accessed.borrow_mut().insert(name.to_string());
        self.map.get(name).map(String::as_str)
    }

    /// The set of names any `get` was called with (test instrumentation for the undeclared-param
    /// arm). Not part of the production contract.
    pub fn accessed_names(&self) -> std::collections::BTreeSet<String> {
        self.accessed.borrow().clone()
    }
}

                                                                                                    

                                                                                                  
pub fn probe_key_file(_ctx: &ProbeCtx, value: &str) -> ProbeResult {
    if value.contains("-----BEGIN") || value.contains('\n') {
        return ProbeResult::Unmet(
            "this looks like raw key material — the interview collects key PATHS only; \
             save the key to a file and supply its path"
                .into(),
        );
    }
    if std::path::Path::new(value).is_file() {
        ProbeResult::Met
    } else {
        ProbeResult::Unmet(format!(
            "{value} is not an existing file — supply a key file path"
        ))
    }
}

/// A directory path whose PARENT must exist (the step itself creates the leaf, e.g. the keys dir).
pub fn probe_creatable_dir(_ctx: &ProbeCtx, value: &str) -> ProbeResult {
    let p = std::path::Path::new(value);
    if p.is_dir() {
        return ProbeResult::Met;
    }
    match p.parent() {
        Some(parent) if parent.as_os_str().is_empty() || parent.is_dir() => ProbeResult::Met,
        Some(parent) => ProbeResult::Unmet(format!(
            "{} does not exist — create it or pick a path under an existing directory",
            parent.display()
        )),
        None => ProbeResult::Unmet(format!("{value} has no parent directory")),
    }
}

                                                                                 
/// ceremony write into the repo tree would dirty the checkout the ceremony itself polices
/// (D23's immutability argument depends on it).
pub fn probe_out_dir(ctx: &ProbeCtx, value: &str) -> ProbeResult {
    let p = std::path::Path::new(value);
                                                                                       
                                                                                                
                                                                                                 
                                                                                                   
    if p.is_relative() {
        return ProbeResult::Unmet(format!(
            "out_dir {value} is relative — supply an ABSOLUTE path outside the repo root (a \
             relative out_dir cannot be checked against the repo root and is meaningless in a \
             travelling profile)"
        ));
    }
                                                                                         
                                                                                            
                                                                                              
                                                                                                 
                                                                                           
                                                                                  
    let cand = canonical_existing(p);
    let root = canonical_existing(ctx.repo_root());
    if cand.starts_with(&root) {
        ProbeResult::Unmet(format!(
            "out_dir {value} is under the resolved repo root {} — ceremony artifacts never land \
             in the repo tree; pick a path outside it (e.g. /tmp or a dedicated dir)",
            ctx.repo_root().display()
        ))
    } else {
        probe_creatable_dir(ctx, value)
    }
}

/// Canonicalize a path by resolving its nearest EXISTING ancestor (symlinks and all) and
/// re-joining the not-yet-existing tail — so two spellings of the same location, one through a
                                                                                       
/// no existing ancestor (only `/` exists) falls back to itself.
fn canonical_existing(p: &std::path::Path) -> std::path::PathBuf {
    let mut ancestor = p;
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(real) = ancestor.canonicalize() {
            let mut out = real;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (ancestor.file_name(), ancestor.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                ancestor = parent;
            }
            _ => return p.to_path_buf(),
        }
    }
}

                                                                                             
/// signed-USB ceremony refusal (it never deploys via S10).
pub fn probe_firmware(_ctx: &ProbeCtx, value: &str) -> ProbeResult {
    match value {
        "seabios" | "seabios-gpt" => ProbeResult::Met,
        "uefi" => ProbeResult::Unmet(
            "firmware `uefi` deploys via the signed-USB Secure-Boot ceremony, never the S10 \
             kexec-takeover install — v1 models firmware in {seabios, seabios-gpt}"
                .into(),
        ),
        other => ProbeResult::Unmet(format!(
            "firmware {other:?} is not in the v1 set {{seabios, seabios-gpt}}"
        )),
    }
}

/// A non-empty free-form value (format-level floor; the consuming verb re-validates).
pub fn probe_non_empty(_ctx: &ProbeCtx, value: &str) -> ProbeResult {
    if value.trim().is_empty() {
        ProbeResult::Unmet("the value is empty".into())
    } else {
        ProbeResult::Met
    }
}

/// A value SAFE to pass as a positional argv token to a non-clap external program (`make`,
                                                                                      
/// and shape-validating positionals; a compose that targets a non-clap tool has no such rule, so
/// a value in OPTION or ASSIGNMENT form is read as a flag. Grounded on GNU Make 4.4.1: `-f<mk>`
/// runs a foreign makefile, `--eval=…` and a bare `VAR=value` inject (the `VAR=` override even
/// survives a `--` separator, so a separator alone is insufficient — measured 2026-08-12). This
/// is the value-validation layer the composer must not skip: allowlist, non-empty, no leading
/// `-`, no `=`, and only characters a make target or a docker image ref uses.
pub fn argv_positional_safe(value: &str) -> bool {
    match value.chars().next() {
        None => false,
        Some('-') => false,
        Some(_) => value.chars().all(is_argv_char),
    }
}

fn is_argv_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | ':' | '@' | '-')
}

/// Probe form of [`argv_positional_safe`] for parameters whose value reaches an external argv
/// (`gate_target` → `make`, `container_image` → `docker`).
pub fn probe_argv_positional(_ctx: &ProbeCtx, value: &str) -> ProbeResult {
    if argv_positional_safe(value) {
        ProbeResult::Met
    } else {
        ProbeResult::Unmet(format!(
            "{value:?} is not safe to pass to an external tool (make/docker) — it must be \
             non-empty, not start with `-`, carry no `=`, and use only [A-Za-z0-9._/:@-] \
            "
        ))
    }
}

/// A base-10 unsigned integer (image_version).
pub fn probe_u64(_ctx: &ProbeCtx, value: &str) -> ProbeResult {
    match value.parse::<u64>() {
        Ok(_) => ProbeResult::Met,
        Err(e) => ProbeResult::Unmet(format!("{value:?} is not an unsigned integer: {e}")),
    }
}

/// The `--net` value shape (delegates to the load-bearing build_image validator).
pub fn probe_net(_ctx: &ProbeCtx, value: &str) -> ProbeResult {
    match crate::deploy::build_image::validate_net(value) {
        Ok(_) => ProbeResult::Met,
        Err(e) => ProbeResult::Unmet(e),
    }
}

/// An existing file path (optional params validate only when supplied).
pub fn probe_existing_file(_ctx: &ProbeCtx, value: &str) -> ProbeResult {
    if std::path::Path::new(value).is_file() {
        ProbeResult::Met
    } else {
        ProbeResult::Unmet(format!("{value} is not an existing file"))
    }
}
