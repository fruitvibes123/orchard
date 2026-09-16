                                                                               
//!
//! Tool context = repo root + artifact store + repo-manifest path, resolved through ONE chain:
                                                                                                
//! through [`ResolvedContext`]; the direct env/CWD reads at the old sites are deleted and a
//! fail-closed allowlist guard (`tests/context_matrix.rs`) keeps them out. Sources are printable
                                                            
//!
                                                               
//! - an EXPLICITLY supplied path (flag/profile/env/file tier) that does not resolve refuses
//!   naming the source and the path; it never falls through to a lower tier.
//! - two sources at the SAME tier (a verb-local flag vs the global flag) that disagree refuse
//!   naming both values ([`merge_same_tier`]); tiers the chain orders never refuse — the chain
//!   arbitrates them.
//! - the builtin defaults stay lazy for store/manifest (consumers fail at use, as before); the
                                                                                                 
//!   extended with the override levers.
//!
//! Env tier: exactly `FRUIT_ARTIFACT_STORE` (the one historically-bound var). No new env vars —
                                                                                                  
//!
//! Context file (Q1): `<config base>/recipes-deploy/orchard-context.toml`, `<config base>`
//! resolved XDG-first exactly as `default_keys_dir` does (`XDG_CONFIG_HOME`, else `$HOME/.config`;
                                                                                   
//! `deny_unknown_fields`; `--context <path>` overrides the file LOCATION (explicit ⇒ must exist).
//! Relative values in the file resolve against the file's own directory (CWD-independent);
//! profile-carried context paths must be absolute (a profile travels, its CWD is meaningless).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::profile::Profile;
use crate::ceremony::Utf8PathBuf;
use crate::ceremony::refusal::{Refusal, RefusalId};

                                                                  
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueSource {
    Flag,
    Profile,
    Env,
    File,
    CwdDefault,
}

impl ValueSource {
    pub fn label(self) -> &'static str {
        match self {
            ValueSource::Flag => "flag",
            ValueSource::Profile => "profile",
            ValueSource::Env => "env",
            ValueSource::File => "file",
            ValueSource::CwdDefault => "cwd default",
        }
    }
}

/// Per-value provenance + the context file the resolution consulted (present or not).
#[derive(Debug, Clone)]
pub struct ContextSources {
    pub repo_root: ValueSource,
    pub artifact_store: ValueSource,
    pub repo_manifest: ValueSource,
    /// The context-file path that was consulted, with whether it existed.
    pub context_file: Option<(PathBuf, bool)>,
}

                                                                   
#[derive(Debug, Clone)]
pub struct ResolvedContext {
    pub repo_root: Utf8PathBuf,
    pub artifact_store: Utf8PathBuf,
    pub repo_manifest: Utf8PathBuf,
    pub sources: ContextSources,
}

impl ResolvedContext {
    /// The global flags that pin a spawned child to THIS resolved context so it does not
    /// re-resolve from its own CWD (the P4 context-boundary class). One home for every forwarding
    /// site: the runner's `SelfExe` children (`ceremony::runner::child_invocations`) and
    /// `RunInvocation::argv`/`admit_argv` (the guide→run spawn and the printed resume/admit
    /// commands). Deriving all of them from this one method means a new forwarded value is added
    /// once, not per site.
    pub fn forward_flags(&self) -> Vec<String> {
                                                                                                     
                                                                                             
        let ResolvedContext {
            repo_root,
            artifact_store,
            repo_manifest,
            sources: _,
        } = self;
        vec![
            "--repo-root".to_string(),
            repo_root.as_str().to_string(),
            "--artifact-store".to_string(),
            artifact_store.as_str().to_string(),
            "--repo-manifest".to_string(),
            repo_manifest.as_str().to_string(),
        ]
    }
}

/// The clap-collected global overrides (`--repo-root`, `--artifact-store`, `--repo-manifest`,
/// `--context`).
#[derive(Debug, Clone, Default)]
pub struct ContextFlags {
    pub repo_root: Option<Utf8PathBuf>,
    pub artifact_store: Option<Utf8PathBuf>,
    pub repo_manifest: Option<Utf8PathBuf>,
    pub context_file: Option<Utf8PathBuf>,
}

impl ContextFlags {
    /// Fold a verb-local store flag (`vendor --store`) into the flag tier. Two same-tier sources
                                              
    pub fn with_store_override(
        mut self,
        verb_flag: &str,
        v: Option<Utf8PathBuf>,
    ) -> Result<Self, Refusal> {
        self.artifact_store =
            merge_same_tier("--artifact-store", self.artifact_store.take(), verb_flag, v)?;
        Ok(self)
    }
}

/// The whitelisted context-file schema (Q1): exactly the three context keys.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextFile {
    repo_root: Option<Utf8PathBuf>,
    artifact_store: Option<Utf8PathBuf>,
    repo_manifest: Option<Utf8PathBuf>,
}

/// The injectable resolution inputs: [`resolve_context`] binds the live process (env, cwd, XDG
/// base); tests drive this shape directly so the matrix runs without process-global env races.
pub struct ContextInputs<'a> {
    pub flags: &'a ContextFlags,
    pub profile: Option<&'a Profile>,
    /// `FRUIT_ARTIFACT_STORE`, if set.
    pub env_store: Option<PathBuf>,
    pub cwd: PathBuf,
    /// The XDG-first config base (`XDG_CONFIG_HOME`, else `$HOME/.config`); `None` = no base.
    pub config_base: Option<PathBuf>,
}

/// The env tier's store variable. Named here, the C5 resolver's home, so a forwarding site (the
/// ceremony runner's `child_env`) references the name instead of re-spelling the literal.
pub const ARTIFACT_STORE_ENV: &str = "FRUIT_ARTIFACT_STORE";

/// The builtin store default: `<repo root>/../artifact-store` (lexical, matching the historical
/// default at every deleted site).
pub fn store_default(repo_root: &Path) -> PathBuf {
    repo_root.join("../artifact-store")
}

/// The builtin manifest default: `<repo root>/repo-manifest.toml`. Also the ONE home of the
/// literal for deliberate re-rooted joins (the `market upgrade` staged-overlay verify).
pub fn manifest_default(repo_root: &Path) -> PathBuf {
    repo_root.join("repo-manifest.toml")
}

                                                                                              
/// env tier must test validity, not presence: `var_os` returns `Some("")` for `export X=`, and an
/// empty path resolves relative to the CWD (`"".is_relative()`), so a presence test would silently
/// relocate the store / config / keys base into whatever directory the tool was run in. Empty ==
/// unset is the freedesktop base-dir contract for `XDG_CONFIG_HOME`
/// (https://specifications.freedesktop.org/basedir/latest/) and the safe reading for every path
/// var. The flag tier is already validity-checked (clap rejects `--repo-root ""`) and the profile
/// tier by an `is_relative()` refusal; this gives the env tier the same floor.
pub fn non_empty_var_os(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

                                                                                         
                                                                                                 
/// `$HOME/.config` rather than becoming the CWD-relative `recipes-deploy/…`.
fn config_base() -> Option<PathBuf> {
    non_empty_var_os("XDG_CONFIG_HOME")
        .or_else(|| non_empty_var_os("HOME").map(|h| h.join(".config")))
}

/// The default context-file location under a config base (Q1).
pub fn default_context_file(config_base: &Path) -> PathBuf {
    config_base
        .join("recipes-deploy")
        .join("orchard-context.toml")
}

/// Two sources at the same precedence tier: equal or one absent merges; a disagreement refuses
                                                                                       
pub fn merge_same_tier(
    a_name: &str,
    a: Option<Utf8PathBuf>,
    b_name: &str,
    b: Option<Utf8PathBuf>,
) -> Result<Option<Utf8PathBuf>, Refusal> {
    match (a, b) {
        (Some(x), Some(y)) if x != y => Err(Refusal::new(
            RefusalId::ContextConflict,
            format!(
                "{a_name} ({x}) and {b_name} ({y}) disagree — they set the same context value at \
             the same precedence tier, which the resolution chain cannot arbitrate. Pass one, or \
             make them agree.",
            ),
        )),
        (Some(x), _) => Ok(Some(x)),
        (None, y) => Ok(y),
    }
}

/// Resolve the tool context from the live process: real env, real cwd, XDG-first config base.
pub fn resolve_context(
    flags: &ContextFlags,
    profile: Option<&Profile>,
) -> Result<ResolvedContext, Refusal> {
                                                                                              
                                                                                   
    #[allow(clippy::disallowed_methods)]
    let cwd = std::env::current_dir().map_err(|e| {
        Refusal::new(
            RefusalId::ContextUnresolvable,
            format!("cannot read the current dir: {e}"),
        )
    })?;
    resolve_context_from(&ContextInputs {
        flags,
        profile,
        env_store: non_empty_var_os(ARTIFACT_STORE_ENV),
        cwd,
        config_base: config_base(),
    })
}

/// One candidate value with its source tier and a human name for the refusal message.
struct Candidate {
    value: PathBuf,
    source: ValueSource,
    /// Names the supplying source in refusals, e.g. "--artifact-store" / "the profile's
    /// `artifact_store`" / "FRUIT_ARTIFACT_STORE" / "the context file's `artifact_store`".
    origin: String,
}

/// Walk the chain for one key: the first present tier wins; an explicit winner is validated
                                                                 
fn pick_explicit(
    candidates: Vec<Option<Candidate>>,
    check: impl Fn(&Path) -> Result<(), String>,
) -> Result<Option<(PathBuf, ValueSource)>, Refusal> {
    match candidates.into_iter().flatten().next() {
        Some(c) => {
            check(&c.value).map_err(|e| {
                Refusal::new(
                    RefusalId::ContextUnresolvable,
                    format!("{} names {}: {e}", c.origin, path_text(&c.value)),
                )
            })?;
            Ok(Some((c.value, c.source)))
        }
        None => Ok(None),
    }
}

/// Resolve from injected inputs (the testable core; [`resolve_context`] is the live binding).
pub fn resolve_context_from(inp: &ContextInputs) -> Result<ResolvedContext, Refusal> {
                                                                                              
    let (file_path, file_present, file): (Option<PathBuf>, bool, ContextFile) =
        match &inp.flags.context_file {
            Some(p) => {
                let abs = absolutize(&inp.cwd, p);
                if !abs.is_file() {
                    return Err(Refusal::new(
                        RefusalId::ContextFileInvalid,
                        format!(
                            "--context names {} which is not a file — the explicitly named \
                             context file must exist (no silent fallback)",
                            path_text(&abs)
                        ),
                    ));
                }
                let parsed = parse_context_file(&abs)?;
                (Some(abs), true, parsed)
            }
            None => match &inp.config_base {
                Some(base) => {
                    let p = default_context_file(base);
                    if p.is_file() {
                        let parsed = parse_context_file(&p)?;
                        (Some(p), true, parsed)
                    } else {
                        (Some(p), false, ContextFile::default())
                    }
                }
                None => (None, false, ContextFile::default()),
            },
        };
    let file_dir = file_path
        .as_ref()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf);
                                                                                         
    let from_file = |v: &Option<Utf8PathBuf>| -> Option<PathBuf> {
        v.as_ref().map(|p| match &file_dir {
            Some(d) if p.is_relative() => d.join(p),
            _ => p.to_path_buf(),
        })
    };
                                                                                           
    let from_profile = |key: &str, v: &Option<PathBuf>| -> Result<Option<PathBuf>, Refusal> {
        match v {
            Some(p) if p.is_relative() => Err(Refusal::new(
                RefusalId::ProfileContextPathRelative,
                format!(
                    "the profile's `{key}` ({}) is relative — profile context paths must be \
                     absolute",
                    path_text(p)
                ),
            )),
            other => Ok(other.clone()),
        }
    };

                          
    let root_flag = inp.flags.repo_root.as_ref().map(|p| Candidate {
        value: absolutize(&inp.cwd, p),
        source: ValueSource::Flag,
        origin: "--repo-root".into(),
    });
    let root_profile = from_profile("repo_root", &inp.profile.and_then(|p| p.repo_root.clone()))?
        .map(|v| Candidate {
            value: v,
            source: ValueSource::Profile,
            origin: "the profile's `repo_root`".into(),
        });
    let root_file = from_file(&file.repo_root).map(|v| Candidate {
        value: v,
        source: ValueSource::File,
        origin: "the context file's `repo_root`".into(),
    });
    let check_root = |p: &Path| -> Result<(), String> {
        if p.join("crates/image-builder").is_dir() {
            Ok(())
        } else {
            Err("not an orchard repo root (./crates/image-builder not found)".into())
        }
    };
    let (repo_root, root_source) =
        match pick_explicit(vec![root_flag, root_profile, root_file], check_root)? {
            Some(win) => win,
            None => {
                                                                                        
                if !inp.cwd.join("crates/image-builder").is_dir() {
                    return Err(Refusal::new(
                        RefusalId::ContextUnresolvable,
                        format!(
                            "{} is not an orchard repo root (./crates/image-builder not found) — \
                             run from the repo root, or pass --repo-root / set `repo_root` in \
                             the context file",
                            path_text(&inp.cwd)
                        ),
                    ));
                }
                (inp.cwd.clone(), ValueSource::CwdDefault)
            }
        };
    let repo_root = utf8_context_path("repo root", root_source, repo_root)?;

                               
    let store_flag = inp.flags.artifact_store.as_ref().map(|p| Candidate {
        value: absolutize(&inp.cwd, p),
        source: ValueSource::Flag,
        origin: "--artifact-store".into(),
    });
    let store_profile = from_profile(
        "artifact_store",
        &inp.profile.and_then(|p| p.artifact_store.clone()),
    )?
    .map(|v| Candidate {
        value: v,
        source: ValueSource::Profile,
        origin: "the profile's `artifact_store`".into(),
    });
    let store_env = inp.env_store.as_ref().map(|p| Candidate {
        value: absolutize(&inp.cwd, p),
        source: ValueSource::Env,
        origin: ARTIFACT_STORE_ENV.into(),
    });
    let store_file = from_file(&file.artifact_store).map(|v| Candidate {
        value: v,
        source: ValueSource::File,
        origin: "the context file's `artifact_store`".into(),
    });
    let check_store = |p: &Path| -> Result<(), String> {
        if p.is_dir() {
            Ok(())
        } else {
            Err("not a directory (the artifact store must exist)".into())
        }
    };
    let (artifact_store, store_source) = match pick_explicit(
        vec![store_flag, store_profile, store_env, store_file],
        check_store,
    )? {
        Some(win) => win,
                                                                                             
                                         
        None => (store_default(&repo_root), ValueSource::CwdDefault),
    };
    let artifact_store = utf8_context_path("artifact store", store_source, artifact_store)?;

                              
    let manifest_flag = inp.flags.repo_manifest.as_ref().map(|p| Candidate {
        value: absolutize(&inp.cwd, p),
        source: ValueSource::Flag,
        origin: "--repo-manifest".into(),
    });
    let manifest_profile = from_profile(
        "repo_manifest",
        &inp.profile.and_then(|p| p.repo_manifest.clone()),
    )?
    .map(|v| Candidate {
        value: v,
        source: ValueSource::Profile,
        origin: "the profile's `repo_manifest`".into(),
    });
    let manifest_file = from_file(&file.repo_manifest).map(|v| Candidate {
        value: v,
        source: ValueSource::File,
        origin: "the context file's `repo_manifest`".into(),
    });
    let check_manifest = |p: &Path| -> Result<(), String> {
        if p.is_file() {
            Ok(())
        } else {
            Err("not a file (the repo manifest must exist)".into())
        }
    };
    let (repo_manifest, manifest_source) = match pick_explicit(
        vec![manifest_flag, manifest_profile, manifest_file],
        check_manifest,
    )? {
        Some(win) => win,
        None => (manifest_default(&repo_root), ValueSource::CwdDefault),
    };
    let repo_manifest = utf8_context_path("repo manifest", manifest_source, repo_manifest)?;

    Ok(ResolvedContext {
        repo_root,
        artifact_store,
        repo_manifest,
        sources: ContextSources {
            repo_root: root_source,
            artifact_store: store_source,
            repo_manifest: manifest_source,
            context_file: file_path.map(|p| (p, file_present)),
        },
    })
}

fn absolutize(cwd: &Path, p: &Path) -> PathBuf {
    if p.is_relative() {
        cwd.join(p)
    } else {
        p.to_path_buf()
    }
}

/// The tool context crosses process boundaries as argv text (`forward_flags`), so each resolved
/// path is UTF-8 or the resolution refuses naming the key, the winning tier and an escaped sample
                                                                                                
/// tier joins a relative value against the file's own directory, whose bytes may not be UTF-8; the
/// flag, env, file and CWD-default tiers are all reachable refusals.
fn utf8_context_path(key: &str, source: ValueSource, p: PathBuf) -> Result<Utf8PathBuf, Refusal> {
    match p.into_os_string().into_string() {
        Ok(s) => Ok(Utf8PathBuf::from(s)),
        Err(os) => Err(Refusal::new(
            RefusalId::ContextNotUtf8,
            format!(
                "the {key} resolved from the {} tier is not UTF-8 text: {}",
                source.label(),
                path_text(Path::new(&os))
            ),
        )),
    }
}

fn parse_context_file(path: &Path) -> Result<ContextFile, Refusal> {
    let s = std::fs::read_to_string(path).map_err(|e| {
        Refusal::new(
            RefusalId::ContextFileInvalid,
            format!("read context file {}: {e}", path_text(path)),
        )
    })?;
    toml::from_str(&s).map_err(|e| {
        Refusal::new(
            RefusalId::ContextFileInvalid,
            format!("context file {}: {e}", path_text(path)),
        )
    })
}

/// Render a byte-domain path as UTF-8 text, or as its whole `escape_ascii` form when it is not UTF-8.
fn path_text(p: &Path) -> String {
    match p.to_str() {
        Some(s) => s.to_string(),
        None => p.as_os_str().as_encoded_bytes().escape_ascii().to_string(),
    }
}

                                                                              
/// `--print-context` and the doctor section.
pub fn render_context(ctx: &ResolvedContext) -> String {
    let file_line = match &ctx.sources.context_file {
        Some((p, true)) => format!("context file: {} (present)", path_text(p)),
        Some((p, false)) => format!("context file: {} (absent)", path_text(p)),
        None => "context file: (no config base)".to_string(),
    };
    format!(
        "context ({file_line})\n  repo_root      = {}  ({})\n  artifact_store = {}  ({})\n  \
         repo_manifest  = {}  ({})\n",
        ctx.repo_root,
        ctx.sources.repo_root.label(),
        ctx.artifact_store,
        ctx.sources.artifact_store.label(),
        ctx.repo_manifest,
        ctx.sources.repo_manifest.label(),
    )
}
