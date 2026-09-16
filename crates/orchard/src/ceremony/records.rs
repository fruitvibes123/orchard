                                                                                                   
//! `$XDG_STATE_HOME/orchard/records/<name>.d/` (default `~/.local/state/orchard/records/`), keyed
//! by the profile and OUTSIDE every ceremony checkout, so a resume reads its own records without
                                                                                               
                                                                                               
                                                               
//! `steps.toml` (step provenance: parameter values, input identities, produced-artifact
//! hashes, the S5 confirmation) and `paths.toml` (per-path TWO-PHASE write records).
//!
//! The classifier constraints, from three falsified prior shapes (do not re-derive them):
//! - Content hashes BEFORE and AFTER a write, bound to the run that took them; a marker's
                                                                                       
//!   finalized post-hash against the CURRENT bytes, so an entry outliving its run cannot relabel
//!   later operator bytes.
//! - In the EXECUTING checkout, absence resolves AMBIGUOUS (interactive gate), never a hard
                                                                                    
                                                                                                 
//!   write and finalize is observable.
//! - SIBLING recognition never consults this per-profile record set — it uses the SHARED
                                                                                    

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::refusal::{
    GitReadFailure, GitReadPurpose, GitRunError, Refusal, RefusalId, TypedCure, encode_owned,
};

/// A declared path name as recorded, carried as a render type so its only human rendering is the
/// escaped `Debug` form of the inner `str` (§2.1). No `Deref<Target = str>`, no `AsRef<Path>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeclaredPathName(String);

impl DeclaredPathName {
    pub fn new(s: impl Into<String>) -> Self {
        DeclaredPathName(s.into())
    }

    /// The inner path for an exact-string comparison, the index-info record, a git-free lookup. Not
    /// a human render (§2.1: the only human render is `Display`).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DeclaredPathName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

pub(in crate::ceremony) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

                                                                                         
/// run id, its post state (the bytes+exec the classifier authorized), and the current byte length
/// the record view renders. Carried from classify time to the commit chokepoint, so a consent-window
/// change lands as a landed-vs-witness mismatch rather than a re-read that would move with it.
pub struct PathWitness {
    pub run_id: String,
    pub post: ContentState,
    pub len: Option<u64>,
}

/// The v2 witness schema version stamped into `paths.toml`; a records dir carrying any other
                                           
const RECORDS_SCHEMA_VERSION: u32 = 2;

/// The content state of a declared path at hash time: recorded absence, or a hash plus the
/// effective executable bit (the witness binds bytes AND the exec bit, D-R14-D). Equality includes
/// `exec`, so a mode-only flip at a recorded path no longer matches its record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentState {
    Absent,
    Sha256 { sha256: String, exec: bool },
}

/// A regular file's reading through one handle: bytes hash, byte length, and the raw fd mode.
struct FileReading {
    sha256: String,
    len: u64,
    fd_mode: u32,
}

/// The inode class of a declared path that is not a readable regular file. Selects the
/// operator cure at the recording sites by total match (decision 2026-09-01-condition-typed-cures).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeClass {
    Symlink,
    Directory,
    /// FIFO, socket, block or character device.
    Special,
    /// The path could not be opened or read (an I/O error, not a type refusal).
    Io,
}

impl TypedCure for InodeClass {
    fn cure(&self) -> String {
        match self {
            InodeClass::Symlink => {
                "replace the symlink with the regular file it points at, or remove it, then re-run"
            }
            InodeClass::Directory => {
                "the declared path is a file; remove the directory or restore the file, then re-run"
            }
            InodeClass::Special => "remove the special file at the declared path, then re-run",
            InodeClass::Io => {
                "the path could not be read; check permissions and the filesystem, then re-run"
            }
        }
        .to_string()
    }
}

/// One O_NOFOLLOW handle's verdict for a declared path. A non-regular file (a symlink — dangling
/// included — directory, FIFO, socket, device) is `NonRegular`, never `Absent`: the declared-path
/// content domain is regular files. The `InodeClass` selects the cure; the string names the type
/// in the detail.
enum ContentProbe {
    Absent,
    Regular(FileReading),
    NonRegular(InodeClass, String),
}

/// Probe a path through ONE descriptor: open `O_NOFOLLOW | O_NONBLOCK`, `fstat` the fd, read the
/// fd. No second path resolution between the type check and the read. O_NOFOLLOW makes a symlink
/// (dangling or not) an `ELOOP` open error rather than a followed read; O_NONBLOCK keeps a FIFO
/// from blocking the open. `NotFound` is the only `Absent`.
fn probe_content(path: &Path) -> std::io::Result<ContentProbe> {
    use std::io::Read as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ContentProbe::Absent),
        Err(e) => {
            #[cfg(unix)]
            if e.raw_os_error() == Some(libc::ELOOP) {
                return Ok(ContentProbe::NonRegular(
                    InodeClass::Symlink,
                    "symlink".to_string(),
                ));
            }
            return Err(e);
        }
    };
    let meta = f.metadata()?;
    let ft = meta.file_type();
    if !ft.is_file() {
        let (class, name) = file_type_class_and_name(&ft);
        return Ok(ContentProbe::NonRegular(class, name));
    }
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    #[cfg(unix)]
    let fd_mode = {
        use std::os::unix::fs::MetadataExt as _;
        meta.mode()
    };
    #[cfg(not(unix))]
    let fd_mode = 0u32;
    Ok(ContentProbe::Regular(FileReading {
        sha256: sha256_hex(&bytes),
        len: bytes.len() as u64,
        fd_mode,
    }))
}

#[cfg(unix)]
fn file_type_class_and_name(ft: &std::fs::FileType) -> (InodeClass, String) {
    use std::os::unix::fs::FileTypeExt as _;
    let (class, name) = if ft.is_dir() {
        (InodeClass::Directory, "directory")
    } else if ft.is_symlink() {
        (InodeClass::Symlink, "symlink")
    } else if ft.is_fifo() {
        (InodeClass::Special, "FIFO")
    } else if ft.is_socket() {
        (InodeClass::Special, "socket")
    } else if ft.is_block_device() {
        (InodeClass::Special, "block device")
    } else if ft.is_char_device() {
        (InodeClass::Special, "character device")
    } else {
        (InodeClass::Special, "non-regular file")
    };
    (class, name.to_string())
}

#[cfg(not(unix))]
fn file_type_class_and_name(_ft: &std::fs::FileType) -> (InodeClass, String) {
    (InodeClass::Special, "non-regular file".to_string())
}

/// The §3.3 gate re-read's verdict for a declared path: the recorded bytes and the `ContentState`
/// to compare against the witness, or a recorded absence.
pub(in crate::ceremony) enum GateContent {
    Present { bytes: Vec<u8>, state: ContentState },
    Absent,
}

/// One O_NOFOLLOW handle's reading keeping the bytes (for `git hash-object`). The §3.3 second read;
/// [`probe_content`] discards the bytes because classification needs only the hash.
enum GateProbe {
    Absent,
    Regular(Vec<u8>, u32),
    NonRegular(InodeClass, String),
}

/// [`probe_content`]'s shape, keeping the read bytes. Open `O_NOFOLLOW | O_NONBLOCK`, `fstat`, read.
fn probe_content_keeping_bytes(path: &Path) -> std::io::Result<GateProbe> {
    use std::io::Read as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(GateProbe::Absent),
        Err(e) => {
            #[cfg(unix)]
            if e.raw_os_error() == Some(libc::ELOOP) {
                return Ok(GateProbe::NonRegular(
                    InodeClass::Symlink,
                    "symlink".to_string(),
                ));
            }
            return Err(e);
        }
    };
    let meta = f.metadata()?;
    let ft = meta.file_type();
    if !ft.is_file() {
        let (class, name) = file_type_class_and_name(&ft);
        return Ok(GateProbe::NonRegular(class, name));
    }
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    #[cfg(unix)]
    let fd_mode = {
        use std::os::unix::fs::MetadataExt as _;
        meta.mode()
    };
    #[cfg(not(unix))]
    let fd_mode = 0u32;
    Ok(GateProbe::Regular(bytes, fd_mode))
}

/// The whole git index as an exec oracle (§3.10): the stage-0 mode per path, and the set of paths
/// carrying a non-zero-stage row (unmerged). Read whole (`git ls-files -s -z`, no pathspec), so no
                                                                                         
/// repo-relative path with an exact-string lookup.
pub(in crate::ceremony) struct IndexListing {
    stage0_mode: BTreeMap<String, String>,
    unmerged: BTreeSet<String>,
}

/// `git ls-files -s -z` through the §3.11 command builder, parsed on the first tab. A spawn
/// failure, a non-zero exit, or output outside UTF-8 is the typed `GitRunError`.
fn read_index_listing(repo_root: &Path) -> Result<IndexListing, GitRunError> {
    let text = super::gate_commit::Git::new(repo_root)
        .args(&["ls-files", "-s", "-z"])
        .text("ls-files -s -z")?;
    let mut stage0_mode = BTreeMap::new();
    let mut unmerged = BTreeSet::new();
    for rec in text.split('\0').filter(|r| !r.is_empty()) {
        let Some((meta, path)) = rec.split_once('\t') else {
            continue;
        };
        let mut f = meta.split(' ');
        let mode = f.next().unwrap_or("");
        let _oid = f.next();
        let stage = f.next().unwrap_or("");
        if stage == "0" {
            stage0_mode.insert(path.to_string(), mode.to_string());
        } else {
            unmerged.insert(path.to_string());
        }
    }
    Ok(IndexListing {
        stage0_mode,
        unmerged,
    })
}

/// The git-index exec bit when `core.fileMode=false` (git ignores the worktree bit, so the recorded
                                                                                                  
/// No index row (untracked, an unreadable git state, or only non-zero stages) is false.
fn index_exec(repo_root: &Path, rel: &str) -> bool {
    read_index_listing(repo_root)
        .ok()
        .and_then(|l| l.stage0_mode.get(rel).map(|m| m == "100755"))
        .unwrap_or(false)
}

/// An owed path carrying a non-zero index stage and no stage-0 entry refuses pre-prompt (§3.10):
/// an unresolved merge conflict at a path the gate would commit. §3.1 does not cover this state (a
/// squash merge, a stash apply and `checkout -m` leave stages 1-3 with none of the markers).
pub(in crate::ceremony) fn refuse_unmerged_owed_paths(
    repo_root: &Path,
    owed: &[&str],
) -> Result<(), Refusal> {
    let listing = match read_index_listing(repo_root) {
        Ok(l) => l,
        Err(e) => {
            let detail = format!(
                "cannot read the index of {} for the commit gate's unmerged-path check: {e}",
                repo_root.display()
            );
            return Err(Refusal::typed(
                RefusalId::GitStateUnreadable,
                detail,
                &GitReadFailure {
                    purpose: GitReadPurpose::CommitGate,
                    outcome: e,
                },
            ));
        }
    };
    for p in owed {
        if listing.unmerged.contains(*p) && !listing.stage0_mode.contains_key(*p) {
            return Err(Refusal::new(
                RefusalId::UnmergedOwedPath,
                format!(
                    "declared path {p:?} is unmerged (the index carries conflict stages and no \
                     stage-0 entry); the gate would commit an unresolved conflict"
                ),
            ));
        }
    }
    Ok(())
}

/// `core.fileMode` for a checkout, defaulting true where git cannot answer.
fn read_core_file_mode(repo_root: &Path) -> bool {
    match super::gate_commit::Git::new(repo_root)
        .args(&["config", "--type=bool", "--default=true", "core.fileMode"])
        .text_or_exit("config core.fileMode")
    {
        Ok(super::gate_commit::GitReply::Ok(v)) => v.trim() != "false",
        _ => true,
    }
}

/// One two-phase path record (an entry in `paths.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRecord {
    pub path: String,
    pub run_id: String,
    pub pre: ContentState,
    /// Absent while the write is in flight; a crash leaves it absent ⇒ Interrupted.
    pub post: Option<ContentState>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathsFile {
    #[serde(rename = "schema-version", default)]
    schema_version: u32,
    #[serde(default)]
    record: Vec<PathRecord>,
}

                                                                                 
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepRecord {
    pub step: String,
    pub run_id: String,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    #[serde(default)]
    pub input_identities: BTreeMap<String, String>,
    /// Produced artifact name → where it landed and what the producer declared it hashes to.
    #[serde(default)]
    pub produced: BTreeMap<String, ProducedArtifact>,
}

                                                                                           
/// recorded path — the claim is presence, not that the bytes re-verify); `sha256` is the
                                                                                        
/// the path rather than re-deriving it keeps one home for the naming convention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducedArtifact {
    pub path: String,
    pub sha256: String,
}

/// The S5 confirmation (written by the runner at probe-accept, Task 6; closes D19's
/// unnamed-producer gap): the quiescent handoff tree hash bound to the operator-supplied ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S5Confirmation {
    pub tree_hash: String,
    pub tenant_source_ref: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StepsFile {
    #[serde(default)]
    step: Vec<StepRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    s5_confirmation: Option<S5Confirmation>,
}

/// The run records of one box profile, loaded whole and persisted on every
/// mutation (small files). Persisted ATOMICALLY (temp + sync + rename, R7 I-2): the two-phase
/// design's observability property lives in these bytes, so a crash mid-persist must never leave
/// a truncated file.
                                                                               
/// (stable, reused across handles and re-opens); a monotonic in-process counter, so a token
/// minted by one handle cannot finalize against a DIFFERENT handle — the re-open / second-handle
/// case R10 measured, where the token's `run_id` still equalled the re-loaded entry's `run_id`.
static NEXT_SET_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[derive(Debug)]
pub struct RunRecords {
    dir: PathBuf,
    run_id: String,
                                                                                
    /// re-checked at finalize.
    set_id: u64,
    steps: StepsFile,
    paths: PathsFile,
                                                                                    
    /// `persist` re-reads the file and REFUSES if it changed underneath this handle, so a second
    /// live handle's wholesale rewrite can no longer silently drop this handle's rows.
    disk: BTreeMap<String, String>,
    /// The executing checkout, bound in production by [`RunRecords::with_checkout`]; decides whether
                                                                                      
    /// unit contexts ⇒ the worktree bit.
    checkout: Option<CheckoutMode>,
}

#[derive(Debug)]
struct CheckoutMode {
    repo_root: PathBuf,
    file_mode: bool,
}

/// An in-flight two-phase token (returned by [`open_path_record`]; consumed by
                                                                                   
/// check compares the token's run to the entry's run, a real cross-run identity check — comparing
/// the entry against the receiving set's own `run_id` is a tautology when the set opened the entry.
#[derive(Debug)]
pub struct OpenToken {
    path: PathBuf,
    index: usize,
    run_id: String,
                                                                                       
    /// SAME live handle, so a token from a re-opened or second handle refuses even when its
    /// `run_id` still equals the re-loaded entry's.
    set_id: u64,
}

impl RunRecords {
    /// Open (or create) the operator-side records dir for a profile: `boxes/<name>.toml` →
    /// `<records-root>/<name>.d/` ([`records_state_root`]), OUTSIDE the ceremony checkout.
    pub fn open(profile_path: &Path, run_id: impl Into<String>) -> Result<Self, Refusal> {
        let dir = records_dir_of(&records_state_root(), profile_path);
        Self::open_dir(&dir, run_id)
    }

    pub fn open_dir(dir: &Path, run_id: impl Into<String>) -> Result<Self, Refusal> {
        let load = |name: &str| -> Result<String, Refusal> {
            match std::fs::read_to_string(dir.join(name)) {
                Ok(s) => Ok(s),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
                Err(e) => Err(Refusal::new(
                    RefusalId::RecordsUnreadable,
                    format!("read {}: {e}", dir.join(name).display()),
                )
                .with_cure_extra(records_dir_cure(dir))),
            }
        };
        let parse_err = |name: &str, e: toml::de::Error| {
            Refusal::new(
                RefusalId::RecordsUnreadable,
                format!("parse {}: {e}", dir.join(name).display()),
            )
            .with_cure_extra(records_dir_cure(dir))
        };
        let steps_raw = load("steps.toml")?;
        let paths_raw = load("paths.toml")?;
        let steps: StepsFile =
            toml::from_str(&steps_raw).map_err(|e| parse_err("steps.toml", e))?;
        let mut paths: PathsFile =
            toml::from_str(&paths_raw).map_err(|e| parse_err("paths.toml", e))?;
                                                                                                  
                                                                                                   
                                                                            
        if !paths_raw.trim().is_empty() && paths.schema_version != RECORDS_SCHEMA_VERSION {
            return Err(Refusal::new(
                RefusalId::RecordsSchemaOutdated,
                format!(
                    "the run records at {} are schema-version {} (this orchard writes {})",
                    dir.display(),
                    paths.schema_version,
                    RECORDS_SCHEMA_VERSION
                ),
            )
            .with_cure_extra(records_dir_cure(dir)));
        }
        paths.schema_version = RECORDS_SCHEMA_VERSION;
                                                                                             
                                                                                                   
                                                
        let mut disk = BTreeMap::new();
        disk.insert("steps.toml".to_string(), steps_raw);
        disk.insert("paths.toml".to_string(), paths_raw);
        Ok(RunRecords {
            dir: dir.to_path_buf(),
            run_id: run_id.into(),
            set_id: NEXT_SET_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            steps,
            paths,
            disk,
            checkout: None,
        })
    }

    /// Bind the executing checkout so the exec witness reads git's index mode when
                                                                                         
    /// unset and read the worktree bit.
    pub fn with_checkout(mut self, repo_root: &Path) -> Self {
        let file_mode = read_core_file_mode(repo_root);
        self.checkout = Some(CheckoutMode {
            repo_root: repo_root.to_path_buf(),
            file_mode,
        });
        self
    }

    /// The `(ContentState, Option<len>)` for a declared path through one O_NOFOLLOW handle. A
    /// non-regular or unreadable path is an `Err` carrying its [`InodeClass`] (for the cure) and a
    /// detail string; the call sites map that `Err` per surface.
    fn content_reading(
        &self,
        path: &Path,
    ) -> Result<(ContentState, Option<u64>), (InodeClass, String)> {
        let probe = probe_content(path).map_err(|e| {
            (
                InodeClass::Io,
                format!("{} could not be read: {e}", path.display()),
            )
        })?;
        match probe {
            ContentProbe::Absent => Ok((ContentState::Absent, None)),
            ContentProbe::Regular(r) => {
                let exec = self.effective_exec(path, r.fd_mode);
                Ok((
                    ContentState::Sha256 {
                        sha256: r.sha256,
                        exec,
                    },
                    Some(r.len),
                ))
            }
            ContentProbe::NonRegular(class, kind) => Err((
                class,
                format!(
                    "{} is a {kind}, not a regular file (the declared-path content domain is \
                     regular files)",
                    path.display()
                ),
            )),
        }
    }

    fn effective_exec(&self, path: &Path, fd_mode: u32) -> bool {
        match &self.checkout {
            Some(c) if !c.file_mode => {
                let rel = path
                    .strip_prefix(&c.repo_root)
                    .map(|r| r.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| path.display().to_string());
                index_exec(&c.repo_root, &rel)
            }
            _ => fd_mode & 0o111 != 0,
        }
    }

    /// The §3.3 gate re-read of a declared path: the raw bytes (for `hash-object`) and the
    /// `ContentState` the construction compares against the witness, through one O_NOFOLLOW handle.
    /// A second read of the path, separate from classification (the §3.3 trade: no owed path's
    /// bytes are held across the gate).
    pub(in crate::ceremony) fn gate_content(
        &self,
        path: &Path,
    ) -> Result<GateContent, (InodeClass, String)> {
        let probe = probe_content_keeping_bytes(path).map_err(|e| {
            (
                InodeClass::Io,
                format!("{} could not be read: {e}", path.display()),
            )
        })?;
        match probe {
            GateProbe::Absent => Ok(GateContent::Absent),
            GateProbe::Regular(bytes, fd_mode) => {
                let exec = self.effective_exec(path, fd_mode);
                let sha256 = sha256_hex(&bytes);
                Ok(GateContent::Present {
                    bytes,
                    state: ContentState::Sha256 { sha256, exec },
                })
            }
            GateProbe::NonRegular(class, kind) => Err((
                class,
                format!(
                    "{} is a {kind}, not a regular file (the declared-path content domain is \
                     regular files)",
                    path.display()
                ),
            )),
        }
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn persist(&mut self) -> Result<(), Refusal> {
        std::fs::create_dir_all(&self.dir).map_err(|e| {
            Refusal::new(
                RefusalId::RecordsUnwritable,
                format!("create {}: {e}", self.dir.display()),
            )
            .with_cure_extra(records_dir_cure(&self.dir))
        })?;
                                                                                                
                                                                                                 
                                                                                           
                                                                                     
        let dir = self.dir.clone();
        let write = |name: &str,
                     body: Result<String, Refusal>,
                     last_seen: &str|
         -> Result<String, Refusal> {
            let final_path = dir.join(name);
            let body = body?;
                                                                                                   
                                                                                                  
                                                                                                   
                                                                                            
                                                                         
            let current = match std::fs::read_to_string(&final_path) {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => {
                    return Err(Refusal::new(
                        RefusalId::RecordsUnwritable,
                        format!("re-read {} before write: {e}", final_path.display()),
                    )
                    .with_cure_extra(records_dir_cure(&dir)));
                }
            };
            if current != last_seen {
                return Err(Refusal::new(
                    RefusalId::InternalInvariantViolated,
                    format!(
                        "{} changed underneath this run-records handle (a second live handle on \
                         the same records dir) — refusing to overwrite it",
                        final_path.display()
                    ),
                ));
            }
            let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
                                                                                               
                                                                                                     
                                                         
            let _ = std::fs::remove_file(&tmp);
            {
                use std::io::Write as _;
                let refuse_tmp = |op: &str, e: std::io::Error| {
                    Refusal::new(
                        RefusalId::RecordsUnwritable,
                        format!("{op} {}: {e}", tmp.display()),
                    )
                    .with_cure_extra(records_dir_cure(&dir))
                };
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp)
                    .map_err(|e| refuse_tmp("open", e))?;
                f.write_all(body.as_bytes())
                    .and_then(|()| f.sync_all())
                    .map_err(|e| {
                        let _ = std::fs::remove_file(&tmp);
                        refuse_tmp("write", e)
                    })?;
            }
            std::fs::rename(&tmp, &final_path).map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                Refusal::new(
                    RefusalId::RecordsUnwritable,
                    format!(
                        "rename {} into {}: {e}",
                        tmp.display(),
                        final_path.display()
                    ),
                )
                .with_cure_extra(records_dir_cure(&dir))
            })?;
            Ok(body)
        };
        let steps_last = self.disk.get("steps.toml").cloned().unwrap_or_default();
        let steps_written = write(
            "steps.toml",
            encode_owned(&self.steps, dir.join("steps.toml").display()),
            &steps_last,
        )?;
        self.disk.insert("steps.toml".to_string(), steps_written);
        let paths_last = self.disk.get("paths.toml").cloned().unwrap_or_default();
        let paths_written = write(
            "paths.toml",
            encode_owned(&self.paths, dir.join("paths.toml").display()),
            &paths_last,
        )?;
        self.disk.insert("paths.toml".to_string(), paths_written);
        Ok(())
    }

    /// Record a completed step's provenance (replacing any earlier record of the same step).
    pub fn record_step(&mut self, rec: StepRecord) -> Result<(), Refusal> {
        self.steps.step.retain(|s| s.step != rec.step);
        self.steps.step.push(rec);
        self.persist()
    }

    pub fn step_record(&self, step: &str) -> Option<&StepRecord> {
        self.steps.step.iter().find(|s| s.step == step)
    }

    /// The S5 confirmation (runner-written at probe-accept).
    pub fn record_s5_confirmation(&mut self, c: S5Confirmation) -> Result<(), Refusal> {
        self.steps.s5_confirmation = Some(c);
        self.persist()
    }

    pub fn s5_confirmation(&self) -> Option<&S5Confirmation> {
        self.steps.s5_confirmation.as_ref()
    }
}

/// A fresh run id: the wall-clock start plus process id. Records are keyed by STEP, so the run
/// id is provenance (which run wrote this entry) and the two-phase token's cross-run identity
/// check, never a lookup key — it only has to differ between concurrent or successive runs.
pub fn mint_run_id() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}-{}", std::process::id())
}

/// The records-base override, for hermetic tests and operators who relocate state
/// (`ORCHARD_STATE_DIR`). Mirrors lock.rs's `ORCHARD_LOCK_DIR` override discipline.
pub const STATE_DIR_ENV: &str = "ORCHARD_STATE_DIR";

/// The operator-side records root: `$ORCHARD_STATE_DIR/records` when set, else
/// `$XDG_STATE_HOME/orchard/records`, else `$HOME/.local/state/orchard/records`. Per-USER and
                                                                                           
                                                                       
                                                                                               
/// state, the lock is a per-host mutex, so they do not share a root.
pub fn records_state_root() -> PathBuf {
    records_state_root_from(
        std::env::var_os(STATE_DIR_ENV).filter(|v| !v.is_empty()),
        std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()),
        std::env::var_os("HOME").filter(|v| !v.is_empty()),
    )
}

/// The testable core: reads no env, so the default provably does not depend on ambient state
                                                           
fn records_state_root_from(
    state_override: Option<std::ffi::OsString>,
    xdg_state_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> PathBuf {
    if let Some(dir) = state_override {
        return PathBuf::from(dir).join("records");
    }
    let base = xdg_state_home
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home.map(|h| PathBuf::from(h).join(".local").join("state")))
        .unwrap_or_else(|| PathBuf::from(".local").join("state"));
    base.join("orchard").join("records")
}

/// The operator-facing records-dir specific: the real resolved dir, so the cure names
/// where the records live rather than a static `boxes/<name>.d/` convention that drifted when the
                                                                                            
/// at open; the template holds no path.
pub(in crate::ceremony) fn records_dir_cure(dir: &Path) -> String {
    format!("the run records dir is {}", dir.display())
}

                                                                                                 
/// operator-side per [`records_state_root`]).
pub fn records_dir_of(records_root: &Path, profile_path: &Path) -> PathBuf {
    let stem = profile_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("box");
    records_root.join(format!("{stem}.d"))
}

/// Phase 1 of a declared-path write: hash the PRE state, bind it to this run, and persist the
/// open entry BEFORE the write happens (a crash before finalize is then observable as
/// Interrupted).
pub fn open_path_record(rec: &mut RunRecords, path: &Path) -> Result<OpenToken, Refusal> {
    let (pre, _) = rec.content_reading(path).map_err(|(class, detail)| {
        Refusal::typed(
            RefusalId::DeclaredPathUnhashable,
            format!("hash pre-state of {}: {detail}", path.display()),
            &class,
        )
    })?;
    rec.paths.record.push(PathRecord {
        path: path.display().to_string(),
        run_id: rec.run_id.clone(),
        pre,
        post: None,
    });
    rec.persist()?;
    Ok(OpenToken {
        path: path.to_path_buf(),
        index: rec.paths.record.len() - 1,
        run_id: rec.run_id.clone(),
        set_id: rec.set_id,
    })
}

/// Phase 2: hash the POST state and finalize the entry. The token is validated by IDENTITY (the
/// minting HANDLE's `set_id` + path + the token's run id + still-open), not by bare index
                                                                          
/// second handle, or another run — refuses instead of stamping this run's post-hash from bytes a
/// later moment wrote. The `set_id` is the load-bearing predicate; the run/path checks stay as
/// defence in depth (a same-handle token cannot mismatch them).
pub fn finalize_path_record(rec: &mut RunRecords, tok: OpenToken) -> Result<(), Refusal> {
                                                                                               
                                                                                           
    if tok.set_id != rec.set_id {
        return Err(Refusal::new(
            RefusalId::InternalInvariantViolated,
            format!(
                "finalize token was minted by a different run-records handle (token set={}, this \
                 handle set={}) — a token only finalizes against the handle that opened it; re-opening the records dir mints a new handle",
                tok.set_id, rec.set_id
            ),
        ));
    }
    let (post, _) = rec.content_reading(&tok.path).map_err(|(class, detail)| {
        Refusal::typed(
            RefusalId::DeclaredPathUnhashable,
            format!("hash post-state of {}: {detail}", tok.path.display()),
            &class,
        )
    })?;
    let want_path = tok.path.display().to_string();
    let entry = rec.paths.record.get_mut(tok.index).ok_or_else(|| {
        Refusal::new(
            RefusalId::InternalInvariantViolated,
            format!("open token for {} has no entry", tok.path.display()),
        )
    })?;
    if entry.path != want_path || entry.run_id != tok.run_id || entry.post.is_some() {
        return Err(Refusal::new(
            RefusalId::InternalInvariantViolated,
            format!(
                "finalize token does not identify an open entry it minted (token path={:?} \
                 run={:?}; entry path={:?} run={:?} already_finalized={}) — the token was minted \
                 against a different run or record set",
                want_path,
                tok.run_id,
                entry.path,
                entry.run_id,
                entry.post.is_some()
            ),
        ));
    }
    entry.post = Some(post);
    rec.persist()
}

/// Record a write the runner observed only AFTER it happened, with the pre-state supplied by the
/// caller (from git HEAD). The two-phase form ([`open_path_record`] + [`finalize_path_record`])
/// is what makes an interruption observable, and it is used wherever the runner can name the
/// path BEFORE the step. It cannot for a DIRECTORY-shaped declared write (`vendor/`): which files
/// a re-vendor touches is known only afterwards. Those get a completed entry here, so a later run
/// can still tell ceremony output from operator work; the cost, stated: an interrupted
/// directory-tree write leaves no entry at all and classifies `Ambiguous`, which routes to the
/// same interactive gate `Interrupted` does.
pub fn record_completed_write(
    rec: &mut RunRecords,
    path: &Path,
    pre: ContentState,
) -> Result<(), Refusal> {
    let (post, _) = rec.content_reading(path).map_err(|(class, detail)| {
        Refusal::typed(
            RefusalId::DeclaredPathUnhashable,
            format!("hash post-state of {}: {detail}", path.display()),
            &class,
        )
    })?;
    rec.paths.record.push(PathRecord {
        path: path.display().to_string(),
        run_id: rec.run_id.clone(),
        pre,
        post: Some(post),
    });
    rec.persist()
}

/// The content state of a path AT GIT HEAD (the pre-state for a write the runner names only
/// afterwards). A path absent from HEAD — an untracked file the step created — is `Absent`.
pub fn head_content_state(repo_root: &Path, rel: &str) -> ContentState {
    match super::gate_commit::Git::new(repo_root)
        .args(&["show", &format!("HEAD:{rel}")])
        .content_or_exit("show HEAD:<rel>")
    {
        Ok(super::gate_commit::GitReply::Ok(bytes)) => ContentState::Sha256 {
            sha256: sha256_hex(&bytes),
            exec: head_exec(repo_root, rel),
        },
        _ => ContentState::Absent,
    }
}

/// The exec bit at HEAD for a recording pre-state (§3.10): the whole tree (`git ls-tree -r -z
/// HEAD`) read through the §3.11 builder with no pathspec, keyed by the repo-relative `rel` with
                                                                               
fn head_exec(repo_root: &Path, rel: &str) -> bool {
    read_head_exec_set(repo_root)
        .map(|s| s.contains(rel))
        .unwrap_or(false)
}

/// The set of repo-relative paths at `100755` in HEAD's tree. `None` on a spawn failure, a
/// non-zero exit, or output outside UTF-8.
fn read_head_exec_set(repo_root: &Path) -> Option<BTreeSet<String>> {
    let text = super::gate_commit::Git::new(repo_root)
        .args(&["ls-tree", "-r", "-z", "HEAD"])
        .text("ls-tree -r -z HEAD")
        .ok()?;
    let mut set = BTreeSet::new();
    for rec in text.split('\0').filter(|r| !r.is_empty()) {
        let Some((meta, path)) = rec.split_once('\t') else {
            continue;
        };
        if meta.split(' ').next() == Some("100755") {
            set.insert(path.to_string());
        }
    }
    Some(set)
}

                                            
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirtClass {
    /// The current bytes equal a FINALIZED record from THIS run: ceremony-recorded content
    /// (headless-committable under the forwarded token).
    CleanOrRecorded,
    /// The current bytes equal a FINALIZED record from a DIFFERENT run: content known and clean,
    /// from a prior run; commits under its own attribution heading, never under this run's
        
    PriorRunRecorded,
    /// No record speaks for the current bytes (absence, or bytes differing from every finalized
                                                                                                  
    /// external cure, never a prompt.
    Ambiguous,
    /// An open-without-finalize entry exists for the path (killed mid-step): stops every regime with
                                                                                  
    Interrupted,
}

impl DirtClass {
    /// The classes in commit-message section order.
    pub const ALL: [DirtClass; 4] = [
        DirtClass::CleanOrRecorded,
        DirtClass::PriorRunRecorded,
        DirtClass::Interrupted,
        DirtClass::Ambiguous,
    ];

    /// Whether the run records speak for these bytes: a finalized post-hash equals the current
                                                                        
    /// speakability here to compile.
    pub fn speakable(self) -> bool {
        match self {
            DirtClass::CleanOrRecorded | DirtClass::PriorRunRecorded => true,
            DirtClass::Ambiguous | DirtClass::Interrupted => false,
        }
    }

    /// Commit-message section order. A new class must decide its section here to compile.
    pub fn section_order(self) -> u8 {
        match self {
            DirtClass::CleanOrRecorded => 0,
            DirtClass::PriorRunRecorded => 1,
            DirtClass::Interrupted => 2,
            DirtClass::Ambiguous => 3,
        }
    }

    /// A dirty class's cause phrase, rendered by two consumers: the headless-stop sentence for
                                                                                                 
    /// must decide its phrase here to compile.
    pub fn cause_phrase(self) -> &'static str {
        match self {
            DirtClass::CleanOrRecorded => "recorded by this run",
            DirtClass::PriorRunRecorded => "recorded by a prior run",
            DirtClass::Ambiguous => "unrecorded",
            DirtClass::Interrupted => "a prior run interrupted mid-write",
        }
    }

                                                                                               
    /// class (decision 2026-09-01-condition-typed-cures). A new class must choose its phrase here
    /// to compile; the speakable classes never reach this stop.
    pub fn unspeakable_cure_phrase(self) -> &'static str {
        match self {
            DirtClass::Ambiguous | DirtClass::CleanOrRecorded | DirtClass::PriorRunRecorded => {
                "settle or commit the named path(s) yourself, then re-run"
            }
            DirtClass::Interrupted => {
                "restore or settle the interrupted write at the named path(s) (the re-executed \
                 step re-writes and finalizes), then re-run"
            }
        }
    }
}

/// Classify DIRTY content at a declared executing-checkout path (plan-inputs §Records). The
/// verdict comes from the LATEST entry for the path (records append chronologically), NOT an
                                                                                                 
/// path forever, so a later CLEAN finalized write could never settle it). Rule:
                                                                           
/// - current bytes equal a finalized post-hash from THIS run ⇒ CleanOrRecorded;
                                                                                      
/// - otherwise (no entry, or current bytes match no finalized post-hash) ⇒ Ambiguous.
///
/// A marker never relabels later operator bytes: recorded-ness is decided by comparing a
                                                                                       
/// make foreign bytes CleanOrRecorded. Attribution (which run wrote the bytes) is `run_id`-scoped;
/// safety (torn vs clean vs unknown) is decided across runs (decision 2026-08-28-guided-ceremony-r8-axis-redesigns).
pub fn classify_executing_dirt(rec: &RunRecords, path: &Path) -> DirtClass {
    classify_and_witness(rec, path).0
}

                                                                                     
/// `content_reading`, so the rendered class and the collected witness cannot disagree across a
/// consent-window write. A witness exists exactly for the speakable classes (a finalized record
/// speaks for the current bytes). [`classify_executing_dirt`] is this function's class alone.
pub fn classify_and_witness(rec: &RunRecords, path: &Path) -> (DirtClass, Option<PathWitness>) {
    let key = path.display().to_string();
    let latest_unfinalized = rec
        .paths
        .record
        .iter()
        .rev()
        .find(|r| r.path == key)
        .is_some_and(|r| r.post.is_none());
    if latest_unfinalized {
        return (DirtClass::Interrupted, None);
    }
                                                                           
    let Ok((current, len)) = rec.content_reading(path) else {
        return (DirtClass::Ambiguous, None);
    };
    match verified_record(rec, &key, &current) {
        Some(r) => {
            let class = if r.run_id == rec.run_id() {
                DirtClass::CleanOrRecorded
            } else {
                DirtClass::PriorRunRecorded
            };
            let witness = PathWitness {
                run_id: r.run_id.clone(),
                post: current,
                len,
            };
            (class, Some(witness))
        }
        None => (DirtClass::Ambiguous, None),
    }
}

                                                                                    
/// finalized post-match. This run's entries are the newest for the path, so a this-run match wins
/// (`CleanOrRecorded`) over a prior-run one. `current` carries the exec bit, so a mode-only flip at
/// a recorded path matches no record. One home for the classifier and the record view.
pub(in crate::ceremony) fn verified_record<'a>(
    rec: &'a RunRecords,
    path_key: &str,
    current: &ContentState,
) -> Option<&'a PathRecord> {
    rec.paths
        .record
        .iter()
        .rev()
        .find(|r| r.path == path_key && r.post.as_ref() == Some(current))
}

/// The FLAT `published-pins.toml` schema a publishing repo commits (`schema-version` +
/// `[artifacts] key = "sha"`), grocer's output (`crates/grocer/src/publish.rs`) and the shape
/// image-builder's §3a-1 provenance leg reads (`crates/image-builder/src/provenance.rs`).
                                                                                         
/// the file with the wrong (consume-pins) parser, so recognition was constant-false against a
/// real `published-pins.toml`. `deny_unknown_fields` mirrors the provenance reader's discipline.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishedPins {
    #[serde(rename = "schema-version", default)]
    _schema_version: Option<u32>,
    #[serde(default)]
    artifacts: BTreeMap<String, String>,
}

                                                                                               
/// the SHARED content-addressed store the same publish wrote, never the per-profile records: the
/// file is read as the flat published-pins map and every pinned artifact must verify against the
/// store (`fetch_verified` re-hashes on every path). Any miss ⇒ unrecognized (fail closed).
pub fn sibling_output_recognized(store_path: &Path, sibling_file: &Path) -> bool {
    use recipes_image_builder::artifact_store::{ArtifactStore, DirStore};
    let Ok(text) = std::fs::read_to_string(sibling_file) else {
        return false;
    };
    let Ok(pins) = toml::from_str::<PublishedPins>(&text) else {
        return false;
    };
    if pins.artifacts.is_empty() {
        return false;
    }
    let store = DirStore::new(store_path);
    pins.artifacts
        .iter()
        .all(|(key, sha)| store.fetch_verified(key, sha).is_ok())
}

                                                                                                  
/// records dir under `records_root` (in production, [`records_state_root`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxEntry {
    pub name: String,
    pub profile: PathBuf,
    pub records_dir: Option<PathBuf>,
}

pub fn enumerate_boxes(boxes_dir: &Path, records_root: &Path) -> Vec<BoxEntry> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(boxes_dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("toml")
            && let Some(stem) = p.file_stem().and_then(|s| s.to_str())
        {
            let d = records_dir_of(records_root, &p);
            out.push(BoxEntry {
                name: stem.to_string(),
                records_dir: d.is_dir().then_some(d),
                profile: p,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn os(s: &str) -> Option<OsString> {
        Some(OsString::from(s))
    }

    #[test]
    fn records_state_root_prefers_the_explicit_override() {
                                                                                              
        let root =
            records_state_root_from(os("/srv/orchard-state"), os("/x/state"), os("/home/op"));
        assert_eq!(root, PathBuf::from("/srv/orchard-state").join("records"));
    }

    #[test]
    fn records_state_root_uses_xdg_state_home_when_absolute() {
        let root = records_state_root_from(None, os("/x/state"), os("/home/op"));
        assert_eq!(
            root,
            PathBuf::from("/x/state").join("orchard").join("records")
        );
    }

    #[test]
    fn records_state_root_falls_back_to_home_local_state() {
        let root = records_state_root_from(None, None, os("/home/op"));
        let want = PathBuf::from("/home/op")
            .join(".local")
            .join("state")
            .join("orchard")
            .join("records");
        assert_eq!(root, want);
    }

    #[test]
    fn records_state_root_ignores_a_relative_xdg_state_home() {
                                                                           
        let root = records_state_root_from(None, os("relative/state"), os("/home/op"));
        let want = PathBuf::from("/home/op")
            .join(".local")
            .join("state")
            .join("orchard")
            .join("records");
        assert_eq!(root, want);
    }

    #[test]
    fn records_dir_of_keys_by_profile_stem_under_the_records_root() {
        let root = PathBuf::from("/state/orchard/records");
        let dir = records_dir_of(&root, Path::new("boxes/alpha.toml"));
        assert_eq!(dir, root.join("alpha.d"));
        assert!(dir.starts_with(&root));
        assert!(!dir.starts_with("boxes"));
    }
}
