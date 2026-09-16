//! `orchard market` — the pin-store verify+upgrade tool (the sha256 supply-chain tamper-detection root
//! made operator-facing). `market verify` is the always-on, fail-closed `make verify` gate that
//! consolidates the pre-existing pin checks (provenance, cross-repo seed agreement, vendored re-tar,
//! config re-derive, format-lock drift, apk shape-lock) + a hot cert-presence check, behind one entry.
//! `market upgrade` (Task 10+) stages + propagates a pin bump in one verified, all-or-nothing operation.
//!
                                                                                             
//!
//! ## The fail-closed gate (Task 7)
//! `verify` parses the two central manifests (a parse failure there is a single hard precondition fail —
//! nothing downstream can run), then runs EVERY `§3a` leg, COLLECTING all outcomes rather than
//! short-circuiting on the first failure, so one run surfaces the full damage with `(where, detail)` per
//! failed leg. The set of legs that ran is locked to [`CheckId::HOT_PATH`]: a silently dropped or
//! duplicated check fails closed in [`CheckReport::into_result`] before the gate can ever report "green"
                                                                                                                         

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use recipes_image_builder::apk_drift::{DriftScope, DriftState, apk_drift_scan_scoped};
use recipes_image_builder::artifact_store::{ArtifactStore, DirStore};
use recipes_image_builder::cert_presence::{
    CertAllowlist, CertPresenceError, StaleCert, check_cert_presence, current_pin_map,
    current_pin_values, scan_stale_certs,
};
use recipes_image_builder::pin_manifest::{ArtifactKind, PinManifest, PinManifestError};
use recipes_image_builder::pins::{Pins, PinsError};
use recipes_image_builder::provenance::verify_provenance;
use recipes_image_builder::repo_manifest::{RepoManifest, RepoManifestError};
use recipes_image_builder::seed_agree::verify_seeds_agree;
use recipes_image_builder::store_checks::{
    config_rederive, verify_apk_shape, verify_consume_shape, verify_format_lock,
    verify_vendored_keyrings,
};
use recipes_image_builder::vendor::verify_vendored_tree;
use recipes_image_builder::{Fetcher, PinnedApks};

/// One §3a store-consistency leg `market verify` runs on the hot path. Each is NAMED so the gate can
/// prove it ran the EXACT expected set (the exact-check-set lock — a silently dropped or duplicated leg
/// fails closed, never silently passes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckId {
    /// The repo-manifest's artifact set EXACTLY equals consume-pins's (fail-closed on omission/extra).
    ManifestArtifactSet,
    /// §3a-1: each consume-pin sha == the owning repo's published-pins sha.
    Provenance,
    /// §3a-2: every repo's `pins.toml` byte-agrees with seed-vault's canonical.
    SeedsAgree,
    /// §3a-3: re-tar each vendored source drop (`--format=gnu`), sha == pin.
    VendoredRederive,
    /// §3a-4: sha256(recipes/service-manifest.toml) == the config pin.
    ConfigRederive,
    /// §3a-5: generated rust-toolchain/Containerfile match `pins.toml` + the retired fetch scripts
                                     
    FormatLockDrift,
    /// §3a-6: the apk closure is exactly the pinned shape (count + build-input allowlist).
    ApkShapeLock,
    /// §3a-7: no cert in the trail (the cookbook launchpad) bare-quotes a current pin value.
    CertPresence,
    /// §3a-8: every vendored keyring (kernel.org + rust-lang) is byte-exact vs its pins + nothing
    /// unpinned in either dir (the exact-set `EXPECTED_KEYRINGS` lock).
    VendoredKeyrings,
}

impl CheckId {
    /// The EXACT, ordered set of checks the hot path must run (the exact-check-set lock literal). A leg
    /// added to `run_checks` but absent here — or here but not run — fails closed in
    /// [`CheckReport::into_result`]. Adding/removing a leg is a deliberate edit to THIS literal.
    pub const HOT_PATH: &'static [CheckId] = &[
        CheckId::ManifestArtifactSet,
        CheckId::Provenance,
        CheckId::SeedsAgree,
        CheckId::VendoredRederive,
        CheckId::ConfigRederive,
        CheckId::FormatLockDrift,
        CheckId::ApkShapeLock,
        CheckId::CertPresence,
                                                                                                    
                                                                                                 
        CheckId::VendoredKeyrings,
    ];

    /// Short stable label for the operator report + the per-leg summary.
    pub fn label(self) -> &'static str {
        match self {
            CheckId::ManifestArtifactSet => "manifest-artifact-set",
            CheckId::Provenance => "§3a-1 provenance",
            CheckId::SeedsAgree => "§3a-2 seeds-agree",
            CheckId::VendoredRederive => "§3a-3 vendored-rederive",
            CheckId::ConfigRederive => "§3a-4 config-rederive",
            CheckId::FormatLockDrift => "§3a-5 format-lock",
            CheckId::ApkShapeLock => "§3a-6 apk-shape",
            CheckId::CertPresence => "§3a-7 cert-presence",
            CheckId::VendoredKeyrings => "§3a-8 vendored-keyrings",
        }
    }
}

/// One failed check leg, for the collect-all-failures report.
#[derive(Debug)]
pub struct CheckFailure {
    /// Which leg failed (the "where").
    pub id: CheckId,
    /// The leg's own typed error, rendered — carries its `(artifact, expected, got)` detail.
    pub detail: String,
}

/// Every failure from one `market verify` run. Display = the multi-line operator report (no short-circuit:
/// every failed leg appears).
#[derive(Debug)]
pub struct CheckFailures(pub Vec<CheckFailure>);

impl std::fmt::Display for CheckFailures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "market verify: {} check(s) FAILED:", self.0.len())?;
        for cf in &self.0 {
            writeln!(f, "  [{}] {}", cf.id.label(), cf.detail)?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MarketError {
    /// Precondition: the central `consume-pins.toml` must parse (nothing downstream can run otherwise).
    #[error("pin manifest: {0}")]
    PinManifest(#[from] PinManifestError),
    /// Precondition: the `repo-manifest.toml` must parse.
    #[error("repo manifest: {0}")]
    RepoManifest(#[from] RepoManifestError),
    /// One or more §3a legs failed — ALL are collected (no short-circuit), so one run shows the full damage.
    #[error("{0}")]
    ChecksFailed(CheckFailures),
    /// The gate ran a different leg set than the locked [`CheckId::HOT_PATH`] (a leg was silently dropped
    /// or duplicated) — fail closed before any "green" report (the exact-check-set lock).
    #[error(
        "market verify: executed checks {executed:?} != locked set {expected:?} (a check was dropped or duplicated — the exact-check-set lock)"
    )]
    CheckSetDrift {
        executed: Vec<CheckId>,
        expected: Vec<CheckId>,
    },
    /// The `--cert-presence` dry-run leg failed (unconfigured / trail absent / a bare-quoted live pin) —
    /// the rendered §3a-7 detail (Display lists every reder for the retrofit). Also carries the `--certs`
    /// thorough-mode failures (presence + §3b staleness).
    #[error("{0}")]
    CertPresence(String),
    /// The `--all` store-hash leg failed — a store-backed artifact is absent from the artifact-store or its
    /// bytes don't hash to its pin (an absent store is itself a HARD FAIL, never a skip; AC3-store).
    #[error("market verify --all: {0}")]
    StoreHash(String),
    /// `market outdated`: the LOCAL apk lock couldn't be read/parsed (the advisory scan needs the pinned
    /// set). Distinct from a mirror failure, which is fail-SOFT inside the report (`checked: false`).
    #[error("market outdated: {0}")]
    Outdated(String),
}

/// The §3a-7 allow-missing token: `--allow-missing cert-trail` skips cert-presence when the configured
/// trail (the cookbook launchpad, a sibling repo) isn't checked out — the partial-checkout escape,
/// symmetric to an absent owning repo.
pub const CERT_TRAIL_TOKEN: &str = "cert-trail";

/// The §3a-7 cert-presence leg's own error (orchestration around `cert_presence.rs`). Goes through
/// `CheckReport::run`/the dry-run by `Display`, so it never needs to be a [`MarketError`] variant.
#[derive(Debug, thiserror::Error)]
enum CertLegError {
    #[error(
        "repo-manifest declares no `cert-trail` — §3a-7 cert-presence is unconfigured (add `cert-trail = \"../../cookbook/docs/audits\"`)"
    )]
    NotConfigured,
    #[error(
        "cert trail absent at {0} — pass `--allow-missing {CERT_TRAIL_TOKEN}` for a partial checkout (the cookbook launchpad isn't present)"
    )]
    TrailAbsent(String),
    #[error("pins.toml: {0}")]
    Pins(#[from] PinsError),
    #[error(transparent)]
    CertPresence(#[from] CertPresenceError),
    /// `--certs` §3b staleness: one or more live (non-`superseded-by`) certs certify a non-current pin.
    #[error("{}", render_stale(.0))]
    Stale(Vec<StaleCert>),
}

/// Render every stale cert as its own line (collect-all): the file, the key, the quoted (stale) sha, and the
/// current pin it should have certified (or that the key is unknown).
fn render_stale(stale: &[StaleCert]) -> String {
    let mut s = format!(
        "{} cert(s) certify a non-current pin (re-pin the cert, or mark it `superseded-by:` if retired):",
        stale.len()
    );
    for c in stale {
        match &c.current {
            Some(cur) => s.push_str(&format!(
                "\n  {} certifies-pin {} = {} but the current pin is {cur}",
                c.file, c.key, c.quoted
            )),
                                                                                                             
                                                                                
            None => s.push_str(&format!(
                "\n  {} has a stale/invalid certifies-pin: {} = {} (no matching current pin)",
                c.file, c.key, c.quoted
            )),
        }
    }
    s
}

/// The `ManifestArtifactSet` leg: the consume-pins set is EXACTLY the canonical per-kind shape (§3a-1
                                                                                                         
                                                                                                        
/// two checks have distinct error types, so they're stringified through one `Result<String, String>`.
fn artifact_set_leg(manifest: &RepoManifest, consume: &PinManifest) -> Result<String, String> {
                                                                                                        
                                                                                                     
    manifest
        .assert_artifact_set(consume)
        .map_err(|e| e.to_string())?;
    verify_consume_shape(consume).map_err(|e| e.to_string())?;
                                                                                                   
                                                                                                  
    let count = |k: ArtifactKind| consume.artifacts.values().filter(|a| a.kind == k).count();
    Ok(format!(
        "{} artifacts ({}/{}/{}) / {} repos",
        consume.artifacts.len(),
        count(ArtifactKind::Binary),
        count(ArtifactKind::Source),
        count(ArtifactKind::Config),
        manifest.repos.len()
    ))
}

/// §3a-7: resolve the configured cert trail (in the cookbook launchpad) and assert no cert bare-quotes a
/// current pin value. An absent trail is a HARD FAIL unless `--allow-missing cert-trail` (the
/// partial-checkout escape). Returns a one-line summary on success.
fn cert_presence_leg(
    manifest: &RepoManifest,
    consume: &PinManifest,
    repo_root: &Path,
    allow_missing: &[String],
) -> Result<String, CertLegError> {
    let trail = manifest
        .cert_trail_path(repo_root)
        .ok_or(CertLegError::NotConfigured)?;
    if !trail.is_dir() {
        if allow_missing.iter().any(|r| r == CERT_TRAIL_TOKEN) {
            return Ok(format!(
                "skipped (cert-trail absent at {})",
                trail.display()
            ));
        }
        return Err(CertLegError::TrailAbsent(trail.display().to_string()));
    }
    let pins = Pins::load(repo_root)?;
    let current = current_pin_values(consume, &pins);
    let allowlist = CertAllowlist::load_or_empty(&repo_root.join("market-cert-allowlist.toml"));
    check_cert_presence(&trail, &current, &allowlist)?;
    Ok(format!("OK ({} current pin values policed)", current.len()))
}

/// `market verify --cert-presence` — run ONLY the §3a-7 leg against the live trail (the retrofit dry-run),
/// reporting EVERY reder. Fail-closed (non-zero on any reder) so it can't silently "pass", but the operator
/// reads the full reder list off the error to drive the trichotomy retrofit. Bypasses the exact-check-set
/// lock — it deliberately runs ONE leg, not the gate.
pub fn cert_presence_dry_run(opts: &VerifyOpts) -> Result<String, MarketError> {
    let consume = PinManifest::load(&opts.repo_root.join("consume-pins.toml"))?;
    let manifest = RepoManifest::load(&opts.repo_manifest)?;
    cert_presence_leg(&manifest, &consume, &opts.repo_root, &opts.allow_missing)
        .map(|s| format!("market verify --cert-presence: {s}"))
        .map_err(|e| MarketError::CertPresence(e.to_string()))
}

/// `--certs` (Task 12, off the hot path): the THOROUGH cert-trail audit — re-run the §3a-7 presence scan
/// across the whole trail AND assert §3b staleness: every live (non-`superseded-by`) `certifies-pin: K = sha`
/// must quote the CURRENT pin for K. A stale live cert (or a cert for an unknown key) FAILS; a
/// `superseded-by`-marked record is exempt. Skip is only via `--allow-missing cert-trail`.
fn certs_thorough_leg(
    manifest: &RepoManifest,
    consume: &PinManifest,
    repo_root: &Path,
    allow_missing: &[String],
) -> Result<String, CertLegError> {
    let trail = manifest
        .cert_trail_path(repo_root)
        .ok_or(CertLegError::NotConfigured)?;
    if !trail.is_dir() {
        if allow_missing.iter().any(|r| r == CERT_TRAIL_TOKEN) {
            return Ok(format!(
                "skipped (cert-trail absent at {})",
                trail.display()
            ));
        }
        return Err(CertLegError::TrailAbsent(trail.display().to_string()));
    }
    let pins = Pins::load(repo_root)?;
    let current = current_pin_values(consume, &pins);
    let current_map = current_pin_map(consume, &pins);
    let allowlist = CertAllowlist::load_or_empty(&repo_root.join("market-cert-allowlist.toml"));
                                                                                 
    check_cert_presence(&trail, &current, &allowlist)?;
    let stale = scan_stale_certs(&trail, &current_map)?;
    if !stale.is_empty() {
        return Err(CertLegError::Stale(stale));
    }
    Ok(format!(
        "OK ({} pin keys — presence + staleness across the trail)",
        current_map.len()
    ))
}

/// `--all` (Task 12, off the hot path): hash EVERY store-backed consume artifact against its pin in the
/// artifact-store (C5-resolved, `VerifyOpts::artifact_store`). An absent store/artifact or
/// a byte↔pin mismatch is a HARD FAIL, never a skip (AC3-store) — via the SAME fail-closed `fetch_verified`
/// gate the bake consumes through (no second hashing path to drift).
fn store_hash_leg(consume: &PinManifest, store: &Path) -> Result<String, MarketError> {
    let backend = DirStore::new(store);
    let mut n = 0usize;
    for (key, pin) in &consume.artifacts {
        backend
            .fetch_verified(key, &pin.sha256)
            .map_err(|e| MarketError::StoreHash(format!("{e} (store {})", store.display())))?;
        n += 1;
    }
    Ok(format!(
        "{n} artifacts hashed == pin (store {})",
        store.display()
    ))
}

pub struct VerifyOpts {
    /// The orchard repo root (holds `consume-pins.toml`; C5-resolved at the CLI).
    pub repo_root: PathBuf,
    /// The repo-manifest path (C5-resolved; the staged verify re-roots it into the overlay).
    pub repo_manifest: PathBuf,
    /// The artifact store (C5-resolved; consumed by the `--all` store-hash leg).
    pub artifact_store: PathBuf,
    /// Also run the thorough off-hot-path cert-trail audit (Task 12).
    pub certs: bool,
    /// Also hash each artifact-store binary against its pin (Task 12).
    pub all: bool,
    /// Owning repos permitted to be absent (explicit, reviewed; the partial-checkout dev loop).
    pub allow_missing: Vec<String>,
}

/// Accumulates each leg's outcome so `market verify` reports EVERY failure in one run (no short-circuit)
/// and can assert it ran the exact locked check set.
struct CheckReport {
    /// `(id, Ok(summary) | Err(rendered detail))` in run order.
    outcomes: Vec<(CheckId, Result<String, String>)>,
}

impl CheckReport {
    fn new() -> Self {
        Self {
            outcomes: Vec::new(),
        }
    }

    /// Record a leg's outcome, rendering any typed error to a string (carrying its `(artifact, expected,
    /// got)` detail) so heterogeneous check errors collect uniformly. Generic over the leg's error type.
    fn run<E: std::fmt::Display>(&mut self, id: CheckId, outcome: Result<String, E>) {
        self.outcomes.push((id, outcome.map_err(|e| e.to_string())));
    }

    /// The legs that actually ran, in order (for the exact-check-set lock).
    fn executed(&self) -> Vec<CheckId> {
        self.outcomes.iter().map(|(id, _)| *id).collect()
    }

    /// Fail closed unless the executed set EXACTLY equals the locked `HOT_PATH` AND every leg passed.
    fn into_result(self) -> Result<String, MarketError> {
                                                                                                      
                                                                                                        
                                                                                                  
        let executed = self.executed();
        let executed_set: BTreeSet<CheckId> = executed.iter().copied().collect();
        let expected_set: BTreeSet<CheckId> = CheckId::HOT_PATH.iter().copied().collect();
        if executed.len() != CheckId::HOT_PATH.len() || executed_set != expected_set {
            return Err(MarketError::CheckSetDrift {
                executed,
                expected: CheckId::HOT_PATH.to_vec(),
            });
        }

        let failures: Vec<CheckFailure> = self
            .outcomes
            .iter()
            .filter_map(|(id, r)| {
                r.as_ref().err().map(|d| CheckFailure {
                    id: *id,
                    detail: d.clone(),
                })
            })
            .collect();
        if !failures.is_empty() {
            return Err(MarketError::ChecksFailed(CheckFailures(failures)));
        }

                                                                   
        let parts: Vec<String> = self
            .outcomes
            .iter()
            .map(|(id, r)| format!("{}: {}", id.label(), r.as_ref().expect("all green")))
            .collect();
        Ok(format!("market verify OK — {}", parts.join("; ")))
    }
}

/// Compact note for a leg that skipped absent (explicitly allow-missing'd) owning repos.
fn skipnote(skipped: &[String]) -> String {
    if skipped.is_empty() {
        String::new()
    } else {
        format!(" (skipped absent: {})", skipped.join(", "))
    }
}

/// Run every hot-path leg, COLLECTING all outcomes (no short-circuit past the two parse preconditions).
/// The leg set + order here is locked to [`CheckId::HOT_PATH`] by [`CheckReport::into_result`].
fn run_checks(opts: &VerifyOpts) -> Result<CheckReport, MarketError> {
                                                                                            
    let consume = PinManifest::load(&opts.repo_root.join("consume-pins.toml"))?;
    let manifest = RepoManifest::load(&opts.repo_manifest)?;

    let root = &opts.repo_root;
    let am = &opts.allow_missing;
    let mut r = CheckReport::new();

                                                                                                     
                                                                                                 
                                                                                        
    r.run(
        CheckId::ManifestArtifactSet,
        artifact_set_leg(&manifest, &consume),
    );
                                                                            
    r.run(
        CheckId::Provenance,
        verify_provenance(&manifest, &consume, root, am)
            .map(|p| format!("{} links{}", p.checked, skipnote(&p.skipped))),
    );
                                                                                                   
    r.run(
        CheckId::SeedsAgree,
        verify_seeds_agree(&manifest, root, am)
            .map(|s| format!("{} copies{}", s.checked, skipnote(&s.skipped))),
    );
                                                                                                              
    r.run(
        CheckId::VendoredRederive,
        verify_vendored_tree(&root.join("vendor"), &consume).map(|n| format!("{n} drops")),
    );
                                                                                            
    r.run(
        CheckId::ConfigRederive,
        config_rederive(&manifest, &consume, root, am)
            .map(|checked| if checked { "OK" } else { "skipped" }.to_string()),
    );
                                                                                                                                           
    r.run(
        CheckId::FormatLockDrift,
        verify_format_lock(root).map(|()| "OK".to_string()),
    );
                                                                                                                 
    r.run(
        CheckId::ApkShapeLock,
        verify_apk_shape(root).map(|n| format!("{n} pkgs")),
    );
                                                                                                               
    r.run(
        CheckId::CertPresence,
        cert_presence_leg(&manifest, &consume, root, am),
    );
                                                                                                            
    r.run(
        CheckId::VendoredKeyrings,
        verify_vendored_keyrings(root).map(|n| format!("{n} files")),
    );

    Ok(r)
}

/// `market verify` — the fail-closed gate. Runs §3a-1…§3a-7 + the manifest exact-set lock; returns a per-leg
/// summary on full green, or collects EVERY failure (with `(where, detail)`) into
/// [`MarketError::ChecksFailed`]; an incomplete leg set fails closed via the exact-check-set lock.
/// `--allow-missing <repo>` is the only path past an absent owning repo. The opt-in `--certs` (thorough
/// cert-trail audit) + `--all` (store-binary hashing) thorough modes run AFTER the hot gate is green (Task 12).
pub fn verify(opts: &VerifyOpts) -> Result<String, MarketError> {
    let mut summary = run_checks(opts)?.into_result()?;
    if opts.certs {
        let consume = PinManifest::load(&opts.repo_root.join("consume-pins.toml"))?;
        let manifest = RepoManifest::load(&opts.repo_manifest)?;
        let extra = certs_thorough_leg(&manifest, &consume, &opts.repo_root, &opts.allow_missing)
            .map_err(|e| MarketError::CertPresence(e.to_string()))?;
        summary.push_str(&format!("; --certs: {extra}"));
    }
    if opts.all {
        let consume = PinManifest::load(&opts.repo_root.join("consume-pins.toml"))?;
        let extra = store_hash_leg(&consume, &opts.artifact_store)?;
        summary.push_str(&format!("; --all: {extra}"));
    }
    Ok(summary)
}

                                                                                   

/// Options for [`outdated`]. The fetch seam is injected (production: `HttpFetcher::new()`) so the
/// report is testable offline, mirroring `VerifyOpts`' shape.
pub struct OutdatedOpts {
    /// The orchard repo root (holds `crates/image-builder/pinned-apks.toml`, the scanned lock).
    pub repo_root: PathBuf,
    /// Classify the whole lock (runtime closure too), not just the `[[build_input]]` 404 drivers.
    pub all_packages: bool,
    /// The APKINDEX transport.
    pub fetch: Box<dyn Fetcher>,
}

/// The rendered report + the two facts the CLI's `--exit-drift` NAG keys off.
pub struct OutdatedReport {
    pub text: String,
    pub any_gone: bool,
    /// `false` = the mirror couldn't be consulted (fail-soft; the text says so, the exit code stays 0).
    pub checked: bool,
}

/// The `--exit-drift` NAG mode (spec §5.2): a best-effort operator/CI nag, NOT a security gate —
                                                       
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitDrift {
    /// Flag absent: pure report, always exit 0.
    Never,
    /// `--exit-drift`: non-zero when any pin is Gone (the build-breaking state).
    OnGone,
    /// `--exit-drift=any`: non-zero on any non-current pin. Under the two-state
    /// `DriftState{Current,Gone}` model (the GC'd-mirror §5.1 refinement) every non-current pin IS
    /// Gone, so this coincides with `OnGone` today; both spellings stay for operator intent.
    OnAny,
}

/// `market outdated` — fetch + parse the mirror APKINDEX and report pinned-vs-available drift.
/// ADVISORY: never fails a build or gate; a mirror failure yields a fail-soft report
/// (`checked: false`), never an `Err`. The only `Err` is a LOCAL precondition (unreadable lock).
pub fn outdated(opts: &OutdatedOpts) -> Result<OutdatedReport, MarketError> {
    let lock_path = opts.repo_root.join("crates/image-builder/pinned-apks.toml");
    let lock_text = std::fs::read_to_string(&lock_path)
        .map_err(|e| MarketError::Outdated(format!("read {}: {e}", lock_path.display())))?;
    let pins =
        PinnedApks::from_toml_str(&lock_text).map_err(|e| MarketError::Outdated(e.to_string()))?;
    let scope = if opts.all_packages {
        DriftScope::AllPackages
    } else {
        DriftScope::BuildInputs
    };
    let scan = apk_drift_scan_scoped(&pins, opts.fetch.as_ref(), scope);

    if !scan.checked {
        return Ok(OutdatedReport {
            text: "market outdated: couldn't reach the mirror to check drift (fail-soft — \
                   nothing checked; the advisory scan never blocks anything)."
                .into(),
            any_gone: false,
            checked: false,
        });
    }

                                                                                                  
                                                                                                  
                                  
    let gone: Vec<_> = scan
        .packages
        .iter()
        .filter(|p| p.state == DriftState::Gone)
        .collect();
    let current_n = scan.packages.len() - gone.len();
    let name_w = gone.iter().map(|p| p.name.len()).max().unwrap_or(0);
    let ver_w = gone.iter().map(|p| p.pinned.len()).max().unwrap_or(0);
    let mut lines = vec![format!(
        "market outdated — apk pins vs the mirror (alpine v{}):",
        pins.alpine_version
    )];
    for p in &gone {
        let avail = match &p.available {
            Some(v) => format!("(mirror serves {v})"),
            None => "(no longer in the index)".to_string(),
        };
        lines.push(format!(
            "  {:name_w$}   {:ver_w$}   GONE   {avail}   \u{2190} expect a build 404 (the mirror moved on); run `market upgrade --apks`",
            p.name, p.pinned
        ));
    }
    lines.push(format!(
        "  {} pin(s) gone, {} current.",
        gone.len(),
        current_n
    ));
    lines.push("(advisory — nothing changed; `market verify` is the fail-closed gate.)".into());
    Ok(OutdatedReport {
        text: lines.join("\n"),
        any_gone: !gone.is_empty(),
        checked: true,
    })
}

/// Map the `--exit-drift` mode + a report to the process exit code (pure; the CLI applies it).
                                                                                                   
pub fn outdated_exit_code(when: ExitDrift, report: &OutdatedReport) -> i32 {
    if !report.checked {
        return 0;
    }
    match when {
        ExitDrift::Never => 0,
        ExitDrift::OnGone | ExitDrift::OnAny => i32::from(report.any_gone),
    }
}

                                                                                                   
/// the WHOLE lock (an `--apks` re-pin re-resolves the whole closure), rendered as
/// pinned → mirror-current lines. Purely additive to the step-list preview; fail-soft (an
/// unreachable mirror yields a couldn't-check line, never an error); the `available` field comes
/// pre-sanitized from the scan.
pub fn apks_dry_run_preview(repo_root: &Path, fetch: &dyn Fetcher) -> String {
                                                                                       
    let lock_path = repo_root.join("crates/image-builder/pinned-apks.toml");
    let Ok(lock_text) = std::fs::read_to_string(&lock_path) else {
        return format!(
            "(no drift preview — couldn't read {}; the step plan above still holds)",
            lock_path.display()
        );
    };
    let Ok(pins) = PinnedApks::from_toml_str(&lock_text) else {
        return "(no drift preview — the apk lock didn't parse; the step plan above still holds)"
            .into();
    };
    let scan = apk_drift_scan_scoped(&pins, fetch, DriftScope::AllPackages);
    if !scan.checked {
        return "(couldn't reach the mirror for the drift preview — the step plan above still \
                holds; the re-pin itself will surface any fetch problem)"
            .into();
    }
    let gone: Vec<_> = scan
        .packages
        .iter()
        .filter(|p| p.state == DriftState::Gone)
        .collect();
    let current_n = scan.packages.len() - gone.len();
    let mut lines = vec!["drift preview — what the re-resolve will move (mirror-current):".into()];
    for p in &gone {
        let to = p.available.as_deref().unwrap_or("(gone from the index)");
        lines.push(format!("  {}   {} \u{2192} {to}", p.name, p.pinned));
    }
    lines.push(format!(
        "  {} pin(s) drifted, {current_n} current. The re-pin dual-verifies every fetched .apk; \
         nothing swaps except on a green staged verify.",
        gone.len()
    ));
    lines.join("\n")
}

                                                                                               
/// build container from `pins.toml` (`[rust].container_digest` — docker runs an image id
/// directly), never a mutable tag like `recipes-imgbuild:dev`. The explicit flag overrides.
pub fn default_apks_container_image(pins: &Pins) -> String {
    pins.rust.container_digest.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a report that ran the full `HOT_PATH` set; legs whose id is in `fail` get an Err outcome.
    fn full_report(fail: &[CheckId]) -> CheckReport {
        let mut r = CheckReport::new();
        for &id in CheckId::HOT_PATH {
            if fail.contains(&id) {
                r.run(
                    id,
                    Err::<String, String>(format!("drift in {}", id.label())),
                );
            } else {
                r.run(id, Ok::<String, String>("ok".to_string()));
            }
        }
        r
    }

    #[test]
    fn all_green_full_set_passes() {
        let summary = full_report(&[])
            .into_result()
            .expect("full green set passes");
        assert!(summary.starts_with("market verify OK"), "{summary}");
    }

    #[test]
    fn a_single_failed_leg_is_reported() {
        let err = full_report(&[CheckId::Provenance])
            .into_result()
            .unwrap_err();
        match err {
            MarketError::ChecksFailed(CheckFailures(f)) => {
                assert_eq!(f.len(), 1);
                assert_eq!(f[0].id, CheckId::Provenance);
            }
            other => panic!("expected ChecksFailed, got {other:?}"),
        }
    }

    #[test]
    fn all_failures_are_collected_not_short_circuited() {
                                                                                            
        let err = full_report(&[CheckId::Provenance, CheckId::ApkShapeLock])
            .into_result()
            .unwrap_err();
        match err {
            MarketError::ChecksFailed(CheckFailures(f)) => {
                let ids: BTreeSet<CheckId> = f.iter().map(|c| c.id).collect();
                assert_eq!(f.len(), 2, "both failures collected");
                assert!(ids.contains(&CheckId::Provenance));
                assert!(ids.contains(&CheckId::ApkShapeLock));
            }
            other => panic!("expected ChecksFailed, got {other:?}"),
        }
    }

    #[test]
    fn a_dropped_check_fails_closed_the_exact_set_lock() {
                                                                                                           
                                                         
        let mut r = CheckReport::new();
        for &id in CheckId::HOT_PATH {
            if id == CheckId::ApkShapeLock {
                continue;                          
            }
            r.run(id, Ok::<String, String>("ok".to_string()));
        }
        assert!(
            matches!(r.into_result(), Err(MarketError::CheckSetDrift { .. })),
            "a dropped check must fail closed, not silently pass"
        );
    }

    #[test]
    fn a_duplicated_check_fails_closed_the_exact_set_lock() {
        let mut r = full_report(&[]);
                                                                                       
        r.run(CheckId::Provenance, Ok::<String, String>("ok".to_string()));
        assert!(matches!(
            r.into_result(),
            Err(MarketError::CheckSetDrift { .. })
        ));
    }

    #[test]
    fn hot_path_is_the_locked_nine_legs() {
                                                                                                          
                                                                                                          
                                                                                                     
        let expected: BTreeSet<CheckId> = [
            CheckId::ManifestArtifactSet,
            CheckId::Provenance,
            CheckId::SeedsAgree,
            CheckId::VendoredRederive,
            CheckId::ConfigRederive,
            CheckId::FormatLockDrift,
            CheckId::ApkShapeLock,
            CheckId::CertPresence,
            CheckId::VendoredKeyrings,
        ]
        .into_iter()
        .collect();
        let got: BTreeSet<CheckId> = CheckId::HOT_PATH.iter().copied().collect();
        assert_eq!(got, expected);
        assert_eq!(CheckId::HOT_PATH.len(), 9, "exactly nine hot-path legs");
    }

                                                              

    fn one_binary_consume() -> PinManifest {
        PinManifest::from_toml_str(&format!(
            "schema-version = 1\n[artifacts.fb-acme]\nsha256 = \"{}\"\nkind = \"binary\"\n",
            "a".repeat(64)
        ))
        .unwrap()
    }

    #[test]
    fn store_hash_leg_fails_closed_on_an_absent_store() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("orchard");                                                   
        std::fs::create_dir_all(&root).unwrap();
        let err = store_hash_leg(&one_binary_consume(), &root).unwrap_err();
        assert!(
            matches!(err, MarketError::StoreHash(_)),
            "an absent store must HARD FAIL --all, got {err:?}"
        );
    }

    #[test]
    fn store_hash_leg_fails_on_a_byte_pin_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("orchard");
        let store = dir.path().join("artifact-store");                             
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("fb-acme"), b"not the pinned bytes").unwrap();
        let err = store_hash_leg(&one_binary_consume(), &root).unwrap_err();
        assert!(
            matches!(err, MarketError::StoreHash(_)),
            "a byte<->pin mismatch must fail --all, got {err:?}"
        );
    }

                                                                                                                    

    /// A minimal orchard fixture for the `--certs` leg: a valid `pins.toml`, a `cert-trail = "audits"`
    /// manifest, a consume-pins with `dragonfruit-src = aaa…`, and one cert carrying `cert_body`.
    fn certs_fixture(root: &Path, cert_body: &str) -> (RepoManifest, PinManifest) {
        let c = "c".repeat(64);                                                                         
        std::fs::write(
            root.join("pins.toml"),
            format!(
                "[kernel]\nversion = \"6.18.34\"\nsha256 = \"{c}\"\n\
                 [syslinux]\nversion = \"6.04-pre1\"\nsha256 = \"{c}\"\n\
                 [rust]\nversion = \"1.96.0\"\nalpine_base = \"alpine:3.23\"\n\
                 alpine_base_digest = \"sha256:{c}\"\n\
                 toolchain_musl_url = \"https://static.rust-lang.org/dist/d/rust-1.96.0-x86_64-unknown-linux-musl.tar.xz\"\n\
                 toolchain_musl_sha256 = \"{c}\"\n\
                 std_uefi_url = \"https://static.rust-lang.org/dist/d/rust-std-1.96.0-x86_64-unknown-uefi.tar.xz\"\n\
                 std_uefi_sha256 = \"{c}\"\ncontainer_digest = \"sha256:{c}\"\n\
                 [kernel-keyring]\n\"gregkh.asc\" = \"{c}\"\n\
                 [rust-keyring]\n\"rust-signing.asc\" = \"{c}\"\n"
            ),
        )
        .unwrap();
        std::fs::create_dir_all(root.join("audits")).unwrap();
        std::fs::write(root.join("audits/cert.md"), cert_body).unwrap();
        let manifest = RepoManifest::from_toml_str(
            "schema-version = 1\ncert-trail = \"audits\"\n\
             [repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"dragonfruit-src\"]\n",
        )
        .unwrap();
        let consume = PinManifest::from_toml_str(&format!(
            "schema-version = 1\n[artifacts.dragonfruit-src]\nsha256 = \"{}\"\nkind = \"source\"\n",
            "a".repeat(64)
        ))
        .unwrap();
        (manifest, consume)
    }

    #[test]
    fn certs_thorough_leg_flags_a_stale_live_cert() {
        let dir = tempfile::tempdir().unwrap();
                                                                                                  
        let (m, c) = certs_fixture(
            dir.path(),
            &format!("certifies-pin: dragonfruit-src = {}\n", "b".repeat(64)),
        );
        let err = certs_thorough_leg(&m, &c, dir.path(), &[]).unwrap_err();
        assert!(
            matches!(err, CertLegError::Stale(_)),
            "a stale live cert must FAIL --certs, got {err:?}"
        );
    }

    #[test]
    fn certs_thorough_leg_exempts_a_superseded_cert() {
        let dir = tempfile::tempdir().unwrap();
        let (m, c) = certs_fixture(
            dir.path(),
            &format!(
                "superseded-by: oldcommit\ncertifies-pin: dragonfruit-src = {}\n",
                "b".repeat(64)
            ),
        );
        assert!(
            certs_thorough_leg(&m, &c, dir.path(), &[]).is_ok(),
            "a `superseded-by`-marked cert must not be flagged stale"
        );
    }
}

#[cfg(test)]
mod outdated_tests {
    use super::*;
    use recipes_image_builder::apk_drift::apkindex_url;
    use std::io::Write as _;

    fn gz(buf: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(buf).unwrap();
        e.finish().unwrap()
    }

    fn apkindex(entries: &[(&str, &str)]) -> Vec<u8> {
        let text: String = entries
            .iter()
            .map(|(p, v)| format!("P:{p}\nV:{v}\n\n"))
            .collect();
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(text.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "APKINDEX", text.as_bytes()).unwrap();
        gz(&b.into_inner().unwrap())
    }

    struct MapFetcher(std::collections::BTreeMap<String, Vec<u8>>);

    impl Fetcher for MapFetcher {
        fn get(&self, url: &str) -> Result<Vec<u8>, String> {
            self.0.get(url).cloned().ok_or_else(|| "HTTP 404".into())
        }
    }

    /// A tempdir repo root whose `crates/image-builder/pinned-apks.toml` pins `build_inputs`.
    fn repo_with_lock(build_inputs: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let lockdir = dir.path().join("crates/image-builder");
        std::fs::create_dir_all(&lockdir).unwrap();
        let rows: String = build_inputs
            .iter()
            .map(|(n, v)| {
                format!(
                    "[[build_input]]\nname = \"{n}\"\nversion = \"{v}\"\nsha256 = \"aa\"\nsigning_key = \"k\"\n"
                )
            })
            .collect();
        std::fs::write(
            lockdir.join("pinned-apks.toml"),
            format!("alpine_version = \"3.23\"\n{rows}"),
        )
        .unwrap();
        dir
    }

    fn serving(main: Vec<u8>, community: Vec<u8>) -> Box<MapFetcher> {
        Box::new(MapFetcher(std::collections::BTreeMap::from([
            (apkindex_url("3.23", "main"), main),
            (apkindex_url("3.23", "community"), community),
        ])))
    }

    #[test]
    fn outdated_reports_gone_and_current() {
        let repo = repo_with_lock(&[("linux-virt", "6.18.36-r0"), ("syslinux", "6.04_pre1-r15")]);
        let opts = OutdatedOpts {
            repo_root: repo.path().to_path_buf(),
            all_packages: false,
            fetch: serving(
                apkindex(&[("linux-virt", "6.18.38-r0"), ("syslinux", "6.04_pre1-r15")]),
                apkindex(&[]),
            ),
        };
        let report = outdated(&opts).unwrap();
        assert!(report.checked);
        assert!(report.any_gone);
        assert!(
            report.text.contains("linux-virt"),
            "names the gone pin: {}",
            report.text
        );
        assert!(
            report.text.contains("6.18.36-r0"),
            "names the pinned version"
        );
        assert!(
            report.text.contains("6.18.38-r0"),
            "names the available version"
        );
        assert!(report.text.contains("GONE"));
        assert!(
            report.text.contains("market upgrade --apks"),
            "points at the cure: {}",
            report.text
        );
        assert!(
            report.text.contains("1 current"),
            "counts the current pins: {}",
            report.text
        );
        assert!(
            !report.text.contains("syslinux   6.04_pre1-r15   GONE"),
            "a current pin is not a GONE row"
        );
        assert!(
            report.text.contains("advisory"),
            "the advisory banner is present: {}",
            report.text
        );
    }

    #[test]
    fn outdated_fail_soft_when_unreachable() {
        let repo = repo_with_lock(&[("linux-virt", "6.18.36-r0")]);
        let opts = OutdatedOpts {
            repo_root: repo.path().to_path_buf(),
            all_packages: false,
            fetch: Box::new(MapFetcher(std::collections::BTreeMap::new())),
        };
        let report = outdated(&opts).unwrap();
        assert!(!report.checked);
        assert!(!report.any_gone);
        assert!(
            report.text.contains("couldn't reach the mirror"),
            "the fail-soft notice: {}",
            report.text
        );
    }

    #[test]
    fn outdated_errs_only_on_a_local_lock_problem() {
        let dir = tempfile::tempdir().unwrap();                       
        let opts = OutdatedOpts {
            repo_root: dir.path().to_path_buf(),
            all_packages: false,
            fetch: Box::new(MapFetcher(std::collections::BTreeMap::new())),
        };
        assert!(matches!(outdated(&opts), Err(MarketError::Outdated(_))));
    }

    #[test]
    fn exit_code_matrix() {
        let gone = OutdatedReport {
            text: String::new(),
            any_gone: true,
            checked: true,
        };
        let clean = OutdatedReport {
            text: String::new(),
            any_gone: false,
            checked: true,
        };
        let unchecked = OutdatedReport {
            text: String::new(),
            any_gone: false,
            checked: false,
        };
                                  
        assert_eq!(outdated_exit_code(ExitDrift::Never, &gone), 0);
                                             
        assert_eq!(outdated_exit_code(ExitDrift::OnGone, &gone), 1);
        assert_eq!(outdated_exit_code(ExitDrift::OnAny, &gone), 1);
        assert_eq!(outdated_exit_code(ExitDrift::OnGone, &clean), 0);
        assert_eq!(outdated_exit_code(ExitDrift::OnAny, &clean), 0);
                                                                                               
        assert_eq!(outdated_exit_code(ExitDrift::OnGone, &unchecked), 0);
        assert_eq!(outdated_exit_code(ExitDrift::OnAny, &unchecked), 0);
    }
}

#[cfg(test)]
mod dry_run_preview_tests {
    use super::*;
    use recipes_image_builder::apk_drift::apkindex_url;
    use std::io::Write as _;

    fn gz(buf: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(buf).unwrap();
        e.finish().unwrap()
    }

    fn apkindex(entries: &[(&str, &str)]) -> Vec<u8> {
        let text: String = entries
            .iter()
            .map(|(p, v)| format!("P:{p}\nV:{v}\n\n"))
            .collect();
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(text.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "APKINDEX", text.as_bytes()).unwrap();
        gz(&b.into_inner().unwrap())
    }

    struct MapFetcher(std::collections::BTreeMap<String, Vec<u8>>);

    impl Fetcher for MapFetcher {
        fn get(&self, url: &str) -> Result<Vec<u8>, String> {
            self.0.get(url).cloned().ok_or_else(|| "HTTP 404".into())
        }
    }

    /// A repo root whose lock has one drifted RUNTIME package + one current build_input — the
    /// preview must cover the whole closure (an --apks re-pin re-resolves everything).
    fn repo_and_fetcher() -> (tempfile::TempDir, MapFetcher) {
        let dir = tempfile::tempdir().unwrap();
        let lockdir = dir.path().join("crates/image-builder");
        std::fs::create_dir_all(&lockdir).unwrap();
        std::fs::write(
            lockdir.join("pinned-apks.toml"),
            "alpine_version = \"3.23\"\n\
             [[package]]\nname = \"haproxy\"\nversion = \"3.2.19-r0\"\nsha256 = \"aa\"\nsigning_key = \"k\"\n\
             [[build_input]]\nname = \"linux-virt\"\nversion = \"6.18.38-r0\"\nsha256 = \"bb\"\nsigning_key = \"k\"\n",
        )
        .unwrap();
        let f = MapFetcher(std::collections::BTreeMap::from([
            (
                apkindex_url("3.23", "main"),
                apkindex(&[("haproxy", "3.2.21-r0"), ("linux-virt", "6.18.38-r0")]),
            ),
            (apkindex_url("3.23", "community"), apkindex(&[])),
        ]));
        (dir, f)
    }

    #[test]
    fn preview_lists_the_whole_closure_deltas() {
        let (repo, f) = repo_and_fetcher();
        let text = apks_dry_run_preview(repo.path(), &f);
        assert!(
            text.contains("haproxy") && text.contains("3.2.19-r0") && text.contains("3.2.21-r0"),
            "the drifted RUNTIME pin's delta shows: {text}"
        );
        assert!(
            text.contains("1 current"),
            "counts the current pins: {text}"
        );
        assert!(
            text.contains("dual-verif"),
            "reminds that the re-pin dual-verifies (advisory preview, verified re-pin): {text}"
        );
    }

    #[test]
    fn preview_is_fail_soft() {
        let (repo, _) = repo_and_fetcher();
        let f = MapFetcher(std::collections::BTreeMap::new());
        let text = apks_dry_run_preview(repo.path(), &f);
        assert!(
            text.contains("couldn't reach the mirror"),
            "unreachable mirror = a notice, never an error: {text}"
        );
    }

    #[test]
    fn preview_survives_a_missing_lock() {
        let dir = tempfile::tempdir().unwrap();
        let f = MapFetcher(std::collections::BTreeMap::new());
        let text = apks_dry_run_preview(dir.path(), &f);
        assert!(
            text.contains("no drift preview"),
            "a preview must never fail the dry-run: {text}"
        );
    }

    #[test]
    fn container_default_is_the_pinned_digest_not_a_tag() {
        let pins = Pins::load(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap(),
        )
        .expect("the repo pins.toml parses");
        let default = default_apks_container_image(&pins);
        assert!(
            default.starts_with("sha256:"),
            "digest-pinned ref, never a mutable tag: {default}"
        );
        assert_eq!(default, pins.rust.container_digest);
    }
}
