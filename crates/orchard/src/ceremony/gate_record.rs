                                                                                        
//!
                                                                                                  
//! artifact set AND the build parameter values, but the record's producer (a gate leg, running in
//! a test binary) and the source of those parameter values (the build, run earlier by a different
//! invocation) sit in different filesystem and trust domains with no transport between them. So
//! `orchard build` writes `<img>.provenance.toml` beside the image triple, and the gate harness
//! reads ONLY that file. It never accepts build parameters from its own invocation environment or
//! CLI — that is the operator-attested shape D17 rejected, where the harness is told what it is
//! gating instead of reading it from the artifact.
//!
//! `<img>.layout.toml` cannot serve: it carries no `domain`
                                                                                                
//! rule branches on.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::refusal::{Refusal, RefusalId, encode_owned};

/// The provenance schema version. A newer sidecar refuses rather than being read partially.
pub const PROVENANCE_SCHEMA_VERSION: u32 = 1;

/// `<img>.provenance.toml`: what the build was told, what it consumed, and what it produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    #[serde(rename = "schema-version")]
    pub schema_version: u32,
    /// The `.img` triple's base label (the clean git sha, or `<sha>-dirty`).
    pub image_label: String,
    /// The build parameter VALUES, as the build resolved them. The gate harness reads its
    /// parameters from here and from nowhere else.
    pub params: BuildParams,
    /// The produced artifact hashes, as the build's own `.sha256` sidecars declare them.
    pub produced: ProducedHashes,
}

/// The build parameters a gate record binds. Only values that change the produced bytes or select
/// the gate composition belong here; a value the gate does not branch on would be recorded noise
/// that a mismatch could then refuse over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildParams {
                                                                                             
    /// `<img>.layout.toml`, which is why this sidecar exists at all.
    pub domain: String,
    pub net: String,
    pub firmware: String,
    pub image_version: u64,
    /// The git sha the image was built from (the `ceremony-head` input identity).
    pub git_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducedHashes {
    pub img: String,
    pub layout: String,
    pub vmlinuz: String,
    pub initramfs: String,
}

/// `<img>` → `<img>.provenance.toml`, and the same derivation for the other sidecars, so the
/// naming lives in one place.
pub fn provenance_path(img: &Path) -> PathBuf {
    sidecar(img, "provenance.toml")
}

fn sidecar(img: &Path, suffix: &str) -> PathBuf {
    let mut name = img
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".to_string());
    name.push('.');
    name.push_str(suffix);
    img.with_file_name(name)
}

/// Read the hex digest out of a `sha256sum`-format sidecar (`<hex>  <name>\n`). `None` for an
/// absent, unreadable or malformed file — every caller treats that as "no declared hash", never
/// as an empty one.
pub fn read_sha256_sidecar(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let hex = text.split_whitespace().next()?;
    (hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())).then(|| hex.to_string())
}

fn sha256_file(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    Some(hex::encode(Sha256::digest(std::fs::read(path).ok()?)))
}

/// Compose the sidecar from a completed build's outputs. The large artifacts' hashes come from
/// the build's OWN `.sha256` sidecars (already computed over the same bytes), so emitting
/// provenance re-reads no multi-gigabyte file.
pub fn compose(
    image_label: &str,
    params: BuildParams,
    img: &Path,
    layout: &Path,
    vmlinuz: &Path,
    initramfs: &Path,
) -> Result<Provenance, Refusal> {
    let declared = |artifact: &Path, sidecar_suffix: &str| -> Result<String, Refusal> {
        read_sha256_sidecar(&sidecar(img, sidecar_suffix)).ok_or_else(|| {
            Refusal::new(
                RefusalId::ProvenanceUnusable,
                format!(
                    "the build's own sha256 sidecar for {} is absent or malformed, so the \
                     provenance cannot declare what was produced",
                    artifact.display()
                ),
            )
        })
    };
    Ok(Provenance {
        schema_version: PROVENANCE_SCHEMA_VERSION,
        image_label: image_label.to_string(),
        params,
        produced: ProducedHashes {
            img: declared(img, "sha256")?,
                                                                          
            layout: sha256_file(layout).ok_or_else(|| {
                Refusal::new(
                    RefusalId::ProvenanceUnusable,
                    format!("cannot read {} to hash it", layout.display()),
                )
            })?,
            vmlinuz: declared(vmlinuz, "vmlinuz.sha256")?,
            initramfs: declared(initramfs, "initramfs.sha256")?,
        },
    })
}

/// Write the sidecar beside the image triple.
pub fn write(img: &Path, p: &Provenance) -> Result<PathBuf, Refusal> {
    let path = provenance_path(img);
    let body = encode_owned(p, path.display())?;
    write_atomic(&path, &body, PathWriteId::Sidecar)?;
    Ok(path)
}

/// Read the sidecar beside an image. FAIL-CLOSED at every step: absent, unparseable, or a newer
/// schema all REFUSE. There is no fallback to invocation-supplied parameters — a harness that
                                                                                
pub fn read(img: &Path) -> Result<Provenance, Refusal> {
    let path = provenance_path(img);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        Refusal::new(
            RefusalId::ProvenanceUnusable,
            format!("read {}: {e}", path.display()),
        )
        .with_cure_extra(
            "the sidecar is written by `orchard build` beside the image triple; rebuild the \
             image, or copy the triple WITH its sidecars"
                .to_string(),
        )
    })?;
    let p: Provenance = toml::from_str(&text).map_err(|e| {
        Refusal::new(
            RefusalId::ProvenanceUnusable,
            format!("parse {}: {e}", path.display()),
        )
    })?;
    if p.schema_version > PROVENANCE_SCHEMA_VERSION {
        return Err(Refusal::new(
            RefusalId::ProvenanceUnusable,
            format!(
                "{} declares schema-version {} and this orchard understands {PROVENANCE_SCHEMA_VERSION}",
                path.display(),
                p.schema_version
            ),
        ));
    }
    Ok(p)
}

                                                                                                    

/// The gate-record schema version.
pub const GATE_RECORD_SCHEMA_VERSION: u32 = 1;

/// One leg the gate actually ran, as the leg itself recorded it on pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegRun {
    pub id: String,
}

/// `<img>.gate-record.toml`: what a gate RUN attests. Legs append-merge into it as they pass; the
/// runner copies the finished file into the profile's records dir at S8 completion, and
                                                                                                   
/// clearing `/tmp` or an out_dir is routine, and S9 can hold a run for days between S8 and S10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateRecord {
    #[serde(rename = "schema-version")]
    pub schema_version: u32,
    /// The make target whose leg composition this run was.
    pub gate_target: String,
    pub image_label: String,
    /// The content hashes of the artifact set the legs booted, as the legs read them from the
    /// image triple's own sidecars.
    pub staged: ProducedHashes,
    /// The build parameters, copied from the provenance sidecar the legs read.
    pub params: BuildParams,
    /// The legs that PASSED, appended by each leg.
    #[serde(default)]
    pub leg: Vec<LegRun>,
}

/// One leg of a declared gate composition, as the leg registry describes it (Task 7's derivation:
/// the values come from driving each leg's own registered `DryrunOpts` constructor through its
/// boot path's netdev builder, never from a hand list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegSpec {
    pub id: String,
                                                                                               
    /// does not satisfy S8, because the produced-bytes gate is about bytes that boot.
    pub boots: bool,
    /// Does the leg's ACTUAL network mode block guest outbound NAT (`,restrict=on` in the argv
    /// its own constructor produces)? Capability is not the predicate — every `make boot-gate`
                                                                               
    pub hermetic: bool,
                                                                                        
    /// production SeaBIOS installed-disk boot, not just a `-kernel` direct boot.
    pub boot_path: BootPath,
}

/// The boot paths a leg can drive — the four netdev construction sites, named so the real-domain
/// composition rule can require the production one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootPath {
    /// `-kernel`/`-initrd` direct boot (the dryrun leg).
    DirectKernel,
    /// The installed disk under SeaBIOS — the production boot path.
    SeabiosInstalledDisk,
    /// The prod-e2e harness boot.
    ProdE2e,
    /// The UEFI/OVMF path.
    Uefi,
}

/// The composition a gate target declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredComposition {
    pub gate_target: String,
    pub legs: Vec<LegSpec>,
}

impl DeclaredComposition {
    fn ids(&self) -> std::collections::BTreeSet<&str> {
        self.legs.iter().map(|l| l.id.as_str()).collect()
    }
}

                                                                                               
/// contains a leg that BOOTS, is HERMETIC by its actual mode, and drives the production SeaBIOS
/// installed-disk boot. Both consumers read it — S10's `verify` and the post-build hint's choice
/// of gate (`ceremony::derive::real_domain_gate`) — so the hint can never promise a gate the
/// precondition would refuse.
pub fn satisfies_real_domain(legs: &[LegSpec]) -> bool {
    legs.iter()
        .any(|l| l.boots && l.hermetic && l.boot_path == BootPath::SeabiosInstalledDisk)
}

                                                                                  
///
/// Ordering is by cost of being wrong, not by convenience: the COMPOSITION questions come first
/// (a composition that could never satisfy S8 makes every later check moot), then the identity
/// questions (does this record speak about THIS image), then the leg-set equality.
pub fn verify(
    record: &GateRecord,
    provenance: &Provenance,
    declared: &DeclaredComposition,
    domain: super::test_domains::DomainClass,
) -> Result<(), Refusal> {
    use super::test_domains::DomainClass;
                              
    if !declared.legs.iter().any(|l| l.boots) {
        return Err(Refusal::new(
            RefusalId::GateCompositionUnsatisfiable,
            format!(
                "the gate target {:?} declares no leg that BOOTS the image, so no run of it can \
                 satisfy the produced-bytes gate",
                declared.gate_target
            ),
        ));
    }
                                                                                                 
    if domain == DomainClass::Real {
        let usable: Vec<&LegSpec> = declared
            .legs
            .iter()
            .filter(|l| l.hermetic && l.boots)
            .collect();
        let installed_disk = usable
            .iter()
            .any(|l| l.boot_path == BootPath::SeabiosInstalledDisk);
        if !satisfies_real_domain(&declared.legs) {
            return Err(Refusal::new(
                RefusalId::RealDomainGateUnavailable,
                format!(
                    "this image bakes the real domain {:?}, so its gate boot must be hermetic AND \
                     must exercise the SeaBIOS installed-disk boot; the target {:?} offers \
                     {} hermetic booting leg(s) and {} an installed-disk one",
                    provenance.params.domain,
                    declared.gate_target,
                    usable.len(),
                    if installed_disk {
                        "includes"
                    } else {
                        "includes no"
                    }
                ),
            ));
        }
    }
                                                         
    if record.image_label != provenance.image_label {
        return Err(Refusal::new(
            RefusalId::GateRecordMismatch,
            format!(
                "the gate record attests image {:?} and the staged image is {:?}",
                record.image_label, provenance.image_label
            ),
        ));
    }
    if record.staged != provenance.produced {
        return Err(Refusal::new(
            RefusalId::GateRecordMismatch,
            format!(
                "the gate record's staged-set hashes do not match the image triple's own \
                 (record img={}, image img={})",
                record.staged.img, provenance.produced.img
            ),
        ));
    }
    if record.params != provenance.params {
        return Err(Refusal::new(
            RefusalId::GateRecordMismatch,
            "the gate record's build parameters do not match the image's provenance sidecar — the \
             record was emitted for a differently-parameterized build"
                .to_string(),
        ));
    }
    if record.gate_target != declared.gate_target {
        return Err(Refusal::new(
            RefusalId::GateRecordMismatch,
            format!(
                "the gate record was emitted by target {:?} and this step declares {:?}",
                record.gate_target, declared.gate_target
            ),
        ));
    }
                                                                                                
                                                                                               
    let ran: std::collections::BTreeSet<&str> = record.leg.iter().map(|l| l.id.as_str()).collect();
    let want = declared.ids();
    if ran != want {
        let missing: Vec<&&str> = want.difference(&ran).collect();
        let extra: Vec<&&str> = ran.difference(&want).collect();
        return Err(Refusal::new(
            RefusalId::GateRecordMismatch,
            format!(
                "the gate record's executed leg set differs from the declared composition — \
                 declared {want:?}, executed {ran:?} (never ran: {missing:?}; not declared: \
                 {extra:?})"
            ),
        ));
    }
    Ok(())
}

/// The refusal ids `write_atomic` may carry (FAC-GC-16 shape 4b). Its only error source is a
/// `std::io::Error` on the temp or final path, so a path-write remedy is the only true one; any
/// non-path id at the call is a compile error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathWriteId {
    Sidecar,
    Profile,
}

impl PathWriteId {
    fn id(self) -> RefusalId {
        match self {
            PathWriteId::Sidecar => RefusalId::SidecarUnwritable,
            PathWriteId::Profile => RefusalId::ProfileUnwritable,
        }
    }
}

/// Write bytes ATOMICALLY: a temp file in the same directory, synced, then renamed. The gate
/// record and the profile are read by OTHER processes while a run is in flight (the runner adopts
/// the record; S10's precondition reads it), and `fs::write` truncates in place — a reader landing
/// between the truncate and the write sees a partial file. `records.rs` already writes this way
/// for the same reason; this is that discipline applied to the files this cycle added.
pub fn write_atomic(path: &Path, body: &str, id: PathWriteId) -> Result<(), Refusal> {
    use std::io::Write as _;
    let id = id.id();
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "out".into()),
        std::process::id()
    ));
    let refuse =
        |op: &str, e: std::io::Error| Refusal::new(id, format!("{op} {}: {e}", tmp.display()));
                                                                                              
    let _ = std::fs::remove_file(&tmp);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| refuse("open", e))?;
        f.write_all(body.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                refuse("write", e)
            })?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        Refusal::new(id, format!("rename into {}: {e}", path.display()))
    })
}

/// `<img>` → `<img>.gate-record.toml` (the emitter's drop point).
pub fn gate_record_path(img: &Path) -> PathBuf {
    sidecar(img, "gate-record.toml")
}

                                                              
pub fn profile_gate_record_path(records_dir: &Path) -> PathBuf {
    records_dir.join("gate-record.toml")
}

/// Read a gate record from an explicit path, fail-closed on absence, parse and schema skew.
pub fn read_gate_record(path: &Path) -> Result<GateRecord, Refusal> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Refusal::new(
            RefusalId::GateRecordMissing,
            format!("read {}: {e}", path.display()),
        )
    })?;
    let r: GateRecord = toml::from_str(&text).map_err(|e| {
        Refusal::new(
            RefusalId::GateRecordMissing,
            format!("parse {}: {e}", path.display()),
        )
    })?;
    if r.schema_version > GATE_RECORD_SCHEMA_VERSION {
        return Err(Refusal::new(
            RefusalId::GateRecordSchemaSkew,
            format!(
                "{} declares schema-version {} and this orchard understands \
                 {GATE_RECORD_SCHEMA_VERSION}",
                path.display(),
                r.schema_version
            ),
        ));
    }
    Ok(r)
}

                                                                                                    

/// The environment variable a gate TARGET sets to name itself, so a passing leg can record which
/// composition it was part of. This is the invocation identifying ITSELF, not the harness being
/// told what it is gating — the build parameters still come only from the provenance sidecar, and
/// `verify` cross-checks this name against the DECLARED target, so a wrong value refuses.
pub const GATE_TARGET_ENV: &str = "RECIPES_GATE_TARGET";

/// Append this leg's pass into `<img>.gate-record.toml`, creating the record from the image's
/// provenance on the first leg. Called by a gate leg AFTER its assertions pass — never before, so
/// a failed leg leaves no row.
///
/// A run with no [`GATE_TARGET_ENV`] emits NOTHING and says so: a leg run outside a gate target is
/// not a gate run. That is fail-closed by construction — no record means S10 refuses.
///
/// Legs append under an advisory exclusive `flock` on the record file, so two legs of one binary
/// running in parallel cannot interleave a read-modify-write.
pub fn emit_leg_pass(img: &Path, leg_id: &str) -> Result<bool, Refusal> {
    let Some(gate_target) = std::env::var(GATE_TARGET_ENV)
        .ok()
        .filter(|v| !v.is_empty())
    else {
        return Ok(false);
    };
    let provenance = read(img)?;
    let path = gate_record_path(img);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| {
            Refusal::new(
                RefusalId::SidecarUnwritable,
                format!("open {} for append: {e}", path.display()),
            )
        })?;
    let _guard = FlockGuard::acquire(&file, &path)?;
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut record: GateRecord = if existing.trim().is_empty() {
        GateRecord {
            schema_version: GATE_RECORD_SCHEMA_VERSION,
            gate_target: gate_target.clone(),
            image_label: provenance.image_label.clone(),
            staged: provenance.produced.clone(),
            params: provenance.params.clone(),
            leg: Vec::new(),
        }
    } else {
        toml::from_str(&existing).map_err(|e| {
            Refusal::new(
                RefusalId::GateRecordMissing,
                format!("parse {} for append: {e}", path.display()),
            )
            .with_cure_extra(format!(
                "remove the unusable record at {} first",
                path.display()
            ))
        })?
    };
                                                                                                 
                                                                                                
                                                                        
    if record.gate_target != gate_target || record.image_label != provenance.image_label {
        return Err(Refusal::new(
            RefusalId::GateRecordMismatch,
            format!(
                "{} already holds a run of target {:?} over image {:?}, and this leg ran target \
                 {gate_target:?} over image {:?} — remove the stale record and re-run the gate",
                path.display(),
                record.gate_target,
                record.image_label,
                provenance.image_label
            ),
        ));
    }
    if !record.leg.iter().any(|l| l.id == leg_id) {
        record.leg.push(LegRun {
            id: leg_id.to_string(),
        });
    }
    let body = encode_owned(&record, path.display())?;
    write_atomic(&path, &body, PathWriteId::Sidecar)?;
    Ok(true)
}

/// An advisory exclusive lock held for the life of the value. Blocking (`LOCK_EX` without
/// `LOCK_NB`): a second leg WAITS for its turn to append rather than failing, because a leg that
/// passed must land its row.
struct FlockGuard<'a> {
    file: &'a std::fs::File,
}

impl<'a> FlockGuard<'a> {
    fn acquire(file: &'a std::fs::File, path: &Path) -> Result<Self, Refusal> {
                                                                                 
        let rc = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(file), libc::LOCK_EX) };
        if rc != 0 {
            return Err(Refusal::new(
                RefusalId::SidecarUnwritable,
                format!(
                    "lock {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ),
            ));
        }
        Ok(FlockGuard { file })
    }
}

impl Drop for FlockGuard<'_> {
    fn drop(&mut self) {
                                                                                      
        unsafe {
            libc::flock(std::os::fd::AsRawFd::as_raw_fd(self.file), libc::LOCK_UN);
        }
    }
}

/// S8 completion: copy the emitter's record from beside the image into the profile's records dir
                                                                                                    
/// can hold a run for days between S8 and S10 — so the adopted copy in the records dir is what S8's
/// done probe and S10's precondition read.
pub fn adopt_gate_record(img: &Path, records_dir: &Path) -> Result<PathBuf, Refusal> {
    let src = gate_record_path(img);
    let dst = profile_gate_record_path(records_dir);
                                                                                               
                                                                                        
    let record = read_gate_record(&src)?;
    let body = encode_owned(&record, "the adopted record")?;
    std::fs::create_dir_all(records_dir).map_err(|e| {
        Refusal::new(
            RefusalId::SidecarUnwritable,
            format!("create {}: {e}", records_dir.display()),
        )
        .with_cure_extra(super::records::records_dir_cure(records_dir))
    })?;
    write_atomic(&dst, &body, PathWriteId::Sidecar)
        .map_err(|r| r.with_cure_extra(super::records::records_dir_cure(records_dir)))?;
    Ok(dst)
}

                                                                                               
/// image, these parameters, and a leg set equal to the declared gate target's composition.
///
/// Fail-closed at every missing input: a probe that cannot see the staged image, the records dir,
/// or the target's recipe reports NOT-ready rather than assuming.
pub fn s10_precondition(
    staged_image: Option<&Path>,
    records_dir: Option<&Path>,
    repo_root: &Path,
    gate_target: &str,
) -> super::probes::ProbeResult {
    use super::probes::ProbeResult;
    let (Some(img), Some(dir)) = (staged_image, records_dir) else {
        return ProbeResult::Unevaluable(
            "the staged image and the profile's records dir are supplied by the runner; without \
             them the gate record cannot be checked"
                .into(),
        );
    };
    let provenance = match read(img) {
        Ok(p) => p,
        Err(e) => return ProbeResult::Unmet(format!("{}: {}", e.detail, e.cure().as_str())),
    };
    let record = match read_gate_record(&profile_gate_record_path(dir)) {
        Ok(r) => r,
        Err(e) => return ProbeResult::Unmet(format!("{}: {}", e.detail, e.cure().as_str())),
    };
    let makefile = match std::fs::read_to_string(repo_root.join("Makefile")) {
        Ok(t) => t,
        Err(e) => {
            return ProbeResult::Unevaluable(format!(
                "cannot read the gate target's recipe ({}): {e}",
                repo_root.join("Makefile").display()
            ));
        }
    };
    let declared = match super::leg_registry::composition_of(&makefile, gate_target) {
        Ok(c) => c,
        Err(e) => {
            return ProbeResult::Unmet(format!(
                "the declared gate target {gate_target:?} does not yield a checkable \
                 composition: {e}"
            ));
        }
    };
    match verify(
        &record,
        &provenance,
        &declared,
        super::test_domains::classify(&provenance.params.domain),
    ) {
        Ok(()) => ProbeResult::Met,
        Err(e) => ProbeResult::Unmet(format!(
            "{}: {}. Recover a rebuilt-image wedge by deleting the stale records {} and \
             {}, then re-running — the gate re-emits over the staged image.",
            e.detail,
            e.cure().as_str(),
            profile_gate_record_path(dir).display(),
            gate_record_path(img).display(),
        )),
    }
}
