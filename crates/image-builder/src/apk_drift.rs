//! Host-side apk drift scan (the market comfort cycle): fetch + parse the mirror APKINDEX and
//! classify each pinned apk against the mirror-current version. ADVISORY + OFF THE TRUST PATH —
//! reads no pin file, writes nothing, and is never consulted by `verify`/`upgrade`'s accept
                                                                                                  
//! `DriftReport { checked: false }`, never an error the caller must treat as fatal. BOUNDED: one
//! decompressed-byte ceiling over the whole gzip→tar stream (headers + every member), so a
//! hostile index cannot OOM the scan (it runs auto-invoked on the reactive build-error path).
//! SANITIZED: the untrusted `available` field is terminal-safe before any caller prints it.
//!
//! The REAL dl-cdn `APKINDEX.tar.gz` shape (verified empirically 2026-07-07 on v3.23/main): TWO
//! concatenated gzip members — a signature tar SEGMENT (`.SIGN.RSA.*`, apk-style, with NO
//! end-of-archive terminator blocks) ‖ the index tar (`DESCRIPTION` + `APKINDEX`). The decode is
//! therefore `MultiGzDecoder` (a plain `GzDecoder` stops after the signature member and never
//! sees `APKINDEX`), and ONE tar walk flows across the segment boundary (no terminator between).

use std::collections::BTreeMap;
use std::io::Read;

use crate::{Fetcher, PinnedApks};

/// Decompressed-byte ceiling for one APKINDEX parse — the whole gzip→tar stream is counted.
/// A real index is ~2-3 MB decompressed; 64 MiB is generous headroom, far below host RAM
/// (mirrors `KERNEL_TAR_CEILING`'s reject-don't-OOM discipline).
pub const APKINDEX_DECOMPRESSED_CEILING: u64 = 64 * 1024 * 1024;

/// Drift classification of one pinned apk vs the mirror index. dl-cdn GARBAGE-COLLECTS old
/// revisions (verified empirically: the superseded `linux-virt-6.18.36-r0.apk` 404s while
/// `-6.18.38-r0.apk` serves), so pinned ≠ mirror-current IS the build-breaking 404 case: `Gone`.
/// A "newer exists but yours is still served" state does not occur on a GC'd mirror (plan §5.1
/// refinement of the spec's three-state enum).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftState {
    /// The pinned version is exactly what the mirror serves.
    Current,
    /// The pinned version is no longer served (absent name, or superseded → GC'd): a build 404.
    Gone,
}

/// One pinned apk's drift row. `available` is the mirror-current version — an UNTRUSTED field,
/// already passed through [`sanitize_version`] (safe to print); `None` = the package name is
/// absent from the index entirely.
#[derive(Debug, Clone)]
pub struct PkgDrift {
    pub name: String,
    pub pinned: String,
    pub available: Option<String>,
    pub state: DriftState,
}

/// The scan result. `checked: false` = the mirror couldn't be consulted (unreachable, malformed,
/// or over-ceiling index) — the fail-soft signal; `packages` is empty in that case.
#[derive(Debug, Clone)]
pub struct DriftReport {
    pub packages: Vec<PkgDrift>,
    pub checked: bool,
}

/// Which pinned set to classify: the `[[build_input]]` pins (the build-404 drivers — the
/// default) or the whole lock (build_inputs + the runtime `[[package]]` closure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftScope {
    BuildInputs,
    AllPackages,
}

/// The APKINDEX URL for `alpine_version` + `repo` (main|community) — the sibling of
/// `AlpineApkProvider::apk_urls`'s per-apk shape.
pub fn apkindex_url(alpine_version: &str, repo: &str) -> String {
    format!("https://dl-cdn.alpinelinux.org/alpine/v{alpine_version}/{repo}/x86_64/APKINDEX.tar.gz")
}

/// Sanitize an untrusted mirror version field for terminal printing: keep printable ASCII
/// `[A-Za-z0-9._+~-]` up to 64 bytes; every other byte becomes `?` (no control/escape bytes can
/// reach a terminal). Sanitization lives HERE — on the scan's output — not in any one caller
                                                    
pub fn sanitize_version(raw: &str) -> String {
    raw.bytes()
        .take(64)
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'+' | b'~' | b'-' => b as char,
            _ => '?',
        })
        .collect()
}

/// Fetch + parse the main+community APKINDEX for `pins.alpine_version` and classify each pinned
/// `[[build_input]]`. Fail-SOFT: any fetch/parse/ceiling failure for EITHER repo yields
/// `checked: false` (never an error). ADVISORY — reads no pin file, writes nothing, never on the
/// verify/upgrade accept path.
pub fn apk_drift_scan(pins: &PinnedApks, fetch: &dyn Fetcher) -> DriftReport {
    apk_drift_scan_scoped(pins, fetch, DriftScope::BuildInputs)
}

/// [`apk_drift_scan`] with an explicit scope (`market outdated --all-packages` classifies the
/// whole lock). Same fail-soft/advisory contract.
pub fn apk_drift_scan_scoped(
    pins: &PinnedApks,
    fetch: &dyn Fetcher,
    scope: DriftScope,
) -> DriftReport {
    let fail_soft = DriftReport {
        packages: Vec::new(),
        checked: false,
    };
                                                                                                
                                                                                               
    let mut index: BTreeMap<String, String> = BTreeMap::new();
    for repo in ["main", "community"] {
        let url = apkindex_url(&pins.alpine_version, repo);
        let Ok(bytes) = fetch.get(&url) else {
            return fail_soft;
        };
        let Ok(versions) = index_versions(&bytes) else {
            return fail_soft;
        };
        for (name, version) in versions {
            index.entry(name).or_insert(version);
        }
    }

    let pinned: Vec<&crate::PinnedPackage> = match scope {
        DriftScope::BuildInputs => pins.build_inputs.iter().collect(),
        DriftScope::AllPackages => {
                                                                                             
            let mut seen = std::collections::HashSet::new();
            pins.build_inputs
                .iter()
                .chain(pins.packages.iter())
                .filter(|p| seen.insert(p.name.as_str()))
                .collect()
        }
    };

    let packages = pinned
        .into_iter()
        .map(|pin| {
            let (available, state) = match index.get(&pin.name) {
                None => (None, DriftState::Gone),
                Some(v) if *v == pin.version => (Some(sanitize_version(v)), DriftState::Current),
                Some(v) => (Some(sanitize_version(v)), DriftState::Gone),
            };
            PkgDrift {
                name: pin.name.clone(),
                pinned: pin.version.clone(),
                available,
                state,
            }
        })
        .collect();

    DriftReport {
        packages,
        checked: true,
    }
}

                      

/// A reader that fails once more than `ceiling` total bytes have passed through it — the
/// decompression bound. Wraps the MultiGzDecoder INSIDE the tar walk, so headers, skipped
/// members, and the APKINDEX content all count against ONE budget.
struct Capped<R: Read> {
    inner: R,
    consumed: u64,
    ceiling: u64,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.consumed = self.consumed.saturating_add(n as u64);
        if self.consumed > self.ceiling {
            return Err(std::io::Error::other(format!(
                "APKINDEX decompressed stream exceeds the {}-byte ceiling",
                self.ceiling
            )));
        }
        Ok(n)
    }
}

/// Decode + walk one fetched `APKINDEX.tar.gz` (multi-member gzip; see the module doc) and
/// return the `name -> version` map from its `APKINDEX` member. Any decode/walk/read/UTF-8
/// failure, an over-ceiling stream, or a missing `APKINDEX` member is an `Err` — the caller
/// maps every error to the fail-soft report.
fn index_versions(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let gz = flate2::bufread::MultiGzDecoder::new(bytes);
    let capped = Capped {
        inner: gz,
        consumed: 0,
        ceiling: APKINDEX_DECOMPRESSED_CEILING,
    };
    let mut archive = tar::Archive::new(capped);
    let entries = archive.entries().map_err(|e| format!("tar walk: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("tar entry: {e}"))?;
        let path = entry.path().map_err(|e| format!("entry name: {e}"))?;
        let name = path.to_string_lossy().into_owned();
        if name.strip_prefix("./").unwrap_or(&name) == "APKINDEX" {
            let mut text = String::new();
            entry
                .read_to_string(&mut text)
                .map_err(|e| format!("APKINDEX read: {e}"))?;
            return Ok(parse_index_blocks(&text));
        }
    }
    Err("no APKINDEX member in the fetched index".into())
}

/// Parse the APKINDEX text: `key:value` lines in blank-line-separated blocks; `P:` = package
/// name, `V:` = version. A block missing either is skipped (one malformed block never poisons
/// the whole advisory index); first block wins for a repeated name within one index.
fn parse_index_blocks(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for block in text.split("\n\n") {
        let mut name = None;
        let mut version = None;
        for line in block.lines() {
            if let Some(v) = line.strip_prefix("P:") {
                name = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("V:") {
                version = Some(v.trim().to_string());
            }
        }
        if let (Some(n), Some(v)) = (name, version) {
            map.entry(n).or_insert(v);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Build a gzipped tar whose `APKINDEX` member holds `P:`/`V:` blocks — the plain
    /// single-member fixture shape.
    fn apkindex(entries: &[(&str, &str)]) -> Vec<u8> {
        let text: String = entries
            .iter()
            .map(|(p, v)| format!("C:Q1fake=\nP:{p}\nV:{v}\nA:x86_64\n\n"))
            .collect();
        gz(&tar_one("APKINDEX", text.as_bytes()))
    }

    fn gz(buf: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(buf).unwrap();
        e.finish().unwrap()
    }

    fn tar_one(name: &str, content: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, content).unwrap();
        b.into_inner().unwrap()
    }

    struct MapFetcher(BTreeMap<String, Vec<u8>>);

    impl Fetcher for MapFetcher {
        fn get(&self, url: &str) -> Result<Vec<u8>, String> {
            self.0.get(url).cloned().ok_or_else(|| "HTTP 404".into())
        }
    }

    fn pins(build_inputs: &[(&str, &str)]) -> PinnedApks {
        let rows: String = build_inputs
            .iter()
            .map(|(n, v)| {
                format!("[[build_input]]\nname = \"{n}\"\nversion = \"{v}\"\nsha256 = \"aa\"\nsigning_key = \"k\"\n")
            })
            .collect();
        PinnedApks::from_toml_str(&format!("alpine_version = \"3.23\"\n{rows}")).unwrap()
    }

    /// Both repos served from one index body (community may be a distinct body per test).
    fn fetcher_serving(main: Vec<u8>, community: Vec<u8>) -> MapFetcher {
        MapFetcher(BTreeMap::from([
            (apkindex_url("3.23", "main"), main),
            (apkindex_url("3.23", "community"), community),
        ]))
    }

    #[test]
    fn apkindex_url_shape() {
        assert_eq!(
            apkindex_url("3.23", "main"),
            "https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/APKINDEX.tar.gz"
        );
    }

    #[test]
    fn gone_when_pinned_version_absent_from_index() {
        let index = apkindex(&[("linux-virt", "6.18.38-r0")]);
        let f = fetcher_serving(index, apkindex(&[]));
        let report = apk_drift_scan(&pins(&[("linux-virt", "6.18.36-r0")]), &f);
        assert!(report.checked);
        assert_eq!(report.packages.len(), 1);
        let p = &report.packages[0];
        assert_eq!(
            p.state,
            DriftState::Gone,
            "superseded pin on a GC'd mirror = Gone"
        );
        assert_eq!(p.available.as_deref(), Some("6.18.38-r0"));
        assert_eq!(p.pinned, "6.18.36-r0");
    }

    #[test]
    fn gone_with_no_available_when_name_absent_entirely() {
        let f = fetcher_serving(apkindex(&[("musl", "1.2.5-r23")]), apkindex(&[]));
        let report = apk_drift_scan(&pins(&[("linux-virt", "6.18.36-r0")]), &f);
        assert!(report.checked);
        assert_eq!(report.packages[0].state, DriftState::Gone);
        assert_eq!(report.packages[0].available, None, "package gone entirely");
    }

    #[test]
    fn current_when_pinned_equals_index() {
        let f = fetcher_serving(apkindex(&[("linux-virt", "6.18.38-r0")]), apkindex(&[]));
        let report = apk_drift_scan(&pins(&[("linux-virt", "6.18.38-r0")]), &f);
        assert!(report.checked);
        assert_eq!(report.packages[0].state, DriftState::Current);
    }

    #[test]
    fn unreachable_mirror_is_fail_soft() {
        let f = MapFetcher(BTreeMap::new());                     
        let report = apk_drift_scan(&pins(&[("linux-virt", "6.18.36-r0")]), &f);
        assert!(
            !report.checked,
            "unreachable mirror = checked:false, not an error"
        );
        assert!(report.packages.is_empty());
    }

    #[test]
    fn main_and_community_both_consulted() {
                                                                                 
        let f = fetcher_serving(
            apkindex(&[("linux-virt", "6.18.38-r0")]),
            apkindex(&[("syslinux", "6.04_pre1-r15")]),
        );
        let report = apk_drift_scan(
            &pins(&[("linux-virt", "6.18.38-r0"), ("syslinux", "6.04_pre1-r15")]),
            &f,
        );
        assert!(report.checked);
        assert!(report
            .packages
            .iter()
            .all(|p| p.state == DriftState::Current));
    }

    #[test]
    fn main_wins_over_community_for_a_shared_name() {
        let f = fetcher_serving(
            apkindex(&[("linux-virt", "6.18.38-r0")]),
            apkindex(&[("linux-virt", "9.99.99-r0")]),
        );
        let report = apk_drift_scan(&pins(&[("linux-virt", "6.18.38-r0")]), &f);
        assert_eq!(
            report.packages[0].state,
            DriftState::Current,
            "main is authoritative when both repos list a name"
        );
    }

    #[test]
    fn decompression_bomb_is_refused_fail_soft() {
                                                                                               
                                                                                                  
        let bomb_text = vec![b'a'; (APKINDEX_DECOMPRESSED_CEILING + 4096) as usize];
        let bomb = gz(&tar_one("APKINDEX", &bomb_text));
        assert!(
            bomb.len() < 1024 * 1024,
            "the compressed bomb is small — the ceiling is what bounds the decompressed side"
        );
        let f = fetcher_serving(bomb, apkindex(&[]));
        let report = apk_drift_scan(&pins(&[("linux-virt", "6.18.36-r0")]), &f);
        assert!(!report.checked, "over-ceiling index = checked:false");
        assert!(report.packages.is_empty());
    }

    #[test]
    fn garbage_and_missing_member_are_fail_soft() {
                           
        let f = fetcher_serving(b"not gzip".to_vec(), apkindex(&[]));
        assert!(!apk_drift_scan(&pins(&[("linux-virt", "1")]), &f).checked);
                                                  
        let f = fetcher_serving(gz(&tar_one("DESCRIPTION", b"x")), apkindex(&[]));
        assert!(!apk_drift_scan(&pins(&[("linux-virt", "1")]), &f).checked);
    }

    #[test]
    fn live_mirror_shape_two_gzip_members_signature_then_index() {
                                                                                           
                                                                                             
        let sig_entry = tar_one(
            ".SIGN.RSA.alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub",
            b"sig",
        );
                                                                                               
                                                                                                 
        let sig_segment_no_terminator = &sig_entry[..1024];
        let index_text = "C:Q1x=\nP:linux-virt\nV:6.18.38-r0\nA:x86_64\n\n";
        let mut two_members = gz(sig_segment_no_terminator);
        two_members.extend_from_slice(&gz(&tar_one("APKINDEX", index_text.as_bytes())));
        let f = fetcher_serving(two_members, apkindex(&[]));
        let report = apk_drift_scan(&pins(&[("linux-virt", "6.18.36-r0")]), &f);
        assert!(report.checked, "the live two-member shape must parse");
        assert_eq!(report.packages[0].state, DriftState::Gone);
        assert_eq!(report.packages[0].available.as_deref(), Some("6.18.38-r0"));
    }

    #[test]
    fn sanitize_version_strips_control_bytes() {
        assert_eq!(sanitize_version("6.1\x1b[31m8"), "6.1??31m8");                         
        assert!(!sanitize_version("6.1\x1b[31m8").contains('\x1b'));
        let clean = "6.18.38-r0_p1+git~abc";
        assert_eq!(
            sanitize_version(clean),
            clean,
            "clean versions pass through"
        );
        let long = "a".repeat(100);
        assert_eq!(sanitize_version(&long).len(), 64, "over-64-bytes truncates");
        assert_eq!(
            sanitize_version("ver\u{202e}sion"),
            "ver???sion",
            "non-ASCII → per-byte ?"
        );
    }

    #[test]
    fn all_packages_scope_classifies_the_runtime_closure_too() {
        let lock = PinnedApks::from_toml_str(
            "alpine_version = \"3.23\"\n\
             [[package]]\nname = \"musl\"\nversion = \"1.2.5-r23\"\nsha256 = \"aa\"\nsigning_key = \"k\"\n\
             [[build_input]]\nname = \"linux-virt\"\nversion = \"6.18.38-r0\"\nsha256 = \"bb\"\nsigning_key = \"k\"\n",
        )
        .unwrap();
        let f = fetcher_serving(
            apkindex(&[("linux-virt", "6.18.38-r0"), ("musl", "1.2.5-r24")]),
            apkindex(&[]),
        );
        let build_only = apk_drift_scan(&lock, &f);
        assert_eq!(
            build_only.packages.len(),
            1,
            "default scope = build_inputs only"
        );
        let all = apk_drift_scan_scoped(&lock, &f, DriftScope::AllPackages);
        assert_eq!(all.packages.len(), 2);
        let musl = all.packages.iter().find(|p| p.name == "musl").unwrap();
        assert_eq!(
            musl.state,
            DriftState::Gone,
            "superseded runtime pin classifies too"
        );
    }
}
