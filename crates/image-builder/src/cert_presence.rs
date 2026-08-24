//! §3a-7 cert-presence (the hot half of the cert-staleness control): the certification trail can't
//! bare-quote a live pin. For every CURRENT pin value, scan the cert trail; any file quoting that 64-hex
//! must license it with a front-matter `certifies-pin: <key> = <sha>`, OR be named in the reviewed
//! file-level allowlist (a from-pins BUILD RECORD or an audit report quoting a pin as evidence, not a
//! certification). The universe is the finite set of current pin values, so this is allowlist-shaped.
//!
                                                                                                          
//! a superseded cert's pin is non-current by definition, so it is auto-exempt via the universe (a stale
//! value matches no current pin), and a `superseded-by:` file that ALSO quotes a *live* pin must still
//! red. `superseded-by:` is a `--certs`-only annotation (the §3b staleness assertion), wired in Task 12.
//!
                                                                                                      
//! caller passes `audits_root` explicitly; allowlist paths are relative to it. The self-test runs against
//! a SYNTHETIC fixture tree (not the live trail), so it is non-vacuous independent of the retrofit state.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::pin_manifest::PinManifest;
use crate::pins::Pins;

/// One file that bare-quotes a current pin value with no licensing marker — a §3a-7 reder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reder {
    /// The reding file, relative to the cert-trail root.
    pub file: String,
    /// The current pin value (64-hex) it quotes without a `certifies-pin:` marker or allowlist entry.
    pub sha: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CertPresenceError {
    #[error("io {path}: {reason}")]
    Io { path: String, reason: String },
    #[error("{}", fmt_reders(.0))]
    BareQuotes(Vec<Reder>),
}

/// Render every reder as its own line (collect-all — the retrofit needs the FULL list in one pass, not
/// fail-on-first; each line names the file + the pin it must mark or allowlist).
fn fmt_reders(reders: &[Reder]) -> String {
    let mut s = format!(
        "{} cert-trail file(s) bare-quote a current pin with no `certifies-pin:` marker and no \
         market-cert-allowlist.toml entry (cert vs build-record — -7/§3b):",
        reders.len()
    );
    for r in reders {
        s.push_str(&format!("\n  {} quotes {}", r.file, r.sha));
    }
    s
}

/// The finite universe of CURRENT pin values §3a-7 polices: the 13 `consume-pins` values + the 3
/// `pins.toml` upstream pins (kernel/syslinux sha256 + the rust container digest's hex) + the
/// `[kernel-keyring]` vendored-file shas (§3a-8 — pins like any other). The per-package apk shas are
/// excluded (certs don't quote them; the closure is guarded by §3a-6).
pub fn current_pin_values(consume: &PinManifest, pins: &Pins) -> BTreeSet<String> {
    let mut s: BTreeSet<String> = consume
        .artifacts
        .values()
        .map(|p| p.sha256.clone())
        .collect();
    s.insert(pins.kernel.sha256.clone());
    s.insert(pins.syslinux.sha256.clone());
                                                                         
    let digest = &pins.rust.container_digest;
    s.insert(digest.strip_prefix("sha256:").unwrap_or(digest).to_string());
    for sha in pins
        .kernel_keyring
        .values()
        .chain(pins.rust_keyring.values())
    {
        s.insert(sha.clone());
    }
    s
}

/// The CURRENT pin value BY KEY (lowercase canonical) — the same universe as [`current_pin_values`], keyed so
/// the `--certs` §3b staleness assertion can check a `certifies-pin: <key> = <sha>` against the live pin for
/// that exact key. Keys: the 13 `consume-pins` keys + `kernel`/`syslinux`/`rust` (the `pins.toml` upstreams)
/// + `kernel-keyring/<file>` per vendored keyring pin (§3a-8).
pub fn current_pin_map(consume: &PinManifest, pins: &Pins) -> BTreeMap<String, String> {
    let mut m: BTreeMap<String, String> = consume
        .artifacts
        .iter()
        .map(|(k, p)| (k.clone(), p.sha256.to_ascii_lowercase()))
        .collect();
    m.insert(
        "kernel".to_string(),
        pins.kernel.sha256.to_ascii_lowercase(),
    );
    m.insert(
        "syslinux".to_string(),
        pins.syslinux.sha256.to_ascii_lowercase(),
    );
    let digest = &pins.rust.container_digest;
    m.insert(
        "rust".to_string(),
        digest
            .strip_prefix("sha256:")
            .unwrap_or(digest)
            .to_ascii_lowercase(),
    );
    for (file, sha) in &pins.kernel_keyring {
        m.insert(format!("kernel-keyring/{file}"), sha.to_ascii_lowercase());
    }
    for (file, sha) in &pins.rust_keyring {
        m.insert(format!("rust-keyring/{file}"), sha.to_ascii_lowercase());
    }
    m
}

/// The reviewed file-level allowlist (`market-cert-allowlist.toml`): files under the cert trail that
/// RECORD the pins they built from (a from-pins boot record) rather than CERTIFY a pin. Paths are relative
/// to `audits_root`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertAllowlist {
    #[serde(rename = "schema-version")]
    pub schema_version: u32,
    #[serde(default)]
    pub files: Vec<String>,
}

impl CertAllowlist {
    pub fn from_toml_str(s: &str) -> Result<Self, String> {
        toml::from_str(s).map_err(|e| e.to_string())
    }

    /// Load the allowlist, or an empty one if the file is absent (an empty allowlist allows nothing).
    pub fn load_or_empty(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::from_toml_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    fn allows(&self, rel: &str) -> bool {
        self.files.iter().any(|f| f == rel)
    }
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b)
}

/// Maximal hex runs of EXACTLY 64 chars (the canonical pin-token shape). Case-insensitive (the caller
                                                                                                           
/// it matches only a canonical pin token and won't false-positive on a 128-hex sha512 / KAT vector that
/// merely CONTAINS a 64-run. Split-across-whitespace or padded-longer-run quotes are outside this
/// canonical-token model by design (a reader doesn't parse `<pin> f` or `<pin>\n` as the pin).
fn scan_64hex(body: &str) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if is_hex(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_hex(bytes[i]) {
                i += 1;
            }
            if i - start == 64 {
                out.push(&body[start..i]);
            }
        } else {
            i += 1;
        }
    }
    out
}

/// A `certifies-pin: <key> = <64hex>` line → its `(key, 64-hex sha)`.
fn certifies_pin_kv(line: &str) -> Option<(&str, &str)> {
    let l = line.trim_start();
    let rest = l.strip_prefix("certifies-pin:")?;
    let (key, sha) = rest.split_once('=')?;
    let key = key.trim();
    let sha = sha.trim().trim_matches(['"', '`', '\'']);
    (!key.is_empty() && sha.len() == 64 && sha.bytes().all(is_hex)).then_some((key, sha))
}

/// A `certifies-pin: <key> = <64hex>` line → the licensed 64-hex sha (the presence-scan view; drops the key).
fn certifies_pin_sha(line: &str) -> Option<&str> {
    certifies_pin_kv(line).map(|(_key, sha)| sha)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if p.is_dir() {
            walk(&p, out)?;
        } else {
            out.push(p);
        }
    }
    Ok(())
}

/// §3a-7 (collect-all): scan `audits_root` (the cert trail) and return EVERY reder — any file quoting a
/// CURRENT pin value without licensing it (a `certifies-pin: <key> = <thatsha>` marker, a `superseded-by:`
/// marker, or a `market-cert-allowlist.toml` entry). Returns ALL reders in one pass (the retrofit needs the
/// full list, not fail-on-first); a file quoting the same current pin repeatedly counts once. An absent
/// `audits_root` is an empty scan (nothing to police) — the caller decides whether the trail must exist.
pub fn scan_reders(
    audits_root: &Path,
    current: &BTreeSet<String>,
    allowlist: &CertAllowlist,
) -> Result<Vec<Reder>, CertPresenceError> {
    let mut files = Vec::new();
    if audits_root.is_dir() {
        walk(audits_root, &mut files).map_err(|e| CertPresenceError::Io {
            path: audits_root.display().to_string(),
            reason: e.to_string(),
        })?;
    }
    let mut reders = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(audits_root)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        if allowlist.allows(&rel) {
            continue;
        }
        let bytes = std::fs::read(&f).map_err(|e| CertPresenceError::Io {
            path: f.display().to_string(),
            reason: e.to_string(),
        })?;
                                                                                                        
                                                                                                       
                                                                                                        
                                                                                                   
                                                                                                              
        let body = String::from_utf8_lossy(&bytes).into_owned();
        let licensed: BTreeSet<String> = body
            .lines()
            .filter_map(certifies_pin_sha)
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let mut seen_in_file: BTreeSet<String> = BTreeSet::new();
        for tok in scan_64hex(&body) {
                                                                                                        
                                                                                                      
                                                                                                         
            let tok = tok.to_ascii_lowercase();
            if current.contains(&tok)
                && !licensed.contains(&tok)
                && seen_in_file.insert(tok.clone())
            {
                reders.push(Reder {
                    file: rel.clone(),
                    sha: tok,
                });
            }
        }
    }
    Ok(reders)
}

/// §3a-7 (fail-closed): the hot-path gate — [`scan_reders`], then HARD FAIL listing every reder if any
/// remain. Zero reders ⟹ the cert trail is clean (every current-pin quote is marked or allowlisted).
pub fn check_cert_presence(
    audits_root: &Path,
    current: &BTreeSet<String>,
    allowlist: &CertAllowlist,
) -> Result<(), CertPresenceError> {
    let reders = scan_reders(audits_root, current, allowlist)?;
    if reders.is_empty() {
        Ok(())
    } else {
        Err(CertPresenceError::BareQuotes(reders))
    }
}

/// One `certifies-pin: <key> = <sha>` whose `sha` is NOT the current pin for `key` — a live cert gone stale
/// (the §3b staleness defect the `--certs` thorough mode catches).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleCert {
    /// The certifying file, relative to the cert-trail root.
    pub file: String,
    /// The key the cert claims to certify.
    pub key: String,
    /// The 64-hex the cert quotes (lowercased).
    pub quoted: String,
    /// The current pin for `key` (lowercased), or `None` if `key` is not a current pin key at all.
    pub current: Option<String>,
}

/// True iff `body` carries a `superseded-by:` front-matter marker — a deliberately retired cert, whose
/// `certifies-pin` quotes a now-stale pin by design (so the §3b staleness assertion skips it). NB: this is
                                                                                                               
/// reds in [`scan_reders`]; the marker only annotates the cert as retired for the staleness view.
fn has_superseded_marker(body: &str) -> bool {
    body.lines()
        .any(|l| l.trim_start().starts_with("superseded-by:"))
}

/// §3b staleness (`--certs`, collect-all): scan `audits_root` and return EVERY non-`superseded-by`
/// `certifies-pin: <key> = <sha>` whose `sha` is not the live pin for `key` (a stale live cert, or a cert for
/// an unknown key). `current_map` is keyed lowercase ([`current_pin_map`]); the quoted sha is lowercased
/// before comparison so case can't hide a match. An absent `audits_root` is an empty scan.
pub fn scan_stale_certs(
    audits_root: &Path,
    current_map: &BTreeMap<String, String>,
) -> Result<Vec<StaleCert>, CertPresenceError> {
    let mut files = Vec::new();
    if audits_root.is_dir() {
        walk(audits_root, &mut files).map_err(|e| CertPresenceError::Io {
            path: audits_root.display().to_string(),
            reason: e.to_string(),
        })?;
    }
    let mut stale = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(audits_root)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = std::fs::read(&f).map_err(|e| CertPresenceError::Io {
            path: f.display().to_string(),
            reason: e.to_string(),
        })?;
        let body = String::from_utf8_lossy(&bytes).into_owned();
                                                                                                              
                                                                                    
        if has_superseded_marker(&body) {
            continue;
        }
        for line in body.lines() {
                                                                                                       
                                                                                                           
            if !line.trim_start().starts_with("certifies-pin:") {
                continue;
            }
            match certifies_pin_kv(line) {
                Some((key, sha)) => {
                    let quoted = sha.to_ascii_lowercase();
                    match current_map.get(key) {
                        Some(cur) if *cur == quoted => {}                                 
                        other => stale.push(StaleCert {
                            file: rel.clone(),
                            key: key.to_string(),
                            quoted,
                            current: other.cloned(),
                        }),
                    }
                }
                                                                                                       
                                                                                                              
                                                                                                         
                                                                 
                None => {
                    let key = line
                        .trim_start()
                        .strip_prefix("certifies-pin:")
                        .and_then(|rest| rest.split_once('='))
                        .map(|(k, _)| k.trim().to_string())
                        .filter(|k| !k.is_empty())
                        .unwrap_or_else(|| "(unparsed)".to_string());
                    stale.push(StaleCert {
                        file: rel.clone(),
                        key,
                        quoted: "(malformed — the value is not a single 64-hex token)".to_string(),
                        current: None,
                    });
                }
            }
        }
    }
    Ok(stale)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current() -> BTreeSet<String> {
                                       
        ["a".repeat(64)].into_iter().collect()
    }

    fn audits(files: &[(&str, &str)]) -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        for (rel, body) in files {
            let p = t.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        t
    }

    fn empty() -> CertAllowlist {
        CertAllowlist {
            schema_version: 1,
            files: vec![],
        }
    }

    #[test]
    fn bare_quote_of_a_current_pin_fails() {
        let cur = current();
        let a = "a".repeat(64);
        let t = audits(&[("c1.md", &format!("the dragonfruit-src pin is {a}\n"))]);
        match check_cert_presence(t.path(), &cur, &empty()) {
            Err(CertPresenceError::BareQuotes(reders)) => {
                assert_eq!(
                    reders,
                    vec![Reder {
                        file: "c1.md".into(),
                        sha: a
                    }]
                );
            }
            other => panic!("a bare-quoted current pin must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn scan_reders_collects_every_reding_file() {
                                                                                                            
                                                                                               
        let cur = current();
        let a = "a".repeat(64);
        let t = audits(&[
            ("a/c1.md", &format!("pin {a} appears {a} twice here\n")),
            ("b/c2.md", &format!("and again {a}\n")),
        ]);
        let mut reders = scan_reders(t.path(), &cur, &empty()).unwrap();
        reders.sort_by(|x, y| x.file.cmp(&y.file));
        assert_eq!(
            reders,
            vec![
                Reder {
                    file: "a/c1.md".into(),
                    sha: a.clone()
                },
                Reder {
                    file: "b/c2.md".into(),
                    sha: a
                },
            ]
        );
    }

    #[test]
    fn certifies_pin_marker_licenses_the_quote() {
        let cur = current();
        let a = "a".repeat(64);
        let t = audits(&[(
            "c1.md",
            &format!("certifies-pin: dragonfruit-src = {a}\n\nthe pin {a} is current\n"),
        )]);
        assert!(check_cert_presence(t.path(), &cur, &empty()).is_ok());
    }

    #[test]
    fn superseded_by_does_not_exempt_a_current_pin_quote() {
                                                                                                       
                                                                                                          
                                                                                            
        let cur = current();
        let a = "a".repeat(64);
        let t = audits(&[(
            "c1.md",
            &format!("superseded-by: deadbeefcommit\n\nbut still bare-quotes a live pin {a}\n"),
        )]);
        match check_cert_presence(t.path(), &cur, &empty()) {
            Err(CertPresenceError::BareQuotes(reders)) => {
                assert_eq!(reders.len(), 1);
                assert_eq!(reders[0].sha, a);
            }
            other => {
                panic!("a superseded-by file quoting a live pin must still red, got {other:?}")
            }
        }
    }

    #[test]
    fn an_uppercase_quote_of_a_live_pin_is_caught() {
                                                                                                     
        let cur = current();
        let upper = "A".repeat(64);                                                       
        let t = audits(&[("c1.md", &format!("the pin is {upper}\n"))]);
        match check_cert_presence(t.path(), &cur, &empty()) {
            Err(CertPresenceError::BareQuotes(reders)) => {
                assert_eq!(
                    reders[0].sha,
                    "a".repeat(64),
                    "reported normalized to lowercase"
                );
            }
            other => panic!("an uppercase live-pin quote must red, got {other:?}"),
        }
    }

    #[test]
    fn a_text_cert_with_a_stray_byte_is_still_policed() {
                                                                                                         
                                                                                             
        let cur = current();
        let a = "a".repeat(64);
        let mut body = format!("a live pin {a} ").into_bytes();
        body.push(0xff);                                                    
        body.extend_from_slice(b"\n");
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("c.md"), body).unwrap();
        match check_cert_presence(t.path(), &cur, &empty()) {
            Err(CertPresenceError::BareQuotes(reders)) => assert_eq!(reders[0].sha, a),
            other => panic!("a stray byte must not hide a reding cert, got {other:?}"),
        }
    }

    #[test]
    fn allowlisted_build_record_is_skipped() {
        let cur = current();
        let a = "a".repeat(64);
        let t = audits(&[(
            "blocker/boot-gate-frompins.md",
            &format!("built from {a}\n"),
        )]);
        let al = CertAllowlist {
            schema_version: 1,
            files: vec!["blocker/boot-gate-frompins.md".to_string()],
        };
        assert!(check_cert_presence(t.path(), &cur, &al).is_ok());
    }

    #[test]
    fn non_utf8_attachment_is_skipped_not_an_error() {
                                                                                                         
                                                                                                    
        let cur = current();
        let a = "a".repeat(64);
        let t = audits(&[("c.md", &format!("bare {a}\n"))]);
        std::fs::write(t.path().join("shot.png"), [0xff, 0xd8, 0xff, 0xe0]).unwrap();
        let reders = scan_reders(t.path(), &cur, &empty()).unwrap();
        assert_eq!(
            reders,
            vec![Reder {
                file: "c.md".into(),
                sha: a
            }]
        );
    }

    #[test]
    fn non_current_hex_is_never_policed() {
        let cur = current();
        let b = "b".repeat(64);                    
        let t = audits(&[("c1.md", &format!("a verity root hash {b}\n"))]);
        assert!(check_cert_presence(t.path(), &cur, &empty()).is_ok());
    }

                                             

    fn current_map() -> BTreeMap<String, String> {
                                                            
        [("dragonfruit-src".to_string(), "a".repeat(64))]
            .into_iter()
            .collect()
    }

    #[test]
    fn a_certifies_pin_matching_the_live_pin_is_clean() {
        let a = "a".repeat(64);
        let t = audits(&[("c1.md", &format!("certifies-pin: dragonfruit-src = {a}\n"))]);
        assert!(scan_stale_certs(t.path(), &current_map())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_certifies_pin_quoting_a_non_current_sha_is_flagged_stale() {
                                                                                                             
                                                              
        let b = "b".repeat(64);
        let t = audits(&[("c1.md", &format!("certifies-pin: dragonfruit-src = {b}\n"))]);
        let stale = scan_stale_certs(t.path(), &current_map()).unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].key, "dragonfruit-src");
        assert_eq!(stale[0].quoted, b);
        assert_eq!(stale[0].current.as_deref(), Some("a".repeat(64).as_str()));
    }

    #[test]
    fn a_superseded_cert_with_a_stale_pin_is_not_flagged() {
                                                                                                              
                                                                                             
        let b = "b".repeat(64);
        let t = audits(&[(
            "c1.md",
            &format!("superseded-by: abc123commit\ncertifies-pin: dragonfruit-src = {b}\n"),
        )]);
        assert!(scan_stale_certs(t.path(), &current_map())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_certifies_pin_for_an_unknown_key_is_flagged() {
                                                                                                          
                                                                    
        let a = "a".repeat(64);
        let t = audits(&[("c1.md", &format!("certifies-pin: ghost = {a}\n"))]);
        let stale = scan_stale_certs(t.path(), &current_map()).unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].key, "ghost");
        assert_eq!(stale[0].current, None);
    }

    #[test]
    fn a_certifies_pin_with_a_trailing_annotation_fails_closed() {
                                                                                                            
                                                                                                           
                                                                                                         
        let b = "b".repeat(64);                                             
        for body in [
            format!("certifies-pin: dragonfruit-src = {b} = note\n"),
            format!("certifies-pin: dragonfruit-src = {b}  (bumped 2026-06)\n"),
            format!("certifies-pin: dragonfruit-src = {b}, see commit\n"),
        ] {
            let t = audits(&[("c1.md", &body)]);
            let stale = scan_stale_certs(t.path(), &current_map()).unwrap();
            assert_eq!(
                stale.len(),
                1,
                "trailing-annotated cert must be flagged: {body:?}"
            );
            assert_eq!(stale[0].key, "dragonfruit-src");
        }
    }

    #[test]
    fn prose_mentioning_certifies_pin_midline_is_not_flagged() {
                                                                                                            
                                                                                                        
        let b = "b".repeat(64);
        let t = audits(&[(
            "c1.md",
            &format!(
                "Per the spec, a cert must carry `certifies-pin: K = {b}` in its front-matter.\n"
            ),
        )]);
        assert!(scan_stale_certs(t.path(), &current_map())
            .unwrap()
            .is_empty());
    }
}
