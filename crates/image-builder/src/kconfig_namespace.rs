//! Producer of the C4 gate's Kconfig-namespace fixture, inside the repo's verified-input chain.
//!
//! The fixture (`kconfig-namespace-<version>.txt`) is the sorted `config`/`menuconfig` declaration
//! set of the pinned kernel source, consulted by `tests/kernel_pin_sources.rs` to reject a pin or
                                                                                                    
//! the tree that `sources::extract_verified_xz` unpacks from the `pins.toml [kernel].sha256`-verified
                                                                                                    
//! (version + sha256) verbatim from `pins.toml`, and one [`parse_header`] is the reader the gate uses,
                                                      

use crate::sources::{extract_verified_xz, SourcesError, KERNEL_TAR_CEILING};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum RegenError {
    #[error(
        "tarball sha256 {actual} does not equal pins.toml [kernel].sha256 {expected} — REFUSING \
         (only the pinned bytes may produce a fixture)"
    )]
    ShaMismatch { expected: String, actual: String },
    #[error("verified extraction of the pinned tarball: {0}")]
    Extract(String),
    #[error("no config symbols extracted from the pinned kernel tree — REFUSING an empty fixture")]
    EmptyNamespace,
    #[error("io at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// The version+sha256 a fixture header carries. One reader for the one writer ([`render`]).
#[derive(Debug, PartialEq, Eq)]
pub struct FixtureHeader {
    pub version: String,
    pub sha256: String,
}

/// Parse `# linux-<version> <sha256> kconfig namespace`. Returns None for any other shape (an
/// old two-token `# linux-<version> kconfig namespace`, a missing field, a missing marker).
pub fn parse_header(line: &str) -> Option<FixtureHeader> {
    let mid = line
        .strip_prefix("# linux-")?
        .strip_suffix(" kconfig namespace")?;
    let (version, sha256) = mid.split_once(' ')?;
    if version.is_empty() || sha256.is_empty() || sha256.contains(' ') {
        return None;
    }
    Some(FixtureHeader {
        version: version.to_string(),
        sha256: sha256.to_string(),
    })
}

/// Render the fixture: the header line, then one sorted `CONFIG_<name>` per line. `names` is already
/// the prefixed, `LC_ALL=C`-sorted-unique set (a `BTreeSet<String>` of ASCII strings iterates in byte
/// order).
pub fn render(version: &str, sha256: &str, names: &BTreeSet<String>) -> String {
    let mut s = String::with_capacity(names.len() * 24 + 80);
    s.push_str("# linux-");
    s.push_str(version);
    s.push(' ');
    s.push_str(sha256);
    s.push_str(" kconfig namespace\n");
    for n in names {
        s.push_str(n);
        s.push('\n');
    }
    s
}

fn is_kconfig_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | 0x0b | 0x0c)
}

fn is_symbol_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// The name a `config`/`menuconfig` declaration line declares, or None:
/// `^[[:space:]]*(menu)?config[[:space:]]+([A-Za-z0-9_-]+)[[:space:]]*(#.*)?$`. Returns the bare
/// name; the caller prefixes `CONFIG_`.
pub fn declared_symbol(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len && is_kconfig_space(bytes[i]) {
        i += 1;
    }
    let rest = &line[i..];
    let kw = if rest.starts_with("menuconfig") {
        10
    } else if rest.starts_with("config") {
        6
    } else {
        return None;
    };
    let mut j = i + kw;
    let sep = j;
    while j < len && is_kconfig_space(bytes[j]) {
        j += 1;
    }
    if j == sep {
        return None;                                              
    }
    let sym_start = j;
    while j < len && is_symbol_byte(bytes[j]) {
        j += 1;
    }
    if j == sym_start {
        return None;                
    }
    let symbol = &line[sym_start..j];
    while j < len && is_kconfig_space(bytes[j]) {
        j += 1;
    }
    if j < len {
        if bytes[j] == b'#' {
            j = len;                                              
        } else {
            return None;                                                          
        }
    }
    if j != len {
        return None;
    }
    Some(symbol)
}

/// Every `CONFIG_<name>` a source tree declares, sorted-unique. Walks `Kconfig*` regular files
/// (symlinks skipped), reading each and collecting [`declared_symbol`] hits. Files under
                                                                                                    
/// declared by a Kconfig file outside those two trees, per-architecture reachability not evaluated.
/// Lines split on `\n` with a trailing `\r` stripped; the Kconfig lexer does not strip it
/// (warn_ignored_character).
pub fn namespace_of_tree(tree: &Path) -> Result<BTreeSet<String>, RegenError> {
    let mut names = BTreeSet::new();
    walk(tree, tree, &mut names)?;
    Ok(names)
}

                                                  
const EXCLUDED_SUBTREES: [&str; 2] = ["scripts/kconfig/tests", "Documentation/kbuild"];

fn is_excluded_subtree(root: &Path, dir: &Path) -> bool {
    dir.strip_prefix(root)
        .map(|rel| EXCLUDED_SUBTREES.iter().any(|e| rel == Path::new(e)))
        .unwrap_or(false)
}

fn walk(root: &Path, dir: &Path, names: &mut BTreeSet<String>) -> Result<(), RegenError> {
    let entries = std::fs::read_dir(dir).map_err(|source| RegenError::Io {
        path: dir.display().to_string(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| RegenError::Io {
            path: dir.display().to_string(),
            source,
        })?;
        let ft = entry.file_type().map_err(|source| RegenError::Io {
            path: entry.path().display().to_string(),
            source,
        })?;
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if !is_excluded_subtree(root, &entry.path()) {
                walk(root, &entry.path(), names)?;
            }
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        if !entry.file_name().to_string_lossy().starts_with("Kconfig") {
            continue;
        }
        let path = entry.path();
        let text = std::fs::read(&path).map_err(|source| RegenError::Io {
            path: path.display().to_string(),
            source,
        })?;
        collect_from_bytes(&text, names);
    }
    Ok(())
}

fn collect_from_bytes(bytes: &[u8], names: &mut BTreeSet<String>) {
    for raw in bytes.split(|&b| b == b'\n') {
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        let Ok(line) = std::str::from_utf8(raw) else {
            continue;
        };
        if let Some(sym) = declared_symbol(line) {
            names.insert(format!("CONFIG_{sym}"));
        }
    }
}

/// What a regen produced.
#[derive(Debug)]
pub struct Regen {
    pub name_count: usize,
    pub out_path: PathBuf,
}

/// Extract the sha-verified pinned tarball, collect its Kconfig namespace, and atomically write the
/// fixture to `out_path`. The sha gate is `extract_verified_xz`'s `ExpectPin`, which refuses before
/// any decode; `sha256` is `pins.toml [kernel].sha256` and the header restates `version` + `sha256`
/// verbatim. Refuses an empty namespace. On any failure an existing fixture at `out_path` is left
/// byte-intact and the temp file is removed.
pub fn regenerate(
    xz: &[u8],
    version: &str,
    sha256: &str,
    out_path: &Path,
) -> Result<Regen, RegenError> {
                                                                                      
    let actual = hex::encode(Sha256::digest(xz));
    if actual != sha256 {
        return Err(RegenError::ShaMismatch {
            expected: sha256.to_string(),
            actual,
        });
    }

    let holder = tempfile::tempdir().map_err(|source| RegenError::Io {
        path: "extract holder tempdir".to_string(),
        source,
    })?;
    let dest = holder.path().join("src");
    std::fs::create_dir(&dest).map_err(|source| RegenError::Io {
        path: dest.display().to_string(),
        source,
    })?;
    let (_verified, inner) = extract_verified_xz(xz, sha256, KERNEL_TAR_CEILING, &dest)
        .map_err(|e: SourcesError| RegenError::Extract(e.to_string()))?;

    let names = namespace_of_tree(&inner)?;
    if names.is_empty() {
        return Err(RegenError::EmptyNamespace);
    }
    let content = render(version, sha256, &names);

    let out_dir = out_path.parent().ok_or_else(|| RegenError::Io {
        path: out_path.display().to_string(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "out path has no parent dir",
        ),
    })?;
    let mut tmp = tempfile::NamedTempFile::new_in(out_dir).map_err(|source| RegenError::Io {
        path: out_dir.display().to_string(),
        source,
    })?;
    std::io::Write::write_all(&mut tmp, content.as_bytes()).map_err(|source| RegenError::Io {
        path: "fixture temp".to_string(),
        source,
    })?;
                                                                                               
                                                       
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .map_err(|source| RegenError::Io {
                path: "fixture temp".to_string(),
                source,
            })?;
    }
    tmp.persist(out_path).map_err(|e| RegenError::Io {
        path: out_path.display().to_string(),
        source: e.error,
    })?;
    Ok(Regen {
        name_count: names.len(),
        out_path: out_path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_symbol_matches_both_keywords_and_a_trailing_comment() {
        assert_eq!(declared_symbol("config FOO"), Some("FOO"));
        assert_eq!(declared_symbol("menuconfig BAR"), Some("BAR"));
        assert_eq!(declared_symbol("config FOO # help"), Some("FOO"));
        assert_eq!(declared_symbol("config FOO\t"), Some("FOO"));
        assert_eq!(declared_symbol("\tconfig FOO"), Some("FOO"));
        assert_eq!(declared_symbol("config FOO   #x"), Some("FOO"));
    }

    #[test]
    fn declared_symbol_rejects_the_negative_shapes() {
        for bad in [
            "#config FOO",                                      
            "config",                                       
            "config FOO bar",                                     
            "myconfig FOO",                                       
            "menu config FOO",                                  
            "configFOO",                                                             
            "  help",                                       
            "\tThis symbol enables config FOO",                                
            "",                                         
        ] {
            assert_eq!(declared_symbol(bad), None, "should reject: {bad:?}");
        }
    }

    #[test]
    fn indented_choice_block_declarations_are_accepted() {
                                                                         
        assert_eq!(declared_symbol("  config FOO"), Some("FOO"));
    }

    #[test]
    fn namespace_of_tree_collects_and_sorts_prefixed_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Kconfig"),
            b"config ZED\nmenuconfig ALPHA\n# comment\nconfig ZED\nsome prose\n",
        )
        .unwrap();
        let sub = dir.path().join("drivers");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("Kconfig.debug"), b"config MID\n").unwrap();
        std::fs::write(sub.join("notes.txt"), b"config SKIP\n").unwrap();
        let ns = namespace_of_tree(dir.path()).unwrap();
        let got: Vec<&str> = ns.iter().map(String::as_str).collect();
        assert_eq!(got, ["CONFIG_ALPHA", "CONFIG_MID", "CONFIG_ZED"]);
    }

    #[test]
    fn walk_skips_the_kconfig_test_and_kbuild_example_subtrees() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("Kconfig"), b"config REAL\n").unwrap();
        let excl_tests = root.join("scripts/kconfig/tests/choice0");
        std::fs::create_dir_all(&excl_tests).unwrap();
        std::fs::write(excl_tests.join("Kconfig"), b"config TESTFIXTURE\n").unwrap();
        let excl_kbuild = root.join("Documentation/kbuild");
        std::fs::create_dir_all(&excl_kbuild).unwrap();
        std::fs::write(
            excl_kbuild.join("Kconfig.recursion"),
            b"config DOCEXAMPLE\n",
        )
        .unwrap();
        let kept_scripts = root.join("scripts/gcc-plugins");
        std::fs::create_dir_all(&kept_scripts).unwrap();
        std::fs::write(kept_scripts.join("Kconfig"), b"config KEPTSCRIPTS\n").unwrap();
                                                                                                
                                                               
        let near_tests = root.join("scripts/kconfig/tests-extra");
        std::fs::create_dir_all(&near_tests).unwrap();
        std::fs::write(near_tests.join("Kconfig"), b"config NEARTESTS\n").unwrap();
        let near_kbuild = root.join("Documentation/kbuild-extra");
        std::fs::create_dir_all(&near_kbuild).unwrap();
        std::fs::write(near_kbuild.join("Kconfig"), b"config NEARKBUILD\n").unwrap();
        let ns = namespace_of_tree(root).unwrap();
        let got: Vec<&str> = ns.iter().map(String::as_str).collect();
        assert_eq!(
            got,
            [
                "CONFIG_KEPTSCRIPTS",
                "CONFIG_NEARKBUILD",
                "CONFIG_NEARTESTS",
                "CONFIG_REAL"
            ]
        );
    }

    #[test]
    fn header_round_trips_and_rejects_the_old_two_token_form() {
        let mut names = BTreeSet::new();
        names.insert("CONFIG_A".to_string());
        let sha = "a".repeat(64);
        let content = render("6.18.34", &sha, &names);
        let first = content.lines().next().unwrap();
        assert_eq!(first, format!("# linux-6.18.34 {sha} kconfig namespace"));
        let h = parse_header(first).unwrap();
        assert_eq!(h.version, "6.18.34");
        assert_eq!(h.sha256, sha);
                             
        assert_eq!(parse_header("# linux-6.18.34 kconfig namespace"), None);
        assert_eq!(parse_header("# linux- kconfig namespace"), None);
        assert_eq!(parse_header("random line"), None);
    }

    fn xz_of(tar: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = liblzma::write::XzEncoder::new(Vec::new(), 6);
        enc.write_all(tar).unwrap();
        enc.finish().unwrap()
    }

    fn tar_topdir(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut dh = tar::Header::new_gnu();
        dh.set_entry_type(tar::EntryType::Directory);
        dh.set_size(0);
        dh.set_mode(0o755);
        dh.set_mtime(0);
        b.append_data(&mut dh, "linux-9.9/", &[][..]).unwrap();
        for (path, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(0);
            b.append_data(&mut h, path, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn regenerate_writes_the_fixture_and_is_idempotent() {
        let tar = tar_topdir(&[("linux-9.9/Kconfig", b"config FOO\nmenuconfig BAR\n")]);
        let xz = xz_of(&tar);
        let sha = hex::encode(Sha256::digest(&xz));
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("kconfig-namespace-9.9.txt");
        let r = regenerate(&xz, "9.9", &sha, &out).unwrap();
        assert_eq!(r.name_count, 2);
        let text = std::fs::read_to_string(&out).unwrap();
        assert_eq!(
            text,
            format!("# linux-9.9 {sha} kconfig namespace\nCONFIG_BAR\nCONFIG_FOO\n")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&out).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o644, "fixture mode");
        }
                                    
        regenerate(&xz, "9.9", &sha, &out).unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), text);
    }

    #[test]
    fn regenerate_refuses_a_sha_mismatch_and_leaves_an_existing_fixture_intact() {
        let tar = tar_topdir(&[("linux-9.9/Kconfig", b"config FOO\n")]);
        let xz = xz_of(&tar);
        let real = hex::encode(Sha256::digest(&xz));
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("kconfig-namespace-9.9.txt");
        std::fs::write(&out, b"PRIOR").unwrap();
        let wrong = "0".repeat(64);
        let err = regenerate(&xz, "9.9", &wrong, &out).unwrap_err();
        match &err {
            RegenError::ShaMismatch { expected, actual } => {
                assert_eq!(expected, &wrong);
                assert_eq!(actual, &real);
            }
            other => panic!("expected ShaMismatch, got {other}"),
        }
        assert_eq!(std::fs::read(&out).unwrap(), b"PRIOR");
        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp"))
            .collect();
        assert!(leftover.is_empty(), "no temp left behind");
    }

    #[test]
    fn regenerate_refuses_an_empty_namespace() {
        let tar = tar_topdir(&[("linux-9.9/README", b"no kconfig here\n")]);
        let xz = xz_of(&tar);
        let sha = hex::encode(Sha256::digest(&xz));
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("kconfig-namespace-9.9.txt");
        let err = regenerate(&xz, "9.9", &sha, &out).unwrap_err();
        assert!(matches!(err, RegenError::EmptyNamespace), "got {err}");
        assert!(!out.exists(), "no fixture written on refusal");
    }
}
