                                                                                     
//! forbidden_serde_attrs pattern): the PIN-MANIFEST parser (`src/pin_manifest.rs`) must never gain a
//! serde attribute that re-opens the fail-open class — `default`/`flatten`/`untagged`/`alias`/`skip`/
//! internally-tagged (`tag = …`) each silently disable the unknown-field guard or widen the accepted
//! shape past deny_unknown_fields + required-fields. Permitted: `deny_unknown_fields`, `rename`,
//! `rename_all`.
//!
//! SCOPE: this guard reads ONLY `pin_manifest.rs`. The rest of image-builder (config/apk_world/lib …)
//! legitimately uses `#[serde(default)]` etc. on non-pin structs, so a whole-crate scan would false-
//! positive — the pin-manifest contract is what must stay strict, not the whole crate. If a pin-related
//! serde struct is ever added in ANOTHER file (a published-pins/consume-pins loader, or `ArtifactPin`
//! moving), widen the scanned set to include it (F-3b-P1-R1-3). Mirrors fb-manifest's
//! `forbidden_serde_attrs.rs` predicate + its always-run self-test.

/// Substrings that must never appear inside a `#[serde(...)]` attribute on the pin-manifest structs.
const FORBIDDEN: &[&str] = &[
    "flatten", "untagged", "default", "alias", "skip", "tag ", "tag=", "tag\t",
];

/// True iff `line` carries a forbidden serde attribute. Match `serde(` ANYWHERE on a NON-comment line
/// (F-3b-P1-R1-2): the earlier `starts_with("#[serde(")` anchor MISSED `#[cfg_attr(feature = "x",
/// serde(default))]` (the line starts with `#[cfg_attr`) and a second attribute macro on one physical
/// line. Matching `serde(` (not `#[serde(`) is what catches the cfg_attr-smuggled form; the
/// `!starts_with("//")` clause keeps a doc comment that MENTIONS the attrs (pin_manifest.rs's own
/// header) quiet, so the broadened match introduces no false-positive.
fn is_offending_serde_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    !trimmed.starts_with("//")
        && line.contains("serde(")
        && FORBIDDEN.iter().any(|bad| line.contains(bad))
}

#[test]
fn pin_manifest_carries_no_fail_open_serde_attrs() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/pin_manifest.rs"))
        .expect("read pin_manifest.rs");
    let hits: Vec<String> = src
        .lines()
        .enumerate()
        .filter(|(_, l)| is_offending_serde_line(l))
        .map(|(i, l)| format!("{}: {}", i + 1, l.trim()))
        .collect();
    assert!(
        hits.is_empty(),
        "forbidden serde attribute(s) on the pin manifest:\n{}",
        hits.join("\n")
    );
}

/// Self-test (no-false-assurance: a guard that never fires is theater). The predicate FIRES on each
/// forbidden attribute and stays quiet on the whitelisted attrs + on a doc comment that merely mentions
/// the words (pin_manifest.rs's own header is exactly such a line).
#[test]
fn the_guard_detects_violations_and_ignores_safe_lines() {
                                         
    assert!(is_offending_serde_line(r#"    #[serde(default)]"#));
    assert!(is_offending_serde_line(r#"#[serde(default = "x")]"#));
    assert!(is_offending_serde_line(r#"#[serde(flatten)]"#));
    assert!(is_offending_serde_line(r#"#[serde(tag = "kind")]"#));
    assert!(is_offending_serde_line(r#"#[serde(untagged)]"#));
    assert!(is_offending_serde_line(r#"#[serde(alias = "x")]"#));
    assert!(is_offending_serde_line(r#"#[serde(skip_deserializing)]"#));
                                                                    
    assert!(!is_offending_serde_line(
        r#"#[serde(deny_unknown_fields, rename_all = "lowercase")]"#
    ));
    assert!(!is_offending_serde_line(
        r#"    #[serde(rename = "schema-version")]"#
    ));
                                                                                               
    assert!(!is_offending_serde_line(
        r#"//! exactly 64 lowercase hex. NO #[serde(default/flatten/untagged/alias)] anywhere —"#
    ));
                                                                                                    
    assert!(is_offending_serde_line(
        r#"#[cfg_attr(feature = "x", serde(default))]"#
    ));
    assert!(is_offending_serde_line(
        r#"#[derive(Deserialize)] #[serde(default)]"#
    ));
}
