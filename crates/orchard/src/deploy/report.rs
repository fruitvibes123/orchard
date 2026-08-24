                                                                                              
//! HEALTHY bulk to a count, always ITEMIZES anomalies/actionables (columnar, sorted by the caller),
//! and ABBREVIATES digests to 12-hex git-style for DISPLAY only. Classification, pruning, and every
//! integrity decision keep the full sha internally; a `--full` flag restores 64-hex. Applied to
//! `market store status`/`prune` + `restore-image`.

use recipes_image_builder::restore_image::StagedManifestEntry;

/// Abbreviate each sha to 12-hex (git-style), auto-extending the width (in 4-hex steps) to the
/// shortest length at which every DISPLAYED prefix in the slice is unique. `full` ⇒ the 64-hex
/// verbatim. DISPLAY-ONLY — never used for classification/pruning/integrity.
pub fn abbrev_digests(shas: &[String], full: bool) -> Vec<String> {
    if full {
        return shas.to_vec();
    }
    let mut width = 12;
    loop {
        let prefixes: Vec<String> = shas
            .iter()
            .map(|s| s.chars().take(width).collect())
            .collect();
        let unique: std::collections::HashSet<&String> = prefixes.iter().collect();
                                                                                                 
        if unique.len() == prefixes.len() || width >= 64 {
            return prefixes;
        }
        width += 4;
    }
}

/// A small binary size humanizer for the rollup line.
fn human_size(bytes: u64) -> String {
    const U: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < 3 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// The restore-image staged-manifest report (Component 8 / 8c). DEFAULT = a per-top-level-directory
/// rollup (count + total size per dir; dir-less entries collect under `(root)` so nothing falls out
/// of the rollup silently), PLUS always-itemized anomaly rows — the db target, ANY `authorized_keys`
/// entry present in the staged tar (a data-tar-smuggled login key — the LEGIT operator pubkey is
/// staged out-of-band, never a manifest entry, and is verified separately by `prod --restore-from`),
/// and every entry whose owner DEVIATES from the resolved db-owner (the class the manifest exists to
/// surface). `full` ⇒ the complete per-file dump of THIS manifest. The reviewable trail is the rollup;
/// the full dump is on demand; the retained daily tars stay ground truth.
pub fn restore_manifest_rollup(
    entries: &[StagedManifestEntry],
    resolved_owner: (u32, u32),
    db_rel: &str,
    full: bool,
) -> String {
    if full {
        let mut s = format!("staged manifest ({} entries):\n", entries.len());
        s.push_str(&format!(
            "  {:>10}  {:>11}  {:>6}  path\n",
            "size", "owner", "mode"
        ));
        for e in entries {
            s.push_str(&format!(
                "  {:>10}  {:>5}:{:<5}  {:>6o}  {}\n",
                e.size, e.uid, e.gid, e.mode, e.path
            ));
        }
        return s;
    }
                                                                                                 
                                                                                                        
                                                                                                    
                                                                                                      
    let is_anomaly = |e: &StagedManifestEntry| -> bool {
        e.path == db_rel || e.path.contains("authorized_keys") || (e.uid, e.gid) != resolved_owner
    };
    let mut groups: std::collections::BTreeMap<String, (usize, u64)> =
        std::collections::BTreeMap::new();
    for e in entries {
        let dir = match e.path.split_once('/') {
            Some((d, _)) => d.to_string(),
            None => "(root)".to_string(),
        };
        let g = groups.entry(dir).or_insert((0, 0));
        g.0 += 1;
        g.1 += e.size;
    }
    let mut s = format!(
        "staged manifest: {} entries in {} top-level group(s), resolved owner {}:{}\n",
        entries.len(),
        groups.len(),
        resolved_owner.0,
        resolved_owner.1
    );
    for (dir, (count, total)) in &groups {
        s.push_str(&format!(
            "  {dir}/  {count} entries, {}\n",
            human_size(*total)
        ));
    }
    let anomalies: Vec<&StagedManifestEntry> = entries.iter().filter(|e| is_anomaly(e)).collect();
    if !anomalies.is_empty() {
        s.push_str(&format!(
            "always-shown ({}) — db target / tar-smuggled authorized_keys / owner deviations:\n",
            anomalies.len()
        ));
        for a in &anomalies {
            s.push_str(&format!(
                "  {:>10}  {}:{}  {:o}  {}\n",
                a.size, a.uid, a.gid, a.mode, a.path
            ));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abbrev_is_12_hex_by_default() {
        let a = abbrev_digests(&["a".repeat(64)], false);
        assert_eq!(a[0].len(), 12);
    }

    #[test]
    fn abbrev_extends_on_collision() {
        let mut x = "abcdef012345".to_string();
        x.push_str(&"0".repeat(52));                           
        let mut y = "abcdef012345".to_string();
        y.push_str(&"1".repeat(52));
        let a = abbrev_digests(&[x, y], false);
        assert_ne!(a[0], a[1], "collision must extend to disambiguate");
        assert!(a[0].len() > 12);
    }

    #[test]
    fn full_flag_restores_64_hex() {
        let s = "a".repeat(64);
        assert_eq!(abbrev_digests(std::slice::from_ref(&s), true), vec![s]);
    }

    fn entry(path: &str, uid: u32, gid: u32, mode: u32, size: u64) -> StagedManifestEntry {
        StagedManifestEntry {
            path: path.into(),
            uid,
            gid,
            mode,
            size,
        }
    }

    #[test]
    fn rollup_itemizes_a_deviant_owner_entry() {
        let entries = vec![
            entry("recipes/a", 100, 100, 0o644, 10),
            entry("recipes/evil", 0, 0, 0o644, 10),                                  
        ];
        let out = restore_manifest_rollup(&entries, (100, 100), "recipes/recipes.db", false);
        assert!(
            out.contains("recipes/evil"),
            "deviant owner MUST itemize: {out}"
        );
        assert!(
            out.contains("recipes/") && out.contains("entries"),
            "the dir rolls up: {out}"
        );
    }

    #[test]
    fn a_tar_smuggled_authorized_keys_entry_is_flagged() {
                                                                                                   
                                                                                                   
                                                                                                    
        let entries = vec![
            entry("recipes/a", 100, 100, 0o644, 10),
            entry("recipes/.ssh/authorized_keys", 100, 100, 0o600, 32),                                 
        ];
        let out = restore_manifest_rollup(&entries, (100, 100), "recipes/recipes.db", false);
        assert!(
            out.contains("authorized_keys"),
            "a tar-smuggled authorized_keys must itemize: {out}"
        );
    }

    #[test]
    fn uniform_owner_rolls_up_with_no_per_file_rows() {
        let entries = vec![
            entry("recipes/a", 100, 100, 0o644, 10),
            entry("recipes/b", 100, 100, 0o644, 10),
        ];
        let out = restore_manifest_rollup(&entries, (100, 100), "recipes/recipes.db", false);
        assert!(!out.contains("recipes/a"), "no per-benign-file row: {out}");
    }

    #[test]
    fn manifest_full_dumps_every_file() {
        let entries = vec![entry("recipes/a", 100, 100, 0o644, 10)];
        let out = restore_manifest_rollup(&entries, (100, 100), "recipes/recipes.db", true);
        assert!(out.contains("recipes/a"), "{out}");
    }

    #[test]
    fn dir_less_entries_group_under_root() {
        let entries = vec![entry("toplevelfile", 100, 100, 0o644, 10)];
        let out = restore_manifest_rollup(&entries, (100, 100), "recipes/recipes.db", false);
        assert!(out.contains("(root)"), "{out}");
    }
}
