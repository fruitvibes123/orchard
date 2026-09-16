                                                                                                
//!
                                                                                               
//! construction (the spine cannot invoke a sibling build), so this probe NARROWS the torn-read
//! window rather than closing it — T7 carries the residual and Q6's atomic tenant-side end-marker
//! is what closes it.
//!
//! GROUNDED on the writer, not on reasoning about it (`recipes/build-binaries.sh:19-26` at
//! recipes `fc1ac28b`): `normalize_recipes_handoff` is `rm -rf <handoff>`, `mkdir -p
//! <handoff>/release`, then one `cp` per binary into `release/<built-name>`. So an absent, empty
//! or half-populated tree is not "maybe fine, read again" — it is EXACTLY the mid-write window,
//! and the shape check refuses it outright.
//!
//! The re-read interval is derived from that writer's MEASURED burst, not chosen: 5 runs of the
//! real `rm -rf` + `mkdir` + two `cp`s over the real artifact sizes (11.8 MB + 4.8 MB, from the
//! artifact store) on the dev host, 2026-08-19, ran 7-9 ms end to end, with the gap between the
//! two `cp` completions at 2-3 ms. `INTERVAL` is 500 ms — about 55x the whole burst — and three
//! reads mean TWO consecutive intervals must both land in the same state.

use std::path::Path;

use super::probes::ProbeResult;

/// The binaries `normalize_recipes_handoff` copies into `release/`. A REAL tenant coupling, not a
/// cosmetic one: the built names are the tenant's (`recipes`'s own binary is built as `recipes`,
/// not as its artifact key `recipes-app`), and nothing in the repo-manifest or the ceremony
                                                                                              
pub const TENANT_HANDOFF_BINARIES: &[&str] = &["recipes", "recipes-admin"];

/// Re-read interval, derived from the measured writer burst (module note).
pub const INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// How many reads must agree. Three reads = two consecutive intervals.
pub const READS: usize = 3;

/// The SHAPE half: does this tree match the publish layout? Absent, empty and partially-populated
/// trees are the mid-write window and are refused here, before any stability question is asked.
pub fn shape(root: &Path) -> ProbeResult {
    if !root.is_dir() {
        return ProbeResult::Unmet(format!(
            "{} does not exist — run S5 (`make publish` in the tenant repo)",
            root.display()
        ));
    }
    for name in TENANT_HANDOFF_BINARIES {
        let p = root.join("release").join(name);
        match std::fs::metadata(&p) {
            Ok(m) if m.is_file() && m.len() > 0 => {}
            Ok(m) if m.is_file() => {
                return ProbeResult::Unmet(format!(
                    "{} is empty — the publish is mid-write; re-run when it finishes",
                    p.display()
                ));
            }
            _ => {
                return ProbeResult::Unmet(format!(
                    "{} is missing — the handoff tree does not match the publish layout \
                     (release/<binary>); re-run `make publish` and let it finish",
                    p.display()
                ));
            }
        }
    }
    ProbeResult::Met
}

/// The full probe: shape, then stability across [`READS`] reads [`INTERVAL`] apart. Returns the
/// quiescent tree hash so the caller can bind it into the S5 confirmation record (D19's named
/// producer).
pub fn quiescent(root: &Path) -> Result<String, ProbeResult> {
    quiescent_with(root, READS, INTERVAL)
}

/// The parameterized core, so the arms drive the same code with a zero interval.
pub fn quiescent_with(
    root: &Path,
    reads: usize,
    interval: std::time::Duration,
) -> Result<String, ProbeResult> {
    if let ProbeResult::Unmet(why) | ProbeResult::Unevaluable(why) = shape(root) {
        return Err(ProbeResult::Unmet(why));
    }
    let mut last: Option<String> = None;
    for i in 0..reads.max(2) {
        if i > 0 {
            std::thread::sleep(interval);
        }
        let Some(h) = super::admission::handoff_tree_hash(root) else {
            return Err(ProbeResult::Unevaluable(format!(
                "{} could not be read whole",
                root.display()
            )));
        };
        if let Some(prev) = &last
            && *prev != h
        {
            return Err(ProbeResult::Unmet(format!(
                "{} changed between reads {interval:?} apart — the publish is still writing; \
                 re-run when it finishes",
                root.display()
            )));
        }
        last = Some(h);
    }
    Ok(last.expect("at least two reads"))
}
