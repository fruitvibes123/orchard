                                                                                               
//! never from restated step knowledge. The run face prints it before admission completes; it is
                                                                                            
                          

use super::admission::{Admitted, RunInvocation};
use super::spine::SPINE;
use crate::deploy::context::ResolvedContext;

/// Render the summary for a `run` invocation. Values come from the resolved parameter set, the
/// step list and its done decisions from the admission-time plan.
pub fn render(admitted: &Admitted, inv: &RunInvocation, ctx: &ResolvedContext) -> String {
    let mut s = String::new();
    s.push_str("ceremony run\n");
    s.push_str(&format!(
        "  profile:        {}\n",
        inv.profile_path.as_str()
    ));
    s.push_str(&format!("  repo root:      {}\n", ctx.repo_root.display()));
    s.push_str(&format!(
        "  artifact store: {}\n",
        ctx.artifact_store.display()
    ));
    if let Some(t) = &inv.target {
        s.push_str(&format!("  target:         {t}\n"));
    }
    s.push_str("\nsteps\n");
    for step in SPINE.iter() {
        let planned = admitted.plan.iter().find(|p| p.id == step.id);
        let mark = match planned {
            Some(p) if p.is_done() => "SKIP",
            _ => "run ",
        };
        s.push_str(&format!("  {mark}  {}  {}\n", step.id.token(), step.title));
    }
    s.push_str("\nparameters\n");
    let mut shown = std::collections::BTreeSet::new();
    for step in SPINE.iter() {
        for p in step.params {
            let Some(v) = admitted.values.get(p.name) else {
                continue;
            };
            if shown.insert(p.name) {
                s.push_str(&format!("  {} = {v}\n", p.name));
            }
        }
    }
    s
}
