//! Embed the HEAD commit as `RECIPES_BUILD_GIT_SHA` so `orchard build` can flag a STALE binary —
                                                                                              
//! orchestration (service tree, oneshot wiring, build sequence) is COMPILED INTO `orchard`, so a
//! not-recompiled `orchard` would ship a stale tree under a fresh `--git-sha` label. Best-effort: a
//! git-less build embeds "unknown" and the runtime guard (`build_image::check_build_freshness`) skips.
//!
                                                                                                       
//! `CARGO_FEATURE_DEPLOY` (so the in-image musl `recipes-admin`, built WITHOUT `deploy`, carried no sha).
//! The deploy code moved to `orchard`, so its build-sha PRODUCER moves with its CONSUMER
//! (`build_image.rs`'s `option_env!("RECIPES_BUILD_GIT_SHA")`) — otherwise the guard reads `None` and is
//! silently defeated. `orchard` IS the operator-host deploy tool, so the embed is UNCONDITIONAL (no
//! feature gate). The env-var name stays `RECIPES_BUILD_GIT_SHA` to match the unchanged consumer (the
//! `recipes.* → fb.*`/de-recipes renames are later-blocker work).

use std::path::Path;
use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=RECIPES_BUILD_GIT_SHA={sha}");
                                                                                                       
                                                                                                    
                                                                                                         
                                                                                                      
                                                                                                        
                                                   
    let root = Path::new("../..");
    let dotgit = root.join(".git");
    let gitdir = if dotgit.is_file() {
        std::fs::read_to_string(&dotgit)
            .ok()
            .and_then(|s| s.strip_prefix("gitdir:").map(|p| p.trim().to_string()))
            .map(|p| {
                let p = Path::new(&p);
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    root.join(p)
                }
            })
    } else {
        Some(dotgit)
    };
    if let Some(gitdir) = gitdir {
        for name in ["HEAD", "logs/HEAD"] {
            let p = gitdir.join(name);
            if p.exists() {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
    }
}
