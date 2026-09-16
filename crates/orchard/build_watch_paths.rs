                                                                                                  
                                                                                              
                                        
  
                                                  
                                                                                             
                                                                                          
                                                                                                   
                                                                                                 
                                                                                                  
                                                                                              
                                                                                                
                                                                                               
                                                                                               
                           

/// Resolve the rerun-watch set for the checkout whose `.git` (dir or worktree gitfile) is at
/// `dot_git`. Empty when no git is present (cargo then falls back to package-file tracking; the
/// embed stays "unknown" — the pre-existing best-effort posture).
fn watch_paths(dot_git: &std::path::Path) -> Vec<std::path::PathBuf> {
    use std::path::{Path, PathBuf};
                                                                                             
    let gitdir: PathBuf = if dot_git.is_dir() {
        dot_git.to_path_buf()
    } else {
        let Ok(s) = std::fs::read_to_string(dot_git) else {
            return Vec::new();
        };
        let Some(p) = s.strip_prefix("gitdir:") else {
            return Vec::new();
        };
        let p = Path::new(p.trim());
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            dot_git.parent().unwrap_or(Path::new(".")).join(p)
        }
    };
                                                                                                 
                                                                                       
    let commondir: PathBuf = match std::fs::read_to_string(gitdir.join("commondir")) {
        Ok(s) => {
            let p = Path::new(s.trim());
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                gitdir.join(p)
            }
        }
        Err(_) => gitdir.clone(),
    };
    let head = gitdir.join("HEAD");
    let mut out = Vec::new();
                                                                                                 
                                                    
    if let Ok(h) = std::fs::read_to_string(&head)
        && let Some(r) = h.strip_prefix("ref:")
    {
        out.push(commondir.join(r.trim()));
    }
    out.push(head);
    out.push(commondir.join("packed-refs"));
    out
}
