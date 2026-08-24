                                                                                                     
//! Fruit Basket RUNTIME crate (box-init/initramfs-init/fb-*) — those are fetched as pinned binaries,
//! never compiled here. Vendored SOURCE (grape/dragonfruit/fb-manifest/rambutan under vendor/) is
//! allowed (it's pinned + verified). This asserts the assembled-from-pins posture structurally.
use std::path::Path;

#[test]
fn orchard_workspace_has_no_tenant_or_fb_runtime_crate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
                                                                                                    
                                                                                                           
                                                                                                         
                                                                                                           
    #[derive(serde::Deserialize)]
    struct Workspace {
        workspace: WorkspaceTable,
    }
    #[derive(serde::Deserialize)]
    struct WorkspaceTable {
        members: Vec<String>,
    }
    #[derive(serde::Deserialize)]
    struct MemberManifest {
        package: MemberPackage,
    }
    #[derive(serde::Deserialize)]
    struct MemberPackage {
        name: String,
    }
    const FETCHED_BINARY_CRATES: &[&str] = &[
        "recipes",
        "box-init",
        "initramfs-init",
        "fb-acme",
        "fb-oneshots",
        "fb-backup",
        "fb-cert-check",
    ];
    let cargo = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let ws: Workspace = toml::from_str(&cargo).expect("parse Orchard workspace Cargo.toml");
    for member in &ws.workspace.members {
        assert!(
            !member.contains('*'),
            "workspace member `{member}` is a GLOB — §9 requires EXPLICIT members so a `crates/*` can't \
             silently pull in a fetched-binary crate"
        );
        let mc = std::fs::read_to_string(root.join(member).join("Cargo.toml"))
            .unwrap_or_else(|e| panic!("read workspace member {member}/Cargo.toml: {e}"));
        let pkg: MemberManifest =
            toml::from_str(&mc).unwrap_or_else(|e| panic!("parse {member}/Cargo.toml: {e}"));
        assert!(
            !FETCHED_BINARY_CRATES.contains(&pkg.package.name.as_str()),
            "workspace member `{member}` resolves to the fetched-binary crate `{}` — §9: it must be a \
             pinned store artifact, not a compiled workspace member",
            pkg.package.name
        );
    }
                                                                                           
    for (name, ct) in walk_cargo_tomls(&root) {
        assert!(
            !ct.contains("../seed-vault")
                && !ct.contains("../fruit-basket")
                && !ct.contains("../recipes"),
            "{name} still has a sibling-path dep — 3b consumes via vendor/ + the pinned store"
        );
    }
                                                                                                    
                                                                                                      
                                                                                                   
    assert!(
        !root
            .join("crates/image-builder/reference-tenant.toml")
            .exists(),
        "orchard must not carry an in-tree recipes manifest — the reference tenant is store-pinned"
    );
}

fn walk_cargo_tomls(root: &Path) -> Vec<(String, String)> {
    let mut out = vec![(
        "Cargo.toml".into(),
        std::fs::read_to_string(root.join("Cargo.toml")).unwrap(),
    )];
    let crates = root.join("crates");
    if let Ok(rd) = std::fs::read_dir(&crates) {
        for e in rd.flatten() {
            let ct = e.path().join("Cargo.toml");
            if ct.exists() {
                out.push((
                    format!("crates/{}/Cargo.toml", e.file_name().to_string_lossy()),
                    std::fs::read_to_string(&ct).unwrap(),
                ));
            }
        }
    }
    out
}
