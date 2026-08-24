                                                                                                
//! ends with the natural next command(s) so the operator never reconstructs the ceremony from
//! memory. Consumed also by `doctor --for boot-gate` (C2) and `prime` (C6).

use std::path::Path;

/// Render a `next:` block: a header line then each command indented two spaces. Empty slice ⇒ "".
pub fn next_steps(lines: &[String]) -> String {
    if lines.is_empty() {
        return String::new();
    }
    let mut s = String::from("next:\n");
    for l in lines {
        s.push_str("  ");
        s.push_str(l);
        s.push('\n');
    }
    s
}

/// The two natural next commands after `orchard build`: boot-smoke it, then deploy it.
pub fn build_next_steps(img: &Path) -> Vec<String> {
    let img = img.display();
    vec![
        format!("orchard dryrun --image {img}    # boot-smoke it under QEMU"),
        format!(
            "orchard prod <ip> --image {img} --pubkey ~/.ssh/box_operator.pub --wipe-confirmed"
        ),
    ]
}

/// After `generate-keys`: commit the trust anchors (else the next `build` refuses the dirty tree —
/// the exact footgun this cycle closes), then stage the pinned source.
pub fn generate_keys_next_steps() -> Vec<String> {
    vec![
                                                                                                   
                                                                                                
        "git add crates/image-builder/pinned-cert-fingerprints.toml && git commit -m 'pin cert fingerprints'   # so build won't refuse a dirty tree".into(),
        "orchard prime    # stage the pinned kernel + syslinux source".into(),
    ]
}

/// After `generate-keys --secure-boot`: commit the pinned PK/KEK/db fingerprints (else the next
/// `build` refuses the dirty tree — the SAME footgun `generate_keys_next_steps` closes for the cert
                                                                                                 
/// ceremony just wrote (echoed so the `git add` matches the path it printed).
pub fn generate_keys_secure_boot_next_steps(db_path: &Path) -> Vec<String> {
    vec![
        format!(
            "git add {} && git commit -m 'pin secure-boot db fingerprints'   # so build won't refuse a dirty tree",
            db_path.display()
        ),
        "orchard build --domain <your-domain> --firmware uefi --secure-boot    # then orchard sign-sb + enroll PK/KEK/db".into(),
    ]
}

/// After `prime`: build the image triple from the staged source.
pub fn prime_next_steps() -> Vec<String> {
    vec![
        "orchard build --domain <your-domain>    # build the image triple from the primed source"
            .into(),
    ]
}

/// After `vendor`: build with the vendored source drops.
pub fn vendor_next_steps() -> Vec<String> {
    vec!["orchard build --domain <your-domain>    # build with the vendored source drops".into()]
}

/// After `sign-sb`: stage the installer USB carrying the signed loader. `img` = the just-signed
                                                                                                  
/// hardware choice the tool can't know).
pub fn sign_sb_next_steps(img: &Path) -> Vec<String> {
    vec![format!(
        "orchard build-installer-usb --from {} --install-to <usb-dev>    # stage the signed installer",
        img.display()
    )]
}

                                                                                                    
/// (+ the PROD/RESCUE `_PRIVKEY`) with the built image path spliced in when known, `<img>`/`<privkey>`
/// placeholders otherwise. The gate's own panic-if-unset discipline is untouched — this is the UX
/// answer to the env surface, NOT a wrapper around the gate.
pub fn boot_gate_env_skeleton(image: Option<&Path>) -> Vec<String> {
    let img = image
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<img>".to_string());
    vec![
        "# set the boot-gate env, then run `make boot-gate` (guide §6):".into(),
        format!("export RECIPES_DRYRUN_IMG={img}"),
        format!("export RECIPES_PROD_IMG={img}"),
        "export RECIPES_PROD_PRIVKEY=<operator-ssh-privkey>".into(),
        format!("export RECIPES_RESCUE_IMG={img}"),
        "export RECIPES_RESCUE_PRIVKEY=<operator-ssh-privkey>".into(),
        "make boot-gate".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_header_and_indented_lines() {
        let s = next_steps(&[
            "orchard dryrun --image /tmp/x.img".into(),
            "orchard prod <ip> …".into(),
        ]);
        assert_eq!(
            s,
            "next:\n  orchard dryrun --image /tmp/x.img\n  orchard prod <ip> …\n"
        );
    }

    #[test]
    fn empty_slice_renders_nothing() {
        assert_eq!(next_steps(&[]), "");
    }

    #[test]
    fn build_next_steps_splice_the_real_image_path() {
        let v = build_next_steps(std::path::Path::new("/tmp/recipes-image-abc.img"));
        assert_eq!(v.len(), 2);
        assert!(v[0].contains("orchard dryrun --image /tmp/recipes-image-abc.img"));
        assert!(v[1].contains("orchard prod <ip> --image /tmp/recipes-image-abc.img --pubkey"));
    }

    #[test]
    fn generate_keys_next_reminds_to_commit_fingerprints() {
        let v = generate_keys_next_steps();
                                                                                                  
                                                                                     
        assert!(
            v.iter().any(|l| l.contains("git commit")
                && l.contains("crates/image-builder/pinned-cert-fingerprints.toml")),
            "{v:?}"
        );
    }

    #[test]
    fn generate_keys_secure_boot_next_reminds_to_commit_the_db_pin() {
                                                                                                   
                                                                             
        let v = generate_keys_secure_boot_next_steps(std::path::Path::new(
            "/repo/crates/image-builder/pinned-secure-boot-db.toml",
        ));
        assert!(
            v.iter().any(|l| l.contains("git commit")
                && l.contains("/repo/crates/image-builder/pinned-secure-boot-db.toml")),
            "{v:?}"
        );
    }

    #[test]
    fn prime_next_points_at_build() {
        assert!(
            prime_next_steps()
                .iter()
                .any(|l| l.contains("orchard build --domain"))
        );
    }

    #[test]
    fn vendor_next_points_at_build() {
        assert!(
            vendor_next_steps()
                .iter()
                .any(|l| l.contains("orchard build --domain"))
        );
    }

    #[test]
    fn sign_sb_next_splices_the_real_image_not_a_placeholder() {
        let v = sign_sb_next_steps(std::path::Path::new("/tmp/uefi.img"));
        assert!(v.iter().any(|l| l.contains("build-installer-usb")));
        assert!(
            v.iter().any(|l| l.contains("--from /tmp/uefi.img")),
            "real path: {v:?}"
        );
        assert!(
            !v.iter().any(|l| l.contains("<img>")),
            "no placeholder: {v:?}"
        );
    }

    #[test]
    fn boot_gate_skeleton_splices_a_real_image_else_placeholder() {
        let with = boot_gate_env_skeleton(Some(std::path::Path::new("/tmp/x.img")));
        assert!(
            with.iter()
                .any(|l| l.contains("RECIPES_DRYRUN_IMG=/tmp/x.img"))
        );
        assert!(
            with.iter()
                .any(|l| l.contains("RECIPES_PROD_IMG=/tmp/x.img"))
        );
        let without = boot_gate_env_skeleton(None);
        assert!(
            without
                .iter()
                .any(|l| l.contains("RECIPES_DRYRUN_IMG=<img>"))
        );
    }
}
