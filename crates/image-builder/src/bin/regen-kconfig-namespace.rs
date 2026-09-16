//! Regenerate the C4 gate's Kconfig-namespace fixture from the pinned kernel tarball.
//!
//! Argument: the staged `linux-<version>.tar.xz` (`orchard prime` output). The version + sha256 come
//! from `pins.toml`; the fixture path is derived from the version. The tarball must hash to
//! `pins.toml [kernel].sha256` or the run refuses, so only the pinned bytes produce a fixture.

use recipes_image_builder::kconfig_namespace::regenerate;
use recipes_image_builder::pins::Pins;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("regen-kconfig-namespace: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let mut args = std::env::args_os().skip(1);
    let tarball = args.next().ok_or(
        "usage: regen-kconfig-namespace <staged linux-<version>.tar.xz>\n\
         (the tarball must hash to pins.toml [kernel].sha256)",
    )?;
    if args.next().is_some() {
        return Err("expected exactly one argument: the staged linux-<version>.tar.xz".to_string());
    }
    let tarball = PathBuf::from(tarball);

                                                                                            
    #[allow(clippy::disallowed_methods)]
    let cwd = std::env::current_dir().map_err(|e| format!("read current dir: {e}"))?;
    let repo_root = cwd
        .ancestors()
        .find(|d| d.join("pins.toml").is_file())
        .ok_or_else(|| format!("no pins.toml in {} or any ancestor", cwd.display()))?;
    let crate_dir = repo_root.join("crates/image-builder");
    if !crate_dir.is_dir() {
        return Err(format!(
            "{} holds pins.toml but not crates/image-builder",
            repo_root.display()
        ));
    }

    let pins = Pins::load(repo_root).map_err(|e| format!("load pins.toml: {e}"))?;
    let version = &pins.kernel.version;
    let sha256 = &pins.kernel.sha256;
    let out_path = crate_dir.join(format!("kconfig-namespace-{version}.txt"));

    let xz = std::fs::read(&tarball).map_err(|e| {
        format!(
            "read staged tarball {}: {e} — run `orchard prime` (or `make prime`) first",
            tarball.display()
        )
    })?;

    let regen = regenerate(&xz, version, sha256, &out_path).map_err(|e| e.to_string())?;
    Ok(format!(
        "wrote {} ({} names) for linux-{version} {sha256}",
        regen.out_path.display(),
        regen.name_count
    ))
}
