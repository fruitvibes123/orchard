//! Crypto-supply allowlist (CLOSED SET) for the Orchard ship-and-build dependency trees.
//!
//! This was a 4-name blocklist (`no_forbidden_crypto_deps`: openssl-sys / native-tls / aws-lc-*).
//! A blocklist answers "is this KNOWN-bad crate absent?" and silently passes everything it did not
//! enumerate — a *renamed* C-crypto crate, a new TLS backend, a transitive surprise. This is the
//! allowlist counter-pattern (cf. `rambutan/tests/tree_lock.rs`): assert the shipped crate set is
//! *exactly* the listed crates, so any addition (new, renamed, transitive) trips `make verify`
//! loudly and forces a deliberate decision. The threat is unchanged (the Phase-0.5 surface cut: no
//! TLS C-stack; `rcgen`/`ureq` pinned to the pure-`ring` provider, so `ring` / `rustls` /
//! `rustls-webpki` / `webpki-roots` are the sanctioned crypto and ARE listed, while
//! `openssl-sys`/`native-tls`/`aws-lc-*` are not — their entry, or a rename, is an unlisted member →
//! RED); the mechanism moves from "deny 4 names" to "the set is closed" — strictly stronger on the
//! name axis (a *renamed* C-crypto crate now trips) and matched on the build axis (see Scope below).
//!
//! NOTE on `dragonfruit`: it is INTENTIONALLY in this allowlist — the `orchard` CLI legitimately
//! links `dragonfruit[sign]` to sign artifacts on the operator host. The CRUX "box never signs"
//! boundary (dragonfruit absent from the in-image build crates, present only in the CLI) is the
//! separate `crux-orchard` Makefile gate, not this sentry. `grape` / `fb-manifest` are vendored
//! pinned SOURCE path-deps and so are in the workspace lock too — both listed.
//!
//! Two trees: the Orchard workspace (image-builder / syslinux-install / orchard CLI + the vendored
//! path-deps), pinned to the operator-host target (`x86_64-unknown-linux-gnu`); and the
//! out-of-workspace `vendor/rambutan` UEFI loader (its OWN `[workspace]`, 0 root-lock entries),
//! pinned to its boot target (`x86_64-unknown-uefi`) — matching `vendor/rambutan/tests/tree_lock.rs`.
//!
//! ## Scope — what the closed set covers, and what it deliberately does NOT
//!
//! Per tree, two edge sets, each pinned to its target and resolved `--locked` (a stale lock fails
//! loud, never a silent re-resolve):
//!   * `--edges normal` == `*_SHIPPED` — what links into the artifact.
//!   * `--edges normal,build` == `*_SHIPPED` ∪ `*_BUILD_ONLY` — what ships OR runs in the build. The
//!     workspace build-only delta is the sanctioned host build toolchain (`cc` / `jobserver` /
//!     `pkg-config` / the build-script version probes); a NEW build-time C-FFI crate (e.g.
//!     `openssl-sys` via `[build-dependencies]`, dragging the C toolchain into the image build) is an
//!     unlisted member → RED. This is the axis the old `Cargo.lock`-text scan covered and the
//!     `--edges normal` cut had dropped.
//!
//! Out of scope BY DESIGN (named per the Safeguards rule — a replacement that narrows coverage must
//! say so): **dev-dependencies** (host-only `cargo test` tooling) and **non-target** crates
//! (Windows/wasi/darwin-cfg crates in `Cargo.lock` but never compiled for the host or the UEFI
//! loader). Granularity is crate-NAME level by design. Update the arrays ONLY alongside an audited
//! dependency change.

use std::collections::BTreeSet;
use std::process::Command;

/// The exact shipped set (normal edges) of the Orchard workspace, resolved for the operator host.
const WORKSPACE_SHIPPED: &[&str] = &[
    "adler2",
    "aead",
    "anstream",
    "anstyle",
    "anstyle-parse",
    "anstyle-query",
                                                                                               
                                                                                              
                                                                                                 
                                                                                                      
    "argon2",
    "asn1-rs",
    "asn1-rs-derive",
    "asn1-rs-impl",
    "backhand",
    "base16ct",
    "base64",
    "base64ct",
    "bitflags",
    "bitvec",
    "blake2",
    "block-buffer",
    "cashew",
    "cfg-if",
    "chacha20",
    "chacha20poly1305",
    "chrono",
    "cipher",
    "clap",
    "clap_builder",
    "clap_derive",
    "clap_lex",
    "colorchoice",
    "const-oid",
    "cpufeatures",
    "crc32fast",
    "crypto-bigint",
    "crypto-common",
    "curve25519-dalek",
    "curve25519-dalek-derive",
    "darling",
    "darling_core",
    "darling_macro",
    "data-encoding",
    "deku",
    "deku_derive",
    "der",
    "deranged",
    "der-parser",
    "digest",
    "displaydoc",
    "dragonfruit",
    "ecdsa",
    "ed25519",
    "ed25519-dalek",
    "elf",
    "elliptic-curve",
    "equivalent",
    "fastrand",
    "fb-manifest",
    "ff",
    "filetime",
    "flate2",
    "fnv",
    "form_urlencoded",
    "funty",
    "generic-array",
    "getrandom",
    "grape",
    "grocer",
    "group",
    "hashbrown",
    "heck",
    "hex",
    "hkdf",
    "hmac",
    "iana-time-zone",
    "icu_collections",
    "icu_locale_core",
    "icu_normalizer",
    "icu_normalizer_data",
    "icu_properties",
    "icu_properties_data",
    "icu_provider",
    "ident_case",
    "idna",
    "idna_adapter",
    "indexmap",
    "inout",
    "is_terminal_polyfill",
    "itoa",
    "lazy_static",
    "libc",
    "liblzma",
    "liblzma-sys",
    "libm",
    "linux-raw-sys",
    "litemap",
    "log",
    "memchr",
    "minimal-lexical",
    "miniz_oxide",
    "nom",
    "no_std_io2",
    "num-bigint",
    "num-bigint-dig",
    "num-conv",
    "num_cpus",
    "num-integer",
    "num-iter",
    "num-traits",
    "oid-registry",
    "once_cell",
    "opaque-debug",
    "orchard",
    "orchard-shim",
    "p256",
    "password-hash",
    "pem",
    "pem-rfc7468",
    "percent-encoding",
    "pin-project-lite",
    "pkcs1",
    "pkcs8",
    "poly1305",
    "potential_utf",
    "powerfmt",
    "ppv-lite86",
    "primeorder",
    "proc-macro2",
    "proc-macro-crate",
    "quote",
    "radium",
    "rand",
    "rand_chacha",
    "rand_core",
    "rcgen",
    "recipes-image-builder",
    "rfc6979",
    "ring",
    "rpassword",
    "rsa",
    "rtoolbox",
    "rusticata-macros",
    "rustix",
    "rustls",
    "rustls-pki-types",
    "rustls-webpki",
    "rustversion",
    "sec1",
    "serde",
    "serde_core",
    "serde_derive",
    "serde_json",
    "serde_spanned",
    "sha1",
    "sha2",
    "signature",
    "simd-adler32",
    "smallvec",
    "solana-nohash-hasher",
    "spin",
    "spki",
    "stable_deref_trait",
    "strsim",
    "subtle",
    "syn",
    "synstructure",
    "syslinux-install",
    "tap",
    "tar",
    "tempfile",
    "thiserror",
    "thiserror-impl",
    "time",
    "time-core",
    "time-macros",
    "tinystr",
    "toml",
    "toml_datetime",
    "toml_edit",
    "toml_parser",
    "toml_write",
    "tracing",
    "tracing-attributes",
    "tracing-core",
    "typenum",
    "unicode-ident",
    "universal-hash",
    "untrusted",
    "ureq",
    "url",
    "utf8_iter",
    "utf8parse",
    "webpki-roots",
    "winnow",
    "writeable",
    "wyz",
    "x509-parser",
    "xattr",
    "xxhash-rust",
    "yasna",
    "yoke",
    "yoke-derive",
    "zerocopy",
    "zerofrom",
    "zerofrom-derive",
    "zeroize",
    "zerotrie",
    "zerovec",
    "zerovec-derive",
    "zmij",
];

/// The build-only delta for the Orchard workspace: the sanctioned host build toolchain (`cc` /
/// `jobserver` / `pkg-config`, the ring/rustls C-compile machinery) + build-script version probes.
/// Kept as its own short list so the build-time C surface is reviewable; a NEW build-time C-FFI crate
/// (openssl-sys, native-tls, …) is a DISTINCT name absent from both lists → ENTERED → RED.
const WORKSPACE_BUILD_ONLY: &[&str] = &[
    "autocfg",
    "cc",
    "find-msvc-tools",
    "jobserver",
    "pkg-config",
    "rustc_version",
    "semver",
    "shlex",
    "version_check",
];

/// The exact shipped set of the out-of-workspace `vendor/rambutan` UEFI loader (its own
/// `[workspace]`), resolved for the boot target. Mirrors `vendor/rambutan/tests/tree_lock.rs`.
const RAMBUTAN_SHIPPED: &[&str] = &[
    "block-buffer",
    "cfg-if",
    "cpufeatures",
    "crypto-common",
    "digest",
    "generic-array",
    "rambutan",
    "sha2",
    "typenum",
];

/// The build-only delta for the `vendor/rambutan` UEFI loader: just the `version_check` build-script
/// probe. The loader build chain must stay pure-Rust; a C-FFI build-dep here is an unlisted member
/// → RED.
const RAMBUTAN_BUILD_ONLY: &[&str] = &["version_check"];

const HOST_TARGET: &str = "x86_64-unknown-linux-gnu";
const UEFI_TARGET: &str = "x86_64-unknown-uefi";

/// Repo root, relative to this crate (`crates/image-builder`).
fn workspace_root() -> String {
    format!("{}/../..", env!("CARGO_MANIFEST_DIR"))
}

/// Parse `cargo tree --prefix none` output into the set of crate names (first column per non-empty
/// line; `(*)` dedup markers and version columns dropped). A `BTreeSet` sorts and dedups.
fn parse_tree(tree: &str) -> BTreeSet<String> {
    tree.lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// Run `cargo tree` with the given args from `dir` and return the shipped crate-name set. Fails
/// closed: a non-zero exit panics rather than silently scanning an empty set.
fn cargo_tree_set(dir: &str, args: &[&str]) -> BTreeSet<String> {
    let out = Command::new(env!("CARGO"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("spawn `cargo tree {args:?}`: {e}"));
    assert!(
        out.status.success(),
        "`cargo tree {args:?}` failed (status {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    parse_tree(&String::from_utf8(out.stdout).expect("cargo tree stdout is utf8"))
}

/// The closed-set comparison, factored out so `diff_self_test` exercises it without shelling out.
/// Returns `(entered, left)`: crates in `actual` but not allowlisted, and allowlisted but absent.
fn diff_against_allowlist(
    actual: &BTreeSet<String>,
    expected: &[&str],
) -> (Vec<String>, Vec<String>) {
    let expected_set: BTreeSet<&str> = expected.iter().copied().collect();
    let entered: Vec<String> = actual
        .iter()
        .filter(|c| !expected_set.contains(c.as_str()))
        .cloned()
        .collect();
    let left: Vec<String> = expected
        .iter()
        .filter(|c| !actual.contains(**c))
        .map(|c| c.to_string())
        .collect();
    (entered, left)
}

fn assert_closed_set(actual: &BTreeSet<String>, expected: &[&str], scope: &str) {
    let (entered, left) = diff_against_allowlist(actual, expected);
    assert!(
        entered.is_empty() && left.is_empty(),
        "dependency set for {scope} no longer matches the allowlist.\n  \
         ENTERED (in the tree, not allowlisted): {entered:?}\n  \
         LEFT (allowlisted, not in the tree):    {left:?}\n\
         \n  \
         This gate is a CLOSED SET, not a blocklist: every crate in scope must be listed, so a renamed\n  \
         or new C/TLS crypto stack (openssl-sys, native-tls, aws-lc-*, ...) — shipped OR a build-dep\n  \
         dragging in the C toolchain — cannot slip in unnoticed. If an ENTERED crate pulls a C/TLS\n  \
         crypto stack, pin rustls consumers to the `ring` provider and drop the dependency instead of\n  \
         listing it; if it is a build-time C-FFI crate, keep it out of the build. Otherwise the change\n  \
         is legitimate — update the allowlist DELIBERATELY (this red is the decision point), in the\n  \
         same commit as the audited dependency change."
    );
}

#[test]
fn workspace_shipped_set_is_exactly_the_allowlist() {
    let actual = cargo_tree_set(
        &workspace_root(),
        &[
            "tree",
            "--workspace",
            "--edges",
            "normal",
            "--target",
            HOST_TARGET,
            "--locked",
            "--prefix",
            "none",
        ],
    );
    assert_closed_set(
        &actual,
        WORKSPACE_SHIPPED,
        "the Orchard workspace, shipped/normal edges (x86_64-unknown-linux-gnu)",
    );
}

/// The build-edge closed set: `--edges normal,build` must equal `WORKSPACE_SHIPPED` ∪
/// `WORKSPACE_BUILD_ONLY`. Recovers the build-dependency axis the old `Cargo.lock`-text blocklist
/// covered (and the `--edges normal` shipped cut had dropped): a C-crypto stack entering via
/// `[build-dependencies]` (dragging the C toolchain into the image build) is an unlisted member → RED.
#[test]
fn workspace_build_edge_set_is_exactly_shipped_plus_build_tools() {
    let actual = cargo_tree_set(
        &workspace_root(),
        &[
            "tree",
            "--workspace",
            "--edges",
            "normal,build",
            "--target",
            HOST_TARGET,
            "--locked",
            "--prefix",
            "none",
        ],
    );
    let expected: Vec<&str> = WORKSPACE_SHIPPED
        .iter()
        .chain(WORKSPACE_BUILD_ONLY)
        .copied()
        .collect();
    assert_closed_set(
        &actual,
        &expected,
        "the Orchard workspace, ship+build edges (x86_64-unknown-linux-gnu)",
    );
}

#[test]
fn rambutan_vendored_shipped_set_is_exactly_the_allowlist() {
    let actual = cargo_tree_set(
        &workspace_root(),
        &[
            "tree",
            "--manifest-path",
            "vendor/rambutan/Cargo.toml",
            "--edges",
            "normal",
            "--target",
            UEFI_TARGET,
            "--locked",
            "--prefix",
            "none",
        ],
    );
    assert_closed_set(
        &actual,
        RAMBUTAN_SHIPPED,
        "the vendored rambutan UEFI loader, shipped/normal edges (x86_64-unknown-uefi)",
    );
}

/// The UEFI-loader build-edge closed set: `--edges normal,build` must equal `RAMBUTAN_SHIPPED` ∪
/// `RAMBUTAN_BUILD_ONLY`. The loader build chain must stay pure-Rust; a C-FFI build-dep here is an
/// unlisted member → RED.
#[test]
fn rambutan_vendored_build_edge_set_is_exactly_shipped_plus_build_tools() {
    let actual = cargo_tree_set(
        &workspace_root(),
        &[
            "tree",
            "--manifest-path",
            "vendor/rambutan/Cargo.toml",
            "--edges",
            "normal,build",
            "--target",
            UEFI_TARGET,
            "--locked",
            "--prefix",
            "none",
        ],
    );
    let expected: Vec<&str> = RAMBUTAN_SHIPPED
        .iter()
        .chain(RAMBUTAN_BUILD_ONLY)
        .copied()
        .collect();
    assert_closed_set(
        &actual,
        &expected,
        "the vendored rambutan UEFI loader, ship+build edges (x86_64-unknown-uefi)",
    );
}

/// Self-test: prove the closed-set comparison fires in both directions (a guard that cannot fire is
/// theater). An intruder is reported as ENTERED; a dropped member as LEFT.
#[test]
fn diff_self_test_fires_on_intruder_and_on_missing() {
    let expected = &["alpha", "beta", "gamma"];

                                                                      
    let with_intruder: BTreeSet<String> = ["alpha", "beta", "gamma", "openssl-sys"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let (entered, left) = diff_against_allowlist(&with_intruder, expected);
    assert_eq!(
        entered,
        vec!["openssl-sys".to_string()],
        "intruder must be ENTERED"
    );
    assert!(left.is_empty());

                                                  
    let with_missing: BTreeSet<String> =
        ["alpha", "gamma"].into_iter().map(str::to_string).collect();
    let (entered, left) = diff_against_allowlist(&with_missing, expected);
    assert!(entered.is_empty());
    assert_eq!(
        left,
        vec!["beta".to_string()],
        "dropped member must be LEFT"
    );

                                                                            
    let exact: BTreeSet<String> = expected.iter().map(|s| s.to_string()).collect();
    let (entered, left) = diff_against_allowlist(&exact, expected);
    assert!(
        entered.is_empty() && left.is_empty(),
        "exact match must be clean"
    );
}
