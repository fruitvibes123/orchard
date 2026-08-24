//! Crypto-supply allowlist (CLOSED SET) for the Seed Vault ship-and-build dependency tree.
//!
//! This was a 4-name blocklist (`no_forbidden_crypto_deps`: openssl-sys / native-tls / aws-lc-*).
//! A blocklist answers "is this KNOWN-bad crate absent?" and silently passes everything it did not
//! enumerate — a *renamed* C-crypto crate, a new TLS backend, a transitive surprise. This is the
//! allowlist counter-pattern (cf. `rambutan/tests/tree_lock.rs`, itself "the dragonfruit precedent"
//! done right): assert the crate set is *exactly* the listed crates, so any addition (new, renamed,
//! transitive) trips `make verify` loudly and forces a deliberate decision. The threat is unchanged
//! (the Phase-0.5 surface cut: no C/TLS crypto stack; rustls consumers pinned to `ring`); the
//! mechanism moves from "deny 4 names" to "the set is closed" — strictly stronger on the name axis
//! (a *renamed* C-crypto crate now trips) and matched on the build axis (see Scope below).
//!
//! ## Scope — what the closed set covers, and what it deliberately does NOT
//!
//! Per scope, two edge sets, each pinned to its ship target and resolved `--locked` (a stale lock
//! fails loud, never a silent re-resolve):
//!   * `--edges normal` == `*_SHIPPED` — what links into the artifact.
//!   * `--edges normal,build` == `*_SHIPPED` ∪ `*_BUILD_ONLY` — what ships OR runs in the build. The
//!     build-only delta is the sanctioned host build toolchain (cc / bindgen / clang-sys / the dalek
//!     build-script version probes / …), kept as its own short list so a NEW build-time C-FFI crate
//!     (e.g. `openssl-sys` arriving via `[build-dependencies]`) is an unlisted member → RED. This is
//!     the axis the old `Cargo.lock`-text scan covered and the first `--edges normal` cut had dropped.
//!
//! Two scopes: the main workspace @ the box target (`x86_64-unknown-linux-gnu`) + the
//! `dragonfruit-nostd-gate` standalone @ the firmware target (`thumbv8m.main-none-eabihf`, the
//! default-features=false dalek/sha2 config the C3 firmware actually compiles). The `--target` pins
//! make each set host-independent.
//!
//! Out of scope BY DESIGN (named per the Safeguards rule — a replacement that narrows coverage must
//! say so): **dev-dependencies** (host-only `cargo test` tooling) and **non-ship-target** crates
//! (Windows/wasi/darwin-cfg crates in `Cargo.lock` but never compiled for the box or the firmware).
//! Granularity is crate-NAME level by design (a forbidden crate has a distinct name; a second
//! *version* of a sanctioned crate is not new crypto surface). Update the arrays ONLY alongside an
//! audited dependency change.

use std::collections::BTreeSet;
use std::process::Command;

/// The exact set of crates that ship (normal edges) across the Seed Vault workspace, resolved for
/// the box target. Members (coconut … pomelo, dragonfruit) appear as their own tree roots.
const WORKSPACE_SHIPPED: &[&str] = &[
    "allocator-api2",
    "argon2",
    "arrayref",
    "arrayvec",
    "async-stream",
    "async-stream-impl",
    "async-trait",
    "atoi",
    "atomic",
    "banana",
    "base64",
    "base64ct",
    "binascii",
    "bitflags",
    "blake2",
    "blake3",
    "block-buffer",
    "bytes",
    "cfg-if",
    "coconut",
    "concurrent-queue",
    "constant_time_eq",
    "cookie",
    "cpufeatures",
    "crc",
    "crc-catalog",
    "crossbeam-queue",
    "crossbeam-utils",
    "crypto-common",
    "curve25519-dalek",
    "curve25519-dalek-derive",
    "deranged",
    "devise",
    "devise_codegen",
    "devise_core",
    "digest",
    "displaydoc",
    "dotenvy",
    "dragonfruit",
    "durian",
    "ed25519",
    "ed25519-dalek",
    "either",
    "encoding_rs",
    "equivalent",
    "errno",
    "event-listener",
    "fastrand",
    "fig",
    "figment",
    "flume",
    "fnv",
    "foldhash",
    "form_urlencoded",
    "futures",
    "futures-channel",
    "futures-core",
    "futures-executor",
    "futures-intrusive",
    "futures-io",
    "futures-sink",
    "futures-task",
    "futures-util",
    "generic-array",
    "getrandom",
    "glob",
    "grape",
    "grapefruit",
    "h2",
    "hashbrown",
    "hashlink",
    "heck",
    "hex",
    "hkdf",
    "hmac",
    "http",
    "httparse",
    "http-body",
    "httpdate",
    "hyper",
    "icu_collections",
    "icu_locale_core",
    "icu_normalizer",
    "icu_normalizer_data",
    "icu_properties",
    "icu_properties_data",
    "icu_provider",
    "idna",
    "idna_adapter",
    "indexmap",
    "inlinable_string",
    "is-terminal",
    "itoa",
    "libc",
    "libsqlite3-sys",
    "linux-raw-sys",
    "litemap",
    "lock_api",
    "log",
    "lru",
    "lychee",
    "mangosteen",
    "memchr",
    "mime",
    "mio",
    "multer",
    "num-conv",
    "num_cpus",
    "num-traits",
    "once_cell",
    "parking",
    "parking_lot",
    "parking_lot_core",
    "password-hash",
    "pear",
    "pear_codegen",
    "percent-encoding",
    "pin-project-lite",
    "pomegranate",
    "pomelo",
    "potential_utf",
    "powerfmt",
    "ppv-lite86",
    "proc-macro2",
    "proc-macro2-diagnostics",
    "quote",
    "rand",
    "rand_chacha",
    "rand_core",
    "ref-cast",
    "ref-cast-impl",
    "rocket",
    "rocket_codegen",
    "rocket_http",
    "rustix",
    "ryu",
    "scopeguard",
    "serde",
    "serde_core",
    "serde_derive",
    "serde_json",
    "serde_spanned",
    "serde_urlencoded",
    "sha2",
    "signal-hook-registry",
    "signature",
    "slab",
    "smallvec",
    "socket2",
    "spin",
    "sqlx",
    "sqlx-core",
    "sqlx-macros",
    "sqlx-macros-core",
    "sqlx-sqlite",
    "stable_deref_trait",
    "stable-pattern",
    "state",
    "subtle",
    "syn",
    "synstructure",
    "tempfile",
    "thiserror",
    "thiserror-impl",
    "time",
    "time-core",
    "time-macros",
    "tinystr",
    "tokio",
    "tokio-macros",
    "tokio-stream",
    "tokio-util",
    "toml",
    "toml_datetime",
    "toml_edit",
    "toml_write",
    "tower-service",
    "tracing",
    "tracing-attributes",
    "tracing-core",
    "try-lock",
    "typenum",
    "ubyte",
    "uncased",
    "unicode-ident",
    "unicode-xid",
    "url",
    "utf8_iter",
    "version_check",
    "want",
    "winnow",
    "writeable",
    "yansi",
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

/// The build-only delta for the main workspace (crates under `--edges normal,build` but NOT `normal`)
/// — the sanctioned host build toolchain that runs during the build but never links into the binary.
/// `cc`/`bindgen`/`clang-sys`/`pkg-config`/`vcpkg` (+ bindgen's own `regex`/`nom`/… subtree) are the
/// openssl-sys/aws-lc build machinery's neighbours; a forbidden build-dep (openssl-sys, native-tls,
/// …) is a DISTINCT name absent from both lists → ENTERED → RED. Its own short list so the build-time
/// C surface is reviewable at a glance.
const WORKSPACE_BUILD_ONLY: &[&str] = &[
    "autocfg",
    "bindgen",
    "cc",
    "cexpr",
    "clang-sys",
    "find-msvc-tools",
    "itertools",
    "lazy_static",
    "lazycell",
    "libloading",
    "minimal-lexical",
    "nom",
    "pkg-config",
    "regex",
    "regex-automata",
    "regex-syntax",
    "rustc-hash",
    "rustc_version",
    "semver",
    "shlex",
    "vcpkg",
];

/// The exact shipped set for the `dragonfruit-nostd-gate` standalone workspace, resolved for the
/// firmware target (the no_std verify config the C3 RP2350 reuses byte-for-byte). This is the
/// tightest, most security-critical set: the boot/sign-trust window must stay `core` + RustCrypto.
const NOSTD_GATE_SHIPPED: &[&str] = &[
    "block-buffer",
    "cfg-if",
    "crypto-common",
    "curve25519-dalek",
    "digest",
    "dragonfruit",
    "dragonfruit-nostd-gate",
    "ed25519",
    "ed25519-dalek",
    "generic-array",
    "proc-macro2",
    "quote",
    "sha2",
    "signature",
    "subtle",
    "syn",
    "thiserror",
    "thiserror-impl",
    "typenum",
    "unicode-ident",
    "zeroize",
];

/// The build-only delta for the `dragonfruit-nostd-gate` firmware config: the dalek/RustCrypto
/// build-script version probes (`rustc_version` → `semver`, `version_check`). A NEW build-time C-FFI
/// crate here is an unlisted member → RED. This is the tightest scope — the firmware build chain
/// should stay pure-Rust version detection, no C toolchain.
const NOSTD_GATE_BUILD_ONLY: &[&str] = &["rustc_version", "semver", "version_check"];

const LINUX_TARGET: &str = "x86_64-unknown-linux-gnu";
const FIRMWARE_TARGET: &str = "thumbv8m.main-none-eabihf";

/// Repo root, relative to this crate (`crates/dragonfruit`).
fn workspace_root() -> String {
    format!("{}/../..", env!("CARGO_MANIFEST_DIR"))
}

/// Parse `cargo tree --prefix none` output into the set of crate names (first column per non-empty
/// line; the tree's `(*)` dedup markers and version columns are dropped). A `BTreeSet` sorts and
/// dedups, so a crate appearing in many subtrees collapses to one entry.
fn parse_tree(tree: &str) -> BTreeSet<String> {
    tree.lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// Run `cargo tree` with the given args from `dir` and return the shipped crate-name set. Fails
/// closed: a non-zero exit (e.g. an unresolved manifest) panics rather than silently scanning an
                                                                       
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

/// The closed-set comparison, factored out so it is exercised by `diff_self_test` without shelling
/// out. Returns `(entered, left)`: crates present in `actual` but not allowlisted, and crates
/// allowlisted but absent from `actual`.
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

/// Assert the live shipped set equals the allowlist, with a message that names the security intent
/// behind the tripwire (the convention: a name match is a tripwire, document the stronger control).
fn assert_closed_set(actual: &BTreeSet<String>, expected: &[&str], scope: &str) {
    let (entered, left) = diff_against_allowlist(actual, expected);
    assert!(
        entered.is_empty() && left.is_empty(),
        "dependency set for {scope} no longer matches the allowlist.\n  \
         ENTERED (in the tree, not allowlisted): {entered:?}\n  \
         LEFT (allowlisted, not in the tree):    {left:?}\n\
         \n  \
         This gate is a CLOSED SET, not a blocklist: every crate in scope must be listed, so a renamed\n  \
         or new C/TLS crypto stack (openssl-sys, native-tls, aws-lc-*, boring-*, a non-`ring` rustls\n  \
         provider, ...) — shipped OR a build-dep dragging in the C toolchain — cannot slip in\n  \
         unnoticed. If an ENTERED crate pulls a C/TLS crypto stack, pin rustls consumers to the\n  \
         `ring` provider and drop the dependency instead of listing it; if it is a build-time C-FFI\n  \
         crate, keep it out of the build. Otherwise the change is legitimate — update the allowlist\n  \
         DELIBERATELY (this red is the decision point), in the same commit as the audited dependency\n  \
         change."
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
            LINUX_TARGET,
            "--locked",
            "--prefix",
            "none",
        ],
    );
    assert_closed_set(
        &actual,
        WORKSPACE_SHIPPED,
        "the Seed Vault workspace, shipped/normal edges (x86_64-unknown-linux-gnu)",
    );
}

/// The build-edge closed set: `--edges normal,build` must equal `WORKSPACE_SHIPPED` ∪
/// `WORKSPACE_BUILD_ONLY`. Recovers the build-dependency axis the old `Cargo.lock`-text blocklist
/// covered (and the `--edges normal` shipped cut had dropped): a C-crypto stack entering via
/// `[build-dependencies]` (dragging the C toolchain into the build) is an unlisted member → RED.
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
            LINUX_TARGET,
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
        "the Seed Vault workspace, ship+build edges (x86_64-unknown-linux-gnu)",
    );
}

#[test]
fn nostd_gate_shipped_set_is_exactly_the_allowlist() {
    let actual = cargo_tree_set(
        &workspace_root(),
        &[
            "tree",
            "--manifest-path",
            "crates/dragonfruit-nostd-gate/Cargo.toml",
            "--edges",
            "normal",
            "--target",
            FIRMWARE_TARGET,
            "--locked",
            "--prefix",
            "none",
        ],
    );
    assert_closed_set(
        &actual,
        NOSTD_GATE_SHIPPED,
        "the dragonfruit-nostd-gate firmware config, shipped/normal edges (thumbv8m.main-none-eabihf)",
    );
}

/// The firmware build-edge closed set: `--edges normal,build` must equal `NOSTD_GATE_SHIPPED` ∪
/// `NOSTD_GATE_BUILD_ONLY`. The tightest scope — the boot/sign-trust firmware build chain must stay
/// pure-Rust version detection; a C-FFI build-dep here is an unlisted member → RED.
#[test]
fn nostd_gate_build_edge_set_is_exactly_shipped_plus_build_tools() {
    let actual = cargo_tree_set(
        &workspace_root(),
        &[
            "tree",
            "--manifest-path",
            "crates/dragonfruit-nostd-gate/Cargo.toml",
            "--edges",
            "normal,build",
            "--target",
            FIRMWARE_TARGET,
            "--locked",
            "--prefix",
            "none",
        ],
    );
    let expected: Vec<&str> = NOSTD_GATE_SHIPPED
        .iter()
        .chain(NOSTD_GATE_BUILD_ONLY)
        .copied()
        .collect();
    assert_closed_set(
        &actual,
        &expected,
        "the dragonfruit-nostd-gate firmware config, ship+build edges (thumbv8m.main-none-eabihf)",
    );
}

/// Self-test: prove the closed-set comparison actually fires (a guard that cannot fire is theater).
/// An intruder must be reported as ENTERED, and a dropped crate as LEFT — in both directions.
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
