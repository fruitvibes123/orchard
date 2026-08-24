# cashew

A pure-Rust, **verify-only** OpenPGP/RSA detached-signature checker: verify an armored detached
signature (the kernel.org `linux-X.Y.Z.tar.sign` shape) over a caller-**streamed** byte sequence,
against a caller-supplied **vendored keyring** filtered by caller-supplied **pinned fingerprints**.
It is the verify primitive the `market upgrade --kernel` pin bump consumes; a verify BYPASS here
would let an attacker-supplied kernel source tree enter the box build supply chain, so the whole
crate is a whitelist — every form not explicitly permitted is a named `Error`, and refusal is the
only non-success outcome.

**This crate does NOT** sign, fetch, decompress, or wire itself to `--kernel` — those live in the
consumer. It is the crate-scoped verify kernel only.

## Design contract (one screen)

- **Whitelist grammar** (RFC 4880 subset): v4 signatures, RSA (pubkey algo 1), SHA-256/512 only.
  Every unlisted version / algorithm / packet tag / length form is a named `Err`.
- **No-skip law:** every signature in a loadable keyring must cryptographically verify in its
  positional role, or the whole load fails — no tolerate-and-skip channel.
- **Issuer hints carry no trust:** `finalize` computes the digest once and tries
  every validated candidate key of every pinned signer. `UnknownSigner` fires at **load** only (a
  pin absent from the file); a failed verification is always `BadSignature`.
- **SHA-1 is fingerprint-only:** constructed at exactly one site (`key.rs::v4_fingerprint`,
  identification), never for any signature of any role. Any signature hash ∉ {8,10} is
  `WeakHash(algo)` — one uniform class.
- **Zero hand-rolled cryptography:** the RFC-4880 *format* layer is hand-rolled; all hashing / RSA
  verification delegate to the in-tree `rsa` / `sha2` / `sha1` crates. **Zero net-new crates** enter
  the workspace closure.
- **No-panic parse paths** behind a `catch_unwind` boundary at every fallible public entry → a
  structured `Error::ParserPanic`, never a crash. A `panic = "unwind"` compile guard keeps that
  boundary armed.
- **Sealed `Verified`:** no public constructor; holding one means a stream verified against a pinned
  signer's validated key under the whole policy.

The full design record and multi-round audit trail live in the operator's private engineering hub;
this README carries the load-bearing contract.

**Known dependency advisory (inert here):** `rsa 0.9.10` carries RUSTSEC-2023-0071 (the "Marvin"
timing side channel). It targets RSA **private-key** operations; cashew is verify-only (public inputs
only), so it is inert by construction. See the rationale at the `rsa`
dependency in `Cargo.toml` before ignoring the advisory or changing the `rsa` version.

## Vendoring contract (for consumers)

The keyring is NOT "whatever gpg exports" — it is a **minimized, attribute-free, pruned, armored**
export from a named `pgpkeys.git` commit, produced with a **pinned toolchain** (gpg 2.4.9 /
libgcrypt 1.12.2), then **sha256-pinned** by the consumer. See
`tests/fixtures/README.md`. Key material comes from `pgpkeys.git` ONLY — never a keyserver.

## Guarantee evidence map

| Guarantee | Evidenced by |
|-----------|--------------|
| Zero net-new external crates | `git diff <orchard-main> HEAD -- Cargo.lock` adds ONE `[[package]]`: `cashew` (see the closure below); `image-builder/tests/shipped_crate_allowlist.rs` carries the single new workspace entry, landed in the crate-creation commit |
| Real-keyring anchors | `key.rs` `real_blocks_parse_and_fingerprints_match_pins` (computed fpr == pins), `real_self_cert_hash_algos_match_metadata` ([10,8,8]/[10]); `policy.rs` `real_blocks_validate_with_exactly_primary_candidates` (candidate set == {Primary}); `lib.rs` `real_issuer_consistency_anchor` (real `.sign` hashed issuer == Greg's pinned primary ∈ candidates) |
| Differential positives | `verify.rs` `generated_positive_matrix_verifies` (16 gpg sigs incl. 5 MiB), `leading_zero_mpi_signature_verifies_via_padding`; `api.rs` `shape_a_verifies_via_primary` / `shape_b_verifies_via_subkey` / `chunk_invariance_end_to_end` |
| Every grammar mutation → named class | `tests/negatives.rs` (the row-for-row coverage map) + the per-layer unit negatives it indexes (`sig.rs`, `key.rs`, `policy.rs`, `verify.rs`) |
| Truncation + fuzz: zero `ParserPanic` | `tests/robustness.rs` `truncation_sweep_both_entry_points`, `bounded_deterministic_fuzz_zero_parser_panics` (4096×4 corpus) |
| Real `.sign` parses to the expected tuple | `sig.rs` `real_sign_parses_to_metadata_values` (v4/0x00/RSA/SHA-256); `api.rs` `real_sign_constructs_and_wires_end_to_end` |
| Posture + `make verify` green | `#![forbid(unsafe_code)]` + the clippy wall (`lib.rs`) + the `panic = "unwind"` compile guard; `make verify` (`clippy --all-targets -D warnings` + full test set) |
| Allowlist entry in the creation commit | `image-builder/tests/shipped_crate_allowlist.rs` (commit `feat(cashew): crate scaffold …`) |

### Shipped closure (`cargo tree -p cashew --edges normal`)

cashew's direct deps are `base64 0.22.1`, `rsa 0.9.10`, `sha1 0.10.6`, `sha2 0.10.9` — all at the
exact versions already in the pre-cashew `Cargo.lock`. Their transitive closure (const-oid, digest,
num-bigint-dig, pkcs1/pkcs8/spki/der, signature, subtle, zeroize, …) was likewise already present via
the workspace's other RustCrypto consumers. The verified proof is the one-line lock delta above:
**adding cashew introduced exactly one new `[[package]]` stanza — its own.**

## Fixtures

- `tests/fixtures/real/` — the vendored kernel.org material (Greg + Sasha pruned exports, a real
  `linux-6.6.30.tar.sign`) + `METADATA.toml` (provenance, pins, recorded sizes + per-sig hash algos).
  Deterministic, toolchain-pinned.
- `tests/fixtures/gen/` — a throwaway differential corpus (both signing-key shapes, policy-negative
  keys, payloads × hashes, a leading-zero-MPI sig, a SHA-1 sig, an expiring sig). Regenerate with
  `tests/fixtures/gen.sh` (dev-host only; gpg 2.4.x; keys are random per run — tests bind to
  `gen/MANIFEST.toml`, never hardcoded fingerprints). Tests NEVER invoke gpg.
