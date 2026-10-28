# keyring/rust-lang

`rust-signing.asc` is the vendored Rust release signing key, the PGP trust root for
`orchard market upgrade --rust <ver>` (Component C). Before a new Rust toolchain is pinned, the
fetched release manifest (`channel-rust-<ver>.toml`) must PGP-verify against exactly this key through
the `cashew` crate. Nothing else consumes the key. The container build does not re-verify:
authenticity is established once, at bump, and the manifest's component `xz_hash`es, re-pinned into
`pins.toml [rust].*_sha256`, carry immutability to the `sha256sum -c` at container build (spec
§2/§3.5).

## Pinned signer

| file | signer | v4 fingerprint (the consumer pin, `rust_bump.rs`) |
|---|---|---|
| `rust-signing.asc` | Rust Language (Tag and Release Signing Key) | `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE` |

`pub rsa4096 [SC]` (2013-09-26) with `[E]` and `[S]` subkeys. Rust signs release manifests with its
`[SC]` primary, confirmed against two real `channel-rust-*.toml.asc` files (algo 1 / RSA, digest algo
10 / SHA-512, issuer == the primary). Nothing relies on the `[S]` subkey: a future subkey-signed
manifest fails closed (`BadSignature`) and becomes a keyring-refresh review event, never an
auto-trusted subkey.

### Out-of-band fingerprint source

The v4 fingerprint is itself SHA-1, so the sha256 pin is the security anchor and the fingerprint is a
review cross-check. Its source is independent of `static.rust-lang.org`:

- Arch Linux's git-reviewed `rust` PKGBUILD: `validpgpkeys` = `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE`
  ("Rust Language (Tag and Release Signing Key)"). Re-deriving against this out-of-band value catches a
  CDN compromise that swaps both the key file and a CDN-hosted "documented fingerprint".
- A second git-reviewable PGP-fingerprint source is scarce. Most distros (Void / Alpine / Chimera /
  NixOS / Fedora, checked) checksum the rust tarballs and do not PGP-verify them, so they carry no
  fingerprint. Arch is the clean anchor found; the fingerprint is the decade-stable, widely cited Rust
  release key. A refresh that finds a second source adds it; the current pin does not wait on one.

## SHA-1 exception

cashew's strict `Keyring::load` loads the kernel keyring (`keyring/kernel.org`), where every
self-signature must be SHA-256/512 under the no-skip law. The Rust release key cannot load that way.
All four of its self-signatures are SHA-1 (the UID self-cert, the two subkey bindings and the `[S]`
back-sig), and the key has never been re-signed (verified packet by packet). It therefore loads
through cashew's one documented exception, `Keyring::load_pinned_bare`: trust comes from the sha256
pin and the out-of-band-grounded fingerprint, never from the key's own weak self-signatures. The bare
path binds only the primary, never a subkey, so a vendoring tamper that appends a subkey gains
nothing. It skips self-cert, validity and revocation processing. SHA-1 is never a verify input; the
manifest data signature it checks is RSA/SHA-512.

## Integrity checks

Two layers police the key bytes:

1. The sha256 pin in `pins.toml [rust-keyring]` (all four repo copies), checked
   - by `market verify` §3a-8 (file byte-exactness, and nothing unpinned in `keyring/rust-lang/`), and
   - by the bump itself before cashew parses a single byte (a pin mismatch aborts pre-parse).
2. `load_pinned_bare` exact consumption: the reused armor/packet/key grammar rejects any unaccounted
   packet, and every armored block must resolve to a caller pin, so appended material is a hard load
   failure.

## Provenance and derivation

- Source: `https://static.rust-lang.org/rust-key.gpg.ascii`, the Rust project's published release key
  (5326 bytes), never a keyserver. The rust CDN serves it. The vendored bytes are sha256-pinned and
  the fingerprint is grounded out of band, so that source is acceptable.
- No prune, unlike the kernel keyring. The bare path skips self-cert processing, and a §5.0-style
  prune could not rescue an all-SHA-1 key in any case: the SHA-1 is on the sole live UID. The file is
  vendored as published, byte for byte.
- Derivation and re-pin:

```sh
curl -fsS https://static.rust-lang.org/rust-key.gpg.ascii -o keyring/rust-lang/rust-signing.asc
sha256sum keyring/rust-lang/rust-signing.asc          # -> the [rust-keyring] pin
gpg --show-keys keyring/rust-lang/rust-signing.asc     # confirm fpr == the Arch-grounded value above
```

- Expected: `rust-signing.asc` 5326 bytes, sha256
  `e54b09a439647e006b4831eec9785cbaaf3e07ab371c3a6ee6a68e1bdb9fbc6b`, fingerprint
  `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE`.

## Rotation and refresh

A re-signed key, a rotation to a signing subkey, or a Rust-project key change is a review event,
never routine:

1. Re-fetch from the source. Re-confirm the fingerprint against the out-of-band Arch anchor and any
   additional git-reviewable source found at refresh time.
2. Re-pin the new sha256 in `pins.toml [rust-keyring]` in all four repos byte-identically (seed-vault,
   orchard, fruit-basket, recipes; §3a-2 seeds-agree enforces this).
3. If Rust starts signing manifests with a subkey, the change needs a deliberate decision. The bare
   path binds the primary only, so a subkey-signed manifest fails closed until the trust model is
   revisited. Re-examine whether the subkey binding can be grounded; do not widen the bind.
4. Commit keyring and pins together; the diff is the review surface. `market verify` must be green
   before and after.

An unknown signer or a bad manifest signature fails closed (`UnknownSigner` / `BadSignature`) until
this procedure vendors the key.

## Real-network operator check

CI proves the bump and the container-rebuild mechanism on committed fixtures (`RECIPES_RUST_GATE`),
and the Phase-1 leg loads the real key via `load_pinned_bare` (the real-key anchor). The real full
path is a named operator/dev step outside CI, on a full 4-repo checkout with network and docker:

```sh
cargo run -p orchard -- market upgrade --rust <ver>
```

Expect a manifest fetch and cashew-verify, a four-file `pins.toml` diff (version + the two component
url/sha lines), a `docker build` of the rearchitected container (many minutes, a near-full-box
rebuild), and every binary recompiled against it. The result is staged, verified and swapped, never
auto-committed. Review the diff before committing.
