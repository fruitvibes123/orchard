# keyring/rust-lang — the vendored Rust release signing key (bump-time PGP trust anchor)

This file is the **trust root** for `orchard market upgrade --rust <ver>` (Component C): before a new
Rust toolchain is pinned, the fetched release manifest (`channel-rust-<ver>.toml`) must PGP-verify (via
the `cashew` crate) against **exactly this key**. It is consumed nowhere else — the container build does
NOT re-verify (authenticity is established once, at bump; the manifest's component `xz_hash`es, re-pinned
into `pins.toml [rust].*_sha256`, carry immutability to the `sha256sum -c` at container build — spec
§2/§3.5).

## The load-bearing difference from `keyring/kernel.org` — the SHA-1 exception

The kernel keyring is loaded by cashew's **strict** `Keyring::load` (every self-signature must be
SHA-256/512 under the no-skip law). The **Rust release key cannot be loaded that way**: all four of its
self-signatures are **SHA-1** (the UID self-cert + the two subkey bindings + the [S] back-sig — it has
never re-signed; verified packet-by-packet). So it is loaded via cashew's ONE documented
exception, **`Keyring::load_pinned_bare`**: trust comes from the **sha256 pin below + the
out-of-band-grounded fingerprint**, NOT from the key's own (weak) self-signatures. The bare path binds
**only the PRIMARY** (never a subkey — an appended-subkey vendoring tamper gains nothing)
and **skips** self-cert / validity / revocation processing; SHA-1 is never a verify input (the manifest
DATA signature it checks is RSA/**SHA-512**, strong).

Two integrity layers police these bytes:

1. **sha256 pin** in `pins.toml [rust-keyring]` (all four repo copies), checked
   - by `market verify` §3a-8 (file byte-exactness + *nothing unpinned in this directory*), and
   - by the bump itself, **before** cashew parses a single byte (a pin mismatch aborts pre-parse).
2. **cashew's `load_pinned_bare` exact-consumption** — the reused armor/packet/key grammar rejects any
   unaccounted packet, and every armored block must resolve to a caller pin, so appended material is a
   hard load failure.

## The pinned signer

| file | signer | v4 fingerprint (the consumer pin, `rust_bump.rs`) |
|---|---|---|
| `rust-signing.asc` | Rust Language (Tag and Release Signing Key) | `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE` |

`pub rsa4096 [SC]` (2013-09-26) + `[E]` + `[S]` subkeys. Rust signs release manifests with its **[SC]
primary** (confirmed against two real `channel-rust-*.toml.asc`: algo 1 / RSA, digest algo 10 / SHA-512,
issuer == the primary). The `[S]` subkey is **explicitly NOT relied on** — a future
subkey-signed manifest fails closed (`BadSignature`) → a keyring-refresh review event, never an
auto-trusted subkey.

### The fingerprint is grounded OUT-OF-BAND (independent of the rust CDN)

The v4 fingerprint is itself SHA-1, so it is **not** the security anchor — the sha256 pin is. But it is
a review cross-check, and it is grounded independent of `static.rust-lang.org`:

- **Arch Linux's git-reviewed `rust` PKGBUILD `validpgpkeys`** = `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE`
  ("Rust Language (Tag and Release Signing Key)"). A CDN compromise that swaps both the key file and a
  CDN-hosted "documented fingerprint" is caught by re-deriving against this out-of-band value.
- **2nd-source scarcity:** a 2nd git-reviewable PGP-fingerprint source is genuinely
  scarce — most distros (Void / Alpine / Chimera / NixOS / Fedora, checked) **checksum** the rust
  tarballs rather than PGP-verify them, so they carry no fingerprint. Arch is the clean anchor found; the
  fingerprint is the decade-stable, widely-cited Rust release key. Add a 2nd source if one is found at a
  refresh — not blocked on it.

## Provenance + derivation

- **Source:** `https://static.rust-lang.org/rust-key.gpg.ascii` (the Rust project's published release
  key, **5326 bytes**). Served from the rust CDN — acceptable here because (a) the vendored bytes are
  sha256-pinned and (b) the fingerprint is grounded out-of-band (above). **NEVER a keyserver.**
- **No prune** (unlike the kernel keyring): the bare path skips self-cert processing entirely, and a
  §5.0-style prune could not rescue an all-SHA-1 key regardless (the SHA-1 is on the sole live UID). The
  file is vendored **as published**, byte-for-byte.
- **Derivation / re-pin:**

```sh
curl -fsS https://static.rust-lang.org/rust-key.gpg.ascii -o keyring/rust-lang/rust-signing.asc
sha256sum keyring/rust-lang/rust-signing.asc          # -> the [rust-keyring] pin
gpg --show-keys keyring/rust-lang/rust-signing.asc     # confirm fpr == the Arch-grounded value above
```

- **Expected:** `rust-signing.asc` 5326 bytes, sha256
  `e54b09a439647e006b4831eec9785cbaaf3e07ab371c3a6ee6a68e1bdb9fbc6b`, fingerprint
  `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE`.

## Rotation / refresh — a REVIEW EVENT, never routine

A re-signed key, a rotation to a signing subkey, or a Rust-project key change:

1. Re-fetch from the source; **re-confirm the fingerprint against the out-of-band Arch anchor** (and any
   additional git-reviewable source found at refresh time).
2. Re-pin the new sha256 in `pins.toml [rust-keyring]` **in all four repos byte-identically** (seed-vault
   + orchard + fruit-basket + recipes — §3a-2 seeds-agree enforces this).
3. If Rust starts signing manifests with a **subkey**, that is a deliberate decision: the bare path binds
   the primary only, so a subkey-signed manifest fails closed until the trust model is revisited (do NOT
   simply widen the bind — re-examine whether the subkey binding can be grounded).
4. Commit keyring + pins together; the diff IS the review surface. `market verify` must be green before
   and after.

An unknown signer / bad manifest signature fails closed (`UnknownSigner` / `BadSignature`) until this
procedure vendors the key — that failure is the system working.

## The real-network operator check (named, not CI-claimed)

CI proves the bump + the container-rebuild MECHANISM on committed fixtures (`RECIPES_RUST_GATE`), and the
Phase-1 leg loads THIS real key via `load_pinned_bare` (the real-key anchor). The real full path is an
operator/dev step, on a full 4-repo checkout with network + docker:

```sh
cargo run -p orchard -- market upgrade --rust <ver>
```

Expect: a manifest fetch + cashew-verify, a four-file `pins.toml` diff (version + the two component
url/sha lines), a `docker build` of the rearchitected container (many minutes — a near-full-box rebuild),
every binary recompiled against it, staged, verified, swapped, **never auto-committed**. Review the diff
before committing.
