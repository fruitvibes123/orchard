# keyring/kernel.org

`gregkh.asc` and `sashal.asc` are the vendored kernel.org signer keys, the PGP trust root for
`orchard market upgrade --kernel <ver>`. Before a new kernel version is pinned, the fetched
`linux-<ver>.tar.sign` must PGP-verify over the uncompressed tarball against exactly these keys
through the `cashew` crate. Nothing else consumes them. The bake does not re-verify: authenticity is
established once, at bump, and `pins.toml [kernel].sha256` carries immutability to the bake.

## Pinned signers

| file | signer | v4 fingerprint (the consumer pin, `kernel_bump.rs`) |
|---|---|---|
| `gregkh.asc` | Greg Kroah-Hartman | `647F28654894E3BD457199BE38DBBDC86092693E` |
| `sashal.asc` | Sasha Levin | `E27E5D8A3403A2EF66873BBCDEA66FF797772CDC` |

Both sign stable-release tarballs with their `[SC]` primary key; neither key has a signing subkey
(verified against pgpkeys.git and live `.sign` files). Linus and Ben Hutchings are not vendored. Their
keys are added only if mainline or an older LTS is ever pinned, which is a review event.

## Integrity checks

Two layers police the key bytes:

1. sha256 pins in `pins.toml [kernel-keyring]` (all four repo copies), checked
   - by `market verify` §3a-8 (file byte-exactness, and nothing unpinned in `keyring/kernel.org/`), and
   - by the bump itself before cashew parses a single byte (a pin mismatch aborts pre-parse).
2. cashew's load-time no-skip law: every signature packet in a loadable file must cryptographically
   verify in its positional role, so any edit to the vendored material is a hard load failure.

## Provenance and derivation (§5.0 vendored-input contract)

The files are minimized, attribute-free, pruned, armored exports, byte-reproducible under the pinned
toolchain; a reviewer checks them by re-deriving the bytes.

- Source: the authoritative kernel.org developer keyring,
  `git://git.kernel.org/pub/scm/docs/kernel/pgpkeys.git`, commit
  `ebb799f8016c129731873ac4c0beafa68617b2a4`. Never a keyserver: a short-ID keyserver fetch for Greg
  returned a poisoned "Totally Legit Signing Key" decoy, and a stale keyserver copy lacked his 2026-05
  re-signatures. The cashew audit trail records both incidents.
- Pinned toolchain: gpg 2.4.9 + libgcrypt 1.12.2. `export-minimal` semantics drift across gpg
  versions (dev.gnupg.org T7990), so byte-reproducibility is claimed within the pinned toolchain only.
  A toolchain bump is a review event that re-derives and re-pins.
- Command, per signer, against a keystore populated only from the named pgpkeys.git commit:

```sh
gpg --armor \
    --export-options export-minimal,no-export-attributes \
    --export-filter 'keep-uid=<keep_uid below>' \
    --export-filter drop-subkey=usage=e \
    --export <full-fingerprint>
```

- Per-signer `keep-uid` filters. Dead-employer UIDs carry the signers' legacy SHA-1 self-certs, so
  the filters keep live UIDs only and cashew's strict {SHA-256, SHA-512} whitelist holds:
  - gregkh: `mbox=greg@kroah.com || mbox=gregkh@kernel.org || mbox=gregkh@linuxfoundation.org`
  - sashal: `mbox=sashal@kernel.org`
- Expected output: `gregkh.asc` 3439 bytes, sha256
  `9dbf6e08cfd1b08c5123596091fdef160dc8ff4be9b1ee8e8b4113b04387f87c`; `sashal.asc` 1644 bytes,
  sha256 `c4ed1898871201915d3e5f502925a877a43b772dab1eb93f0844f2d64584ac2a`. These equal the cashew
  real-fixture exports (`crates/cashew/tests/fixtures/real/`, same derivation), whose METADATA.toml
  records the fuller per-key facts.

## Rotation and refresh

A new signing subkey, a new stable signer, a re-signed key, or a gpg-toolchain bump is a review
event, never routine:

1. Update pgpkeys.git to a new named commit. Adjust the `keep-uid` / `drop-subkey` filters if the key
   shape changed; a future signing subkey needs a deliberate revisit of the filter, checking the effect of
   `drop-subkey=usage=e` on it.
2. Re-derive with the pinned toolchain; confirm byte-reproducibility across two runs.
3. Prune-shift differential: compare the governing-self-sig verdict gpg reports on the unpruned
   pgpkeys.git key against cashew's verdict on the pruned file. A divergence is a review stop.
4. Re-pin the new sha256(s) in `pins.toml [kernel-keyring]` in all four repos byte-identically
   (seed-vault, orchard, fruit-basket, recipes; §3a-2 seeds-agree enforces this).
5. Commit keyring and pins together; the diff is the review surface. `market verify` must be green
   before and after.

An unknown signer on a real tarball fails closed as `UnknownSigner`/`BadSignature` until this
procedure vendors the key.

cashew runs no online revocation check, an accepted tradeoff; the re-derivable review procedure is
the backstop. cashew honors in-keyring revocation certificates at load.

## Real-network operator check

CI proves the bump on committed fixtures (`RECIPES_KERNEL_GATE`). The real path is a named
operator/dev step outside CI, run on a full 4-repo checkout with network:

```sh
cargo run -p orchard -- market upgrade --kernel <ver>
```

Expect a ~150 MB `.tar.xz` fetch and a streamed ~1.5 GB decompress-verify (cashew streams, so there
is no multi-GB RAM spike), then a four-file `pins.toml` diff and regenerated sync-pins outputs, staged,
verified and swapped, never auto-committed. Review the diff (version + sha256 lines only) before
committing.
