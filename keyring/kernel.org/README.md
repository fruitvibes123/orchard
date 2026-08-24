# keyring/kernel.org — the vendored kernel.org signer keyring (bump-time PGP trust anchor)

These files are the **trust root** for `orchard market upgrade --kernel <ver>`: before a new kernel
version is pinned, the fetched `linux-<ver>.tar.sign` must PGP-verify (via the `cashew` crate) over
the uncompressed tarball against **exactly these keys**. They are consumed nowhere else — the bake
does NOT re-verify (authenticity is established once, at bump; the `pins.toml [kernel].sha256`
carries immutability to the bake).

Two integrity layers police these bytes:

1. **sha256 pins** in `pins.toml [kernel-keyring]` (all four repo copies), checked
   - by `market verify` §3a-8 (file byte-exactness + *nothing unpinned in this directory*), and
   - by the bump itself, **before** cashew parses a single byte (a pin mismatch aborts pre-parse).
2. **cashew's load-time no-skip law** — every signature packet in a loadable file must
   cryptographically verify in its positional role, so any edit to the vendored material is a hard
   load failure (cashew's no-skip law).

## The pinned signers

| file | signer | v4 fingerprint (the consumer pin, `kernel_bump.rs`) |
|---|---|---|
| `gregkh.asc` | Greg Kroah-Hartman | `647F28654894E3BD457199BE38DBBDC86092693E` |
| `sashal.asc` | Sasha Levin | `E27E5D8A3403A2EF66873BBCDEA66FF797772CDC` |

Both sign stable-release tarballs with their **[SC] primary key** (no signing subkey exists —
verified against pgpkeys.git + live `.sign` files). Linus / Ben Hutchings are NOT
vendored — added only if we ever pin mainline / older LTS (a review event).

## Provenance + derivation (the §5.0 vendored-input contract)

The files are **minimized, attribute-free, PRUNED, armored exports** — byte-reproducible under the
PINNED toolchain, so a reviewer re-derives instead of eyeballing base64 walls:

- **Source:** the authoritative kernel.org developer keyring —
  `git://git.kernel.org/pub/scm/docs/kernel/pgpkeys.git`, commit
  `ebb799f8016c129731873ac4c0beafa68617b2a4`. **NEVER a keyserver** — a short-ID keyserver fetch for
  Greg returned a poisoned "Totally Legit Signing Key" decoy, and a stale keyserver copy lacked his
  2026-05 re-signatures (both incidents recorded in the cashew audit trail).
- **Pinned toolchain:** gpg **2.4.9** + libgcrypt **1.12.2**. `export-minimal` semantics drift
  across gpg versions (dev.gnupg.org T7990), so byte-reproducibility is claimed **within the pinned
  toolchain only**; a toolchain bump = a review event that re-derives + re-pins.
- **Command** (per signer, against a keystore populated ONLY from the named pgpkeys.git commit):

```sh
gpg --armor \
    --export-options export-minimal,no-export-attributes \
    --export-filter 'keep-uid=<keep_uid below>' \
    --export-filter drop-subkey=usage=e \
    --export <full-fingerprint>
```

- **Per-signer `keep-uid` filters** (live UIDs only; dead-employer UIDs carry the signers' legacy
  SHA-1 self-certs and are pruned so cashew's strict {SHA-256, SHA-512} whitelist holds):
  - gregkh: `mbox=greg@kroah.com || mbox=gregkh@kernel.org || mbox=gregkh@linuxfoundation.org`
  - sashal: `mbox=sashal@kernel.org`
- **Expected output:** `gregkh.asc` 3439 bytes, sha256
  `9dbf6e08cfd1b08c5123596091fdef160dc8ff4be9b1ee8e8b4113b04387f87c`; `sashal.asc` 1644 bytes,
  sha256 `c4ed1898871201915d3e5f502925a877a43b772dab1eb93f0844f2d64584ac2a` — these equal the
  cashew real-fixture exports (`crates/cashew/tests/fixtures/real/`, same derivation, whose
  METADATA.toml records the fuller per-key facts).

## Rotation / refresh — a REVIEW EVENT, never routine

A new signing subkey, a new stable signer, a re-signed key, or a gpg-toolchain bump:

1. Update pgpkeys.git to a new named commit; adjust the `keep-uid` / `drop-subkey` filters if the
   key shape changed (a future signing subkey means dropping `drop-subkey=usage=e`'s effect on it —
   revisit the filter deliberately).
2. Re-derive with the pinned toolchain; confirm byte-reproducibility across two runs.
3. **Prune-shift differential:** compare the governing-self-sig verdict gpg
   reports on the **UNPRUNED** pgpkeys.git key against cashew's verdict on the pruned file — a
   divergence is a review stop, not a curiosity.
4. Re-pin the new sha256(s) in `pins.toml [kernel-keyring]` **in all four repos byte-identically**
   (seed-vault + orchard + fruit-basket + recipes — §3a-2 seeds-agree enforces this).
5. Commit keyring + pins together; the diff IS the review surface. `market verify` must be green
   before and after.

An unknown signer on a real tarball fails closed as `UnknownSigner`/`BadSignature` until this
procedure vendors the key — that failure is the system working.

**No online revocation check** (accepted tradeoff): the backstop is exactly this
re-derivable review procedure. In-keyring revocation certificates ARE honored by cashew at load.

## The real-network operator check (named, not CI-claimed)

CI proves the bump on committed fixtures (`RECIPES_KERNEL_GATE`). The real path is an operator/dev
step, run on a full 4-repo checkout with network:

```sh
cargo run -p orchard -- market upgrade --kernel <ver>
```

Expect: ~150 MB `.tar.xz` fetch + a streamed ~1.5 GB decompress-verify (no multi-GB RAM spike —
cashew streams), then a four-file `pins.toml` diff + regenerated sync-pins outputs, staged, verified,
swapped, **never auto-committed**. Review the diff (version + sha256 lines only) before committing.
