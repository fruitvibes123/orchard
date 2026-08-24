# vendor/ — pinned source, GENERATED (do not hand-edit)

These crate trees are **vendored pinned source** for the pinned supply chain. Each was
fetched from the operator artifact store and **verified against its sha256 in
`../consume-pins.toml`** before unpacking (the verify-at-consumption gate; a mismatch aborts).

| dir | store key | owner repo | used by |
|-----|-----------|------------|---------|
| `grape/` | `grape-src` | seed-vault | image-builder + orchard (rescue host-key seed derive) |
| `dragonfruit/` | `dragonfruit-src` | seed-vault | orchard CLI only (`[sign]` — the artifact signer; CRUX) |
| `fb-manifest/` | `fb-manifest-src` | fruit-basket | image-builder (the typed service-manifest schema) |
| `rambutan/` | `rambutan-src` | fruit-basket | the UEFI loader, compiled per-bake in the `Firmware::Uefi` arm only |

`consume-pins.toml` is the authority. To regenerate after a pin-bump:

```sh
make vendor        # = orchard vendor: fetch + verify each *-src tarball, unpack here
```

**Do not hand-edit** these trees — `make vendor` overwrites them, and the committed bytes must
match the pinned shas (a future audit / `repro-check` re-derives them). The committed copy gives
an offline-buildable, reviewable checkout (the operator chose commit-vendored); the shas in
`consume-pins.toml` remain the integrity authority regardless of what's committed here.
