# Alpine trusted signing keys (operator-pinned trust anchors)

Alpine Linux's RSA package-signing public keys — the operator-owned trust anchors the image-builder
verifies pinned apks against (the provenance gate). Note the load-bearing gate is the **sha256
immutability pin** in `pinned-apks.toml`; this RSA signature is provenance / defense-in-depth.

`orchard build` loads every `*.rsa.pub` here into the `AlpineApkProvider`'s
`TrustedKeys` (key = filename minus `.rsa.pub`, matching `pinned-apks.toml`'s `signing_key`; all
current pins use `-6165ee59`). The same keys are mirrored under `tests/fixtures/` for the
`apk_verify` unit tests — these are the production copies.

Provenance: Alpine's official `/etc/apk/keys` set (the `alpine-keys` package). Re-pin only on a
deliberate Alpine signing-key rotation.
