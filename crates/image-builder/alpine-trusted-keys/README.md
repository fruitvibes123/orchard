# Alpine trusted signing keys

Alpine Linux's RSA package-signing public keys, the operator-owned trust anchors the image-builder
verifies pinned apks against (the provenance gate). The load-bearing gate is the sha256 immutability
pin in `pinned-apks.toml`; the RSA signature is provenance and defense in depth.

`orchard build` loads every `*.rsa.pub` in `alpine-trusted-keys/` into the `AlpineApkProvider`'s
`TrustedKeys` (key = filename minus `.rsa.pub`, matching `pinned-apks.toml`'s `signing_key`; all
current pins use `-6165ee59`). These are the production copies; `tests/fixtures/` mirrors the same
keys for the `apk_verify` unit tests.

Provenance: Alpine's official `/etc/apk/keys` set (the `alpine-keys` package). Re-pin only on a
deliberate Alpine signing-key rotation.
