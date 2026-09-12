# Provenance

This package is an in-tree, package-path-adapted fork of
`github.com/libp2p/go-nat` at commit
`01afc089f138bf26b9f467ccba7f53ac34e0c679`.

The upstream license is Apache-2.0 and is retained in `LICENSE`. MU changes add
context-aware external-address lookup and exact finite mapping grant cleanup
while preserving the legacy `NAT` API. The package remains private to the Realm
lifecycle implementation and does not introduce a second discovery engine.
