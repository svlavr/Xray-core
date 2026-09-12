# Provenance

This package is an in-tree, package-path-adapted fork of
`github.com/jackpal/go-nat-pmp` v1.0.2.

The upstream Apache-2.0 copyright and license notice is retained in `LICENSE`.
MU changes add context-aware RPC entry points whose owned UDP socket is closed
and joined on cancellation, while retaining the legacy client methods.
