# Bundled sing dependency

## Status and scope

Owner-selected repository-local dependency, 2026-09-23. Root go.mod replaces
`github.com/sagernet/sing` with `./third_party/sing`. Ordinary checkout builds
use these tracked sources; no external checkout, private dependency repository,
machine-specific replace, special modfile or module-cache modification is needed.

Official Xray baseline `d562d8947d3175db86b4fa849742433a9876cb63` already
requires sing v0.5.1 and sing-shadowsocks v0.2.7. Xray's SS2022 adapters use the
latter's codecs and sing's packet-copy/NAT utilities. This is not a switch to
the sing-box application or its configuration/runtime owner.

## Provenance and invariants

- Upstream: https://github.com/SagerNet/sing.git
- Original v0.5.1 commit: `8c0bf1c05e576e854cb071ca1116958df7bf6692`.
- Reviewed repair commit: `d572e2debaa3694504ef8e3c506b16db10e2f05d`.
- Reviewed Git tree: `04623baa2908ab0639da9efae4f4930c59869c1b`.
- `sing-source.json` records the complete source snapshot's count, size and
  SHA-256 digest over sorted relative paths and file-content SHA-256 hashes.

All tracked regular files from that tree are preserved, including upstream
tests, go.mod/go.sum, README and LICENSE. Git metadata and working-tree files
are not copied. The module keeps its own identity and license; the Xray root
license does not relabel it. Nested upstream workflow files are provenance
content, not newly installed root GitHub workflows.

The repair changes only `common/cache/lrucache.go`,
`common/udpnat/service.go`, `common/udpnat/conn_wait.go`, and adds
`common/cache/identity_test.go`, `common/udpnat/lifecycle_test.go`.
It repairs expected-object retirement, concurrent source metadata access,
close/enqueue cancellation, queued-buffer custody and short-copy reporting.
There is no codec, router, policy engine or SS2022 owner replacement.

## Validation and maintenance

Run `python third_party/check_sing.py` to check snapshot integrity.
The root package traversal does not run tests inside a nested Go module;
test the repaired dependency explicitly:

```text
go -C third_party/sing test -mod=readonly -race ./common/cache ./common/udpnat
go test -mod=readonly -race ./proxy/shadowsocks_2022
```

The root relative replace applies to the root main module. A downstream main
module importing Xray must provide an equivalent dependency replacement; Go
does not inherit dependency modules' replace directives. This checkout result
does not supply that separate downstream adapter/build integration.

Future dependency changes must reconcile the source snapshot, minimal patch,
original fixtures, manifest and focused validation together. Do not regenerate
the digest just to hide unexpected edits. Imported source size is kept separate
from the maintained production patch in the current control/statistics receipt.

## Non-goals and open decisions

This bundle does not select the deferred early decoded handoff or direct UDP
dispatch ideas. Public export, device/artifact validation and release decisions
remain under their own contracts.
