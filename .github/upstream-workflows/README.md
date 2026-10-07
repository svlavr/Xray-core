# Upstream workflow reference

These files are preserved byte-for-byte from official Xray-core commit
`7da5dae6502b787fc6d903863e9a6c5043d107a2`. GitHub does not execute workflows
outside `.github/workflows`. Release, container publication and scheduled asset
updates are not enabled on `codex/mu-core`.

The active workflows run source checks, ordinary Linux/Windows/macOS tests,
full Linux race tests and 32 platform build jobs. The two MIPS jobs also compile
soft-float variants. Build outputs remain temporary runner files; no artifacts,
releases or packages are uploaded. Android cross-builds do not establish device
or application acceptance. Fork regression jobs are added with their source.

Tests, fixtures, dependencies and runtime source retain the official baseline.
Tests prepare GeoIP/GeoSite from immutable public revision
`e4e6584208db6bcdfa340adabf2de509aae5c64f` with SHA256 verification.
All CI inputs are public; no private development pack is required.
