# Changelog

All notable changes to this project will be documented in this file.

This project adheres to Keep a Changelog and Semantic Versioning.

## [Unreleased]
- Planned: improved verifier behavior simulation, additional plugins, richer CLI UX.

## [0.1.0] - 2025-08-08
### Added
- Usability
  - Progress bars for directory/glob scans (`indicatif`).
  - New commands: `validate-rules`, `init-rules`, `repl` (interactive exploration).
  - Embedded default rules and improved YAML error messages with line/column.
  - CFG export flags: `--cfg-dot-out`, `--cfg-ascii-out`, `--print-cfg-ascii`.
- Performance
  - Parallelized multi-file scanning via async tasks (`FuturesUnordered`).
  - SHA-256 based analysis cache under `.ebpf-guardian-cache/`.
- Extensibility
  - Regex-based instruction conditions in rules; optional scripting via `rhai` (feature `scripting`).
  - DOT and ASCII visualizations for CFG.
- Robustness
  - Better ELF validation and diagnostics.
  - Optional LLVM-free build path (`--no-default-features`).
- Documentation & Community
  - Troubleshooting section in README, CONTRIBUTING guide, and CI workflow (fmt, clippy, tests).
- Tooling
  - Criterion benchmarks for CFG build and disassembly.
  - `cargo-fuzz` target for ELF parsing.

### Changed
- Made `llvm-sys` optional behind the `llvm` default feature.

### Security
- Added `SECURITY.md` for vulnerability reporting and scope.

