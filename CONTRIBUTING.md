## Contributing to eBPF Guardian

Thanks for your interest in contributing!

### Getting Started
- Install Rust (stable) and LLVM 17 (see README prerequisites)
- Clone the repo and run:
  - `cargo build`
  - `cargo test`
  - `cargo fmt` and `cargo clippy`

### Development Guidelines
- Code: clear, readable, explicit types for public APIs
- Tests: include unit/integration tests for new functionality
- Lints: `cargo clippy -- -D warnings` must pass
- Formatting: `cargo fmt -- --check` must pass

### Adding Rules
- Place examples in `rules.yaml` and update docs
- Keep rule IDs stable; document `severity`, `description`, and `rule_type`

### Adding Analysis Modules
- Prefer trait-based extensibility; see `analyzer` modules
- Keep memory allocations bounded; avoid unnecessary clones

### Pull Requests
- Keep PRs focused and small
- Include a short description and any trade-offs

### CI
- CI will run fmt, clippy, and tests on Linux

We appreciate your contributions!

