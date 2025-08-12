# eBPF Guardian

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://github.com/ebpf-guardian/cli/actions/workflows/ci.yml/badge.svg)](https://github.com/ebpf-guardian/cli/actions/workflows/ci.yml)

A Rust-based CLI tool for performing static semantic and behavioral analysis of eBPF programs from compiled object files.

## Features

- **Static Analysis**: Analyze eBPF object files (`.o`) or build from C and analyze
- **Control Flow Analysis**: Build and analyze control flow graphs
- **Map Usage Analysis**: Track and analyze eBPF map usage patterns
- **Verifier Scalability Analysis**: Cyclomatic complexity, branch counts, path estimates
- **Rule Engine**: Apply custom security and best practice rules
- **Multiple Output Formats**: Human-readable and JSON output

## Quick Install

### Option 1: Homebrew (macOS)

```bash
# Add our tap and install
brew tap ebpf-guardian/homebrew-ebpf-guardian
brew install ebpf-guardian

# For full features, ensure LLVM is installed:
brew install llvm@17
brew reinstall ebpf-guardian
```

> **Note**: If LLVM 17 is not available, you'll get a minimal build that can analyze existing `.o` files but cannot build from C source.

## Releases

| Version | Date | Description |
|---------|------|-------------|
| [v0.1.0](https://github.com/ebpf-guardian/cli/releases/tag/v0.1.0) | 2024-12-19 | Initial release with core eBPF analysis features |

### Option 2: Install Script

**Unix/Linux/macOS:**
```bash
curl -fsSL https://install.ebpf-guardian.com | bash
```

**Windows (PowerShell):**
```powershell
iwr -useb https://raw.githubusercontent.com/ebpf-guardian/cli/main/scripts/install.ps1 | iex
```

- Automatically detects your platform (macOS, Debian/Ubuntu, Fedora)
- Installs Rust and LLVM 17 when needed
- Builds and installs the `ebguard` CLI

Optional environment flags:

- `EBG_NO_LLVM=1` to install a minimal build without LLVM features
- `EBG_CHANNEL=<stable|beta|nightly>` to pick Rust toolchain (default: stable)
- `EBG_NO_SUDO=1` to avoid sudo if you are already root

Examples:

```bash
# Minimal install without LLVM features
EBG_NO_LLVM=1 curl -fsSL https://install.ebpf-guardian.com | bash

# Use nightly Rust toolchain
EBG_CHANNEL=nightly curl -fsSL https://install.ebpf-guardian.com | bash
```

If you prefer, you can still use the raw GitHub URL:

```bash
curl -fsSL https://raw.githubusercontent.com/ebpf-guardian/cli/main/scripts/install.sh | bash
```

## Installation

### Prerequisites

#### Required
- Rust (latest stable version)
- LLVM 17 with BPF target support (for full functionality)

#### Optional
- Clang (for building eBPF C programs)

#### Quick Dependency Check

We provide a script to check your environment:

```bash
# Make script executable
chmod +x scripts/check_deps.sh

# Run dependency check
./scripts/check_deps.sh
```

#### Installing Dependencies

1. **Rust**
   ```bash
   # Install Rust from https://rustup.rs/
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **LLVM 17**
   ```bash
   # On macOS
   brew install llvm@17
   export LLVM_SYS_170_PREFIX="/opt/homebrew/opt/llvm@17"  # Apple Silicon
   # or: export LLVM_SYS_170_PREFIX="/usr/local/opt/llvm@17"  # Intel Mac

   # On Ubuntu/Debian
   sudo apt install llvm-17-dev clang-17

   # On Fedora/RHEL
   sudo dnf install llvm17-devel clang17
   ```

3. **Verify LLVM/Clang Installation**
   ```bash
   clang --version
   llc --version | grep bpf  # Should show BPF in supported targets
   ```

#### Installation Options

1. **Full Installation (with LLVM)**
   - Includes all features
   - Requires LLVM 17
   - Best for development and full analysis

2. **Basic Installation (without LLVM)**
   - Limited functionality
   - No LLVM dependency
   - Good for basic analysis and rule checking
   ```bash
   # Install without LLVM features
   cargo install --path . --no-default-features
   ```

   Features available without LLVM:
   - ✅ Control flow graph analysis
   - ✅ Map usage analysis
   - ✅ Rule engine
   - ✅ JSON/Table output
   - ✅ Existing object file analysis
   - ❌ Building from C source
   - ❌ LLVM-based optimizations
   - ❌ Advanced verifier predictions

### Troubleshooting

- Missing LLVM or wrong version
  - Install LLVM 17 and set `LLVM_SYS_170_PREFIX` (see Prerequisites)
- `error: unexpected argument '--cfg-dot-out'`
  - You might be running an old global `ebguard`. Reinstall: `cargo install --path .`
- Invalid ELF errors
  - Ensure the file is a BPF object for `EM_BPF` and has a `.text` section
- BTF map syntax issues when compiling C
  - Prefer legacy `struct bpf_map_def` for compatibility with provided headers
- macOS notes
  - Install `llvm@17` with Homebrew; set the prefix for `llvm-sys`

### Installation

```bash
# Clone the repository
git clone https://github.com/ebpf-guardian/cli.git
cd cli

# Install globally (recommended)
cargo install --path .

# Now you can use 'ebguard' from anywhere
ebguard build program.c --scan

# Or, alternatively, create a symlink
cargo build --release
sudo ln -sf "$(pwd)/target/release/ebguard" /usr/local/bin/ebguard
```

## Usage

### Basic Commands

```bash
# Scan an eBPF object file
ebguard scan --file ./path/to/program.o

# Build C source and scan
ebguard scan --file ./path/to/program.c --build

# Scan all .o files in a directory (non-recursive)
ebguard scan --dir ./path/to/dir

# Scan with glob pattern in current directory
ebguard scan --glob "*.o"

# Use a custom rule set
ebguard scan --file ./program.o --rules ./security-rules.yaml

# JSON output
ebguard scan --file ./program.o --format json

# Strict mode (exit non-zero on high severity)
ebguard scan --file ./program.o --strict

# Validate a rules file without scanning
ebguard validate-rules --file ./rules.yaml

# Generate a sample rules file
ebguard init-rules --out ./rules.sample.yaml

# REPL to explore analyses interactively
ebguard repl

# Emit CFG visuals
ebguard scan --file ./program.o --cfg-dot-out program.dot
ebguard scan --file ./program.o --print-cfg-ascii
```

## Rule System

eBPF Guardian uses a YAML-based rule system to define security policies and best practices. Here's an example rule file:

```yaml
# rules/security.yaml
- id: no-shared-writable-map
  name: No Shared Writable Maps
  description: Writable maps should not be shared between programs
  severity: critical
  enabled: true
  condition:
    type: shared_writable_map

- id: no-deprecated-helpers
  name: No Deprecated Helpers
  description: Avoid using deprecated eBPF helper functions
  severity: medium
  enabled: true
  condition:
    type: uses_helper
    helper_name: bpf_trace_printk
```

## Project Structure

```
ebpf-guardian/
├── Cargo.toml           # Project configuration
├── src/
│   ├── main.rs          # CLI entrypoint
│   ├── cli.rs           # Command-line interface
│   ├── analyzer/        # eBPF analysis modules
│   │   ├── mod.rs
│   │   ├── disassembler.rs
│   │   ├── map_tracker.rs
│   │   ├── program_graph.rs
│   │   └── rule_engine.rs
│   ├── loader/          # ELF parsing utilities
│   │   ├── mod.rs
│   │   ├── elf_parser.rs
│   │   └── bpftool.rs   # (reserved for future, not used in static analysis)
│   ├── output/          # Output formatting
│   │   ├── mod.rs
│   │   └── formatter.rs
│   └── utils/           # Utility functions
│       └── logger.rs
└── tests/               # Integration tests
```

## Testing

The project includes a comprehensive test suite with unit tests, integration tests, and sample eBPF programs for testing.

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run tests with logging
RUST_LOG=debug cargo test
```

### Test Structure

- `tests/data/`: Sample eBPF programs for testing
  - `xdp_pass.o`: Simple XDP program
  - `map_example.o`: Program with map usage
  
- `src/*/tests.rs`: Unit tests for each module
  - Analyzer tests
  - Output formatter tests
  - Cache system tests
  
- `tests/cli.rs`: Integration tests for CLI functionality
  - Command-line argument testing
  - Output format verification
  - Rule evaluation
  - Cache system

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under either of

 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

## Acknowledgments

- The Rust eBPF community for their amazing work
- The LLVM project for the excellent tooling
- All contributors who help improve this project