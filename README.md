# eBPF Guardian

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://github.com/yourusername/ebpf-guardian/actions/workflows/rust.yml/badge.svg)](https://github.com/yourusername/ebpf-guardian/actions/workflows/rust.yml)

A Rust-based CLI tool for performing static semantic and behavioral analysis of eBPF programs from compiled object files.

## Features

- **Static Analysis**: Analyze eBPF object files (`.o`) or build from C and analyze
- **Control Flow Analysis**: Build and analyze control flow graphs
- **Map Usage Analysis**: Track and analyze eBPF map usage patterns
- **Verifier Scalability Analysis**: Cyclomatic complexity, branch counts, path estimates
- **Rule Engine**: Apply custom security and best practice rules
- **Multiple Output Formats**: Human-readable and JSON output

## Installation

### Prerequisites

#### Required
- Rust (latest stable version)
- LLVM/Clang with BPF target support

#### Installing LLVM with BPF support

ebguard requires LLVM/Clang with BPF target support. Install it using your system's package manager:

```bash
# On macOS
brew install llvm

# On Ubuntu/Debian
sudo apt install llvm clang

# On Fedora/RHEL
sudo dnf install llvm clang

# Verify LLVM installation
clang --version
llc --version | grep bpf  # Should show BPF in supported targets
```

ebguard will automatically detect LLVM in standard system locations. On macOS, it will check Homebrew's LLVM installation first (`/usr/local/opt/llvm/bin/clang`).

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ebpf-guardian.git
cd ebpf-guardian

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