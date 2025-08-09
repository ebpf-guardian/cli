#!/usr/bin/env bash
set -euo pipefail

# eBPF Guardian installer
# - Auto-detects platform (macOS, Debian/Ubuntu, Fedora)
# - Installs dependencies (Rust, LLVM 17, Clang, build tools)
# - Builds and installs ebguard via cargo
#
# Usage (recommended):
#   curl -fsSL https://raw.githubusercontent.com/glnreddy/ebpf-guardian/main/scripts/install.sh | bash
#
# Flags/env:
#   EBG_NO_SUDO=1             # Avoid sudo for package installs (if already root)
#   EBG_NO_LLVM=1             # Install minimal build without LLVM features
#   EBG_CHANNEL=stable         # Rust toolchain channel (default: stable)

info()  { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
ok()    { printf "\033[1;32m[ OK ]\033[0m %s\n" "$*"; }
warn()  { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err()   { printf "\033[1;31m[FAIL]\033[0m %s\n" "$*"; }

SUDO="sudo"
if [ "${EBG_NO_SUDO:-}" = "1" ] || [ "$(id -u)" = "0" ]; then
  SUDO=""
fi

RUST_CHANNEL="${EBG_CHANNEL:-stable}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    return 1
  fi
}

ensure_rust() {
  if require_cmd cargo && require_cmd rustc; then
    ok "Rust is already installed ($(rustc --version))"
    return 0
  fi
  info "Installing Rust ($RUST_CHANNEL) via rustup (non-interactive)..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "$RUST_CHANNEL"
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
  ok "Rust installed: $(rustc --version)"
}

detect_distro() {
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "${ID:-unknown}"
  else
    echo "unknown"
  fi
}

ensure_deps_macos() {
  if ! require_cmd brew; then
    info "Homebrew not found. Installing Homebrew (non-interactive)..."
    NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # Add brew to PATH for Apple Silicon
    if [ -d "/opt/homebrew/bin" ]; then
      export PATH="/opt/homebrew/bin:$PATH"
    fi
  fi

  info "Installing LLVM 17 via Homebrew..."
  brew install llvm@17 || true
  LLVM_PREFIX=$(brew --prefix llvm@17 2>/dev/null || true)
  if [ -n "$LLVM_PREFIX" ]; then
    export LLVM_SYS_170_PREFIX="$LLVM_PREFIX"
    ok "LLVM 17 found at $LLVM_PREFIX"
  else
    warn "Could not determine LLVM 17 prefix via Homebrew"
  fi
}

ensure_deps_debian() {
  info "Installing build dependencies (Debian/Ubuntu)..."
  $SUDO apt-get update -y
  $SUDO apt-get install -y --no-install-recommends \
    ca-certificates curl git pkg-config build-essential \
    llvm-17-dev clang-17 || true

  # Try to determine LLVM prefix via llvm-config-17
  LLVM_PREFIX=""
  if require_cmd llvm-config-17; then
    LLVM_PREFIX=$(llvm-config-17 --prefix 2>/dev/null || true)
  elif require_cmd llvm-config; then
    LLVM_PREFIX=$(llvm-config --prefix 2>/dev/null || true)
  fi
  if [ -z "$LLVM_PREFIX" ] && [ -d "/usr/lib/llvm-17" ]; then
    LLVM_PREFIX="/usr/lib/llvm-17"
  fi
  if [ -n "$LLVM_PREFIX" ]; then
    export LLVM_SYS_170_PREFIX="$LLVM_PREFIX"
    ok "LLVM 17 prefix: $LLVM_PREFIX"
  else
    warn "LLVM 17 not detected; will attempt minimal install without LLVM if build fails"
  fi
}

ensure_deps_fedora() {
  info "Installing build dependencies (Fedora/RHEL)..."
  $SUDO dnf install -y \
    ca-certificates curl git make gcc gcc-c++ pkgconf-pkg-config \
    llvm17-devel clang17 || true

  if [ -d "/usr/lib/llvm-17" ]; then
    export LLVM_SYS_170_PREFIX="/usr/lib/llvm-17"
    ok "LLVM 17 prefix: /usr/lib/llvm-17"
  else
    warn "LLVM 17 not detected; will attempt minimal install without LLVM if build fails"
  fi
}

ensure_deps_linux() {
  local distro
  distro=$(detect_distro)
  case "$distro" in
    debian|ubuntu|linuxmint|pop|neon)
      ensure_deps_debian ;;
    fedora|rhel|centos|rocky|almalinux)
      ensure_deps_fedora ;;
    *)
      warn "Unrecognized Linux distro '$distro'. Skipping system package installation."
      ;;
  esac
}

install_ebguard() {
  info "Installing ebguard via cargo..."

  # Ensure cargo is in PATH for this shell
  if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
  fi

  local cargo_args=(--locked --git https://github.com/ebpf-guardian/cli.git --bin ebguard)

  # Prefer LLVM-enabled build unless explicitly disabled
  if [ "${EBG_NO_LLVM:-}" = "1" ]; then
    warn "EBG_NO_LLVM=1 set; installing minimal build without LLVM features"
    cargo_args+=(--no-default-features)
  fi

  # CC/CXX selection when specific versioned clang exists
  if require_cmd clang-17; then
    export CC=clang-17
    if require_cmd clang++-17; then
      export CXX=clang++-17
    fi
  fi

  if cargo install "${cargo_args[@]}"; then
    ok "ebguard installed successfully"
    return 0
  fi

  warn "Full install failed. Falling back to minimal build without LLVM features..."
  cargo install --locked --git https://github.com/ebpf-guardian/cli.git --bin ebguard --no-default-features
  ok "ebguard minimal install completed"
}

main() {
  info "Detecting platform..."
  OS_NAME=$(uname -s || echo unknown)
  case "$OS_NAME" in
    Darwin)
      ok "macOS detected"
      ensure_deps_macos ;;
    Linux)
      ok "Linux detected"
      ensure_deps_linux ;;
    *)
      warn "Unsupported OS: $OS_NAME. Proceeding with Rust-only install."
      ;;
  esac

  ensure_rust
  install_ebguard

  echo
  ok "Ready to use! Try:"
  echo "  ebguard --help"
  echo "  ebguard scan --file ./tests/data/simple.o --format table"
}

main "$@"

