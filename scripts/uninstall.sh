#!/usr/bin/env bash
set -euo pipefail

# eBPF Guardian uninstaller
# - Removes ebguard binary
# - Optionally cleans cargo cache
# - Optionally removes LLVM
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ebpf-guardian/cli/main/scripts/uninstall.sh | bash
#
# Flags/env:
#   EBG_CLEAN_CARGO=1        # Also clean cargo cache for ebpf-guardian
#   EBG_REMOVE_LLVM=1        # Also remove LLVM (if installed via script)
#   EBG_NO_SUDO=1           # Avoid sudo for package removals (if already root)

info()  { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
ok()    { printf "\033[1;32m[ OK ]\033[0m %s\n" "$*"; }
warn()  { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err()   { printf "\033[1;31m[FAIL]\033[0m %s\n" "$*"; }

SUDO="sudo"
if [ "${EBG_NO_SUDO:-}" = "1" ] || [ "$(id -u)" = "0" ]; then
  SUDO=""
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    return 1
  fi
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

remove_binary() {
  info "Removing ebguard binary..."
  
  # Try common binary locations
  local binary_paths=(
    "$HOME/.cargo/bin/ebguard"
    "/usr/local/bin/ebguard"
    "/usr/bin/ebguard"
    "/opt/homebrew/bin/ebguard"  # Homebrew on Apple Silicon
  )

  local found=0
  for path in "${binary_paths[@]}"; do
    if [ -f "$path" ]; then
      if [ -w "$path" ] || [ -n "$SUDO" ]; then
        ${SUDO} rm -f "$path"
        ok "Removed $path"
        found=1
      else
        err "Cannot remove $path (permission denied)"
      fi
    fi
  done

  if [ "$found" -eq 0 ]; then
    warn "No ebguard binary found in standard locations"
  fi
}

clean_cargo_cache() {
  if [ "${EBG_CLEAN_CARGO:-}" != "1" ]; then
    return
  fi

  info "Cleaning cargo cache..."
  if require_cmd cargo; then
    # Remove git checkout cache
    rm -rf "$HOME/.cargo/git/checkouts/cli-"*
    # Remove registry cache
    cargo clean -p ebpf-guardian || true
    ok "Cleaned cargo caches"
  else
    warn "Cargo not found, skipping cache cleanup"
  fi
}

remove_llvm_macos() {
  if [ "${EBG_REMOVE_LLVM:-}" != "1" ]; then
    return
  fi

  info "Removing LLVM from Homebrew..."
  if require_cmd brew; then
    brew uninstall llvm@17 || true
    ok "Removed LLVM 17"
  else
    warn "Homebrew not found, skipping LLVM removal"
  fi
}

remove_llvm_debian() {
  if [ "${EBG_REMOVE_LLVM:-}" != "1" ]; then
    return
  fi

  info "Removing LLVM packages..."
  $SUDO apt-get remove -y llvm-17-dev clang-17 || true
  ok "Removed LLVM 17 packages"
}

remove_llvm_fedora() {
  if [ "${EBG_REMOVE_LLVM:-}" != "1" ]; then
    return
  fi

  info "Removing LLVM packages..."
  $SUDO dnf remove -y llvm17-devel clang17 || true
  ok "Removed LLVM 17 packages"
}

cleanup_config() {
  info "Cleaning up configuration files..."
  
  # Remove config directory if it exists
  local config_dir="$HOME/.config/ebpf-guardian"
  if [ -d "$config_dir" ]; then
    rm -rf "$config_dir"
    ok "Removed config directory"
  fi

  # Remove cache directory if it exists
  local cache_dir="$HOME/.cache/ebpf-guardian"
  if [ -d "$cache_dir" ]; then
    rm -rf "$cache_dir"
    ok "Removed cache directory"
  fi
}

main() {
  info "Starting uninstallation..."
  
  # Remove binary first
  remove_binary
  
  # Clean cargo cache if requested
  clean_cargo_cache
  
  # Platform-specific LLVM cleanup
  OS_NAME=$(uname -s || echo unknown)
  case "$OS_NAME" in
    Darwin)
      remove_llvm_macos ;;
    Linux)
      case "$(detect_distro)" in
        debian|ubuntu|linuxmint|pop|neon)
          remove_llvm_debian ;;
        fedora|rhel|centos|rocky|almalinux)
          remove_llvm_fedora ;;
      esac
      ;;
  esac
  
  # Clean up config files
  cleanup_config
  
  echo
  ok "Uninstallation complete!"
  if [ "${EBG_REMOVE_LLVM:-}" != "1" ]; then
    info "Note: LLVM was preserved. Use EBG_REMOVE_LLVM=1 to remove it."
  fi
  if [ "${EBG_CLEAN_CARGO:-}" != "1" ]; then
    info "Note: Cargo caches were preserved. Use EBG_CLEAN_CARGO=1 to clean them."
  fi
}

main "$@"