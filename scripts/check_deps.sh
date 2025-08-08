#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Checking dependencies for ebpf-guardian..."
echo

# Check Rust
echo "Checking Rust installation..."
if command -v rustc >/dev/null 2>&1; then
    version=$(rustc --version)
    echo -e "${GREEN}✓ Rust is installed:${NC} $version"
else
    echo -e "${RED}✗ Rust is not installed${NC}"
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

# Check Cargo
echo "Checking Cargo installation..."
if command -v cargo >/dev/null 2>&1; then
    version=$(cargo --version)
    echo -e "${GREEN}✓ Cargo is installed:${NC} $version"
else
    echo -e "${RED}✗ Cargo is not installed${NC}"
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

# Check LLVM
echo "Checking LLVM installation..."
LLVM_LOCATIONS=(
    "/usr/local/opt/llvm@17/bin/llvm-config"  # Homebrew LLVM 17
    "/opt/homebrew/opt/llvm@17/bin/llvm-config"  # Apple Silicon Homebrew LLVM 17
    "/usr/bin/llvm-config"  # System LLVM
)

LLVM_FOUND=false
for llvm_path in "${LLVM_LOCATIONS[@]}"; do
    if [ -x "$llvm_path" ]; then
        version=$("$llvm_path" --version)
        echo -e "${GREEN}✓ LLVM found at ${llvm_path}:${NC} version $version"
        LLVM_FOUND=true
        # Export LLVM_SYS prefix for the parent shell
        PARENT_DIR=$(dirname $(dirname "$llvm_path"))
        echo "export LLVM_SYS_170_PREFIX=\"$PARENT_DIR\""
        break
    fi
done

if [ "$LLVM_FOUND" = false ]; then
    echo -e "${RED}✗ LLVM 17 not found in standard locations${NC}"
    echo "Please install LLVM 17:"
    echo "  macOS: brew install llvm@17"
    echo "  Ubuntu: apt install llvm-17-dev"
    echo "  Fedora: dnf install llvm17-devel"
    exit 1
fi

# Check Clang
echo "Checking Clang installation..."
if command -v clang >/dev/null 2>&1; then
    version=$(clang --version | head -n 1)
    echo -e "${GREEN}✓ Clang is installed:${NC} $version"
else
    echo -e "${RED}✗ Clang is not installed${NC}"
    echo "Please install Clang with your package manager"
    exit 1
fi

# Check BPF target support
echo "Checking BPF target support..."
if llc --version | grep -q "bpf"; then
    echo -e "${GREEN}✓ BPF target support is available${NC}"
else
    echo -e "${YELLOW}! BPF target support might be missing${NC}"
    echo "Some features may not work without BPF target support"
fi

echo
echo -e "${GREEN}All mandatory dependencies are installed!${NC}"