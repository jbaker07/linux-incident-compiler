#!/usr/bin/env bash
# ebpf-preflight.sh - Check prerequisites for eBPF build
#
# Run this before: cargo build -p agent-linux --features with-ebpf-load
#
# This script is DEV-ONLY. It checks for required packages and prints
# install commands if anything is missing.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "═══════════════════════════════════════════════════════════════"
echo "  eBPF Build Preflight Check"
echo "═══════════════════════════════════════════════════════════════"
echo ""

MISSING=()

# ─────────────────────────────────────────────────────────────────────
# Check: clang
# ─────────────────────────────────────────────────────────────────────
if command -v clang &> /dev/null; then
    CLANG_VERSION=$(clang --version | head -1)
    echo -e "${GREEN}✓${NC} clang: $CLANG_VERSION"
else
    echo -e "${RED}✗${NC} clang: NOT FOUND"
    MISSING+=("clang")
fi

# ─────────────────────────────────────────────────────────────────────
# Check: llvm-strip (optional but useful)
# ─────────────────────────────────────────────────────────────────────
if command -v llvm-strip &> /dev/null; then
    echo -e "${GREEN}✓${NC} llvm-strip: found"
else
    echo -e "${YELLOW}⚠${NC} llvm-strip: not found (optional)"
fi

# ─────────────────────────────────────────────────────────────────────
# Check: pkg-config
# ─────────────────────────────────────────────────────────────────────
if command -v pkg-config &> /dev/null; then
    echo -e "${GREEN}✓${NC} pkg-config: found"
else
    echo -e "${RED}✗${NC} pkg-config: NOT FOUND"
    MISSING+=("pkg-config")
fi

# ─────────────────────────────────────────────────────────────────────
# Check: libelf headers (libelf-dev)
# ─────────────────────────────────────────────────────────────────────
if [ -f /usr/include/libelf.h ] || [ -f /usr/include/gelf.h ]; then
    echo -e "${GREEN}✓${NC} libelf headers: /usr/include/libelf.h"
elif pkg-config --exists libelf 2>/dev/null; then
    echo -e "${GREEN}✓${NC} libelf: $(pkg-config --modversion libelf)"
else
    echo -e "${RED}✗${NC} libelf-dev: NOT FOUND"
    MISSING+=("libelf-dev")
fi

# ─────────────────────────────────────────────────────────────────────
# Check: zlib headers (zlib1g-dev)
# ─────────────────────────────────────────────────────────────────────
if [ -f /usr/include/zlib.h ]; then
    echo -e "${GREEN}✓${NC} zlib headers: /usr/include/zlib.h"
elif pkg-config --exists zlib 2>/dev/null; then
    echo -e "${GREEN}✓${NC} zlib: $(pkg-config --modversion zlib)"
else
    echo -e "${RED}✗${NC} zlib1g-dev: NOT FOUND"
    MISSING+=("zlib1g-dev")
fi

# ─────────────────────────────────────────────────────────────────────
# Check: libbpf headers
# ─────────────────────────────────────────────────────────────────────
if [ -d /usr/include/bpf ] || [ -f /usr/include/bpf/libbpf.h ]; then
    echo -e "${GREEN}✓${NC} libbpf headers: /usr/include/bpf/"
elif pkg-config --exists libbpf 2>/dev/null; then
    echo -e "${GREEN}✓${NC} libbpf: $(pkg-config --modversion libbpf)"
else
    echo -e "${RED}✗${NC} libbpf-dev: NOT FOUND"
    MISSING+=("libbpf-dev")
fi

# ─────────────────────────────────────────────────────────────────────
# Check: Linux headers
# ─────────────────────────────────────────────────────────────────────
KERNEL_VERSION=$(uname -r)
HEADER_PATH="/usr/src/linux-headers-${KERNEL_VERSION}"
if [ -d "$HEADER_PATH" ] || [ -d "/lib/modules/${KERNEL_VERSION}/build" ]; then
    echo -e "${GREEN}✓${NC} kernel headers: $KERNEL_VERSION"
else
    echo -e "${RED}✗${NC} linux-headers-${KERNEL_VERSION}: NOT FOUND"
    MISSING+=("linux-headers-$(uname -r)")
fi

# ─────────────────────────────────────────────────────────────────────
# Check: make
# ─────────────────────────────────────────────────────────────────────
if command -v make &> /dev/null; then
    echo -e "${GREEN}✓${NC} make: found"
else
    echo -e "${RED}✗${NC} make: NOT FOUND"
    MISSING+=("make")
fi

# ─────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"

if [ ${#MISSING[@]} -eq 0 ]; then
    echo -e "${GREEN}All eBPF prerequisites satisfied!${NC}"
    echo ""
    echo "You can now build with:"
    echo "  cargo build -p agent-linux --features with-ebpf-load"
    echo ""
    exit 0
else
    echo -e "${RED}Missing ${#MISSING[@]} package(s)${NC}"
    echo ""
    
    # Detect distro and print install command
    if [ -f /etc/debian_version ]; then
        echo "Install on Ubuntu/Debian:"
        echo -e "  ${YELLOW}sudo apt update && sudo apt install -y ${MISSING[*]}${NC}"
    elif [ -f /etc/fedora-release ]; then
        # Map package names for Fedora
        FEDORA_PKGS=()
        for pkg in "${MISSING[@]}"; do
            case "$pkg" in
                libelf-dev) FEDORA_PKGS+=("elfutils-libelf-devel") ;;
                zlib1g-dev) FEDORA_PKGS+=("zlib-devel") ;;
                libbpf-dev) FEDORA_PKGS+=("libbpf-devel") ;;
                linux-headers-*) FEDORA_PKGS+=("kernel-devel") ;;
                *) FEDORA_PKGS+=("$pkg") ;;
            esac
        done
        echo "Install on Fedora:"
        echo -e "  ${YELLOW}sudo dnf install -y ${FEDORA_PKGS[*]}${NC}"
    elif [ -f /etc/arch-release ]; then
        # Map package names for Arch
        ARCH_PKGS=()
        for pkg in "${MISSING[@]}"; do
            case "$pkg" in
                libelf-dev) ARCH_PKGS+=("libelf") ;;
                zlib1g-dev) ARCH_PKGS+=("zlib") ;;
                libbpf-dev) ARCH_PKGS+=("libbpf") ;;
                linux-headers-*) ARCH_PKGS+=("linux-headers") ;;
                pkg-config) ARCH_PKGS+=("pkgconf") ;;
                *) ARCH_PKGS+=("$pkg") ;;
            esac
        done
        echo "Install on Arch Linux:"
        echo -e "  ${YELLOW}sudo pacman -S ${ARCH_PKGS[*]}${NC}"
    else
        echo "Install these packages using your distro's package manager:"
        echo "  ${MISSING[*]}"
    fi
    echo ""
    exit 1
fi
