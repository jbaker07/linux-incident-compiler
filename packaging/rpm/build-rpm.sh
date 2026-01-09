#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# Build RPM package for Linux Incident Compiler
# Supports: Rocky Linux 9, RHEL 9, Fedora 39+
# ═══════════════════════════════════════════════════════════════════════════
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Package metadata
PKG_NAME="linux-incident-compiler"
PKG_VERSION="${VERSION:-0.1.0}"

echo "═══════════════════════════════════════════════════════════════"
echo "Building RPM package: ${PKG_NAME}-${PKG_VERSION}"
echo "═══════════════════════════════════════════════════════════════"

# Check for rpmbuild
if ! command -v rpmbuild &> /dev/null; then
    echo "Error: rpmbuild not found. Install with:"
    echo "  sudo dnf install rpm-build rpmdevtools"
    exit 1
fi

# Set up RPM build tree
RPMBUILD_DIR="$ROOT_DIR/target/rpmbuild"
mkdir -p "$RPMBUILD_DIR"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# ─────────────────────────────────────────────────────────────────────────────
# Create source tarball
# ─────────────────────────────────────────────────────────────────────────────
echo "Creating source tarball..."

TARBALL_DIR="$RPMBUILD_DIR/SOURCES/${PKG_NAME}-${PKG_VERSION}"
rm -rf "$TARBALL_DIR"
mkdir -p "$TARBALL_DIR"

# Copy source files (excluding target directory and git)
rsync -a --exclude='target' --exclude='.git' --exclude='*.deb' --exclude='*.rpm' \
    "$ROOT_DIR/" "$TARBALL_DIR/"

# Create tarball
cd "$RPMBUILD_DIR/SOURCES"
tar -czf "${PKG_NAME}-${PKG_VERSION}.tar.gz" "${PKG_NAME}-${PKG_VERSION}"
rm -rf "$TARBALL_DIR"

# ─────────────────────────────────────────────────────────────────────────────
# Copy spec file
# ─────────────────────────────────────────────────────────────────────────────
echo "Copying spec file..."
cp "$SCRIPT_DIR/linux-incident-compiler.spec" "$RPMBUILD_DIR/SPECS/"

# Update version in spec file
sed -i "s/^Version:.*/Version:        ${PKG_VERSION}/" "$RPMBUILD_DIR/SPECS/linux-incident-compiler.spec"

# ─────────────────────────────────────────────────────────────────────────────
# Build RPM
# ─────────────────────────────────────────────────────────────────────────────
echo "Building RPM..."

rpmbuild -bb \
    --define "_topdir $RPMBUILD_DIR" \
    "$RPMBUILD_DIR/SPECS/linux-incident-compiler.spec"

# ─────────────────────────────────────────────────────────────────────────────
# Copy output
# ─────────────────────────────────────────────────────────────────────────────
echo "Copying output..."

# Find and copy the built RPM
RPM_FILE=$(find "$RPMBUILD_DIR/RPMS" -name "*.rpm" -type f | head -1)

if [ -n "$RPM_FILE" ]; then
    cp "$RPM_FILE" "$ROOT_DIR/target/"
    RPM_NAME=$(basename "$RPM_FILE")
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "✓ Package built: target/${RPM_NAME}"
    echo ""
    echo "To install:"
    echo "  sudo dnf install target/${RPM_NAME}"
    echo "═══════════════════════════════════════════════════════════════"
else
    echo "Error: No RPM file found in $RPMBUILD_DIR/RPMS"
    exit 1
fi
