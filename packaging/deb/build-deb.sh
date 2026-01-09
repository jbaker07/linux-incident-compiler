#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# Build .deb package for Linux Incident Compiler
# Supports: Ubuntu 22.04+, Debian 12+
# ═══════════════════════════════════════════════════════════════════════════
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Package metadata
PKG_NAME="linux-incident-compiler"
PKG_VERSION="${VERSION:-0.1.0}"
PKG_ARCH="${ARCH:-amd64}"
PKG_MAINTAINER="EDR Team <support@example.com>"

# Output directory
BUILD_DIR="$ROOT_DIR/target/debian"
STAGING_DIR="$BUILD_DIR/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}"

echo "═══════════════════════════════════════════════════════════════"
echo "Building .deb package: ${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"
echo "═══════════════════════════════════════════════════════════════"

# Clean and create staging directory
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

# Create directory structure
mkdir -p "$STAGING_DIR/DEBIAN"
mkdir -p "$STAGING_DIR/opt/edr/bin"
mkdir -p "$STAGING_DIR/opt/edr/playbooks/linux"
mkdir -p "$STAGING_DIR/lib/systemd/system"
mkdir -p "$STAGING_DIR/usr/share/doc/${PKG_NAME}"
mkdir -p "$STAGING_DIR/var/lib/edr"

# ─────────────────────────────────────────────────────────────────────────────
# Build binaries
# ─────────────────────────────────────────────────────────────────────────────
echo "Building release binaries..."
cd "$ROOT_DIR"

# Build main binaries
cargo build --release -p edr-server
cargo build --release -p edr-locald

# Build capture agent with eBPF support
cargo build --release -p agent-linux --features with-ebpf-load || {
    echo "Warning: eBPF build failed, building without eBPF..."
    cargo build --release -p agent-linux
}

# ─────────────────────────────────────────────────────────────────────────────
# Copy binaries
# ─────────────────────────────────────────────────────────────────────────────
echo "Copying binaries..."

cp "$ROOT_DIR/target/release/edr-server" "$STAGING_DIR/opt/edr/bin/"
cp "$ROOT_DIR/target/release/edr-locald" "$STAGING_DIR/opt/edr/bin/"

if [ -f "$ROOT_DIR/target/release/capture_linux_rotating" ]; then
    cp "$ROOT_DIR/target/release/capture_linux_rotating" "$STAGING_DIR/opt/edr/bin/"
fi

chmod 755 "$STAGING_DIR/opt/edr/bin/"*

# ─────────────────────────────────────────────────────────────────────────────
# Copy systemd units
# ─────────────────────────────────────────────────────────────────────────────
echo "Copying systemd units..."
cp "$ROOT_DIR/systemd/"*.service "$STAGING_DIR/lib/systemd/system/"
cp "$ROOT_DIR/systemd/"*.target "$STAGING_DIR/lib/systemd/system/"
chmod 644 "$STAGING_DIR/lib/systemd/system/"*

# ─────────────────────────────────────────────────────────────────────────────
# Copy playbooks
# ─────────────────────────────────────────────────────────────────────────────
echo "Copying playbooks..."
if [ -d "$ROOT_DIR/playbooks/linux" ]; then
    cp -r "$ROOT_DIR/playbooks/linux/"* "$STAGING_DIR/opt/edr/playbooks/linux/" 2>/dev/null || true
fi

# ─────────────────────────────────────────────────────────────────────────────
# Copy documentation
# ─────────────────────────────────────────────────────────────────────────────
echo "Copying documentation..."
cp "$ROOT_DIR/README.md" "$STAGING_DIR/usr/share/doc/${PKG_NAME}/"
if [ -f "$ROOT_DIR/docs/INSTALL_LINUX.md" ]; then
    cp "$ROOT_DIR/docs/INSTALL_LINUX.md" "$STAGING_DIR/usr/share/doc/${PKG_NAME}/"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Create DEBIAN/control
# ─────────────────────────────────────────────────────────────────────────────
echo "Creating control file..."

# Calculate installed size
INSTALLED_SIZE=$(du -sk "$STAGING_DIR" | cut -f1)

cat > "$STAGING_DIR/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${PKG_VERSION}
Section: admin
Priority: optional
Architecture: ${PKG_ARCH}
Installed-Size: ${INSTALLED_SIZE}
Maintainer: ${PKG_MAINTAINER}
Depends: libc6 (>= 2.35), libssl3 (>= 3.0.0) | libssl1.1, systemd
Recommends: libelf1
Description: Linux Incident Compiler - Security incident detection
 Linux Incident Compiler provides endpoint detection and response (EDR)
 capabilities for Linux systems.
 .
 Features:
  - Process execution monitoring
  - File system telemetry
  - Network connection tracking
  - eBPF-based kernel tracing (optional)
  - Playbook-based incident detection
 .
 Supported: Ubuntu 22.04+, Debian 12+
EOF

# ─────────────────────────────────────────────────────────────────────────────
# Copy maintainer scripts
# ─────────────────────────────────────────────────────────────────────────────
echo "Copying maintainer scripts..."
cp "$ROOT_DIR/packaging/debian/postinst" "$STAGING_DIR/DEBIAN/"
cp "$ROOT_DIR/packaging/debian/prerm" "$STAGING_DIR/DEBIAN/"
cp "$ROOT_DIR/packaging/debian/postrm" "$STAGING_DIR/DEBIAN/"
chmod 755 "$STAGING_DIR/DEBIAN/"post* "$STAGING_DIR/DEBIAN/"pre*

# ─────────────────────────────────────────────────────────────────────────────
# Create conffiles
# ─────────────────────────────────────────────────────────────────────────────
cat > "$STAGING_DIR/DEBIAN/conffiles" << EOF
/opt/edr/playbooks/linux
EOF

# ─────────────────────────────────────────────────────────────────────────────
# Build the package
# ─────────────────────────────────────────────────────────────────────────────
echo "Building package..."
cd "$BUILD_DIR"

fakeroot dpkg-deb --build "${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}"

# Move to target directory
mv "${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb" "$ROOT_DIR/target/"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "✓ Package built: target/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"
echo ""
echo "To install:"
echo "  sudo dpkg -i target/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"
echo "  sudo apt-get install -f  # Fix dependencies if needed"
echo "═══════════════════════════════════════════════════════════════"
