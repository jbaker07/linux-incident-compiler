#!/usr/bin/env bash
# install_systemd.sh - Install EDR systemd services
#
# This script installs the EDR stack as systemd services.
# It is idempotent and safe to run multiple times.
#
# Usage:
#   sudo ./scripts/install_systemd.sh [--caps]
#
# Options:
#   --caps    Use capabilities mode instead of root mode for capture
#
# Requirements:
#   - Linux with systemd
#   - Root privileges (sudo)
#   - EDR binaries in /opt/edr/bin or specify EDR_INSTALL_DIR

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════

EDR_INSTALL_DIR="${EDR_INSTALL_DIR:-/opt/edr}"
EDR_DATA_DIR="${EDR_DATA_DIR:-/var/lib/edr}"
EDR_USER="${EDR_USER:-edr}"
EDR_GROUP="${EDR_GROUP:-edr}"
SYSTEMD_DIR="/etc/systemd/system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

USE_CAPS=false
if [[ "${1:-}" == "--caps" ]]; then
    USE_CAPS=true
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ═══════════════════════════════════════════════════════════════════════════
# Functions
# ═══════════════════════════════════════════════════════════════════════════

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_systemd() {
    if ! command -v systemctl &> /dev/null; then
        log_error "systemd not found. This script requires systemd."
        exit 1
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

create_user() {
    if id "$EDR_USER" &>/dev/null; then
        log_info "User $EDR_USER already exists"
    else
        log_info "Creating user $EDR_USER..."
        useradd --system --no-create-home --shell /sbin/nologin "$EDR_USER"
        log_ok "User $EDR_USER created"
    fi
}

create_directories() {
    log_info "Creating directories..."
    
    # Install directories
    mkdir -p "$EDR_INSTALL_DIR/bin"
    mkdir -p "$EDR_INSTALL_DIR/playbooks/linux"
    
    # Data directories
    mkdir -p "$EDR_DATA_DIR/telemetry/segments"
    mkdir -p "$EDR_DATA_DIR/telemetry/logs"
    mkdir -p "$EDR_DATA_DIR/telemetry/runs"
    mkdir -p "$EDR_DATA_DIR/db"
    
    # Set ownership
    chown -R "$EDR_USER:$EDR_GROUP" "$EDR_DATA_DIR"
    chmod 750 "$EDR_DATA_DIR"
    
    log_ok "Directories created"
}

install_binaries() {
    log_info "Installing binaries..."
    
    local binaries=("edr-server" "edr-locald" "capture_linux_rotating")
    local src_dir="$REPO_ROOT/target/release"
    
    for bin in "${binaries[@]}"; do
        if [[ -f "$src_dir/$bin" ]]; then
            cp "$src_dir/$bin" "$EDR_INSTALL_DIR/bin/"
            chmod 755 "$EDR_INSTALL_DIR/bin/$bin"
            log_ok "Installed $bin"
        else
            log_warn "Binary not found: $src_dir/$bin (build with: cargo build --release)"
        fi
    done
}

install_playbooks() {
    log_info "Installing playbooks..."
    
    local src_dir="$REPO_ROOT/playbooks/linux"
    local dst_dir="$EDR_INSTALL_DIR/playbooks/linux"
    
    if [[ -d "$src_dir" ]]; then
        cp -r "$src_dir"/*.yaml "$dst_dir/" 2>/dev/null || true
        cp -r "$src_dir"/*.yml "$dst_dir/" 2>/dev/null || true
        chown -R "$EDR_USER:$EDR_GROUP" "$EDR_INSTALL_DIR/playbooks"
        local count=$(ls -1 "$dst_dir"/*.yaml "$dst_dir"/*.yml 2>/dev/null | wc -l)
        log_ok "Installed $count playbooks"
    else
        log_warn "Playbooks directory not found: $src_dir"
    fi
}

install_systemd_units() {
    log_info "Installing systemd units..."
    
    local unit_dir="$REPO_ROOT/systemd"
    
    # Install target
    cp "$unit_dir/edr.target" "$SYSTEMD_DIR/"
    log_ok "Installed edr.target"
    
    # Install capture service (choose variant)
    if $USE_CAPS; then
        cp "$unit_dir/edr-capture-caps.service" "$SYSTEMD_DIR/edr-capture.service"
        log_ok "Installed edr-capture.service (capabilities mode)"
    else
        cp "$unit_dir/edr-capture.service" "$SYSTEMD_DIR/"
        log_ok "Installed edr-capture.service (root mode)"
    fi
    
    # Install other services
    cp "$unit_dir/edr-locald.service" "$SYSTEMD_DIR/"
    log_ok "Installed edr-locald.service"
    
    cp "$unit_dir/edr-server.service" "$SYSTEMD_DIR/"
    log_ok "Installed edr-server.service"
    
    # Reload systemd
    systemctl daemon-reload
    log_ok "Systemd daemon reloaded"
}

enable_services() {
    log_info "Enabling services..."
    
    systemctl enable edr.target
    systemctl enable edr-capture.service
    systemctl enable edr-locald.service
    systemctl enable edr-server.service
    
    log_ok "Services enabled"
}

setup_bpf_mount() {
    # Ensure /sys/fs/bpf is mounted (for eBPF)
    if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
        if mount -t bpf bpf /sys/fs/bpf 2>/dev/null; then
            log_ok "Mounted /sys/fs/bpf"
        else
            log_warn "/sys/fs/bpf not mounted (eBPF may not work)"
        fi
    fi
}

print_summary() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo -e "${GREEN}EDR Stack Installation Complete${NC}"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "Installation paths:"
    echo "  Binaries:   $EDR_INSTALL_DIR/bin/"
    echo "  Playbooks:  $EDR_INSTALL_DIR/playbooks/linux/"
    echo "  Data:       $EDR_DATA_DIR/"
    echo ""
    echo "Systemd commands:"
    echo "  Start:   sudo systemctl start edr.target"
    echo "  Stop:    sudo systemctl stop edr.target"
    echo "  Status:  sudo systemctl status edr.target"
    echo "  Logs:    sudo journalctl -u edr-server -f"
    echo ""
    echo "Capture mode: $(if $USE_CAPS; then echo 'Capabilities (recommended)'; else echo 'Root (simple)'; fi)"
    echo ""
    echo "Health check (after start):"
    echo "  curl http://localhost:3000/api/health"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

main() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  EDR Stack Systemd Installer"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    
    check_root
    check_systemd
    
    local distro=$(detect_distro)
    log_info "Detected distribution: $distro"
    
    create_user
    create_directories
    install_binaries
    install_playbooks
    install_systemd_units
    enable_services
    setup_bpf_mount
    
    print_summary
}

main "$@"
