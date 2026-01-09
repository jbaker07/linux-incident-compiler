#!/usr/bin/env bash
# uninstall_systemd.sh - Remove EDR systemd services
#
# This script removes the EDR stack systemd services.
# It optionally removes data and binaries.
#
# Usage:
#   sudo ./scripts/uninstall_systemd.sh [--purge]
#
# Options:
#   --purge   Also remove /opt/edr and /var/lib/edr (data loss!)

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════

EDR_INSTALL_DIR="${EDR_INSTALL_DIR:-/opt/edr}"
EDR_DATA_DIR="${EDR_DATA_DIR:-/var/lib/edr}"
EDR_USER="${EDR_USER:-edr}"
SYSTEMD_DIR="/etc/systemd/system"

PURGE=false
if [[ "${1:-}" == "--purge" ]]; then
    PURGE=true
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

stop_services() {
    log_info "Stopping services..."
    
    systemctl stop edr.target 2>/dev/null || true
    systemctl stop edr-server.service 2>/dev/null || true
    systemctl stop edr-locald.service 2>/dev/null || true
    systemctl stop edr-capture.service 2>/dev/null || true
    
    log_ok "Services stopped"
}

disable_services() {
    log_info "Disabling services..."
    
    systemctl disable edr.target 2>/dev/null || true
    systemctl disable edr-server.service 2>/dev/null || true
    systemctl disable edr-locald.service 2>/dev/null || true
    systemctl disable edr-capture.service 2>/dev/null || true
    
    log_ok "Services disabled"
}

remove_systemd_units() {
    log_info "Removing systemd units..."
    
    local units=(
        "edr.target"
        "edr-capture.service"
        "edr-locald.service"
        "edr-server.service"
    )
    
    for unit in "${units[@]}"; do
        if [[ -f "$SYSTEMD_DIR/$unit" ]]; then
            rm -f "$SYSTEMD_DIR/$unit"
            log_ok "Removed $unit"
        fi
    done
    
    systemctl daemon-reload
    log_ok "Systemd daemon reloaded"
}

remove_user() {
    if id "$EDR_USER" &>/dev/null; then
        log_info "Removing user $EDR_USER..."
        userdel "$EDR_USER" 2>/dev/null || true
        log_ok "User $EDR_USER removed"
    fi
}

remove_directories() {
    if $PURGE; then
        log_warn "Purging installation and data directories..."
        
        if [[ -d "$EDR_INSTALL_DIR" ]]; then
            rm -rf "$EDR_INSTALL_DIR"
            log_ok "Removed $EDR_INSTALL_DIR"
        fi
        
        if [[ -d "$EDR_DATA_DIR" ]]; then
            rm -rf "$EDR_DATA_DIR"
            log_ok "Removed $EDR_DATA_DIR"
        fi
    else
        log_info "Keeping installation directories (use --purge to remove)"
        log_info "  $EDR_INSTALL_DIR"
        log_info "  $EDR_DATA_DIR"
    fi
}

print_summary() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo -e "${GREEN}EDR Stack Uninstallation Complete${NC}"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    if $PURGE; then
        echo "All EDR components have been removed, including data."
    else
        echo "Systemd services removed. Data preserved at:"
        echo "  $EDR_INSTALL_DIR"
        echo "  $EDR_DATA_DIR"
        echo ""
        echo "To fully remove, run: sudo $0 --purge"
    fi
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

main() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  EDR Stack Systemd Uninstaller"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    
    check_root
    
    stop_services
    disable_services
    remove_systemd_units
    remove_directories
    
    if $PURGE; then
        remove_user
    fi
    
    print_summary
}

main "$@"
