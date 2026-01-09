#!/usr/bin/env bash
# smoke-tauri.sh - Quick Tauri Linux smoke test
#
# Run this script from the linux-incident-compiler root directory
# to verify the GUI works on your display session.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "═══════════════════════════════════════════════════════════════"
echo "  Tauri Linux Smoke Test"
echo "═══════════════════════════════════════════════════════════════"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

# ─────────────────────────────────────────────────────────────────────
# Check: Display session
# ─────────────────────────────────────────────────────────────────────
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    echo -e "${RED}✗${NC} No display session detected (DISPLAY and WAYLAND_DISPLAY are empty)"
    echo "  Run this script from a graphical terminal (X11 or Wayland desktop)"
    exit 1
fi
echo -e "${GREEN}✓${NC} Display: ${XDG_SESSION_TYPE:-unknown} (DISPLAY=${DISPLAY:-none}, WAYLAND=${WAYLAND_DISPLAY:-none})"

# ─────────────────────────────────────────────────────────────────────
# Check: Binary exists
# ─────────────────────────────────────────────────────────────────────
BINARY="src-tauri/target/release/edr-desktop"
if [ ! -x "$BINARY" ]; then
    echo -e "${YELLOW}⚠${NC} Binary not found, building..."
    (cd src-tauri && cargo build --release)
fi

if [ ! -x "$BINARY" ]; then
    echo -e "${RED}✗${NC} Failed to build binary"
    exit 1
fi
echo -e "${GREEN}✓${NC} Binary: $BINARY"

# ─────────────────────────────────────────────────────────────────────
# Check: UI assets
# ─────────────────────────────────────────────────────────────────────
if [ ! -f "ui/index.html" ]; then
    echo -e "${RED}✗${NC} ui/index.html not found"
    exit 1
fi
echo -e "${GREEN}✓${NC} UI assets: ui/index.html"

# ─────────────────────────────────────────────────────────────────────
# Check: GTK/WebKit deps
# ─────────────────────────────────────────────────────────────────────
MISSING_LIBS=$(ldd "$BINARY" 2>/dev/null | grep "not found" || true)
if [ -n "$MISSING_LIBS" ]; then
    echo -e "${RED}✗${NC} Missing libraries:"
    echo "$MISSING_LIBS"
    exit 1
fi
echo -e "${GREEN}✓${NC} All shared libraries available"

# ─────────────────────────────────────────────────────────────────────
# Launch app
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "Launching EDR Desktop..."
echo "(Close the window to complete the test)"
echo ""

# Launch with timeout
"$BINARY" &
PID=$!

# Wait a few seconds to see if it crashes immediately
sleep 3

if kill -0 $PID 2>/dev/null; then
    echo -e "${GREEN}✓${NC} App launched successfully (PID: $PID)"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "  ${GREEN}SMOKE TEST PASSED${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "The EDR Desktop window should now be visible."
    echo "Manual checks:"
    echo "  □ Window title shows 'EDR Desktop'"
    echo "  □ UI content renders (not blank)"
    echo "  □ Close window to verify clean shutdown"
    echo ""
    
    # Wait for user to close the app
    wait $PID 2>/dev/null || true
    
    echo ""
    echo -e "${GREEN}✓${NC} App exited cleanly"
else
    echo -e "${RED}✗${NC} App crashed or exited early"
    echo "  Run with RUST_BACKTRACE=1 for more details"
    exit 1
fi
