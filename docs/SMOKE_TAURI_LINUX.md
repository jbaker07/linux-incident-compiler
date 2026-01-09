# Tauri Linux Smoke Test Checklist

This checklist validates that the EDR Desktop GUI runs correctly on Linux with
a graphical display session (X11 or Wayland).

---

## Prerequisites

### System Requirements
- **Display Session:** X11 or Wayland (Gnome, KDE, Sway, etc.)
- **Environment Variables:**
  - `$DISPLAY` set (X11) or `$WAYLAND_DISPLAY` set (Wayland)
  - `$XDG_SESSION_TYPE` is `x11` or `wayland`

### Dependencies
Install the following packages:

**Ubuntu/Debian:**
```bash
sudo apt install -y \
  libwebkit2gtk-4.1-dev \
  libgtk-3-dev \
  librsvg2-dev \
  libsoup-3.0-dev \
  libjavascriptcoregtk-4.1-dev
```

**Fedora:**
```bash
sudo dnf install -y \
  webkit2gtk4.1-devel \
  gtk3-devel \
  librsvg2-devel \
  libsoup3-devel \
  javascriptcoregtk4.1-devel
```

---

## Build

```bash
cd src-tauri
cargo build --release
```

The binary is located at: `src-tauri/target/release/edr-desktop`

---

## Smoke Test Procedure

### 1. Launch Application
```bash
./src-tauri/target/release/edr-desktop
```

**Expected:** Application window opens without crash.

### 2. Verify Window
- [ ] Window title shows "EDR Desktop"
- [ ] Window is resizable (grab edges)
- [ ] Window has close/minimize/maximize decorations

### 3. Verify UI Loads
- [ ] Main UI content renders (not blank white screen)
- [ ] Navigation elements visible
- [ ] No JavaScript console errors (check with F12 if available)

### 4. Check Supervisor Status
Look at terminal output for:
```
INFO edr_desktop::supervisor: Supervisor initialized: port=XXXX
INFO edr_desktop: Supervisor state registered, UI ready
```

**Expected:** Supervisor initializes successfully.

### 5. Test Start/Stop (if running as root)
If running with `sudo`:
- [ ] Click "Start" to begin a run
- [ ] Verify capture processes spawn
- [ ] Click "Stop" to end the run
- [ ] Verify clean shutdown

### 6. Verify Non-Root Mode
Without root:
- [ ] App shows "Limited mode" or similar indicator
- [ ] App does not crash
- [ ] Status shows non-admin state

### 7. Window Close
- [ ] Close window via X button
- [ ] Verify clean shutdown in terminal (no errors)

---

## Known Issues

### libEGL Warning
```
libEGL warning: egl: failed to create dri2 screen
```
**Status:** Benign. This is a GPU driver message, not an application error.
The app functions normally despite this warning.

### WebKit2GTK Version
- Requires `webkit2gtk-4.1` (WebKit2GTK 2.38+)
- Older versions may cause rendering issues

### Wayland Clipboard
- Clipboard may require `wl-clipboard` package for copy/paste

---

## Troubleshooting

### Blank White Window
- Check WebKit2GTK is installed
- Verify `ui/index.html` exists in workspace root
- Run with `RUST_LOG=debug` for more info

### Window Doesn't Open
- Check `$DISPLAY` or `$WAYLAND_DISPLAY` is set
- Try running from a terminal inside the desktop session
- Check for missing GTK dependencies: `ldd ./edr-desktop | grep "not found"`

### Crash on Startup
- Run with `RUST_BACKTRACE=1` to get stack trace
- Check icon files are valid PNGs (32x32 RGBA)
- Verify `tauri.conf.json` has correct paths

---

## Quick Validation Script

```bash
#!/usr/bin/env bash
# smoke-tauri.sh - Quick Tauri smoke test

set -e

echo "=== Tauri Linux Smoke Test ==="

# Check display
if [ -z "$DISPLAY" ] && [ -z "$WAYLAND_DISPLAY" ]; then
    echo "ERROR: No display session detected"
    exit 1
fi
echo "✓ Display: ${XDG_SESSION_TYPE:-unknown} (DISPLAY=$DISPLAY)"

# Check binary
BINARY="src-tauri/target/release/edr-desktop"
if [ ! -x "$BINARY" ]; then
    echo "ERROR: Binary not found. Run: cd src-tauri && cargo build --release"
    exit 1
fi
echo "✓ Binary: $BINARY"

# Check UI assets
if [ ! -f "ui/index.html" ]; then
    echo "ERROR: ui/index.html not found"
    exit 1
fi
echo "✓ UI assets present"

# Launch and wait
echo "Launching EDR Desktop..."
timeout 10 "$BINARY" &
PID=$!
sleep 5

if kill -0 $PID 2>/dev/null; then
    echo "✓ App launched successfully (PID: $PID)"
    echo "  Close the window to complete the test."
    wait $PID 2>/dev/null || true
else
    echo "ERROR: App crashed or exited early"
    exit 1
fi

echo "=== Smoke test complete ==="
```

---

## Results

| Test | Status | Notes |
|------|--------|-------|
| Build | ✅ | `cargo build --release` succeeds |
| Launch | ✅ | Window opens, supervisor initializes |
| UI Render | ✅ | Content loads correctly |
| Non-root | ✅ | Works in limited mode |
| Window Close | ✅ | Clean shutdown |

**Validated on:** Ubuntu 22.04 (Wayland), 2026-01-09
