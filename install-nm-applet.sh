#!/bin/bash
set -e

echo "===================================================="
echo "  nm-applet TOFU - Automated Build & Install"
echo "===================================================="

echo "[1/3] Installing build dependencies..."
sudo apt-get update
sudo apt-get install -y meson ninja-build build-essential
sudo apt-get build-dep -y network-manager-applet

echo "[2/3] Configuring and compiling..."
INSTALL_DIR="$HOME/.local/tofu_nm_applet"

if [ -d "build" ]; then
    rm -rf build
fi

meson setup build --prefix="$INSTALL_DIR"
ninja -C build

echo "[3/3] Installing to $INSTALL_DIR..."
ninja -C build install

echo "===================================================="
echo "✅ Installation Complete!"
echo ""
echo "To test the GUI, run the following commands in your terminal:"
echo "  killall nm-applet"
echo "  $INSTALL_DIR/bin/nm-applet &"
echo "===================================================="