#!/bin/bash
set -e

echo "===================================================="
echo "  nm-applet TOFU - System-Wide Build & Install"
echo "===================================================="

echo "[1/3] Installing build dependencies..."
sudo apt-get update
sudo apt-get install -y meson ninja-build build-essential
sudo apt-get build-dep -y network-manager-applet

echo "[2/3] Configuring and compiling..."
if [ -d "build" ]; then
    rm -rf build
fi

# Install to standard system paths
meson setup build --prefix=/usr --sysconfdir=/etc
ninja -C build

echo "[3/3] Installing to system (/usr)..."
sudo ninja -C build install

echo "===================================================="
echo "Installation Complete!"
echo ""
echo "To restart the GUI, run the following commands:"
echo "  killall nm-applet"
echo "  nm-applet &"
echo "===================================================="