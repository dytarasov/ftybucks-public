#!/bin/bash
set -e

BINARY_NAME="shadowtunnel-client"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="$HOME/.config/ftybucks"
ALIAS_NAME="ftybucks"

# --- Embedded config ---
CONFIG='server: "YOUR_SERVER_IP:5432"
psk: "CHANGE_ME"  # generate with: openssl rand -base64 32
dns: "https://1.1.1.1/dns-query"
padding:
  min: 0
  max: 64'

echo ""
echo "==========================="
echo "  FtyBucks — Mac Installer"
echo "==========================="
echo ""

# Find binary next to this script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/$BINARY_NAME"

if [ ! -f "$BINARY" ]; then
    echo "[x] Binary not found: $BINARY"
    exit 1
fi

# Install binary
echo "[*] Installing binary to $INSTALL_DIR/$BINARY_NAME ..."
sudo cp "$BINARY" "$INSTALL_DIR/$BINARY_NAME"
sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
echo "[+] Binary installed"

# Write config
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/client.yaml" ]; then
    echo "$CONFIG" > "$CONFIG_DIR/client.yaml"
    echo "[+] Config written to $CONFIG_DIR/client.yaml"
else
    echo "[~] Config already exists at $CONFIG_DIR/client.yaml, skipping"
fi

# Setup zsh alias
ZSHRC="$HOME/.zshrc"
ALIAS_LINE="alias $ALIAS_NAME='sudo $INSTALL_DIR/$BINARY_NAME connect'"

if [ -f "$ZSHRC" ] && grep -qF "$ALIAS_NAME=" "$ZSHRC"; then
    echo "[~] Alias '$ALIAS_NAME' already in .zshrc, skipping"
else
    echo "" >> "$ZSHRC"
    echo "# FtyBucks VPN" >> "$ZSHRC"
    echo "$ALIAS_LINE" >> "$ZSHRC"
    echo "[+] Alias added: $ALIAS_NAME -> sudo $BINARY_NAME connect"
fi

echo ""
echo "Done! Run: source ~/.zshrc && ftybucks"
echo ""
