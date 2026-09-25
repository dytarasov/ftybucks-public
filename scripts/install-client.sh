#!/bin/bash
set -e

BINARY="shadowtunnel-client"
BUILT="bin/shadowtunnel-client-linux"   # what `make client` produces
CONFIG_DIR="/etc/shadowtunnel"
INSTALL_DIR="/usr/local/bin"

echo "Installing ShadowTunnel client..."

# Copy binary
if [ ! -f "$BUILT" ]; then
    echo "Binary not found: $BUILT — run 'make client' first"
    exit 1
fi
cp "$BUILT" "$INSTALL_DIR/$BINARY"
chmod +x "$INSTALL_DIR/$BINARY"

# Copy config
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/client.yaml" ]; then
    cp configs/client.example.yaml "$CONFIG_DIR/client.yaml"
    echo "Config copied to $CONFIG_DIR/client.yaml — edit it with your server details"
else
    echo "Config already exists at $CONFIG_DIR/client.yaml, skipping"
fi

# Create systemd service
cat > /etc/systemd/system/shadowtunnel.service << 'EOF'
[Unit]
Description=ShadowTunnel VPN Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/shadowtunnel-client connect -c /etc/shadowtunnel/client.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable shadowtunnel

echo "Installed. Start with: sudo systemctl start shadowtunnel"
