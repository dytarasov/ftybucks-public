#!/bin/bash
set -e

BINARY="shadowtunnel-client"
CONFIG_DIR="/etc/shadowtunnel"
INSTALL_DIR="/usr/local/bin"

echo "Installing ShadowTunnel client..."

# Copy binary
cp "bin/$BINARY" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/$BINARY"

# Copy config
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/client.yaml" ]; then
    cp configs/client.yaml "$CONFIG_DIR/"
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
ExecStart=/usr/local/bin/shadowtunnel-client -config /etc/shadowtunnel/client.yaml
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
